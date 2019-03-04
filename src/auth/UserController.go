package auth

import (
	"auth/jcrypt"
	"auth/models"
	"auth/resultor"
	"context"
	"encoding/hex"
	"errors"
	"github.com/jacoblai/httprouter"
	"github.com/jacoblai/validation"
	"github.com/pquerna/ffjson/ffjson"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

func (d *DbEngine) Reg(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	qr := r.URL.Query()
	code := qr.Get("code")
	if code == "" || len(code) != 6 || !InjectionPass([]byte(code)) {
		resultor.RetErr(w, "1003")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	if len(body) == 0 {
		resultor.RetErr(w, "1001")
		return
	}

	//防注入
	if !InjectionPass(body) {
		resultor.RetErr(w, "1002")
		return
	}

	var obj map[string]interface{}
	err = ffjson.Unmarshal(body, &obj)
	if err != nil {
		resultor.RetErr(w, "提交内容错误")
		return
	}

	if !validation.IsCnMobile(obj["phone"]) {
		resultor.RetErr(w, "手机号码无效")
		return
	}

	if !validation.IsEmail(obj["mail"]) {
		resultor.RetErr(w, "邮箱地址无效")
		return
	}

	if len(obj["pwd"].(string)) < 6 {
		resultor.RetErr(w, "密码长度无效")
		return
	}

	s := d.GetColl("smss")
	var sms1 models.Sms
	re := s.FindOne(context.Background(), bson.M{"code": obj["phonecode"], "phone": obj["phone"]})
	if re.Err() != nil {
		resultor.RetErr(w, "手机验证码错误")
		return
	}
	_ = re.Decode(&sms1)

	var sms2 models.Sms
	re = s.FindOne(context.Background(), bson.M{"code": obj["mailcode"], "phone": obj["mail"]})
	if re.Err() != nil {
		resultor.RetErr(w, "邮箱验证码错误")
		return
	}
	_ = re.Decode(&sms2)

	if m, _ := regexp.MatchString(`^[a-z0-9_]+$`, obj["pwd"].(string)); !m {
		resultor.RetErr(w, "密码不合法")
		return
	}

	ag := d.GetColl("users")
	stat := false
	t := time.Now().Local()
	nu := models.User{}
	nu.Id = primitive.NewObjectID()
	nu.CreateAt = t
	nu.IsDisable = &stat
	nu.Pwd = hex.EncodeToString(jcrypt.MsgEncode([]byte(obj["pwd"].(string))))
	nu.Rule = "user"
	nu.Uid = obj["uid"].(string)
	nu.Phone = obj["phone"].(string)
	nu.Mail = obj["mail"].(string)

	agct, err := ag.CountDocuments(context.Background(), bson.M{"phone": obj["phone"]})
	if err != nil || agct > 0 {
		resultor.RetErr(w, "手机号已存在")
		return
	}

	mct, err := ag.CountDocuments(context.Background(), bson.M{"mail": obj["mail"]})
	if err != nil || mct > 0 {
		resultor.RetErr(w, "邮箱已存在")
		return
	}

	if m, _ := regexp.MatchString(`^[a-z0-9]+$`, obj["uid"].(string)); !m {
		resultor.RetErr(w, "用户id不合法")
		return
	}

	aguct, err := ag.CountDocuments(context.Background(), bson.M{"uid": obj["uid"]})
	if err != nil || aguct > 0 {
		resultor.RetErr(w, "用户id已存在")
		return
	}

	_, err = ag.InsertOne(context.Background(), &nu)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	//删除验证码
	s.FindOneAndDelete(context.Background(), bson.M{"_id": sms1.Id})
	s.FindOneAndDelete(context.Background(), bson.M{"_id": sms2.Id})

	resultor.RetChanges(w, 1)
}

func (d *DbEngine) Upwd(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	qr := r.URL.Query()
	code := qr.Get("code")
	if code == "" || len(code) != 6 || !InjectionPass([]byte(code)) {
		resultor.RetErr(w, "1003")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	if len(body) == 0 {
		resultor.RetErr(w, "1001")
		return
	}

	//防注入
	if !InjectionPass(body) {
		resultor.RetErr(w, "1002")
		return
	}

	var obj map[string]string
	err = ffjson.Unmarshal(body, &obj)
	if err != nil {
		resultor.RetErr(w, "提交内容错误")
		return
	}

	if _, ok := obj["kind"]; !ok {
		resultor.RetErr(w, "无效操作符")
		return
	}

	if _, ok := obj["npwd"]; !ok {
		resultor.RetErr(w, "没有接收到新密码")
		return
	}

	if len(obj["npwd"]) < 6 {
		resultor.RetErr(w, "密码长度未够")
		return
	}

	s := d.GetColl("smss")
	var sms models.Sms
	if obj["kind"] == "phone" {
		re := s.FindOne(context.Background(), bson.M{"code": code, "phone": obj["phone"]})
		_ = re.Decode(&sms)
	} else if obj["kind"] == "mail" {
		re := s.FindOne(context.Background(), bson.M{"code": code, "phone": obj["mail"]})
		_ = re.Decode(&sms)
	} else {
		err = errors.New("操作符无效")
	}
	if err != nil {
		resultor.RetErr(w, "验证码错误")
		return
	}

	ag := d.GetColl("users")
	var u models.User
	if obj["kind"] == "phone" {
		re := ag.FindOne(context.Background(), bson.M{"phone": obj["phone"]})
		_ = re.Decode(&u)
	} else {
		re := ag.FindOne(context.Background(), bson.M{"mail": obj["mail"]})
		_ = re.Decode(&u)
	}
	if err != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}

	uobj := make(map[string]interface{})
	uobj["pwd"] = hex.EncodeToString(jcrypt.MsgEncode([]byte(obj["npwd"])))
	uobj["updateat"] = time.Now().Local()
	re := ag.FindOneAndUpdate(context.Background(), bson.M{"_id": u.Id}, bson.M{"$set": uobj})
	if re.Err() != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	//删除验证码
	s.FindOneAndDelete(context.Background(), bson.M{"_id": sms.Id})

	resultor.RetChanges(w, 1)
}

func (d *DbEngine) Uphone(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	qr := r.URL.Query()
	code := qr.Get("code")
	if code == "" || len(code) != 6 || !InjectionPass([]byte(code)) {
		resultor.RetErr(w, "1003")
		return
	}
	ncode := qr.Get("ncode")
	if ncode == "" || len(ncode) != 6 || !InjectionPass([]byte(ncode)) {
		resultor.RetErr(w, "1003")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	if len(body) == 0 {
		resultor.RetErr(w, "1001")
		return
	}

	//防注入
	if !InjectionPass(body) {
		resultor.RetErr(w, "1002")
		return
	}

	var obj map[string]string
	err = ffjson.Unmarshal(body, &obj)
	if err != nil {
		resultor.RetErr(w, "提交内容错误")
		return
	}

	if _, ok := obj["phone"]; !ok {
		resultor.RetErr(w, "没有接收到旧电话号码")
		return
	}

	if !validation.IsCnMobile(obj["phone"]) {
		resultor.RetErr(w, "旧手机号码无效")
		return
	}

	if _, ok := obj["nphone"]; !ok {
		resultor.RetErr(w, "没有接收到新电话号码")
		return
	}

	if !validation.IsCnMobile(obj["nphone"]) {
		resultor.RetErr(w, "新手机号码无效")
		return
	}

	s := d.GetColl("smss")
	var osms models.Sms
	re := s.FindOne(context.Background(), bson.M{"code": code, "phone": obj["phone"]})
	if re.Err() != nil {
		resultor.RetErr(w, "旧手机号码验证码错误")
		return
	}
	_ = re.Decode(&osms)

	var nsms models.Sms
	re = s.FindOne(context.Background(), bson.M{"code": ncode, "phone": obj["nphone"]})
	if re.Err() != nil {
		resultor.RetErr(w, "新手机号码验证码错误")
		return
	}
	_ = re.Decode(&nsms)

	ag := d.GetColl("users")
	var u models.User
	re = ag.FindOne(context.Background(), bson.M{"phone": obj["phone"]})
	if re.Err() != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}
	_ = re.Decode(&u)

	uobj := make(map[string]interface{})
	uobj["phone"] = obj["nphone"]
	uobj["updateat"] = time.Now().Local()

	re = ag.FindOneAndUpdate(context.Background(), bson.M{"_id": u.Id}, bson.M{"$set": uobj})
	if re.Err() != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	//删除验证码
	s.FindOneAndDelete(context.Background(), bson.M{"_id": osms.Id})
	s.FindOneAndDelete(context.Background(), bson.M{"_id": nsms.Id})

	resultor.RetChanges(w, 1)
}

func (d *DbEngine) UMail(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	qr := r.URL.Query()
	code := qr.Get("code")
	if code != "" {
		if code == "" || len(code) != 6 || !InjectionPass([]byte(code)) {
			resultor.RetErr(w, "1003")
			return
		}
	}

	ncode := qr.Get("ncode")
	if ncode == "" || len(ncode) != 6 || !InjectionPass([]byte(ncode)) {
		resultor.RetErr(w, "1003")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	if len(body) == 0 {
		resultor.RetErr(w, "1001")
		return
	}

	//防注入
	if !InjectionPass(body) {
		resultor.RetErr(w, "1002")
		return
	}

	var obj map[string]string
	err = ffjson.Unmarshal(body, &obj)
	if err != nil {
		resultor.RetErr(w, "提交内容错误")
		return
	}

	if code != "" {
		if _, ok := obj["mail"]; !ok {
			resultor.RetErr(w, "没有接收到旧电子邮箱")
			return
		}

		if !validation.IsEmail(obj["mail"]) {
			resultor.RetErr(w, "旧电子邮箱无效")
			return
		}
	}

	if _, ok := obj["nmail"]; !ok {
		resultor.RetErr(w, "没有接收到新电子邮箱")
		return
	}

	if !validation.IsEmail(obj["nmail"]) {
		resultor.RetErr(w, "新电子邮箱无效")
		return
	}

	s := d.GetColl("smss")

	var osms models.Sms
	if code != "" {
		re := s.FindOne(context.Background(), bson.M{"code": code, "phone": obj["mail"]})
		if re.Err() != nil {
			resultor.RetErr(w, "旧电子邮箱验证码错误")
			return
		}
		_ = re.Decode(&osms)
	}

	var nsms models.Sms
	re := s.FindOne(context.Background(), bson.M{"code": ncode, "phone": obj["nmail"]})
	if re.Err() != nil {
		resultor.RetErr(w, "新电子邮箱验证码错误")
		return
	}
	_ = re.Decode(&nsms)

	ag := d.GetColl("users")
	var u models.User
	if code == "" {
		re = ag.FindOne(context.Background(), bson.M{"phone": obj["phone"]})
		if re.Err() != nil {
			resultor.RetErr(w, "用户不存在")
			return
		}
		_ = re.Decode(&u)
	} else {
		re = ag.FindOne(context.Background(), bson.M{"mail": obj["mail"]})
		if re.Err() != nil {
			resultor.RetErr(w, "用户不存在")
			return
		}
		_ = re.Decode(&u)
	}

	uobj := make(map[string]interface{})
	uobj["mail"] = obj["nmail"]
	uobj["updateat"] = time.Now().Local()

	re = ag.FindOneAndUpdate(context.Background(), bson.M{"_id": u.Id}, bson.M{"$set": uobj})
	if re.Err() != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	//删除验证码
	if code != "" {
		s.FindOneAndDelete(context.Background(), bson.M{"_id": osms.Id})
	}
	s.FindOneAndDelete(context.Background(), nsms.Id)

	resultor.RetChanges(w, 1)
}

func (d *DbEngine) UInfo(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	if len(body) == 0 {
		resultor.RetErr(w, "1001")
		return
	}

	//防注入
	if !InjectionPass(body) {
		resultor.RetErr(w, "1002")
		return
	}

	var obj models.User
	err = ffjson.Unmarshal(body, &obj)
	if err != nil {
		resultor.RetErr(w, "提交内容错误")
		return
	}

	bts, _ := ffjson.Marshal(&obj)
	var uobj map[string]interface{}
	_ = ffjson.Unmarshal(bts, &uobj)

	delete(uobj, "id")
	delete(uobj, "pwd")
	delete(uobj, "phone")
	delete(uobj, "mail")
	delete(uobj, "isdisable")
	delete(uobj, "createat")

	//用户信息
	uoid := r.Header.Get("uoid")
	poid, _ := primitive.ObjectIDFromHex(uoid)

	ag := d.GetColl("users")
	var u models.User
	re := ag.FindOne(context.Background(), bson.M{"_id": poid})
	if re.Err() != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}
	_ = re.Decode(&u)

	uobj["updateat"] = time.Now().Local()

	re = ag.FindOneAndUpdate(context.Background(), bson.M{"_id": u.Id}, bson.M{"$set": uobj})
	if re.Err() != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetChanges(w, 1)
}

func (d *DbEngine) GetUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	//用户信息
	rule := r.Header.Get("rule")
	if rule != "admin" {
		resultor.RetErr(w, "账号权限不足")
		return
	}

	qr := r.URL.Query()
	sk := qr.Get("skip")
	skip, _ := strconv.Atoi(sk)
	li := qr.Get("limit")
	limit, _ := strconv.Atoi(li)
	if skip < 0 || limit < 0 {
		resultor.RetErr(w, "1003")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	if len(body) == 0 {
		resultor.RetErr(w, "1001")
		return
	}

	//防注入
	if !InjectionPass(body) {
		resultor.RetErr(w, "1002")
		return
	}

	var obj map[string]interface{}
	err = ffjson.Unmarshal(body, &obj)
	if err != nil {
		resultor.RetErr(w, "提交内容错误")
		return
	}

	c := d.GetColl("users")
	users := make([]map[string]interface{}, 0)
	re, err := c.Find(context.Background(), obj, options.Find().SetProjection(bson.M{"pwd": 0}).SetSkip(int64(skip)).SetLimit(int64(limit)))
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	for re.Next(context.Background()) {
		var m map[string]interface{}
		_ = re.Decode(&m)
		users = append(users, m)
	}
	ct, _ := c.CountDocuments(context.Background(), obj)
	resultor.RetOk(w, &users, int(ct))
}

func (d *DbEngine) PutUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	uoid := ps.ByName("id")
	if uoid == "" || !InjectionPass([]byte(uoid)) {
		resultor.RetErr(w, "1003")
		return
	}

	puoid, err := primitive.ObjectIDFromHex(uoid)
	if err != nil {
		resultor.RetErr(w, "1003")
		return
	}

	//用户信息
	rule := r.Header.Get("rule")
	if rule != "admin" {
		resultor.RetErr(w, "账号权限不足")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	if len(body) == 0 {
		resultor.RetErr(w, "1001")
		return
	}

	//防注入
	if !InjectionPass(body) {
		resultor.RetErr(w, "1002")
		return
	}

	var obj map[string]interface{}
	err = ffjson.Unmarshal(body, &obj)
	if err != nil {
		resultor.RetErr(w, "提交内容错误")
		return
	}

	for k := range obj {
		if k == "pwd" {
			delete(obj, k)
		}
	}

	u := d.GetColl("users")
	re := u.FindOneAndUpdate(context.Background(), bson.M{"_id": puoid}, bson.M{"$set": obj})
	if re.Err() != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetChanges(w, 1)
}
