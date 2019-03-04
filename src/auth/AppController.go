package auth

import (
	"auth/models"
	"auth/resultor"
	"context"
	"github.com/jacoblai/httprouter"
	"github.com/jacoblai/validation"
	"github.com/pquerna/ffjson/ffjson"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"io/ioutil"
	"net/http"
	"time"
)

func (d *DbEngine) CreateApps(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	//用户信息
	uoid := r.Header.Get("uoid")
	rule := r.Header.Get("rule")
	if rule != "admin" && rule != "developer" {
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

	var obj models.App
	err = ffjson.Unmarshal(body, &obj)
	if err != nil {
		resultor.RetErr(w, "提交内容错误")
		return
	}

	if !validation.IsDomain(obj.SafeRequest) {
		resultor.RetErr(w, "安全域名不合法")
		return
	}

	puoid, err := primitive.ObjectIDFromHex(uoid)
	if err != nil {
		resultor.RetErr(w, "1003")
		return
	}

	ag := d.GetColl("users")
	var u models.User
	re := ag.FindOne(context.Background(), bson.M{"_id": puoid})
	if re.Err() != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}
	_ = re.Decode(&u)

	obj.Id = primitive.NewObjectID()
	obj.UserId = u.Id
	obj.AppId = d.RandStringRunes(32)
	obj.AppSecret = d.RandStringRunes(64)
	obj.CreateAt = time.Now().Local()
	stat := false
	obj.IsDisable = &stat

	appdb := d.GetColl(models.T_APP)
	ct, _ := appdb.CountDocuments(context.Background(), bson.M{"name": obj.Name})
	if ct > 0 {
		resultor.RetErr(w, "APP名称已被占用")
		return
	}

	_, err = appdb.InsertOne(context.Background(), &obj)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetOk(w, obj, 1)
}

func (d *DbEngine) GetApps(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	//用户信息
	uoid := r.Header.Get("uoid")
	rule := r.Header.Get("rule")
	if rule != "admin" && rule != "developer" {
		resultor.RetErr(w, "账号权限不足")
		return
	}

	puoid, err := primitive.ObjectIDFromHex(uoid)
	if err != nil {
		resultor.RetErr(w, "1003")
		return
	}

	appdb := d.GetColl("apps")
	var apps []models.App
	re, err := appdb.Find(context.Background(), bson.M{"user_id": puoid})
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	_ = re.Decode(&apps)

	resultor.RetOk(w, apps, len(apps))
}

func (d *DbEngine) GetApp(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	appid := ps.ByName("id")
	if appid == "" || !InjectionPass([]byte(appid)) {
		resultor.RetErr(w, "1003")
		return
	}

	//用户信息
	uoid := r.Header.Get("uoid")
	rule := r.Header.Get("rule")
	if rule != "admin" && rule != "developer" {
		resultor.RetErr(w, "账号权限不足")
		return
	}

	puoid, err := primitive.ObjectIDFromHex(uoid)
	if err != nil {
		resultor.RetErr(w, "1003")
		return
	}

	appdb := d.GetColl("apps")
	var app models.App
	re := appdb.FindOne(context.Background(), bson.M{"user_id": puoid, "app_id": appid})
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	_ = re.Decode(&app)

	resultor.RetOk(w, app, 1)
}

func (d *DbEngine) GetPubApp(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	appid := ps.ByName("id")
	if appid == "" || !InjectionPass([]byte(appid)) {
		resultor.RetErr(w, "1003")
		return
	}

	appdb := d.GetColl("apps")
	var app map[string]interface{}
	re := appdb.FindOne(context.Background(), bson.M{"app_id": appid}, options.FindOne().SetProjection(bson.M{"name": 1, "avatar": 1}))
	if re.Err() != nil {
		resultor.RetErr(w, re.Err().Error())
		return
	}
	_ = re.Decode(&app)

	resultor.RetOk(w, app, 1)
}

func (d *DbEngine) AppAvatar(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()
	appid := ps.ByName("id")
	if appid == "" || !InjectionPass([]byte(appid)) {
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

	if !validation.IsURL(obj["avatar"]) {
		resultor.RetErr(w, "头像地址无效")
		return
	}

	//用户信息
	uoid := r.Header.Get("uoid")
	rule := r.Header.Get("rule")
	if rule != "admin" && rule != "developer" {
		resultor.RetErr(w, "账号权限不足")
		return
	}

	puoid, err := primitive.ObjectIDFromHex(uoid)
	if err != nil {
		resultor.RetErr(w, "1003")
		return
	}

	ag := d.GetColl("users")
	var u models.User
	re := ag.FindOne(context.Background(), bson.M{"_id": puoid})
	if re.Err() != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}
	_ = re.Decode(&u)

	appdb := d.GetColl("apps")
	re = appdb.FindOneAndUpdate(context.Background(), bson.M{"user_id": u.Id, "app_id": appid}, bson.M{"$set": bson.M{"avatar": obj["avatar"]}})
	if re.Err() != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetOk(w, obj["avatar"], 1)
}

func (d *DbEngine) AppNewSecret(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	appid := ps.ByName("id")
	if appid == "" || !InjectionPass([]byte(appid)) {
		resultor.RetErr(w, "1003")
		return
	}

	//用户信息
	uoid := r.Header.Get("uoid")
	rule := r.Header.Get("rule")
	if rule != "admin" && rule != "developer" {
		resultor.RetErr(w, "账号权限不足")
		return
	}

	puoid, err := primitive.ObjectIDFromHex(uoid)
	if err != nil {
		resultor.RetErr(w, "1003")
		return
	}

	ag := d.GetColl("users")
	var u models.User
	re := ag.FindOne(context.Background(), bson.M{"_id": puoid})
	if re.Err() != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}
	_ = re.Decode(&u)

	appdb := d.GetColl("apps")
	re = appdb.FindOneAndUpdate(context.Background(), bson.M{"user_id": u.Id, "app_id": appid}, bson.M{"$set": bson.M{"app_secret": d.RandStringRunes(64)}})
	if re.Err() != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetChanges(w, 1)
}

func (d *DbEngine) AppUpdate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	appid := ps.ByName("id")
	if appid == "" || !InjectionPass([]byte(appid)) {
		resultor.RetErr(w, "1003")
		return
	}

	//用户信息
	uoid := r.Header.Get("uoid")
	rule := r.Header.Get("rule")
	if rule != "admin" && rule != "developer" {
		resultor.RetErr(w, "账号权限不足")
		return
	}

	puoid, err := primitive.ObjectIDFromHex(uoid)
	if err != nil {
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

	delete(obj, "_id")

	if len(obj) == 0 {
		resultor.RetErr(w, "没有收到可更新内容")
		return
	}

	ag := d.GetColl("users")
	var u models.User
	re := ag.FindOne(context.Background(), bson.M{"_id": puoid})
	if re.Err() != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}
	_ = re.Decode(&u)

	appdb := d.GetColl("apps")
	re = appdb.FindOneAndUpdate(context.Background(), bson.M{"user_id": u.Id, "app_id": appid}, bson.M{"$set": obj})
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetChanges(w, 1)
}

func (d *DbEngine) AppDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	appid := ps.ByName("id")
	if appid == "" || !InjectionPass([]byte(appid)) {
		resultor.RetErr(w, "1003")
		return
	}

	//用户信息
	uoid := r.Header.Get("uoid")
	rule := r.Header.Get("rule")
	if rule != "admin" && rule != "developer" {
		resultor.RetErr(w, "账号权限不足")
		return
	}

	puoid, err := primitive.ObjectIDFromHex(uoid)
	if err != nil {
		resultor.RetErr(w, "1003")
		return
	}

	ag := d.GetColl("users")
	var u models.User
	re := ag.FindOne(context.Background(), bson.M{"_id": puoid})
	if re.Err() != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}
	_ = re.Decode(&u)

	appdb := d.GetColl("apps")
	re = appdb.FindOneAndDelete(context.Background(), bson.M{"user_id": u.Id, "app_id": appid})
	if re.Err() != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	//todo 删除所有关联的上传文件

	resultor.RetChanges(w, 1)
}
