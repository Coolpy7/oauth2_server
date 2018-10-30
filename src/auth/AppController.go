package auth

import (
	"auth/models"
	"auth/resultor"
	"github.com/jacoblai/httprouter"
	"github.com/jacoblai/validation"
	"github.com/pquerna/ffjson/ffjson"
	"gopkg.in/mgo.v2/bson"
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

	mg := d.GetSess()
	defer mg.Close()

	ag := d.GetColl(mg, "users")
	var u models.User
	err = ag.FindId(bson.ObjectIdHex(uoid)).One(&u)
	if err != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}

	obj.Id = bson.NewObjectId()
	obj.UserId = u.Id
	obj.AppId = d.RandStringRunes(32)
	obj.AppSecret = d.RandStringRunes(64)
	obj.CreateAt = time.Now().Local()
	stat := false
	obj.IsDisable = &stat

	appdb := d.GetColl(mg, "apps")
	ct, _ := appdb.Find(bson.M{"name": obj.Name}).Count()
	if ct > 0 {
		resultor.RetErr(w, "APP名称已被占用")
		return
	}

	err = appdb.Insert(&obj)
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

	mg := d.GetSess()
	defer mg.Close()

	appdb := d.GetColl(mg, "apps")
	var apps []models.App
	err := appdb.Find(bson.M{"user_id": bson.ObjectIdHex(uoid)}).All(&apps)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

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

	mg := d.GetSess()
	defer mg.Close()

	appdb := d.GetColl(mg, "apps")
	var app models.App
	err := appdb.Find(bson.M{"user_id": bson.ObjectIdHex(uoid), "app_id": appid}).One(&app)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetOk(w, app, 1)
}

func (d *DbEngine) GetPubApp(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	appid := ps.ByName("id")
	if appid == "" || !InjectionPass([]byte(appid)) {
		resultor.RetErr(w, "1003")
		return
	}

	mg := d.GetSess()
	defer mg.Close()

	appdb := d.GetColl(mg, "apps")
	var app map[string]interface{}
	err := appdb.Find(bson.M{"app_id": appid}).Select(bson.M{"name": 1, "avatar": 1}).One(&app)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

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

	mg := d.GetSess()
	defer mg.Close()

	ag := d.GetColl(mg, "users")
	var u models.User
	err = ag.FindId(bson.ObjectIdHex(uoid)).One(&u)
	if err != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}

	appdb := d.GetColl(mg, "apps")
	err = appdb.Update(bson.M{"user_id": u.Id, "app_id": appid}, bson.M{"$set": bson.M{"avatar": obj["avatar"]}})
	if err != nil {
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

	mg := d.GetSess()
	defer mg.Close()

	ag := d.GetColl(mg, "users")
	var u models.User
	err := ag.FindId(bson.ObjectIdHex(uoid)).One(&u)
	if err != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}

	appdb := d.GetColl(mg, "apps")
	err = appdb.Update(bson.M{"user_id": u.Id, "app_id": appid}, bson.M{"$set": bson.M{"app_secret": d.RandStringRunes(64)}})
	if err != nil {
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

	mg := d.GetSess()
	defer mg.Close()

	ag := d.GetColl(mg, "users")
	var u models.User
	err = ag.FindId(bson.ObjectIdHex(uoid)).One(&u)
	if err != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}

	appdb := d.GetColl(mg, "apps")
	err = appdb.Update(bson.M{"user_id": u.Id, "app_id": appid}, bson.M{"$set": obj})
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

	mg := d.GetSess()
	defer mg.Close()

	ag := d.GetColl(mg, "users")
	var u models.User
	err := ag.FindId(bson.ObjectIdHex(uoid)).One(&u)
	if err != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}

	appdb := d.GetColl(mg, "apps")
	err = appdb.Remove(bson.M{"user_id": u.Id, "app_id": appid})
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	//todo 删除所有关联的上传文件

	resultor.RetChanges(w, 1)
}
