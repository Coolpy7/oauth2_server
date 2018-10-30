package auth

import (
	"auth/models"
	"auth/resultor"
	"github.com/jacoblai/httprouter"
	"github.com/pquerna/ffjson/ffjson"
	"gopkg.in/mgo.v2/bson"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func (d *DbEngine) AddForm(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	var obj models.Form
	err = ffjson.Unmarshal(body, &obj)
	if err != nil {
		resultor.RetErr(w, "提交内容错误")
		return
	}

	//用户信息
	uoid := r.Header.Get("uoid")
	rule := r.Header.Get("rule")
	if rule != "user" {
		resultor.RetErr(w, "只允许普通用户申请成为开发者")
		return
	}

	mg := d.GetSess()
	defer mg.Close()

	formdb := d.GetColl(mg, "forms")

	ct, _ := formdb.Find(bson.M{"useroid": bson.ObjectId(uoid), "state": "待审核"}).Count()
	if ct > 0 {
		resultor.RetErr(w, "你已有待审核申请，请联系管理员审核申请记录")
		return
	}

	stat := false
	t := time.Now().Local()
	obj.Id = bson.NewObjectId()
	obj.CreateAt = t
	obj.IsDisable = &stat
	obj.UserOid = bson.ObjectIdHex(uoid)
	obj.State = "待审核"
	err = formdb.Insert(&obj)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetChanges(w, 1)
}

func (d *DbEngine) GetForm(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	state := qr.Get("state")
	cond := bson.M{}
	if state != "" {
		cond["state"] = state
	}

	mg := d.GetSess()
	defer mg.Close()

	c := d.GetColl(mg, "forms")
	query := make([]map[string]interface{}, 0)
	query = append(query, bson.M{"$match": cond})
	query = append(query, bson.M{"$lookup": bson.M{
		"from":         "users",
		"localField":   "useroid",
		"foreignField": "_id",
		"as":           "user",
	}})
	query = append(query, bson.M{"$unwind": "$user"})
	query = append(query, bson.M{"$project": bson.M{"user.pwd": 0}})
	query = append(query, bson.M{"$skip": skip})
	if limit > 0 {
		query = append(query, bson.M{"$limit": limit})
	}
	query = append(query, bson.M{"$sort": bson.M{"createat": -1}})
	var objs []map[string]interface{}
	if err := c.Pipe(query).All(&objs); err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	ct, _ := c.Find(cond).Count()
	resultor.RetOk(w, &objs, ct)
}

func (d *DbEngine) PutForm(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	foid := ps.ByName("id")
	if foid == "" || !InjectionPass([]byte(foid)) || !bson.IsObjectIdHex(foid) {
		resultor.RetErr(w, "1003")
		return
	}

	//用户信息
	rule := r.Header.Get("rule")
	if rule != "admin" {
		resultor.RetErr(w, "账号权限不足")
		return
	}

	qr := r.URL.Query()
	result := qr.Get("result")
	if result != "0" && result != "1" {
		resultor.RetErr(w, "1003")
		return
	}

	rs := "审核通过"
	if result == "1" {
		rs = "拒绝"
	}

	mg := d.GetSess()
	defer mg.Close()

	c := d.GetColl(mg, "forms")
	var form models.Form
	err := c.Find(bson.M{"_id": bson.ObjectIdHex(foid), "state": "待审核"}).One(&form)
	if err != nil {
		resultor.RetErr(w, "该申请已被处理过")
		return
	}

	u := d.GetColl(mg, "users")
	err = u.UpdateId(form.UserOid, bson.M{"$set": bson.M{"rule": "developer"}})
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	err = c.UpdateId(bson.ObjectIdHex(foid), bson.M{"$set": bson.M{"state": "已完成", "result": rs}})
	if err != nil {
		resultor.RetErr(w, "无效申请id")
		return
	}

	resultor.RetChanges(w, 1)
}
