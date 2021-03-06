package auth

import (
	"auth/models"
	"auth/resultor"
	"context"
	"errors"
	"github.com/jacoblai/httprouter"
	"github.com/pquerna/ffjson/ffjson"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
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
	puoid, err := primitive.ObjectIDFromHex(uoid)
	if err != nil {
		resultor.RetErr(w, "1003")
		return
	}

	formdb := d.GetColl("forms")
	ct, _ := formdb.CountDocuments(context.Background(), bson.M{"useroid": puoid, "state": "待审核"})
	if ct > 0 {
		resultor.RetErr(w, "你已有待审核申请，请联系管理员审核申请记录")
		return
	}

	stat := false
	t := time.Now().Local()
	obj.Id = primitive.NewObjectID()
	obj.CreateAt = t
	obj.IsDisable = &stat
	obj.UserOid = puoid
	obj.State = "待审核"
	_, err = formdb.InsertOne(context.Background(), &obj)
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

	c := d.GetColl("forms")
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
	re, err := c.Aggregate(context.Background(), query)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	for re.Next(context.Background()) {
		var m map[string]interface{}
		_ = re.Decode(&m)
		objs = append(objs, m)
	}
	ct, _ := c.CountDocuments(context.Background(), cond)
	resultor.RetOk(w, &objs, int(ct))
}

func (d *DbEngine) PutForm(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	foid := ps.ByName("id")
	if foid == "" || !InjectionPass([]byte(foid)) {
		resultor.RetErr(w, "1003")
		return
	}
	fid, err := primitive.ObjectIDFromHex(foid)
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

	c := d.GetColl("forms")
	var form models.Form
	re := c.FindOne(context.Background(), bson.M{"_id": fid, "state": "待审核"})
	if re.Err() != nil {
		resultor.RetErr(w, "该申请已被处理过")
		return
	}
	_ = re.Decode(&form)

	u := d.GetColl("users")

	sess, err := d.GetSess()
	if err != nil {
		resultor.RetErr(w, "事务开始失败")
		return
	}
	defer sess.EndSession(context.Background())

	err = mongo.WithSession(context.Background(), sess, func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			return err
		}
		re = u.FindOneAndUpdate(sessionContext, bson.M{"_id": form.UserOid}, bson.M{"$set": bson.M{"rule": "developer"}})
		if re.Err() != nil {
			err = sessionContext.AbortTransaction(sessionContext)
			if err != nil {
				return err
			}
			return re.Err()
		}
		re = c.FindOneAndUpdate(context.Background(), bson.M{"_id": fid}, bson.M{"$set": bson.M{"state": "已完成", "result": rs}})
		if re.Err() != nil {
			err = sessionContext.AbortTransaction(sessionContext)
			if err != nil {
				return err
			}
			return errors.New("无效申请id")
		}
		return sessionContext.CommitTransaction(sessionContext)
	})
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetChanges(w, 1)
}
