package auth

import (
	"auth/models"
	"auth/resultor"
	"context"
	"github.com/jacoblai/httprouter"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"strconv"
)

func (d *DbEngine) GetAuths(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()
	qr := r.URL.Query()
	sk := qr.Get("skip")
	skip, _ := strconv.Atoi(sk)
	li := qr.Get("limit")
	limit, _ := strconv.Atoi(li)
	if skip < 0 || limit < 0 {
		resultor.RetErr(w, "1003")
		return
	}

	//用户信息
	uoid := r.Header.Get("uoid")
	puoid, err := primitive.ObjectIDFromHex(uoid)
	if err != nil {
		resultor.RetErr(w, "1003")
		return
	}

	c := d.GetColl("auths")
	cond := bson.M{"user_id": puoid}
	query := make([]map[string]interface{}, 0)
	query = append(query, bson.M{"$match": cond})
	query = append(query, bson.M{"$lookup": bson.M{
		"from":         "apps",
		"localField":   "app_id",
		"foreignField": "app_id",
		"as":           "app",
	}})
	query = append(query, bson.M{"$unwind": "$app"})
	query = append(query, bson.M{"$project": bson.M{"code": 0, "app.app_secret": 0, "app.app_id": 0, "app.safe_download": 0, "app.safe_request": 0, "app.safe_socket": 0, "app.safe_upload": 0, "app.user_id": 0}})
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

func (d *DbEngine) AuthDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	authid := ps.ByName("id")
	if authid == "" || !InjectionPass([]byte(authid)) {
		resultor.RetErr(w, "1003")
		return
	}
	authoid, err := primitive.ObjectIDFromHex(authid)
	if err != nil {
		resultor.RetErr(w, "1003")
		return
	}

	//用户信息
	uoid := r.Header.Get("uoid")
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

	c := d.GetColl("auths")
	re = c.FindOneAndDelete(context.Background(), bson.M{"user_id": u.Id, "_id": authoid})
	if re.Err() != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetChanges(w, 1)
}
