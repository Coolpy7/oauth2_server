package auth

import (
	"auth/models"
	"auth/resultor"
	"github.com/jacoblai/httprouter"
	"gopkg.in/mgo.v2/bson"
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

	mg := d.GetSess()
	defer mg.Close()

	c := d.GetColl(mg, "auths")
	cond := bson.M{"user_id": bson.ObjectIdHex(uoid)}
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
	if err := c.Pipe(query).All(&objs); err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	ct, _ := c.Find(cond).Count()
	resultor.RetOk(w, &objs, ct)
}

func (d *DbEngine) AuthDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	authid := ps.ByName("id")
	if authid == "" || !InjectionPass([]byte(authid)) || !bson.IsObjectIdHex(authid) {
		resultor.RetErr(w, "1003")
		return
	}

	//用户信息
	uoid := r.Header.Get("uoid")

	mg := d.GetSess()
	defer mg.Close()

	ag := d.GetColl(mg, "users")
	var u models.User
	err := ag.FindId(bson.ObjectIdHex(uoid)).One(&u)
	if err != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}

	c := d.GetColl(mg, "auths")
	err = c.Remove(bson.M{"user_id": u.Id, "_id": bson.ObjectIdHex(authid)})
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetChanges(w, 1)
}
