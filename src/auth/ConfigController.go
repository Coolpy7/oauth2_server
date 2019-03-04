package auth

import (
	"auth/resultor"
	"context"
	"github.com/jacoblai/httprouter"
	"github.com/pquerna/ffjson/ffjson"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"io/ioutil"
	"net/http"
)

func (d *DbEngine) GetConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	//用户信息
	rule := r.Header.Get("rule")
	if rule != "admin" {
		resultor.RetErr(w, "账号权限不足")
		return
	}
	oid, err := primitive.ObjectIDFromHex("5bae43aa53c61312eec64c04")
	if err != nil {
		resultor.RetErr(w, "1003")
		return
	}

	c := d.GetColl("configs")
	var objs map[string]interface{}
	re := c.FindOne(context.Background(), bson.M{"_id": oid})
	if re.Err() != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	_ = re.Decode(&objs)
	resultor.RetOk(w, &objs, 1)
}

func (d *DbEngine) PutConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

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

	//for k := range obj {
	//	if obj[k] == "" {
	//		delete(obj, k)
	//	}
	//}

	oid, err := primitive.ObjectIDFromHex("5bae43aa53c61312eec64c04")
	if err != nil {
		resultor.RetErr(w, "1003")
		return
	}

	c := d.GetColl("configs")
	re := c.FindOneAndUpdate(context.Background(), bson.M{"_id": oid}, bson.M{"$set": obj}, options.FindOneAndUpdate().SetUpsert(true))
	if re.Err() != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetChanges(w, 1)
}
