package auth

import (
	"auth/resultor"
	"github.com/jacoblai/httprouter"
	"github.com/pquerna/ffjson/ffjson"
	"gopkg.in/mgo.v2/bson"
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

	mg := d.GetSess()
	defer mg.Close()

	c := d.GetColl(mg, "configs")
	var objs map[string]interface{}
	err := c.FindId(bson.ObjectIdHex("5bae43aa53c61312eec64c04")).One(&objs)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
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

	mg := d.GetSess()
	defer mg.Close()

	c := d.GetColl(mg, "configs")
	_, err = c.Upsert(bson.M{"_id": bson.ObjectIdHex("5bae43aa53c61312eec64c04")}, bson.M{"$set": obj})
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetChanges(w, 1)
}
