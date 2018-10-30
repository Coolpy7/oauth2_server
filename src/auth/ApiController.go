package auth

import (
	"auth/jcrypt"
	"auth/models"
	"auth/resultor"
	"bytes"
	"encoding/hex"
	"github.com/dgrijalva/jwt-go"
	"github.com/jacoblai/httprouter"
	"github.com/jacoblai/validation"
	"github.com/pquerna/ffjson/ffjson"
	"github.com/satori/go.uuid"
	"gopkg.in/mgo.v2/bson"
	"io/ioutil"
	"net/http"
	"time"
)

func (d *DbEngine) GetApiToken(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	var obj map[string]interface{}
	err = ffjson.Unmarshal(body, &obj)
	if err != nil {
		resultor.RetErr(w, "提交内容错误")
		return
	}

	var kind = ""
	if k, ok := obj["kind"]; !ok {
		resultor.RetErr(w, "没有接收登陆类型")
		return
	} else {
		kind = k.(string)
	}

	if kind != "uid" && kind != "phone" {
		resultor.RetErr(w, "没有接收登陆类型")
		return
	}

	if kind == "uid" {
		if _, ok := obj["uid"]; !ok {
			resultor.RetErr(w, "没有接收用户名")
			return
		}
	} else {
		if p, ok := obj["uid"]; !ok {
			resultor.RetErr(w, "没有接收到手机号码")
			return
		} else {
			if !validation.IsCnMobile(p.(string)) {
				resultor.RetErr(w, "手机号码验证失败")
				return
			}
		}
	}

	if _, ok := obj["pwd"]; !ok {
		resultor.RetErr(w, "没有接收密码")
		return
	}

	if len(obj["pwd"].(string)) < 6 {
		resultor.RetErr(w, "密码非法")
		return
	}

	mg := d.GetSess()
	defer mg.Close()

	dls := d.GetColl(mg, "denylogins")
	var dl models.DenyLogin
	dls.Find(bson.M{"uid": obj["uid"]}).One(&dl)
	if dl.Count != nil && *dl.Count >= 5 {
		resultor.RetErr(w, "已超过容错次数，请十五分钟后再试")
		return
	}

	ag := d.GetColl(mg, "users")
	var u models.User
	err = ag.Find(bson.M{kind: obj["uid"]}).One(&u)
	if err != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}

	opwdbts, err := hex.DecodeString(u.Pwd)
	if err != nil {
		resultor.RetErr(w, "系统内部密码组件异常")
		return
	}
	opwd := jcrypt.MsgDecode(opwdbts)
	if !bytes.Equal([]byte(obj["pwd"].(string)), opwd) {
		if dl.Count == nil {
			nv := float64(1)
			dls.Insert(models.DenyLogin{
				Id:       bson.NewObjectId(),
				CreateAt: time.Now().Local(),
				Uid:      obj["uid"].(string),
				Count:    &nv,
			})
		} else {
			dls.Update(bson.M{"uid": obj["uid"].(string)}, bson.M{"$inc": bson.M{"count": 1}})
		}
		resultor.RetErr(w, "登陆失败，密码错误")
		return
	}

	tuuid, _ := uuid.NewV4()
	claims := models.CoolpyClaims{
		UserId: u.Id,
		Uid:    u.Uid,
		Rule:   u.Rule,
		StandardClaims: jwt.StandardClaims{
			Id:        tuuid.String(),
			NotBefore: time.Now().Local().Unix(),
			ExpiresAt: time.Now().Local().Add(2 * time.Hour).Unix(),
			Issuer:    "coolpy7_api",
			IssuedAt:  time.Now().Local().Unix(),
			Audience:  u.Id.Hex(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(d.SigningKey)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	tuuid, _ = uuid.NewV4()
	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Id:        tuuid.String(),
		NotBefore: time.Now().Local().Unix(),
		ExpiresAt: time.Now().Add(10 * time.Hour).Unix(),
		Issuer:    "coolpy7_api",
		IssuedAt:  time.Now().Local().Unix(),
		Audience:  u.Id.Hex(),
	})
	ss1, err := refreshtoken.SignedString(d.SigningKey)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	res := make(map[string]interface{})
	res["token"] = ss
	res["expires_in"] = time.Duration(2 * time.Hour).Seconds()
	res["refresh_token"] = ss1
	res["avatar"] = u.Avatar
	resultor.RetOk(w, res, 1)
}
