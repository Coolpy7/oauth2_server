package auth

import (
	"auth/jcrypt"
	"auth/models"
	"auth/resultor"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/dgrijalva/jwt-go"
	"github.com/jacoblai/httprouter"
	"github.com/pquerna/ffjson/ffjson"
	"gopkg.in/mgo.v2/bson"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

func (d *DbEngine) Authorize(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	http.Redirect(w, r, d.PlayDomainName+"/pages/oauth2?"+r.URL.RawQuery, http.StatusTemporaryRedirect)
}

func (d *DbEngine) AuthLogin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	if _, ok := obj["uid"]; !ok {
		resultor.RetErr(w, "没有接收用户名")
		return
	}

	if obj["uid"] == "admin" {
		resultor.RetErr(w, "管理员不允许参与应用授权应用")
		return
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
	err = ag.Find(bson.M{"uid": obj["uid"]}).One(&u)
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

	codetk := d.RandStringRunes(32)
	codetkdb := d.GetColl(mg, "codetokens")
	err = codetkdb.Insert(&models.CodeToken{
		Id:       bson.NewObjectId(),
		CreateAt: time.Now().Local(),
		UserId:   u.Id,
		Code:     codetk,
	})
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	res := make(map[string]interface{})
	res["codetoken"] = codetk
	res["userid"] = u.Uid
	res["username"] = u.Name
	res["avatar"] = u.Avatar
	res["phone"] = u.Phone
	res["mail"] = u.Mail
	resultor.RetOk(w, res, 1)
}

func (d *DbEngine) Grant(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	qr := r.URL.Query()
	appid := qr.Get("client_id")
	redirectUri := qr.Get("redirect_uri")
	responseType := qr.Get("response_type")
	scope := qr.Get("scope")
	state := qr.Get("state")
	sso := qr.Get("sso")
	sig := qr.Get("sig")

	codetoken := qr.Get("codetoken")

	if !InjectionPass([]byte(codetoken)) || !InjectionPass([]byte(appid)) || !InjectionPass([]byte(redirectUri)) ||
		!InjectionPass([]byte(responseType)) || !InjectionPass([]byte(scope)) || !InjectionPass([]byte(state)) ||
		!InjectionPass([]byte(sso)) || !InjectionPass([]byte(sig)) {
		http.Redirect(w, r, redirectUri+"?err=invalid_inject", http.StatusTemporaryRedirect)
		return
	}

	if m, _ := regexp.MatchString(`^[a-z0-9_]+$`, codetoken); !m || len(codetoken) != 32 {
		http.Redirect(w, r, redirectUri+"?err=invalid_codetoken", http.StatusTemporaryRedirect)
		return
	}

	if m, _ := regexp.MatchString(`^[a-z0-9_]+$`, appid); !m || len(appid) != 32 {
		http.Redirect(w, r, redirectUri+"?err=invalid_app_account", http.StatusTemporaryRedirect)
		return
	}

	if scope != "basic" {
		http.Redirect(w, r, redirectUri+"?err=invalid_scope", http.StatusTemporaryRedirect)
		return
	}

	mg := d.GetSess()
	defer mg.Close()

	codetkdb := d.GetColl(mg, "codetokens")
	var ocd models.CodeToken
	err := codetkdb.Find(bson.M{"code": codetoken}).One(&ocd)
	if err != nil {
		http.Redirect(w, r, redirectUri+"?err=invalid_code_token", http.StatusTemporaryRedirect)
		return
	}
	codetkdb.Remove(bson.M{"code": codetoken})

	appdb := d.GetColl(mg, "apps")
	var app models.App
	err = appdb.Find(bson.M{"app_id": appid}).One(&app)
	if err != nil {
		http.Redirect(w, r, redirectUri+"?err=invalid_app_account_notfount", http.StatusTemporaryRedirect)
		return
	}

	//safe, _ := url.Parse(app.SafeRequest)
	//if r.Host != safe.Host {
	//	http.Redirect(w, r, redirectUri+"?err=invalid_domain", http.StatusTemporaryRedirect)
	//	return
	//}

	code := d.RandStringRunes(32)
	codedb := d.GetColl(mg, "codes")
	rcode := models.Code{
		Id:       bson.NewObjectId(),
		CreateAt: time.Now().Local(),
		UserId:   ocd.UserId,
		Code:     code,
		AppId:    app.AppId,
		Scope:    scope,
	}
	err = codedb.Insert(&rcode)
	if err != nil {
		http.Redirect(w, r, redirectUri+"?err=system_code_create_error", http.StatusTemporaryRedirect)
		return
	}

	//添加用户授权记录，支持平台端收回授权
	authdb := d.GetColl(mg, "auths")
	act, _ := authdb.Find(bson.M{"user_id": ocd.UserId, "app_id": app.AppId}).Count()
	if act == 0 {
		authdb.Insert(&rcode)
	}

	if responseType == "code" {
		//if !validation.IsDomain(redirectUri) {
		//	http.Redirect(w, r, redirectUri+"?err=invalid_redirect_uri", http.StatusTemporaryRedirect)
		//	return
		//}
		http.Redirect(w, r, redirectUri+"?code="+code+"&state="+state, http.StatusTemporaryRedirect)
		return
	} else if responseType == "sso" && ComputeHmac256(sso, app.DiscourseSsoSecret) == sig {
		//ssobts, err := base64.StdEncoding.DecodeString(sso)
		//if err != nil {
		//	http.Redirect(w, r, redirectUri+"?err=invalid_sso_base64", http.StatusTemporaryRedirect)
		//	return
		//}
		//ssoq, err := url.ParseQuery(string(ssobts))
		//if err != nil {
		//	http.Redirect(w, r, redirectUri+"?err=invalid_sso_query", http.StatusTemporaryRedirect)
		//	return
		//}
		//nonec := ssoq.Get("nonce")
		//reurl := ssoq.Get("return_sso_url")

	}

	http.Redirect(w, r, redirectUri+"?err=invalid_response_type", http.StatusTemporaryRedirect)
}

func ComputeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func (d *DbEngine) GetToken(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	//qr := r.URL.Query()
	//code := qr.Get("code")
	////appid := qr.Get("appid")
	////secret := qr.Get("secret")

	//if !InjectionPass([]byte(code)) || !InjectionPass([]byte(appid)) || !InjectionPass([]byte(secret)) {
	//	resultor.RetErr(w, "invalid_inject")
	//	return
	//}

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

	log.Println(string(body))
	qr, err := url.ParseQuery(string(body))
	if err != nil {
		resultor.RetErr(w, "1002")
		return
	}

	code := qr.Get("code")
	grant_type := qr.Get("grant_type") //authorization_code
	redirect_uri := qr.Get("redirect_uri")
	appid := qr.Get("client_id")
	secret := qr.Get("client_secret")

	log.Println(grant_type, redirect_uri)

	if m, _ := regexp.MatchString(`^[a-z0-9_]+$`, code); !m || len(code) != 32 {
		resultor.RetErr(w, "invalid_code")
		return
	}

	if m, _ := regexp.MatchString(`^[a-z0-9_]+$`, appid); !m || len(appid) != 32 {
		resultor.RetErr(w, "invalid_appid")
		return
	}

	if m, _ := regexp.MatchString(`^[a-z0-9_]+$`, secret); !m || len(secret) != 64 {
		resultor.RetErr(w, "invalid_appsecret")
		return
	}

	mg := d.GetSess()
	defer mg.Close()

	codedb := d.GetColl(mg, "codes")
	var ocd models.Code
	err = codedb.Find(bson.M{"code": code}).One(&ocd)
	if err != nil {
		resultor.RetErr(w, "invalid_code_notfound")
		return
	}
	codedb.Remove(bson.M{"code": code})

	if ocd.AppId != appid {
		resultor.RetErr(w, "invalid_appid_notfound")
		return
	}

	appdb := d.GetColl(mg, "apps")
	var app models.App
	err = appdb.Find(bson.M{"app_id": appid, "app_secret": secret}).One(&app)
	if err != nil {
		resultor.RetErr(w, "invalid_appsecret_notfound")
		return
	}

	//safe, _ := url.Parse(app.SafeRequest)
	//if r.Host != safe.Host {
	//	resultor.RetErr(w, "invalid_domain")
	//	return
	//}

	//判断授权信息是否已被回收授权
	authdb := d.GetColl(mg, "auths")
	act, _ := authdb.Find(bson.M{"user_id": ocd.UserId, "app_id": ocd.AppId}).Count()
	if act == 0 {
		resultor.RetErr(w, "invalid_oauth_reject")
		return
	}

	ag := d.GetColl(mg, "users")
	var u models.User
	err = ag.FindId(ocd.UserId).One(&u)
	if err != nil {
		resultor.RetErr(w, "授权用户不存在")
		return
	}

	refreshToken := d.RandStringRunes(128)
	now := time.Now().Local()
	eat := now.Add(2 * time.Hour).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Id:        refreshToken,
		NotBefore: now.Unix(),
		ExpiresAt: eat,
		Issuer:    "coolpy7_oauth",
		IssuedAt:  now.Unix(),
		Audience:  ocd.AppId,
		Subject:   ocd.UserId.Hex(),
	})
	signtoken, err := token.SignedString(d.SigningKey)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	err = authdb.Update(bson.M{"user_id": ocd.UserId, "app_id": ocd.AppId}, bson.M{"$set": bson.M{"code": refreshToken}})
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	res := make(map[string]interface{})
	res["access_token"] = signtoken
	res["token_type"] = "bearer"
	res["expires_in"] = eat
	res["refresh_token"] = refreshToken
	res["scope"] = ocd.Scope
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	bts, _ := ffjson.Marshal(res)
	w.WriteHeader(http.StatusOK)
	w.Write(bts)
}

func (d *DbEngine) RefreshToken(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	qr := r.URL.Query()
	rtoken := qr.Get("token")

	if !InjectionPass([]byte(rtoken)) {
		resultor.RetErr(w, "invalid_inject")
		return
	}

	if m, _ := regexp.MatchString(`^[a-z0-9_]+$`, rtoken); !m || len(rtoken) != 128 {
		resultor.RetErr(w, "invalid_code")
		return
	}

	mg := d.GetSess()
	defer mg.Close()

	authdb := d.GetColl(mg, "auths")
	var ocd models.Code
	err := authdb.Find(bson.M{"code": rtoken}).One(&ocd)
	if err != nil {
		resultor.RetErr(w, "invalid_refresh_token_notfound")
		return
	}

	ag := d.GetColl(mg, "users")
	var u models.User
	err = ag.FindId(ocd.UserId).One(&u)
	if err != nil {
		resultor.RetErr(w, "授权用户不存在")
		return
	}

	refreshToken := d.RandStringRunes(128)
	now := time.Now().Local()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Id:        refreshToken,
		NotBefore: now.Unix(),
		ExpiresAt: now.Add(2 * time.Hour).Unix(),
		Issuer:    "coolpy7_oauth",
		IssuedAt:  now.Unix(),
		Audience:  ocd.AppId,
		Subject:   ocd.UserId.Hex(),
	})
	signtoken, err := token.SignedString(d.SigningKey)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	err = authdb.Update(bson.M{"user_id": ocd.UserId, "app_id": ocd.AppId}, bson.M{"$set": bson.M{"code": refreshToken}})
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	res := make(map[string]interface{})
	res["token"] = signtoken
	res["expires_in"] = time.Duration(2 * time.Hour).Seconds()
	res["refresh_token"] = refreshToken
	res["avatar"] = u.Avatar
	res["user_name"] = u.Name
	resultor.RetOk(w, res, 1)
}

func (d *DbEngine) MeInfo(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	qr := r.URL.Query()
	token := qr.Get("access_token")

	uid := ps.ByName("id")
	if uid == "" || !InjectionPass([]byte(uid)) {
		resultor.RetErr(w, "1003")
		return
	}

	if !InjectionPass([]byte(token)) {
		resultor.RetErr(w, "invalid_inject")
		return
	}

	rtoken, err := jwt.ParseWithClaims(token, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return d.SigningKey, nil
	})

	if tk, ok := rtoken.Claims.(*jwt.StandardClaims); ok && rtoken.Valid && tk.Issuer == "coolpy7_oauth" {
		mg := d.GetSess()
		defer mg.Close()

		//判断授权信息是否已被回收授权
		authdb := d.GetColl(mg, "auths")
		var act models.Code
		err := authdb.Find(bson.M{"user_id": bson.ObjectIdHex(uid), "app_id": tk.Audience}).One(&act)
		if err != nil {
			resultor.RetErr(w, "invalid_oauth_reject")
			return
		}

		ag := d.GetColl(mg, "users")
		var u models.User
		err = ag.FindId(act.UserId).One(&u)
		if err != nil {
			resultor.RetErr(w, "授权用户不存在")
			return
		}

		res := make(map[string]interface{})
		res["id"] = tk.Subject
		res["displayName"] = u.Name
		res["emails"] = u.Mail
		res["photos"] = []string{u.Avatar}
		res["isAdmin"] = false
		w.Header().Set("Content-Type", "application/json;charset=utf-8")
		bts, _ := ffjson.Marshal(res)
		w.WriteHeader(http.StatusOK)
		w.Write(bts)
	} else {
		if err != nil {
			resultor.RetErr(w, err.Error())
		} else {
			resultor.RetErr(w, "token invalid")
		}
	}
}
