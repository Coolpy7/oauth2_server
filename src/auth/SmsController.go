package auth

import (
	"auth/models"
	"auth/resultor"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/GiterLab/aliyun-sms-go-sdk/dysms"
	"github.com/jacoblai/httprouter"
	"github.com/jacoblai/validation"
	"github.com/pquerna/ffjson/ffjson"
	"github.com/satori/go.uuid"
	"gopkg.in/mgo.v2/bson"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (d *DbEngine) SendRegSms(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	if !InjectionPass(body) {
		resultor.RetErr(w, "1002")
		return
	}

	var obj map[string]interface{}
	err = ffjson.Unmarshal(body, &obj)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	for k := range obj {
		if k != "phone" && k != "reg" {
			delete(obj, k)
		} else {
			if obj[k] == "" {
				resultor.RetErr(w, "手机号码为空")
				return
			}
		}
	}

	if !validation.IsCnMobile(obj["phone"]) {
		resultor.RetErr(w, "手机号码无效")
		return
	}

	mg := d.GetSess()
	defer mg.Close()

	if reg, ok := obj["reg"]; ok {
		if reged, ok := reg.(bool); ok && reged {
			ag := d.GetColl(mg, "users")
			var u models.User
			err = ag.Find(bson.M{"phone": obj["phone"]}).One(&u)
			if err != nil {
				resultor.RetErr(w, "用户不存在")
				return
			}
		}
	}

	s := d.GetColl(mg, "smss")
	ct, _ := s.Find(bson.M{"phone": obj["phone"]}).Count()
	if ct > 0 {
		resultor.RetErr(w, "已有生效的验证码，验证码十五分钟内均有效")
		return
	}

	vcode := fmt.Sprintf("%06v", d.rnd.Int31n(1000000))

	cfdb := d.GetColl(mg, "configs")
	var config models.Config
	err = cfdb.FindId(bson.ObjectIdHex("5bae43aa53c61312eec64c04")).One(&config)
	if err != nil {
		resultor.RetErr(w, "当前系统没有配置阿里云通信短信参数")
		return
	}

	id, _ := uuid.NewV4()
	// send to one person
	info, err := dysms.SendSms(id.String(), obj["phone"].(string), config.SmsSign, config.SmsTemplate, `{"code":"`+vcode+`"}`).DoActionWithException()
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}
	if *info.Code != "OK" {
		resultor.RetErr(w, *info.Message)
		return
	}

	ms := models.Sms{
		Id:       bson.NewObjectId(),
		CreateAt: time.Now().Local(),
		Phone:    obj["phone"].(string),
		Code:     vcode,
	}
	err = s.Insert(&ms)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetChanges(w, 1)
}

func (d *DbEngine) Profile(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	//用户信息
	uoid := r.Header.Get("uoid")

	mg := d.GetSess()
	defer mg.Close()

	ag := d.GetColl(mg, "users")
	var u map[string]interface{}
	err := ag.FindId(bson.ObjectIdHex(uoid)).Select(bson.M{"pwd": 0}).One(&u)
	if err != nil {
		resultor.RetErr(w, "用户不存在")
		return
	}

	resultor.RetOk(w, u, 1)
}

func (d *DbEngine) SendMail(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	if !InjectionPass(body) {
		resultor.RetErr(w, "1002")
		return
	}

	var obj map[string]interface{}
	err = ffjson.Unmarshal(body, &obj)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	for k := range obj {
		if k != "mail" && k != "reg" {
			delete(obj, k)
		} else {
			if obj[k] == "" {
				resultor.RetErr(w, "邮箱为空")
				return
			}
		}
	}

	if !validation.IsEmail(obj["mail"]) {
		resultor.RetErr(w, "邮箱无效")
		return
	}

	mg := d.GetSess()
	defer mg.Close()

	if reg, ok := obj["reg"]; ok {
		if reged, ok := reg.(bool); ok && reged {
			ag := d.GetColl(mg, "users")
			var u models.User
			err = ag.Find(bson.M{"mail": obj["mail"]}).One(&u)
			if err != nil {
				resultor.RetErr(w, "用户不存在")
				return
			}
		}
	}

	s := d.GetColl(mg, "smss")
	ct, _ := s.Find(bson.M{"phone": obj["mail"]}).Count()
	if ct > 0 {
		resultor.RetErr(w, "已有生效的验证码，验证码十五分钟内均有效")
		return
	}

	vcode := fmt.Sprintf("%06v", d.rnd.Int31n(1000000))

	subject := "邮箱验证"
	mailbody := `<html><body><h3>验证码：` + vcode + `</h3></body></html>`

	cfdb := d.GetColl(mg, "configs")
	var config models.Config
	err = cfdb.FindId(bson.ObjectIdHex("5bae43aa53c61312eec64c04")).One(&config)
	if err == nil && strings.Contains(config.MailBody, ":vcode") {
		subject = config.MailSubject
		mailbody = strings.Replace(config.MailBody, ":vcode", vcode, -1)
	}

	err = sendMail(AliyunSmsAccessID, AliyunSmsAccessKEY, config.MailService, config.MailAlias, subject, obj["mail"].(string), mailbody)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	ms := models.Sms{
		Id:       bson.NewObjectId(),
		CreateAt: time.Now().Local(),
		Phone:    obj["mail"].(string),
		Code:     vcode,
	}
	err = s.Insert(&ms)
	if err != nil {
		resultor.RetErr(w, err.Error())
		return
	}

	resultor.RetChanges(w, 1)
}

func sendMail(accessKeyId, accessKeySecret, fromEmailAddress, fromEmailAlias, emailSubject, toEmailAddress, content string) error {
	v := url.Values{}
	v.Set("Format", "json")
	v.Set("Version", "2015-11-23")
	v.Set("AccessKeyId", accessKeyId)
	v.Set("SignatureMethod", "HMAC-SHA1")
	v.Set("Timestamp", time.Now().UTC().Format(time.RFC3339))
	v.Set("SignatureVersion", "1.0")
	v.Set("SignatureNonce", randomString(64))
	v.Set("Action", "SingleSendMail")
	v.Set("AccountName", fromEmailAddress)
	v.Set("ReplyToAddress", "false")
	v.Set("AddressType", "0")
	v.Set("FromAlias", fromEmailAlias)
	v.Set("Subject", emailSubject)
	v.Set("HtmlBody", content)
	v.Set("ToAddress", toEmailAddress)

	h := hmac.New(sha1.New, []byte(accessKeySecret+"&"))
	h.Write([]byte("POST&%2F&" + urlEncode(v.Encode())))
	v.Set("Signature", base64.StdEncoding.EncodeToString(h.Sum(nil)))

	req, err := http.NewRequest("POST", "https://dm.aliyuncs.com/", strings.NewReader(v.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{
		Timeout: time.Duration(3 * time.Second),
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return errors.New(string(body))
	}
	return nil
}

func randomString(n int) string {
	const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	rand.Seed(time.Now().UnixNano())
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func urlEncode(input string) string {
	return url.QueryEscape(strings.Replace(strings.Replace(strings.Replace(input, "+", "%20", -1), "*", "%2A", -1), "%7E", "~", -1))
}
