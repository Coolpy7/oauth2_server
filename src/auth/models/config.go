package models

import (
	"gopkg.in/mgo.v2/bson"
)

type Config struct {
	Id     bson.ObjectId `json:"id" bson:"_id,omitempty" jsonschema:"-"`
	Header string        `json:"header,omitempty" bson:"header,omitempty"`
	//Footer     string        `json:"footer,omitempty" bson:"footer,omitempty"`
	//FooterUrl  string        `json:"footerurl,omitempty" bson:"footerurl,omitempty"`
	RegPaper    string `json:"regpaper,omitempty" bson:"regpaper,omitempty"`
	Help        string `json:"help,omitempty" bson:"help,omitempty"`
	AuthIcon    string `json:"authicon,omitempty" bson:"authicon,omitempty"`
	AuthPaper   string `json:"authpaper,omitempty" bson:"authpaper,omitempty"`
	AuthWaring  string `json:"authwaring,omitempty" bson:"authwaring,omitempty"`
	MailAlias   string `json:"mailalias,omitempty" bson:"mailalias,omitempty"`
	MailService string `json:"mailservice,omitempty" bson:"mailservice,omitempty"`
	MailSubject string `json:"mailsubject,omitempty" bson:"mailsubject,omitempty"`
	MailBody    string `json:"mailbody,omitempty" bson:"mailbody,omitempty"`
	SmsSign     string `json:"smssign,omitempty" bson:"smssign,omitempty"`
	SmsTemplate string `json:"smstemplate,omitempty" bson:"smstemplate,omitempty"`
}
