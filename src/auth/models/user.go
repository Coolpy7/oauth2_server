package models

import (
	"gopkg.in/mgo.v2/bson"
	"time"
)

//系统用户账号
type User struct {
	Id        bson.ObjectId `json:"id" bson:"_id,omitempty" jsonschema:"-"`
	CreateAt  time.Time     `json:"createat,omitempty" bson:"createat,omitempty"`
	UpdateAt  time.Time     `json:"updateat,omitempty" bson:"updateat,omitempty"`
	IsDisable *bool         `json:"isdisable,omitempty" bson:"isdisable,omitempty"`

	Uid    string `json:"uid,omitempty" bson:"uid,omitempty" jsonschema:"required,minLength=3,maxLength=16"`
	Pwd    string `json:"pwd,omitempty" bson:"pwd,omitempty" jsonschema:"required,minLength=6,maxLength=64"`
	Name   string `json:"name,omitempty" bson:"name,omitempty" jsonschema:"minLength=2,maxLength=12"`
	Phone  string `json:"phone,omitempty" bson:"phone,omitempty" jsonschema:"required,minLength=11,maxLength=11"`
	Remark string `json:"remark,omitempty" bson:"remark,omitempty"`
	Mail   string `json:"mail,omitempty" bson:"mail,omitempty"`
	Avatar string `json:"avatar,omitempty" bson:"avatar,omitempty"`
	Rule   string `json:"rule,omitempty" bson:"rule,omitempty" jsonschema:"enum=user|developer|admin,description=Rule"`
}
