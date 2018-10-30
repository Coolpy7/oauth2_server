package models

import (
	"gopkg.in/mgo.v2/bson"
	"time"
)

type CodeToken struct {
	Id       bson.ObjectId `json:"id" bson:"_id,omitempty" jsonschema:"-"`
	CreateAt time.Time     `json:"create_at,omitempty" bson:"create_at,omitempty"`
	UserId   bson.ObjectId `json:"user_id,omitempty" bson:"user_id,omitempty" jsonschema:"required,oid"`
	Code     string        `json:"code,omitempty" bson:"code,omitempty" jsonschema:"required"`
}

type Code struct {
	Id       bson.ObjectId `json:"id" bson:"_id,omitempty" jsonschema:"-"`
	CreateAt time.Time     `json:"create_at,omitempty" bson:"create_at,omitempty"`
	UserId   bson.ObjectId `json:"user_id,omitempty" bson:"user_id,omitempty" jsonschema:"required,oid"`
	AppId    string        `json:"app_id,omitempty" bson:"app_id,omitempty"  jsonschema:"required"`
	Code     string        `json:"code,omitempty" bson:"code,omitempty" jsonschema:"required"`
	Scope    string        `json:"scope,omitempty" bson:"scope,omitempty"`
}

type MailCode struct {
	Id       bson.ObjectId `json:"id" bson:"_id,omitempty" jsonschema:"-"`
	CreateAt time.Time     `json:"create_at,omitempty" bson:"create_at,omitempty"`
	UserId   bson.ObjectId `json:"user_id,omitempty" bson:"user_id,omitempty" jsonschema:"required,oid"`
	Mail     string        `json:"mail,omitempty" bson:"mail,omitempty"  jsonschema:"required"`
	Code     string        `json:"code,omitempty" bson:"code,omitempty" jsonschema:"required"`
}
