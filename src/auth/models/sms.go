package models

import (
	"gopkg.in/mgo.v2/bson"
	"time"
)

type Sms struct {
	Id       bson.ObjectId `json:"id" bson:"_id,omitempty" jsonschema:"-"`
	CreateAt time.Time     `json:"createat,omitempty" bson:"createat,omitempty"`

	Phone string `json:"phone,omitempty" bson:"phone,omitempty" jsonschema:"required"`
	Code  string `json:"code,omitempty" bson:"code,omitempty" jsonschema:"required"`
}
