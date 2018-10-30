package models

import (
	"gopkg.in/mgo.v2/bson"
	"time"
)

type DenyLogin struct {
	Id       bson.ObjectId `json:"id" bson:"_id,omitempty" jsonschema:"-"`
	CreateAt time.Time     `json:"createat,omitempty" bson:"createat,omitempty"`
	Uid      string        `json:"uid,omitempty" bson:"uid,omitempty"`
	Count    *float64      `json:"count,omitempty" bson:"count,omitempty"`
}
