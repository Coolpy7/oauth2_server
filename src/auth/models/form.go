package models

import (
	"gopkg.in/mgo.v2/bson"
	"time"
)

type Form struct {
	Id        bson.ObjectId `json:"id" bson:"_id,omitempty" jsonschema:"-"`
	CreateAt  time.Time     `json:"createat,omitempty" bson:"createat,omitempty"`
	UpdateAt  time.Time     `json:"updateat,omitempty" bson:"updateat,omitempty"`
	IsDisable *bool         `json:"isdisable,omitempty" bson:"isdisable,omitempty"`

	UserOid bson.ObjectId `json:"useroid,omitempty" bson:"useroid,omitempty" jsonschema:"required,oid,description=申请人useroid"`
	Result  string        `json:"result,omitempty" bson:"result,omitempty" jsonschema:"enum=审核通过|拒绝,description=审核结果"`
	State   string        `json:"state,omitempty" bson:"state,omitempty" jsonschema:"enum=待审核|已完成,description=状态"`
	Remark  string        `json:"remark,omitempty" bson:"remark,omitempty"`
}
