package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

var T_DenyLogin = "denylogins"

type DenyLogin struct {
	Id       primitive.ObjectID `json:"id" bson:"_id,omitempty" jsonschema:"-"`
	CreateAt time.Time          `json:"createat,omitempty" bson:"createat,omitempty"`
	Uid      string             `json:"uid,omitempty" bson:"uid,omitempty"`
	Count    *float64           `json:"count,omitempty" bson:"count,omitempty"`
}
