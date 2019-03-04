package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

var T_SMSS = "smss"

type Sms struct {
	Id       primitive.ObjectID `json:"id" bson:"_id,omitempty" jsonschema:"-"`
	CreateAt time.Time          `json:"createat,omitempty" bson:"createat,omitempty"`

	Phone string `json:"phone,omitempty" bson:"phone,omitempty" jsonschema:"required"`
	Code  string `json:"code,omitempty" bson:"code,omitempty" jsonschema:"required"`
}
