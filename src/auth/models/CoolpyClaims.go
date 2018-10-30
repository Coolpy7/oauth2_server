package models

import (
	"github.com/dgrijalva/jwt-go"
	"gopkg.in/mgo.v2/bson"
)

type CoolpyClaims struct {
	UserId bson.ObjectId `json:"user_id"`
	Uid    string        `json:"uid"`
	Rule   string        `json:"rule"`
	jwt.StandardClaims
}
