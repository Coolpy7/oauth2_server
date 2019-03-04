package models

import (
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type CoolpyClaims struct {
	UserId primitive.ObjectID `json:"user_id"`
	Uid    string             `json:"uid"`
	Rule   string             `json:"rule"`
	jwt.StandardClaims
}
