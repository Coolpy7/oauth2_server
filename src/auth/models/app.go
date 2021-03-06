package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

var T_APP = "apps"

type App struct {
	Id        primitive.ObjectID `json:"id" bson:"_id,omitempty" jsonschema:"-"`
	CreateAt  time.Time          `json:"create_at,omitempty" bson:"create_at,omitempty"`
	UpdateAt  time.Time          `json:"update_at,omitempty" bson:"update_at,omitempty"`
	IsDisable *bool              `json:"is_disable,omitempty" bson:"is_disable,omitempty"`

	UserId primitive.ObjectID `json:"user_id,omitempty" bson:"user_id,omitempty" jsonschema:"required,oid"`

	AppId              string `json:"app_id,omitempty" bson:"app_id,omitempty" jsonschema:"required"`
	AppSecret          string `json:"app_secret,omitempty" bson:"app_secret,omitempty" jsonschema:"required"`
	Name               string `json:"name,omitempty" bson:"name,omitempty" jsonschema:"required,minLength=3,maxLength=10"`
	Remark             string `json:"remark,omitempty" bson:"remark,omitempty"`
	Avatar             string `json:"avatar,omitempty" bson:"avatar,omitempty"`
	SafeRequest        string `json:"safe_request,omitempty" bson:"safe_request,omitempty" jsonschema:"required"`
	SafeUpload         string `json:"safe_upload,omitempty" bson:"safe_upload,omitempty"`
	SafeDownload       string `json:"safe_download,omitempty" bson:"safe_download,omitempty"`
	SafeSocket         string `json:"safe_socket,omitempty" bson:"safe_socket,omitempty"`
	DiscourseSsoSecret string `json:"discourse_sso_secret,omitempty" bson:"discourse_sso_secret,omitempty" jsonschema:"minLength=6"`
	DiscourseSsoAdmin  string `json:"discourse_sso_admin,omitempty" bson:"discourse_sso_admin,omitempty"`
}
