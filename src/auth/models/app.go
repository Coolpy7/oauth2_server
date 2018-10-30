package models

import (
	"gopkg.in/mgo.v2/bson"
	"time"
)

type App struct {
	Id        bson.ObjectId `json:"id" bson:"_id,omitempty" jsonschema:"-"`
	CreateAt  time.Time     `json:"create_at,omitempty" bson:"create_at,omitempty"`
	UpdateAt  time.Time     `json:"update_at,omitempty" bson:"update_at,omitempty"`
	IsDisable *bool         `json:"is_disable,omitempty" bson:"is_disable,omitempty"`

	UserId bson.ObjectId `json:"user_id,omitempty" bson:"user_id,omitempty" jsonschema:"required,oid"`

	AppId        string `json:"app_id,omitempty" bson:"app_id,omitempty" jsonschema:"required"`
	AppSecret    string `json:"app_secret,omitempty" bson:"app_secret,omitempty" jsonschema:"required"`
	Name         string `json:"name,omitempty" bson:"name,omitempty" jsonschema:"required,minLength=3,maxLength=10"`
	Remark       string `json:"remark,omitempty" bson:"remark,omitempty"`
	Avatar       string `json:"avatar,omitempty" bson:"avatar,omitempty"`
	SafeRequest  string `json:"safe_request,omitempty" bson:"safe_request,omitempty" jsonschema:"required"`
	SafeUpload   string `json:"safe_upload,omitempty" bson:"safe_upload,omitempty"`
	SafeDownload string `json:"safe_download,omitempty" bson:"safe_download,omitempty"`
	SafeSocket   string `json:"safe_socket,omitempty" bson:"safe_socket,omitempty"`
}
