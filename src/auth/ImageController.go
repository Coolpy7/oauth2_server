package auth

import (
	"auth/resultor"
	"bytes"
	"context"
	"github.com/jacoblai/httprouter"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/x/bsonx"
	"gopkg.in/h2non/filetype.v1"
	"io/ioutil"
	"net/http"
	"strconv"
)

func (d *DbEngine) Avatar(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()
	cl, err := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	if err != nil {
		resultor.RetErr(w, "parse content length "+err.Error())
		return
	}
	if cl > 1024*50 {
		resultor.RetErr(w, "只允许上传50KB以内的头像图片")
		return
	}
	file, err := ioutil.ReadAll(r.Body)
	if err != nil {
		resultor.RetErr(w, "read err")
		return
	}
	if len(file) < 261 {
		resultor.RetErr(w, "图片不允许少于261字节")
		return
	}
	//提取http的content-type文件类型
	kind, unkwown := filetype.Match(file[:261])
	if unkwown != nil {
		kind.MIME.Value = "application/octet-stream"
	}

	rd := bytes.NewReader(file)
	fid := primitive.NewObjectID()
	fname := fid.Hex() + "." + kind.Extension
	meta := bsonx.Doc{
		{"Content-type", bsonx.String(kind.MIME.Value)},
		{"Ext", bsonx.String(kind.Extension)},
	}
	bucket, err := gridfs.NewBucket(d.MgEngine.Database("cp7_oauth2_avatars"), options.GridFSBucket().SetName("avatars"))
	if err == nil {
		err = bucket.UploadFromStreamWithID(fid, fname, rd, options.GridFSUpload().SetMetadata(meta))
		if err != nil {
			resultor.RetErr(w, err.Error())
			return
		}
	}

	resultor.RetOk(w, d.Domain+"/api/v1/avatar/"+fid.Hex(), 1)
}

func (d *DbEngine) PhotoGet(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()
	fid := ps.ByName("id")
	if fid == "" || !InjectionPass([]byte(fid)) {
		resultor.RetErr(w, "params err")
		return
	}

	foid, err := primitive.ObjectIDFromHex(fid)
	if err != nil {
		resultor.RetErr(w, "1003")
		return
	}

	bucket, err := gridfs.NewBucket(d.MgEngine.Database("cp7_oauth2_avatars"), options.GridFSBucket().SetName("avatars"))
	if err == nil {
		bt, err := bucket.Find(bson.M{"_id": foid})
		if err == nil {
			for bt.Next(context.Background()) {
				//{"_id": {"$oid":5c7de426e9644d5bd5624093},"length": {"$numberLong":"12527"},"chunkSize": {"$numberInt":"261120"},"uploadDate": {"$date":{"$numberLong":"1551754278850"}},"filename": "5c7de426e9644d5bd5624093.png","metadata": {"Content-type": "image/png","Ext": "png"}}
				w.Header().Set("Content-Type", bt.Current.Lookup("Content-type").String())
				bts := make([]byte, bt.Current.Lookup("length").Int64())
				sm, err := bucket.OpenDownloadStream(foid)
				if err != nil {
					resultor.RetErr(w, "头像不存在")
					return
				}
				_, _ = sm.Read(bts)
				_, _ = w.Write(bts)
				return
			}
		}
	}

	resultor.RetErr(w, "avatar not found")
}
