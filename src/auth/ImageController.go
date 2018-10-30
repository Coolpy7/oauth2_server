package auth

import (
	"auth/resultor"
	"github.com/jacoblai/httprouter"
	"gopkg.in/h2non/filetype.v1"
	"gopkg.in/mgo.v2/bson"
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

	mg := d.GetSess()
	defer mg.Close()

	fid := bson.NewObjectId()
	fs, err := d.GetGridfs(mg, "avatars").Create(fid.Hex() + "." + kind.Extension)
	defer fs.Close()
	if err == nil {
		fs.SetId(fid)
		fs.SetContentType(kind.MIME.Value)
		fs.SetMeta(map[string]interface{}{
			"ext": kind.Extension,
		})
		fs.Write(file)
	}

	resultor.RetOk(w, d.Domain+"/api/v1/avatar/"+fid.Hex(), 1)
}

func (d *DbEngine) PhotoGet(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()
	fid := ps.ByName("id")
	if fid == "" || !bson.IsObjectIdHex(fid) || !InjectionPass([]byte(fid)) {
		resultor.RetErr(w, "params err")
		return
	}

	mg := d.GetSess()
	defer mg.Close()

	fs := d.GetGridfs(mg, "avatars")
	file, err := fs.OpenId(bson.ObjectIdHex(fid))
	if err != nil {
		resultor.RetErr(w, "头像不存在")
		return
	}
	sfile := make([]byte, file.Size())
	file.Read(sfile)
	w.Header().Set("Content-Type", file.ContentType())
	w.Write(sfile)
}
