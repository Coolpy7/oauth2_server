package auth

import (
	"auth/jcrypt"
	"auth/models"
	"encoding/hex"
	"github.com/GiterLab/aliyun-sms-go-sdk/dysms"
	"github.com/jacoblai/mschema"
	"github.com/pquerna/ffjson/ffjson"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"log"
	"math/rand"
	"time"
)

var (
	AliyunSmsAccessID  = ""
	AliyunSmsAccessKEY = ""
)

type DbEngine struct {
	MgEngine       *mgo.Session //关系型数据库引擎
	Mdb            string
	SigningKey     []byte
	rnd            *rand.Rand
	Domain         string
	letterRunes    []rune
	PlayDomainName string
}

func NewDbEngine() *DbEngine {
	//dysms.HTTPDebugEnable = true
	dysms.SetACLClient(AliyunSmsAccessID, AliyunSmsAccessKEY)
	return &DbEngine{
		rnd:         rand.New(rand.NewSource(time.Now().UnixNano())),
		letterRunes: []rune("abcdefghijklmnopqrstuvwxyz0123456789_"),
	}
}

func (d *DbEngine) RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = d.letterRunes[rand.Intn(len(d.letterRunes))]
	}
	return string(b)
}

func (d *DbEngine) Open(mongo, mdb, domain, playdomain, sk string, init int) error {
	d.Mdb = mdb
	d.Domain = domain
	d.PlayDomainName = playdomain
	d.SigningKey = []byte(sk)
	db, err := mgo.Dial(mongo)
	if err != nil {
		panic(err)
	}
	d.MgEngine = db
	d.MgEngine.SetSafe(&mgo.Safe{})
	d.MgEngine.SetMode(mgo.Monotonic, true)
	d.MgEngine.SetPoolLimit(39000)

	//初始化数据库
	if init == 1 {
		session, err := mgo.Dial(mongo)
		if err != nil {
			panic(err)
		}
		defer session.Close()
		// Optional. Switch the session to a monotonic behavior.
		session.SetMode(mgo.Monotonic, true)
		session.SetSafe(&mgo.Safe{})
		//user表
		res := InitDbAndColl(session, mdb, "users", GenJsonSchema(&models.User{}))
		u := session.DB(mdb).C("users")
		err = u.EnsureIndex(mgo.Index{
			Key:    []string{"uid"},
			Unique: true,
		})
		if err != nil {
			log.Println(err)
		}
		err = u.EnsureIndex(mgo.Index{
			Key:    []string{"phone"},
			Unique: true,
		})
		if err != nil {
			log.Println(err)
		}
		ct, _ := u.Find(bson.M{"uid": "admin"}).Count()
		if ct == 0 {
			stat := false
			t := time.Now().Local()
			var obj models.User
			obj.Id = bson.NewObjectId()
			obj.CreateAt = t
			obj.IsDisable = &stat
			obj.Uid = "admin"
			obj.Pwd = hex.EncodeToString(jcrypt.MsgEncode([]byte("coolpy")))
			obj.Name = "系统管理员"
			obj.Phone = "13800000000"
			obj.Rule = "admin"
			u.Insert(&obj)
		}
		res = InitDbAndColl(session, mdb, "smss", GenJsonSchema(&models.Sms{}))
		log.Println(res)
		sms := session.DB(mdb).C("smss")
		err = sms.EnsureIndex(mgo.Index{
			Key:         []string{"createat"},
			ExpireAfter: 15 * time.Minute,
		})
		err = sms.EnsureIndex(mgo.Index{
			Key: []string{"code", "phone"},
		})
		if err != nil {
			log.Println(err)
		}
		//登陆限制表
		res = InitDbAndColl(session, mdb, "denylogins", GenJsonSchema(&models.DenyLogin{}))
		log.Println(res)
		dls := session.DB(mdb).C("denylogins")
		err = dls.EnsureIndex(mgo.Index{
			Key:         []string{"createat"},
			ExpireAfter: 15 * time.Minute,
		})
		err = dls.EnsureIndex(mgo.Index{
			Key: []string{"uid"},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, "apps", GenJsonSchema(&models.App{}))
		log.Println(res)
		apps := session.DB(mdb).C("apps")
		err = apps.EnsureIndex(mgo.Index{
			Key: []string{"user_id"},
		})
		if err != nil {
			log.Println(err)
		}
		err = apps.EnsureIndex(mgo.Index{
			Key: []string{"app_id"},
		})
		if err != nil {
			log.Println(err)
		}
		err = apps.EnsureIndex(mgo.Index{
			Key: []string{"name"},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, "codetokens", GenJsonSchema(&models.CodeToken{}))
		log.Println(res)
		codetks := session.DB(mdb).C("codetokens")
		err = codetks.EnsureIndex(mgo.Index{
			Key:         []string{"createat"},
			ExpireAfter: 5 * time.Minute,
		})
		err = codetks.EnsureIndex(mgo.Index{
			Key: []string{"user_id"},
		})
		if err != nil {
			log.Println(err)
		}
		err = codetks.EnsureIndex(mgo.Index{
			Key: []string{"code"},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, "codes", GenJsonSchema(&models.Code{}))
		log.Println(res)
		cds := session.DB(mdb).C("codes")
		err = cds.EnsureIndex(mgo.Index{
			Key:         []string{"createat"},
			ExpireAfter: 5 * time.Minute,
		})
		err = cds.EnsureIndex(mgo.Index{
			Key: []string{"user_id"},
		})
		if err != nil {
			log.Println(err)
		}
		err = cds.EnsureIndex(mgo.Index{
			Key: []string{"app_id"},
		})
		if err != nil {
			log.Println(err)
		}
		err = cds.EnsureIndex(mgo.Index{
			Key: []string{"code"},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, "auths", GenJsonSchema(&models.Code{}))
		log.Println(res)
		ats := session.DB(mdb).C("auths")
		err = ats.EnsureIndex(mgo.Index{
			Key: []string{"user_id"},
		})
		if err != nil {
			log.Println(err)
		}
		err = ats.EnsureIndex(mgo.Index{
			Key: []string{"app_id"},
		})
		if err != nil {
			log.Println(err)
		}
		err = ats.EnsureIndex(mgo.Index{
			Key: []string{"code"},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, "mailcodes", GenJsonSchema(&models.MailCode{}))
		log.Println(res)
		mks := session.DB(mdb).C("mailcodes")
		err = mks.EnsureIndex(mgo.Index{
			Key:         []string{"createat"},
			ExpireAfter: 6 * time.Hour,
		})
		err = mks.EnsureIndex(mgo.Index{
			Key: []string{"user_id"},
		})
		if err != nil {
			log.Println(err)
		}
		err = mks.EnsureIndex(mgo.Index{
			Key: []string{"code"},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, "forms", GenJsonSchema(&models.Form{}))
		log.Println(res)
		fs := session.DB(mdb).C("forms")
		err = fs.EnsureIndex(mgo.Index{
			Key: []string{"fromoid"},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, "configs", GenJsonSchema(&models.Config{}))
		log.Println(res)
	}

	return nil
}

func (d *DbEngine) GetSess() *mgo.Session {
	return d.MgEngine.Copy()
}

func (d *DbEngine) GetColl(mg *mgo.Session, coll string) *mgo.Collection {
	return mg.DB(d.Mdb).C(coll)
}

func (d *DbEngine) GetGridfs(mg *mgo.Session, coll string) *mgo.GridFS {
	return mg.DB(d.Mdb).GridFS(coll)
}

func InitDbAndColl(session *mgo.Session, db, coll string, model map[string]interface{}) map[string]interface{} {
	result := bson.M{}
	if !CheckCollExists(session.DB(db), coll) {
		session.DB(db).C(coll).Create(&mgo.CollectionInfo{})
	}
	session.DB(db).Run(bson.D{{"collMod", coll}, {"validator", model}}, &result)
	return result
}

func CheckCollExists(db *mgo.Database, coll string) bool {
	names, err := db.CollectionNames()
	if err != nil {
		log.Printf("Failed to get coll names: %v", err)
	}

	for _, name := range names {
		if name == coll {
			return true
		}
	}
	return false
}

//创建数据库验证schema结构对象
func GenJsonSchema(obj interface{}) map[string]interface{} {
	flect := &mschema.Reflector{ExpandedStruct: true, RequiredFromJSONSchemaTags: true, AllowAdditionalProperties: true}
	ob := flect.Reflect(obj)
	bts, _ := ffjson.Marshal(&ob)
	var o map[string]interface{}
	ffjson.Unmarshal(bts, &o)
	return bson.M{"$jsonSchema": o}
}

func (d *DbEngine) Close() {
	d.MgEngine.Close()
}
