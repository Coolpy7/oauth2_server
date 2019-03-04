package auth

import (
	"auth/jcrypt"
	"auth/models"
	"context"
	"encoding/hex"
	"github.com/GiterLab/aliyun-sms-go-sdk/dysms"
	"github.com/jacoblai/mschema"
	"github.com/pquerna/ffjson/ffjson"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
	"go.mongodb.org/mongo-driver/x/bsonx"
	"log"
	"math/rand"
	"time"
)

var (
	AliyunSmsAccessID  = ""
	AliyunSmsAccessKEY = ""
)

type DbEngine struct {
	MgEngine       *mongo.Client //关系型数据库引擎
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

func (d *DbEngine) Open(mg, mdb, domain, playdomain, sk string, init int) error {
	d.Mdb = mdb
	d.Domain = domain
	d.PlayDomainName = playdomain
	d.SigningKey = []byte(sk)

	ops := options.Client().ApplyURI(mg)
	p := uint16(39000)
	ops.MaxPoolSize = &p
	ops.WriteConcern = writeconcern.New(writeconcern.J(true), writeconcern.W(1))
	ops.ReadPreference = readpref.PrimaryPreferred()
	mgClient, err := mongo.NewClient(ops)
	if err != nil {
		return err
	}
	d.MgEngine = mgClient
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = d.MgEngine.Connect(ctx)
	if err != nil {
		return err
	}
	err = d.MgEngine.Ping(ctx, readpref.PrimaryPreferred())
	if err != nil {
		log.Println("ping err", err.Error())
	}

	//初始化数据库
	if init == 1 {
		session, err := mongo.NewClient(ops)
		if err != nil {
			panic(err)
		}
		err = session.Connect(context.Background())
		if err != nil {
			panic(err)
		}
		//user表
		res := InitDbAndColl(session, mdb, models.T_USER, GenJsonSchema(&models.User{}))
		u := session.Database(mdb).Collection(models.T_USER)
		indexview := u.Indexes()
		_, err = indexview.CreateMany(context.Background(), []mongo.IndexModel{
			{
				Keys:    bsonx.Doc{{"uid", bsonx.Int32(1)}},
				Options: options.Index().SetUnique(true),
			},
			{
				Keys: bsonx.Doc{{"phone", bsonx.Int32(1)}},
			},
		})
		if err != nil {
			log.Println(err)
		}
		ct, _ := u.CountDocuments(context.Background(), bson.M{"uid": "admin"})
		if ct == 0 {
			stat := false
			t := time.Now().Local()
			var obj models.User
			obj.Id = primitive.NewObjectID()
			obj.CreateAt = t
			obj.IsDisable = &stat
			obj.Uid = "admin"
			obj.Pwd = hex.EncodeToString(jcrypt.MsgEncode([]byte("coolpy")))
			obj.Name = "系统管理员"
			obj.Phone = "13800000000"
			obj.Rule = "admin"
			_, _ = u.InsertOne(context.Background(), &obj)
		}
		res = InitDbAndColl(session, mdb, models.T_SMSS, GenJsonSchema(&models.Sms{}))
		log.Println(res)
		sms := session.Database(mdb).Collection(models.T_SMSS)
		indexview = sms.Indexes()
		_, err = indexview.CreateMany(context.Background(), []mongo.IndexModel{
			{
				Keys:    bsonx.Doc{{"createat", bsonx.Int32(1)}},
				Options: options.Index().SetExpireAfterSeconds(15 * 60),
			},
			{
				Keys: bsonx.Doc{{"phone", bsonx.Int32(1)}},
			},
			{
				Keys: bsonx.Doc{{"code", bsonx.Int32(1)}},
			},
		})
		if err != nil {
			log.Println(err)
		}
		//登陆限制表
		res = InitDbAndColl(session, mdb, models.T_DenyLogin, GenJsonSchema(&models.DenyLogin{}))
		log.Println(res)
		dls := session.Database(mdb).Collection(models.T_DenyLogin)
		indexview = dls.Indexes()
		_, err = indexview.CreateMany(context.Background(), []mongo.IndexModel{
			{
				Keys:    bsonx.Doc{{"createat", bsonx.Int32(1)}},
				Options: options.Index().SetExpireAfterSeconds(15 * 60),
			},
			{
				Keys: bsonx.Doc{{"uid", bsonx.Int32(1)}},
			},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, models.T_APP, GenJsonSchema(&models.App{}))
		log.Println(res)
		apps := session.Database(mdb).Collection(models.T_APP)
		indexview = apps.Indexes()
		_, err = indexview.CreateMany(context.Background(), []mongo.IndexModel{
			{
				Keys: bsonx.Doc{{"user_id", bsonx.Int32(1)}},
			},
			{
				Keys: bsonx.Doc{{"app_id", bsonx.Int32(1)}},
			},
			{
				Keys: bsonx.Doc{{"name", bsonx.Int32(1)}},
			},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, models.T_CodeToken, GenJsonSchema(&models.CodeToken{}))
		log.Println(res)
		codetks := session.Database(mdb).Collection(models.T_CodeToken)
		indexview = codetks.Indexes()
		_, err = indexview.CreateMany(context.Background(), []mongo.IndexModel{
			{
				Keys:    bsonx.Doc{{"createat", bsonx.Int32(1)}},
				Options: options.Index().SetExpireAfterSeconds(5 * 60),
			},
			{
				Keys: bsonx.Doc{{"user_id", bsonx.Int32(1)}},
			},
			{
				Keys: bsonx.Doc{{"code", bsonx.Int32(1)}},
			},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, models.T_Code, GenJsonSchema(&models.Code{}))
		log.Println(res)
		cds := session.Database(mdb).Collection(models.T_Code)
		indexview = cds.Indexes()
		_, err = indexview.CreateMany(context.Background(), []mongo.IndexModel{
			{
				Keys:    bsonx.Doc{{"createat", bsonx.Int32(1)}},
				Options: options.Index().SetExpireAfterSeconds(5 * 60),
			},
			{
				Keys: bsonx.Doc{{"user_id", bsonx.Int32(1)}},
			},
			{
				Keys: bsonx.Doc{{"app_id", bsonx.Int32(1)}},
			},
			{
				Keys: bsonx.Doc{{"code", bsonx.Int32(1)}},
			},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, "auths", GenJsonSchema(&models.Code{}))
		log.Println(res)
		ats := session.Database(mdb).Collection("auths")
		indexview = ats.Indexes()
		_, err = indexview.CreateMany(context.Background(), []mongo.IndexModel{
			{
				Keys: bsonx.Doc{{"user_id", bsonx.Int32(1)}},
			},
			{
				Keys: bsonx.Doc{{"app_id", bsonx.Int32(1)}},
			},
			{
				Keys: bsonx.Doc{{"code", bsonx.Int32(1)}},
			},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, "mailcodes", GenJsonSchema(&models.MailCode{}))
		log.Println(res)
		mks := session.Database(mdb).Collection("mailcodes")
		indexview = mks.Indexes()
		_, err = indexview.CreateMany(context.Background(), []mongo.IndexModel{
			{
				Keys:    bsonx.Doc{{"createat", bsonx.Int32(1)}},
				Options: options.Index().SetExpireAfterSeconds(60 * 60 * 6),
			},
			{
				Keys: bsonx.Doc{{"user_id", bsonx.Int32(1)}},
			},
			{
				Keys: bsonx.Doc{{"code", bsonx.Int32(1)}},
			},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, "forms", GenJsonSchema(&models.Form{}))
		log.Println(res)
		fs := session.Database(mdb).Collection("forms")
		indexview = fs.Indexes()
		_, err = indexview.CreateMany(context.Background(), []mongo.IndexModel{
			{
				Keys: bsonx.Doc{{"fromoid", bsonx.Int32(1)}},
			},
		})
		if err != nil {
			log.Println(err)
		}
		res = InitDbAndColl(session, mdb, "configs", GenJsonSchema(&models.Config{}))
		log.Println(res)

		session.Disconnect(context.Background())
	}

	return nil
}

func (d *DbEngine) GetSess() (mongo.Session, error) {
	session, err := d.MgEngine.StartSession(options.Session().SetDefaultReadPreference(readpref.Primary()))
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (d *DbEngine) GetColl(coll string) *mongo.Collection {
	col, _ := d.MgEngine.Database(d.Mdb).Collection(coll).Clone()
	return col
}

func InitDbAndColl(session *mongo.Client, db, coll string, model map[string]interface{}) map[string]interface{} {
	result := session.Database(db).RunCommand(context.Background(), bson.D{{"collMod", coll}, {"validator", model}})
	var res map[string]interface{}
	err := result.Decode(&res)
	if err != nil {
		log.Println(err)
	}
	return res
}

//创建数据库验证schema结构对象
func GenJsonSchema(obj interface{}) map[string]interface{} {
	flect := &mschema.Reflector{ExpandedStruct: true, RequiredFromJSONSchemaTags: true, AllowAdditionalProperties: true}
	ob := flect.Reflect(obj)
	bts, _ := ffjson.Marshal(&ob)
	var o map[string]interface{}
	_ = ffjson.Unmarshal(bts, &o)
	return bson.M{"$jsonSchema": o}
}

func (d *DbEngine) Close() {
	d.MgEngine.Disconnect(context.Background())
}
