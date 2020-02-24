package main

import (
	"auth"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/didip/tollbooth"
	"github.com/didip/tollbooth/limiter"
	"github.com/jacoblai/httprouter"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	var (
		jk         = flag.String("jk", "Coolpy7yeah", "jwt密钥")
		aliid      = flag.String("ai", "", "阿里云AccessKey ID")
		alikey     = flag.String("ak", "", "阿里云Access Key Secret")
		addr       = flag.String("l", ":8000", "端口号")
		mongo      = flag.String("m", "mongodb://localhost:27017", "mongodb数据库连接字符串")
		domain     = flag.String("dm", "https://192.168.190.167:8000", "本程序公网域名")
		playdomain = flag.String("pdm", "http://192.168.190.167:3000", "前端公网域名")
	)
	flag.Parse()

	realdir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	dir := realdir + "/data"
	if _, err := os.Stat(dir); err != nil {
		log.Println(err)
		return
	}

	//启动文件日志
	//logFile, logErr := os.OpenFile(dir+"/dal.log", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
	//if logErr != nil {
	//	log.Printf("err: %v\n", logErr)
	//	return
	//
	//}
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	if *aliid == "" || *alikey == "" {
		log.Fatal("aliyun sms access id or key has null")
	} else {
		auth.AliyunSmsAccessID = *aliid
		auth.AliyunSmsAccessKEY = *alikey
	}

	eng := auth.NewDbEngine()
	err = eng.Open(*mongo, "cp7_oauth2", *domain, *playdomain, *jk, 1)
	if err != nil {
		log.Fatal("database connect error")
	}

	lmt := tollbooth.NewLimiter(10, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})
	lmt.SetIPLookups([]string{"RemoteAddr", "X-Forwarded-For", "X-Real-IP"})
	lmt.SetMethods([]string{"GET", "POST", "PUT", "DELETE"})

	router := httprouter.New()

	//短信
	router.POST("/api/v1/sms", eng.LimitHandler(eng.SendRegSms, lmt))
	router.POST("/api/v1/smail", eng.LimitHandler(eng.SendMail, lmt))
	//用户
	router.POST("/api/v1/reg", eng.LimitHandler(eng.Reg, lmt))
	router.POST("/api/v1/token", eng.LimitHandler(eng.GetApiToken, lmt))
	router.POST("/api/v1/pwd", eng.LimitHandler(eng.Upwd, lmt))
	router.POST("/api/v1/phone", eng.LimitHandler(eng.Uphone, lmt))
	router.POST("/api/v1/mail", eng.LimitHandler(eng.UMail, lmt))
	router.POST("/api/v1/info", eng.LimitHandler(eng.Auth(eng.UInfo), lmt))
	router.POST("/api/v1/avatar", eng.LimitHandler(eng.Auth(eng.Avatar), lmt))
	router.GET("/api/v1/profile", eng.LimitHandler(eng.Auth(eng.Profile), lmt))
	//成为开发者
	router.POST("/api/v1/forms", eng.LimitHandler(eng.Auth(eng.AddForm), lmt))
	router.GET("/api/v1/forms", eng.LimitHandler(eng.Auth(eng.GetForm), lmt))
	router.PUT("/api/v1/form/:id", eng.LimitHandler(eng.Auth(eng.PutForm), lmt))
	//管理用户
	router.POST("/api/v1/users", eng.LimitHandler(eng.Auth(eng.GetUser), lmt))
	router.PUT("/api/v1/user/:id", eng.LimitHandler(eng.Auth(eng.PutUser), lmt))
	//app
	router.POST("/api/v1/apps", eng.LimitHandler(eng.Auth(eng.CreateApps), lmt))
	router.GET("/api/v1/apps", eng.LimitHandler(eng.Auth(eng.GetApps), lmt))
	router.GET("/api/v1/app/:id", eng.LimitHandler(eng.Auth(eng.GetApp), lmt))
	router.PUT("/api/v1/app/:id", eng.LimitHandler(eng.Auth(eng.AppUpdate), lmt))
	router.DELETE("/api/v1/app/:id", eng.LimitHandler(eng.Auth(eng.AppDelete), lmt))
	//app other
	router.POST("/api/v1/appavatar/:id", eng.LimitHandler(eng.Auth(eng.AppAvatar), lmt))
	router.PUT("/api/v1/appsecret/:id", eng.LimitHandler(eng.Auth(eng.AppNewSecret), lmt))
	//头像
	router.GET("/api/v1/avatar/:id", eng.LimitHandler(eng.PhotoGet, lmt))
	//授权记录管理
	router.GET("/api/v1/auths", eng.LimitHandler(eng.Auth(eng.GetAuths), lmt))
	router.GET("/api/v1/auth/:id", eng.LimitHandler(eng.Auth(eng.AuthDelete), lmt))
	//https://test.icoolpy.com:8000/oauth2/authorize/?client_id=vsmh4lj8bakwho_q7d_1y7auu2l8jkgg&response_type=sso&scope=basic&state=state
	//https://104.168.30.201:8000/oauth2/authorize/?client_id=1havh6c_qc1uk334bzu0nwhcykgcrch1&redirect_uri=http://baidu.com&response_type=code&scope=basic&state=state
	router.GET("/oauth2/authorize", eng.LimitHandler(eng.Authorize, lmt))
	router.POST("/oauth2/login", eng.LimitHandler(eng.AuthLogin, lmt))
	router.GET("/oauth2/grant", eng.LimitHandler(eng.Grant, lmt))

	router.POST("/oauth2/token", eng.LimitHandler(eng.GetToken, lmt))
	router.GET("/oauth2/refresh", eng.LimitHandler(eng.RefreshToken, lmt))
	router.GET("/oauth2/me/:id", eng.LimitHandler(eng.MeInfo, lmt))
	//app pub
	router.GET("/api/v1/pub/app/:id", eng.LimitHandler(eng.GetPubApp, lmt))
	//system config
	router.GET("/api/v1/configs", eng.LimitHandler(eng.Auth(eng.GetConfig), lmt))
	router.PUT("/api/v1/config", eng.LimitHandler(eng.Auth(eng.PutConfig), lmt))

	srv := &http.Server{Handler: auth.CORS(router), ErrorLog: nil}
	cert, err := tls.LoadX509KeyPair(dir+"/server.pem", dir+"/server.key")
	if err != nil {
		log.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.TLSConfig = config
	srv.Addr = *addr

	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
	}()
	log.Println("server on tls port", *addr)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(realdir+"/build/static/"))))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, realdir+"/build/index.html")
	})
	go func() {
		if err := http.ListenAndServe(":9000", nil); err != nil {
			log.Fatal(err)
		}
	}()
	log.Println("web on port 9000")

	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan bool)
	cleanup := make(chan bool)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for range signalChan {
			ctx, _ := context.WithTimeout(context.Background(), 60*time.Second)
			go func() {
				srv.Shutdown(ctx)
				cleanup <- true
			}()
			<-cleanup
			eng.Close()
			fmt.Println("safe exit")
			cleanupDone <- true
		}
	}()
	<-cleanupDone
}
