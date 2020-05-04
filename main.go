package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/aerth/webd/greylist"
	"github.com/aerth/webd/system"
	"github.com/gorilla/csrf"

	_ "net/http/pprof"
)

func main() {

	// defaults
	var (
		doMongo    = false
		devmode    = false
		addr       = "127.0.0.1:8080"
		configpath = "config.json"
	)

	// flags
	flag.StringVar(&addr, "addr", addr, "address to serve")
	flag.BoolVar(&doMongo, "useMongo", doMongo, "use MongoDB (not implemented yet)")
	flag.BoolVar(&devmode, "dev", devmode, "development mode (insecure)")
	flag.StringVar(&configpath, "conf", configpath, "path to config.json (use - for stdin)")
	flag.Parse()

	if devmode {
		log.SetFlags(log.Lshortfile)
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	// read config file or stdin
	var config system.Config
	if configpath == "-" {
		dec := json.NewDecoder(os.Stdin)
		if err := dec.Decode(&config); err != nil {
			log.Fatalln(err)
		}
		log.Println("read config from stdin")
	} else {
		f, err := os.Open(configpath)
		if err != nil {
			log.Fatalln(err)
		}
		dec := json.NewDecoder(f)
		if err := dec.Decode(&config); err != nil {
			f.Close()
			log.Fatalln(err)
		}
		f.Close()
		log.Println("read config from", configpath)
	}

	// minimal config needed
	if config.Meta.SiteURL == "" {
		log.Fatalln("config needs Meta.siteurl")
	}
	if config.Sec.BlockKey == "" {
		log.Fatalln("config needs Security.block-key")
	}
	if config.Sec.CSRFKey == "" {
		log.Fatalln("config needs Security.csrf-key")
	}
	if config.Sec.HashKey == "" {
		log.Fatalln("config needs Security.hash-key")
	}
	if config.Sec.CookieName == "" {
		log.Fatalln("config needs Security.cookie-name")
	}

	// override is $PORT or $SITEURL are used (heroku, etc?)
	if port := os.Getenv("PORT"); port != "" {
		log.Println("overriding flags and config file with $PORT")
		addr = ":" + port
	}
	if siteurl := os.Getenv("SITEURL"); siteurl != "" {
		log.Println("overriding flags and config file with $SITEURL")
		config.Meta.SiteURL = siteurl
	}

	// check www/public exists
	_, err := os.Open(filepath.Join("www", "public"))
	if err != nil {
		log.Println("Warning: no public web assets found. Did you forget to unzip webassets.zip to ./www/public?")
		log.Fatalln("Try: make www/public")
	}

	if devmode {
		config.Meta.DevelopmentMode = devmode
	}

	// config good. lets start
	s := system.New(config)
	if err := s.InitDB(doMongo); err != nil {
		if err.Error() == "timeout" {
			log.Fatalln("got timeout while trying to open password database. is another process using it?")
		}
		log.Fatalln(err)
	}

	CSRF := csrf.Protect([]byte(config.Sec.CSRFKey),
		csrf.Secure(!devmode), // is dev mode
		csrf.FieldName("_csrf"),
		csrf.CookieName(config.Sec.CookieName+"_csrf"))
	CSRFPOST := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				h.ServeHTTP(w, r)
				return
			}
			CSRF(h).ServeHTTP(w, r)
		})
	}
	// Router
	// TODO: move this into New() ?
	router := &http.ServeMux{}
	router.Handle("/api/", CSRF(http.HandlerFunc(s.ApiHandler)))

	// static files
	router.Handle("/favicon.png", http.HandlerFunc(s.StaticHandler))
	router.Handle("/favicon.ico", http.HandlerFunc(s.StaticHandler))
	router.Handle("/css/", http.HandlerFunc(s.StaticHandler))
	router.Handle("/js/", http.HandlerFunc(s.StaticHandler))
	router.Handle("/webfonts/", http.HandlerFunc(s.StaticHandler))
	router.Handle("/.well-known/", http.HandlerFunc(s.StaticHandler))
	router.Handle("/robots.txt", http.HandlerFunc(s.StaticHandler))
	router.Handle("/humans.txt", http.HandlerFunc(s.StaticHandler))
	router.Handle("/sitemap.xml", http.HandlerFunc(s.StaticHandler))

	// templated
	router.Handle("/logout", CSRF(http.HandlerFunc(s.LogoutHandler)))
	router.Handle("/login", CSRF(http.HandlerFunc(s.LoginHandler)))
	router.Handle("/signup", CSRF(http.HandlerFunc(s.SignupHandler)))
	router.Handle("/dashboard", CSRF(http.HandlerFunc(s.DashboardHandler)))
	router.Handle("/contact", CSRFPOST(http.HandlerFunc(s.ContactHandler)))
	router.Handle("/status", CSRFPOST(http.HandlerFunc(s.StatusHandler)))

	// home and 404s
	router.Handle("/", CSRFPOST(http.HandlerFunc(s.HomeHandler)))

	// friendly link
	go func() {
		<-time.After(time.Second)
		log.Println("Serving:", config.Meta.SiteURL)
	}()

	// setup greylist
	var refreshRate time.Duration // none, no auto refresh
	temporaryBlacklistTime := time.Hour * 24
	if config.Meta.DevelopmentMode {
		log.Println("DEV MODE")
		refreshRate = time.Second * 10
		temporaryBlacklistTime = time.Minute
	}
	glist := greylist.New(config.Sec.Whitelist, config.Sec.Blacklist, refreshRate)
	glist.SetTemporaryBlacklistTime(temporaryBlacklistTime)
	s.SetGreylist(glist)

	// Serve or die!
	log.Fatalln(http.ListenAndServe(addr,
		glist.Protect(s.HitCounter(router))))
}
