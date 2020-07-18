package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	diamondlib "github.com/aerth/diamond/lib"
	"github.com/aerth/webd/config"
	"github.com/aerth/webd/greylist"
	"github.com/aerth/webd/i/captcha"
	"github.com/aerth/webd/system"
	"github.com/gorilla/csrf"

	_ "net/http/pprof"
)

var info = "webd superb application of the web"
var logo = "" +
	"                __        __\n _      _____  / /_  ____/ /\n| | /| / / _ \\/ __ \\/ __  /   " + info + "\n" + "| |/ |/ /  __/ /_/ / /_/ /  \n|__/|__/\\___/_.___/\\__,_/   Source: " +
	"https://github.com/aerth/webd\n\n"

const DefaultListenAddr = "127.0.0.1:8080"
const DefaultListenAddrTLS = "127.0.0.1:1443"

func main() {

	// defaults
	var (
		doMongo     = false
		devmode     = false
		addr        = DefaultListenAddr
		configpath  = "config.json"
		sslCert     = ""
		sslKey      = ""
		sslAddr     = DefaultListenAddrTLS
		showVersion = false
		doKick      = false
	)

	// flags
	flag.StringVar(&addr, "addr", addr, "address to serve")
	flag.BoolVar(&doMongo, "useMongo", doMongo, "use MongoDB (not implemented yet)")
	flag.BoolVar(&doKick, "kick", doKick, "kick running instance before launching")
	flag.BoolVar(&devmode, "dev", devmode, "development mode (insecure)")
	flag.StringVar(&configpath, "conf", configpath, "path to config.json (use - for stdin)")
	flag.StringVar(&sslCert, "sslcert", sslCert, "path to ssl cert")
	flag.StringVar(&sslKey, "sslkey", sslKey, "path to ssl key")
	flag.StringVar(&sslAddr, "ssladdr", sslAddr, "listen TLS if cert and key exist")
	flag.BoolVar(&showVersion, "version", false, "show version and exit")
	doConfigDump := flag.Bool("dumpconfig", false, "dump config and exit")
	flag.Parse()

	log.SetPrefix("[webd] ")
	if doKick {
		d, err := diamondlib.NewClient("/tmp/webd.socket")
		if err == nil {
			log.Println("Sending KICK to old webd instance")
			d.Send("RUNLEVEL", "0")
		}
	}

	if os.Getenv("DEBUG") != "" {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	println(logo)
	println("webd", Version)
	if showVersion {
		os.Exit(0)
	}

	// read config file or stdin
	var config = new(config.Config)
	config.Meta.Version = "webd " + Version
	if configpath == "-" {
		dec := json.NewDecoder(os.Stdin)
		if err := dec.Decode(&config); err != nil {
			log.Fatalln("error decoding json config:", err)
		}
		log.Println("read config from stdin")
	} else {
		f, err := os.Open(configpath)
		if err != nil {
			log.Fatalln("error opening config file:", err)
		}
		dec := json.NewDecoder(f)
		if err := dec.Decode(&config); err != nil {
			f.Close()
			log.Fatalln("error decoding json config:", err)
		}
		f.Close()
		log.Println("read config from", configpath)
		config.ConfigFilePath = configpath
	}

	// override config with flag
	if devmode {
		config.Meta.DevelopmentMode = devmode
	}
	// log format and pprof debug server
	if config.Meta.DevelopmentMode {
		log.SetFlags(log.Lshortfile | log.LstdFlags)
	}

	if addr != DefaultListenAddr || config.Meta.ListenAddr == "" {
		config.Meta.ListenAddr = addr
	}

	if sslAddr != DefaultListenAddrTLS || config.Meta.ListenAddrTLS == "" {
		config.Meta.ListenAddrTLS = sslAddr
	}

	if doKick {
		config.Diamond.Kicks = true
	}

	// check config and init db
	s, err := system.New(config)
	if err != nil {
		log.Fatalln("boot error:", err)
	}

	if *doConfigDump {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent(" ", " ")
		err := enc.Encode(s.Config())
		if err != nil {
			log.Fatalln(err)
		}
		return
	}

	// TODO: only state-changing pages in dashboard
	CSRF := csrf.Protect([]byte(config.Sec.CSRFKey),
		csrf.Secure(!devmode), // is dev mode
		csrf.FieldName("_csrf"),
		csrf.CookieName(config.Sec.CookieName+"_csrf"))
	/*	CSRFPOST := func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
					h.ServeHTTP(w, r)
					return
				}
				CSRF(h).ServeHTTP(w, r)
			})
		}
	*/

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
	router.Handle("/i/captcha/", captcha.Server(250, 75))

	// templated
	router.Handle("/logout", CSRF(http.HandlerFunc(s.LogoutHandler)))
	router.Handle("/login", CSRF(http.HandlerFunc(s.LoginHandler)))
	router.Handle("/signup", CSRF(http.HandlerFunc(s.SignupHandler)))
	router.Handle("/dashboard", CSRF(http.HandlerFunc(s.DashboardHandler)))

	// forms
	router.Handle("/checkout", CSRF(http.HandlerFunc(s.HandleForm)))
	router.Handle("/contact", CSRF(http.HandlerFunc(s.HandleForm)))

	// status
	router.Handle("/status", CSRF(http.HandlerFunc(s.StatusHandler)))
	for x, y := range config.Webhook {
		router.Handle(x, webhookHandler(y))
	}

	// reverse proxy
	for path, dest := range config.ReverseProxy {
		prx, err := system.ReverseProxyHandler(*config, path, dest)
		if err != nil {
			log.Fatalln(err)
		}
		router.Handle(path, prx)
	}

	// home and 404s (OR rest of files in ./public if config allows)
	router.Handle("/", CSRF(http.HandlerFunc(s.HomeHandler)))

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
	if sslCert != "" && sslKey != "" && config.Meta.ListenAddrTLS != "" {
		// friendly link
		go func() {
			<-time.After(time.Second)
			log.Println("serving TLS: ", config.Meta.ListenAddrTLS)
		}()

		go func() {
			log.Fatalln(http.ListenAndServeTLS(config.Meta.ListenAddrTLS, sslCert, sslKey,
				glist.Protect(s.HitCounter(router))))
		}()
	}
	// friendly link
	go func() {
		<-time.After(time.Second)
		log.Println("serving HTTP:", config.Meta.ListenAddr)
		log.Println("View in browser:", config.Meta.SiteURL)
	}()

	if err := s.Run(router); err != nil {
		log.Println(err)
		return
	}

	//	log.Fatalln(http.ListenAndServe(config.Meta.ListenAddr,
	//		glist.Protect(s.HitCounter(router))))
}

type webhookHandler string

func (ww webhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

}
