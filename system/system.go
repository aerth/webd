package system

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	// for pw
	bolt "go.etcd.io/bbolt"

	// for cookies
	"github.com/gorilla/securecookie"

	// greylist
	"github.com/aerth/diamond"
	"github.com/aerth/webd/config"
	"github.com/aerth/webd/i/telegram"
	"gitlab.com/aerth/greylist"
)

type System struct {
	diamond   *diamond.Server
	Stats     Stats
	Info      Info
	dbclient  interface{ Connect(context.Context) error } // BoltDB
	passwdDB  *bolt.DB
	cookies   *securecookie.SecureCookie
	templates map[string]*template.Template
	devmode   bool
	config    config.Config

	badguylock sync.Mutex
	badguys    map[string]*uint32
	greylist   *greylist.List

	i Integrations // integrations

	shutdownChan chan struct{}
	files        struct {
		AuditLog *os.File
		DebugLog *os.File
	}
	listeners []net.Listener // 1 or 2 (http/s). Only used without Diamond
}

func (s *System) SetGreylist(g *greylist.List) {
	s.greylist = g
}

type SignupPacket struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}
type LoginPacket struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}
type User struct {
	Name    string `json:"name"`
	ID      string `json:"id"`
	authkey string // temporary login accept
}

type Stats struct {
	Hits    uint64  `json:"hits"`
	Average float64 `json:"hits-per-second,omitempty"`
	t1      time.Time
	Uptime  float64 `json:"uptime,omitempty"`
}

type Info struct {
	Contact string `json:"contact"`
}

var ErrBadCredentials = errors.New("bad credentials")
var ErrExists = errors.New("record already exists")
var ErrNotFound = errors.New("not found")

func (s *System) NewRPC() *RPC {
	return &RPC{s}
}
func (s *System) Config() config.Config {
	return s.config
}
func New(conf *config.Config) (*System, error) {
	if err := config.CheckConfig(conf); err != nil {
		return nil, err
	}

	var (
		t1        = time.Now()
		hashKey   = []byte(conf.Sec.HashKey)
		blockKey  = []byte(conf.Sec.BlockKey)
		templates = map[string]*template.Template{}
	)

	if conf.Meta.DevelopmentMode {
		blockKey = nil // not encrypted cookies
	}

	files, err := filepath.Glob(filepath.Join(conf.Meta.PathTemplates, "*.html"))
	if err != nil {
		return nil, err
	}
	for _, name := range files {
		name = filepath.Base(name)
		if t, err := parseTemplateFile(*conf, name); err != nil {
			return nil, fmt.Errorf("parseTemplateFile: %v", err)
		} else {
			templates[name] = t
		}
	}
	if conf.Meta.DevelopmentMode {
		log.Printf("Parsed %d templates in %s", len(templates), time.Since(t1))
	}

	sys := &System{
		cookies:   securecookie.New(hashKey, blockKey),
		templates: templates,
		devmode:   conf.Meta.DevelopmentMode,
		badguys:   make(map[string]*uint32),
		config:    *conf,
		Stats:     Stats{t1: time.Now()},
	}

	sys.config.Meta.TemplateData["Version"] = sys.config.Meta.Version

	// catch signals to reload config, templates, or quit.
	//go signalCatcher(sys)

	return sys, nil

}

func (s *System) Respawn() error {
	envv := os.Environ()

	cmd, err := os.Executable()
	if err != nil {
		return err
	}
	if err := syscall.Exec(cmd, os.Args, envv); err != nil {
		return err
	}
	panic("couldn't respawn correctly")
}
func (s *System) Run(router http.Handler) error {
	// config good, initialize database
	if err := s.InitDB(); err != nil {
		if err.Error() == "timeout" {
			log.Println("got timeout while trying to open password database... trying again in one second")
			<-time.After(time.Second)
			if err := s.InitDB(); err != nil {
				return fmt.Errorf("fatal: got timeout while trying to open password database. is another process using it?")
			}
		} else {
			return err
		}
	}

	// Handler

	var handler http.Handler
	if s.greylist != nil {
		handler = s.greylist.Protect(s.HitCounter(router))
	} else {
		log.Println("WARN: Greylist not active")
		handler = s.HitCounter(router)
	}

	// Diamond
	if s.config.Diamond.SocketPath == "" {
		d, err := diamond.New(s.config.Diamond.SocketPath, s.NewRPC())
		if err != nil && s.config.Diamond.Kicks {
			os.Remove(s.config.Diamond.SocketPath)
			s.passwdDB.Close()
			return s.Run(router)
		}
		if err != nil {
			log.Fatalln("error creating diamond:", err)
		}
		log.Println(d, s.greylist, router, s.config.Meta)
		s.diamond = d
		d.AddHTTPHandler(s.config.Meta.ListenAddr, handler)
		d.HookLevel0 = func() []net.Listener {
			s.Close()
			return nil
		}
	}
	// start telegram loop (reads channel)
	if k := s.config.Keys.TelegramBot; k != "" {
		log.Println("Connecting to Telegram")
		tg, err := telegram.New(k)
		if err != nil {
			return err
		}
		err = tg.Start()
		if err != nil {
			return err
		}
		s.i.tg = tg
		s.i.tgupdates = tg.UpdateChan()
		go startTelegramLoop(s)
	}

	if s.config.Diamond.SocketPath == "" {
		go signalCatcher(s)
		addr, err := net.ResolveTCPAddr("tcp", s.config.Meta.ListenAddr)
		if err != nil {
			log.Fatalln(err)
		}
		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			log.Fatalln(err)
		}
		s.listeners = []net.Listener{l}
		err = http.Serve(s.listeners[0], handler)
		if strings.Contains(err.Error(), "used of closed") {
			os.Exit(0)
		}
		log.Fatalln(err)
	} else {
		s.diamond.Runlevel(3)
	}
	signalCatcher(s) // blocks.
	return fmt.Errorf("server is disconnected")
}
func signalCatcher(s *System) {
	sigchan := make(chan os.Signal)
	signal.Notify(sigchan, os.Kill, os.Interrupt, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
	if s.shutdownChan != nil {
		log.Fatal("shutdown channel unset")
	}

	for {
		select {
		case <-s.shutdownChan: // called by Close()
			return
		case sig := <-sigchan:
			log.Println("got signal:", sig.String())
			switch sig {
			case syscall.SIGUSR1:
				log.Println("reloading config")
				if err := s.ReloadConfig(); err != nil {
					log.Println("Error reloading config:", err)
				}
			case syscall.SIGUSR2:
				log.Println("reloading templates")
				if err := s.ReloadTemplates(); err != nil {
					log.Println("Error reloading templates:", err)
				}
			default:
				// close http listener
				// close database
				// close unix socket
				// exit clean
				s.Close() // closes shutdownChan
				if s.config.Diamond.SocketPath == "" &&
					len(s.listeners) > 0 {
					log.Println("Shutting down http(s) server")
					for i := range s.listeners {
						s.listeners[i].Close()
					}
				}
				return
			}
		}
	}

}

func (s *System) ReloadTemplates() error {
	t1 := time.Now()
	var templates = map[string]*template.Template{}
	files, err := filepath.Glob(filepath.Join(s.config.Meta.PathTemplates, "*.html"))
	if err != nil {
		return fmt.Errorf("couldn't enumerate full templates")
	}
	for _, name := range files {
		name = filepath.Base(name)
		//		templates[name], err = template.New(name).ParseFiles(append([]string{filepath.Join(s.config.Meta.PathTemplates, name)}, partials...)...)
		templates[name], err = parseTemplateFile(s.config, name)
		if err != nil {
			return fmt.Errorf("couldn't parse template %q: %v", name, err)
		}
	}
	log.Printf("Parsed %d templates in %s", len(templates), time.Since(t1))
	s.templates = templates
	return nil
}
func (s *System) ReloadConfig() error {
	if s.config.ConfigFilePath == "" {
		return fmt.Errorf("can't reload config, was set using stdin")
	}
	f, err := os.Open(s.config.ConfigFilePath)
	defer f.Close()
	if err != nil {
		return err
	}
	dec := json.NewDecoder(f)
	if err := dec.Decode(&s.config); err != nil {
		return err
	}
	log.Println("reloaded config from", s.config.ConfigFilePath)
	return nil
}

func parseTemplateFile(config config.Config, name string) (*template.Template, error) {
	if config.Meta.DevelopmentMode {
		log.Println("Parsing template:", name)
	}
	partials, err := filepath.Glob(filepath.Join(config.Meta.PathTemplates, pathToPartials()))
	if err != nil {
		return nil, fmt.Errorf("error fetching partials: %v", err)
	}
	if len(partials) == 0 {
		return nil, fmt.Errorf("cant find any partials")
	}

	t, err := template.New(name).ParseFiles(append([]string{filepath.Join(config.Meta.PathTemplates, name)}, partials...)...)
	return t, err
}

func pathToPartials() string { // for glob
	return filepath.Join("_partials", "*.html")
}

func (s *System) Close() error {
	log.Println("Close() being called")

	// close telegram connection
	if s.i.tg != nil {
		s.i.tg.T.StopReceivingUpdates()
	}
	s.i = Integrations{}

	// remove socket (not needed)
	//if s.config.Diamond.SocketPath != "" {
	//	if err2 := os.Remove(s.config.Diamond.SocketPath); err2 != nil {
	//		log.Println("error removing diamond socket:", err2)
	//	}
	//}
	//	os.Remove("/tmp/webd.socket")

	// shutdown signal listener
	if s.shutdownChan != nil {
		close(s.shutdownChan)
	}
	err := s.passwdDB.Close()
	log.Println("Exit clean. Goodbye ;)")
	return err
}
