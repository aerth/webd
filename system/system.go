package system

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	// for pw
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/argon2"

	// for cookies
	"github.com/gorilla/securecookie"

	// greylist
	"github.com/aerth/webd/greylist"
)

func New(config Config) *System {
	t1 := time.Now()
	var hashKey = []byte(config.Sec.HashKey)
	var blockKey = []byte(config.Sec.BlockKey)
	if config.Meta.DevelopmentMode {
		blockKey = nil // not encrypted cookies
	}
	var s = securecookie.New(hashKey, blockKey)
	var templates = map[string]*template.Template{}
	partials, err := filepath.Glob(filepath.Join("www", "templates", "_partials", "*.html"))
	if err != nil {
		log.Fatalln("couldn't enumerate partial templates")
	}
	if config.Meta.DevelopmentMode {
		log.Printf("Found %d partial templates: %q", len(partials), partials)
	}
	for _, name := range []string{"signup.html", "login.html", "index.html", "dashboard.html"} {
		if config.Meta.DevelopmentMode {
			log.Println("Parsing template:", name)
		}
		templates[name] = template.Must(template.New(name).ParseFiles(append([]string{filepath.Join("www", "templates", name)}, partials...)...))
	}
	if config.Meta.DevelopmentMode {
		log.Printf("Parsed %d templates in %s", len(templates), time.Since(t1))
	}

	sys := &System{cookies: s, templates: templates, devmode: config.Meta.DevelopmentMode, badguys: make(map[string]*uint32), config: config, Stats: Stats{t1: time.Now()}}

	go func(s *System) {
		sigchan := make(chan os.Signal)
		signal.Notify(sigchan, os.Kill, os.Interrupt, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
		for {
			select {
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
					os.Exit(111)
				}
			}
		}

	}(sys)

	return sys

}

func (s *System) ReloadTemplates() error {
	t1 := time.Now()
	var templates = map[string]*template.Template{}
	partials, err := filepath.Glob(filepath.Join("www", "templates", "_partials", "*.html"))
	if err != nil {
		return fmt.Errorf("couldn't enumerate partial templates")
	}
	if s.config.Meta.DevelopmentMode {
		log.Printf("Found %d partial templates: %q", len(partials), partials)
	}
	for _, name := range []string{"signup.html", "login.html", "index.html", "dashboard.html"} {
		if s.config.Meta.DevelopmentMode {
			log.Println("Parsing template:", name)
		}
		templates[name], err = template.New(name).ParseFiles(append([]string{filepath.Join("www", "templates", name)}, partials...)...)
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

type System struct {
	Stats     Stats
	Info      Info
	dbclient  interface{ Connect(context.Context) error }
	passwdDB  *bolt.DB
	cookies   *securecookie.SecureCookie
	templates map[string]*template.Template
	devmode   bool
	config    Config

	badguylock sync.Mutex
	badguys    map[string]*uint32
	greylist   *greylist.List
}

func (s *System) SetGreylist(g *greylist.List) {
	s.greylist = g
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

func (s *System) getStats() Stats {
	return s.Stats
}

func (s *System) getInfo() Info {
	return s.Info

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

func (u User) String() string {
	return fmt.Sprintf("User {Name: %s, ID: %s, Authkey: %.6s}", u.Name, u.ID, u.authkey)
}

func (s *System) hasher(in string, salt []byte) []byte {
	return argon2.IDKey(append(salt, []byte(in)...), salt, 2, 1024, 2, 32)
}

// compareDigest compares equality of two equal-length byte slices
func compareDigest(a, b []byte) bool {
	if len(a) != len(b) || len(a) < 32 {
		return false
	}

	return subtle.ConstantTimeCompare(a, b) == 1
}

var ErrBadCredentials = errors.New("bad credentials")
var ErrExists = errors.New("record already exists")
var ErrNotFound = errors.New("not found")
