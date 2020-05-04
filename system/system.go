package system

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"text/template"
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
	log.Printf("Found %d partial templates: %q", len(partials), partials)
	for _, name := range []string{"signup.html", "login.html", "index.html", "dashboard.html"} {
		log.Println("Parsing template:", name)
		templates[name] = template.Must(template.New(name).ParseFiles(append([]string{filepath.Join("www", "templates", name)}, partials...)...))
	}
	log.Printf("Parsed %d templates", len(templates))

	return &System{cookies: s, templates: templates, devmode: config.Meta.DevelopmentMode, badguys: make(map[string]*uint32), config: config, Stats: Stats{t1: time.Now()}}
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
	authkey string `json:"-"` // temporary login accept
}

func (u User) String() string {
	return fmt.Sprintf("User {Name: %s, ID: %s, Authkey: %.6s}", u.Name, u.ID, u.authkey)
}

func (s *System) hasher(in string, salt []byte) []byte {
	return argon2.IDKey(append(salt, []byte(in)...), salt, 2, 1024, 2, 32)
}

func (s *System) doLogin(p LoginPacket) (*User, error) {
	u, err := s.getUserByLogin(p.User)
	if err != nil {
		log.Println("doLogin: getUserByLogin: error:", err)
		return nil, err
	}
	if !s.checkUserPass(u.ID, p.Pass) {
		log.Println("checkuserpass failed")
		return nil, ErrBadCredentials
	}
	p.Pass = ""

	// session key
	authkeyb := make([]byte, 32, 32)
	rand.Read(authkeyb)
	authkey := fmt.Sprintf("%02x", authkeyb)
	err = s.boltdbUpdate("authkeys", p.User, authkeyb)
	if err != nil {
		return nil, err
	}
	u.authkey = authkey

	return u, nil
}

var ErrBadCredentials = errors.New("bad credentials")
var ErrExists = errors.New("record already exists")

func (s *System) doSignup(p SignupPacket) (*User, error) {
	log.Printf("signup new user: %q", p.User)
	rp, err := s.boltdbFetch("password", p.User)
	if err == nil {
		log.Println("user already exists")
		return nil, ErrExists
	}
	if rp != nil {
		return nil, ErrExists
	}
	u, err := s.getUserByLogin(p.User)
	if err == nil {
		return nil, ErrExists
	}
	u = &User{
		ID:   p.User,
		Name: p.User,
	}

	// generate new salt and hash with pw
	salt := make([]byte, 32, 32)
	rand.Read(salt)
	hashed := s.hasher(p.Pass, salt)

	saltAndHash := make([]byte, 64, 64)
	if copy(saltAndHash, salt)+
		copy(saltAndHash[32:], hashed) != 64 {
		log.Println("bad copy")
		return nil, ErrNotFound
	}
	err = s.boltdbUpdate("password", p.User, saltAndHash)
	if err != nil {
		return nil, err
	}

	log.Println("Checking usr password:", u.ID, p.Pass)
	if !s.checkUserPass(u.ID, p.Pass) {
		log.Println("checkuserpass failed")
		return nil, ErrBadCredentials
	}

	b, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}

	err = s.boltdbUpdate("userinfo", p.User, b)
	if err != nil {
		return nil, err
	}

	authkeyb := make([]byte, 32)
	rand.Read(authkeyb)
	authkey := fmt.Sprintf("%02x", authkeyb)
	err = s.boltdbUpdate("authkeys", p.User, authkeyb)
	if err != nil {
		return nil, err
	}
	u.authkey = authkey

	log.Println("Inserted password record:", p.User)
	return u, nil
}

var ErrNotFound = errors.New("not found")
