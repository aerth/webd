package system

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	// for pw, login info, and session storage
	bolt "go.etcd.io/bbolt"

	// hash
	"golang.org/x/crypto/argon2"
)

// get userinfo by login ID
func (s *System) getUserByLogin(name string) (*User, error) {
	if s.config.Meta.DevelopmentMode {
		log.Println("getUserByLogin()")
	}
	b, err := s.boltdbFetch("userinfo", name)
	if err != nil {
		log.Printf("error getting user %q by id: %v", name, err)
		return nil, ErrNotFound
	}
	if len(b) == 0 {
		return nil, ErrNotFound
	}
	var user = &User{}
	if err := json.Unmarshal(b, user); err != nil {
		log.Printf("error unmarshaling stored userinfo: %v", err)
		return nil, ErrNotFound
	}
	//log.Println("got userinfo:", string(b))
	return user, nil
}

// simple check hashed pw vs known hashed pw
func (s *System) checkUserPass(id string, clearPass string) bool {
	if s.config.Meta.DevelopmentMode {
		log.Println("checkUserPass()")
	}
	realHashedPassword, err := s.boltdbFetch("password", id)
	if err != nil {
		log.Println("error fetching user/pass:", err)
		return false
	}
	if len(realHashedPassword) != 64 {
		log.Println("error fetching user/pass:", len(realHashedPassword), "!= 64")
		return false
	}
	salt := make([]byte, 32, 32)
	copy(salt, realHashedPassword[:32])
	hashedPassword := s.hasher(clearPass, salt)
	return compareDigest(hashedPassword, realHashedPassword[32:])
}

// boltdbUpdate uses password db
func (s *System) boltdbUpdate(bucket string, id string, val []byte) error {
	if s.config.Meta.DevelopmentMode {
		log.Println("boltdbUpdate()")
	}
	if err := s.passwdDB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		err := b.Put([]byte(id), val)
		return err
	}); err != nil {
		return err
	}
	return nil
}

// boltdbFetch uses password db, if len == 0, ErrNotFound is returned
func (s *System) boltdbFetch(bucket, id string) ([]byte, error) {
	if s.config.Meta.DevelopmentMode {
		log.Println("boltdbFetch()")
	}
	var pass []byte
	if err := s.passwdDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		v := b.Get([]byte(id))
		pass = v
		return nil
	}); err != nil {
		return nil, err
	}
	if len(pass) == 0 {
		return nil, ErrNotFound
	}
	return pass, nil
}

func (s *System) doLogin(p LoginPacket) (*User, error) {
	u, err := s.getUserByLogin(p.User)
	if err != nil {
		log.Println("doLogin: getUserByLogin: error:", err)
		return nil, ErrBadCredentials
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
		log.Println("doLogin: updating db error:", err)
		return nil, ErrBadCredentials
	}
	u.authkey = authkey

	return u, nil
}

func (s *System) doSignup(p SignupPacket) (*User, error) {
	if !s.config.Sec.OpenSignups {
		return nil, fmt.Errorf("signups are closed")
	}
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
		log.Println("error updating db in signup:", err)
		return nil, ErrNotFound
	}

	log.Println("Checking usr password:", u.ID, p.Pass)
	if !s.checkUserPass(u.ID, p.Pass) {
		log.Println("checkuserpass failed")
		return nil, ErrBadCredentials
	}

	b, err := json.Marshal(u)
	if err != nil {
		log.Println("error marshalling user in signup:", err)
		return nil, ErrNotFound
	}

	err = s.boltdbUpdate("userinfo", p.User, b)
	if err != nil {
		log.Println("error updating db in signup:", err)
		return nil, ErrNotFound
	}

	authkeyb := make([]byte, 32)
	rand.Read(authkeyb)
	authkey := fmt.Sprintf("%02x", authkeyb)
	err = s.boltdbUpdate("authkeys", p.User, authkeyb)
	if err != nil {
		log.Println("error updating db in signup:", err)
		return nil, ErrNotFound
	}
	u.authkey = authkey

	log.Println("Inserted password record:", p.User)
	return u, nil
}

// initialize database connections and create buckets
func (s *System) InitDB() error {
	log.Println("connecting to bolt DB")

	filename := s.config.Sec.BoltDB
	if filename == "" {
		filename = "Passwords.db"
	}

	if _, err := os.Stat(filename); err != nil {
		if os.IsNotExist(err) {
			log.Println("creating new password database:", filename)
		} else {
			log.Printf("couldn't get fileinfo for password db %q: %v", filename, err)
		}
	}

	db, err := bolt.Open(filename, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		if err == bolt.ErrTimeout && !s.config.Diamond.Kicks {
			log.Println("Try -kick boot flag")
		}
		return err
	}

	db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucketIfNotExists([]byte("password"))
		tx.CreateBucketIfNotExists([]byte("userinfo"))
		tx.CreateBucketIfNotExists([]byte("authkeys"))
		return nil
	})
	s.passwdDB = db

	log.Println("connected to bolt DB")

	return nil
}

func (s *System) getStats() Stats {
	return s.Stats
}

func (s *System) getInfo() Info {
	return s.Info

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
