package system

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	// for data
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	// for pw, login info, and session storage
	bolt "go.etcd.io/bbolt"
)

// get userinfo by login ID
func (s *System) getUserByLogin(name string) (*User, error) {
	log.Println("getUserByLogin()")
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
	log.Println("checkUserPass()")
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
	return bytes.Compare(hashedPassword, realHashedPassword[32:]) == 0
}

// dbStore uses mongo
func (s *System) dbStore(method string, id string, val interface{}) error {
	log.Println("dbStore()")
	dbclient, ok := s.dbclient.(*mongo.Client)
	if !ok {
		return fmt.Errorf("got error")
	}
	collection := dbclient.Database("testing").Collection(method)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	_, err := collection.InsertOne(ctx, val)
	return err
}

// dbFetch uses mongo
func (s *System) dbFetch(method string, id string, result interface{}) error {
	log.Println("dbFetch()")
	dbclient, ok := s.dbclient.(*mongo.Client)
	if !ok {
		return fmt.Errorf("got error")
	}
	log.Println("fetching from database:", method, id)
	collection := dbclient.Database("testing").Collection(method)
	filter := bson.M{"ID": id}
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	err := collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		return err
	}
	return nil
}

// boltdbUpdate uses password db
func (s *System) boltdbUpdate(bucket string, id string, val []byte) error {
	log.Println("boltdbUpdate()")
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
	log.Println("boltdbFetch()")
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

// initialize database connections and create buckets
func (s *System) InitDB(doMongo bool) error {
	if doMongo {
		log.Println("connecting to mongoDB")
		client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
		if err != nil {
			return err
		}

		ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
		err = client.Connect(ctx)
		if err != nil {
			return err
		}
		err = client.Ping(ctx, readpref.Primary())
		if err != nil {
			return err
		}

		log.Println("connected to mongoDB")
		s.dbclient = client
	}

	log.Println("connecting to bolt DB")

	db, err := bolt.Open("Passwords.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
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
