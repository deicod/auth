package mgo

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	"github.com/deicod/auth/mgo/models"
	"github.com/deicod/auth/mgo/repos"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestMongoLegacyUsernameIndexUpgrade(t *testing.T) {
	for _, env := range []string{"AUTH_TEST_MONGO_URI", "AUTH_TEST_MONGO_STANDALONE_URI"} {
		for _, collision := range []bool{false, true} {
			name := env + "/clean"
			if collision {
				name = env + "/collisions"
			}
			t.Run(name, func(t *testing.T) {
				f := newMongoFixture(t, env)
				coll := f.db.Collection(f.cfg.UsersCollection)
				// Reproduce v1.2.0's exact username/email indexes with no new guard.
				mongoMust(t, coll.Indexes().DropOne(f.ctx, "users_username_nocase_unique"))
				names := []string{"Alice", "Bob"}
				if collision {
					names[1] = "ALICE"
				}
				ids := []bson.ObjectID{bson.NewObjectID(), bson.NewObjectID()}
				for i, name := range names {
					_, err := coll.InsertOne(f.ctx, models.User{ID: ids[i], Email: ids[i].Hex() + "@example.com", Username: name, PasswordHash: "legacy-hash", Role: "user", CreatedAt: time.Now().UTC()})
					mongoMust(t, err)
				}
				readUsers := func() []bson.M {
					cursor, err := coll.Find(f.ctx, bson.M{})
					mongoMust(t, err)
					var documents []bson.M
					mongoMust(t, cursor.All(f.ctx, &documents))
					return documents
				}
				before := readUsers()
				newService := func() (*Service, error) {
					return NewService(f.ctx, ServiceConfig{Mongo: f.cfg, Argon2: config.Argon2{Time: 1, Memory: 1024, Threads: 1, KeyLen: 32}})
				}
				svc, err := newService()
				if collision {
					if svc != nil {
						_ = svc.Close(f.ctx)
					}
					if !errors.Is(err, core.ErrUsernameExists) || !strings.Contains(err.Error(), "resolve existing") {
						t.Fatalf("legacy collision must block startup with remediation: %v", err)
					}
					if !reflect.DeepEqual(before, readUsers()) {
						t.Fatal("failed migration rewrote legacy accounts")
					}
					assertMongoUsernameIndexes(t, f, false)
					// Only the operator resolves the collision; auth never picks a user.
					_, err = coll.UpdateByID(f.ctx, ids[1], bson.M{"$set": bson.M{"username": "Bob"}})
					mongoMust(t, err)
					before = readUsers()
					svc, err = newService()
				}
				mongoMust(t, err)
				defer func() { mongoMust(t, svc.Close(f.ctx)) }()
				for range 2 {
					mongoMust(t, ensureIndexes(f.ctx, f.db, f.cfg))
				}
				if !reflect.DeepEqual(before, readUsers()) {
					t.Fatal("successful/repeated index upgrade rewrote legacy accounts")
				}
				assertMongoUsernameIndexes(t, f, true)
				repo := repos.NewUserRepository(coll, 5*time.Second)
				found, err := repo.FindByUsername(f.ctx, "aLiCe")
				mongoMust(t, err)
				if found.ID != ids[0] || found.Username != "Alice" {
					t.Fatal("legacy lookup lost case-insensitive/display semantics")
				}
				if err := repo.UpdateFields(f.ctx, ids[1], bson.M{"username": "alice"}); !errors.Is(err, core.ErrUsernameExists) {
					t.Fatalf("upgraded final race guard: %v", err)
				}
			})
		}
	}
}

func assertMongoUsernameIndexes(t *testing.T, f *mongoFixture, upgraded bool) {
	t.Helper()
	cursor, err := f.db.Collection(f.cfg.UsersCollection).Indexes().List(f.ctx)
	mongoMust(t, err)
	var indexes []struct {
		Name      string
		Unique    bool
		Collation struct {
			Locale   string
			Strength int
		}
	}
	mongoMust(t, cursor.All(f.ctx, &indexes))
	oldFound, newFound := false, false
	for _, index := range indexes {
		switch index.Name {
		case "users_username_unique":
			oldFound = index.Unique
		case "users_username_nocase_unique":
			newFound = index.Unique && index.Collation.Locale == "en" && index.Collation.Strength == 2
		}
	}
	if !oldFound || newFound != upgraded {
		t.Fatalf("unexpected migration/index state: old=%t new=%t upgraded=%t", oldFound, newFound, upgraded)
	}
}
