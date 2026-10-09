package mgo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	"github.com/deicod/auth/mgo/models"
	"github.com/deicod/auth/mgo/repos"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type mongoFixture struct {
	svc    *Service
	client *mongo.Client // Deliberately different from the service's client.
	db     *mongo.Database
	cfg    Config
	ctx    context.Context
}

func newMongoFixture(t *testing.T, env string) *mongoFixture {
	t.Helper()
	uri := os.Getenv(env)
	if uri == "" {
		t.Skip("set " + env + " or use scripts/test-mongo.sh for real PSMDB tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	cfg := DefaultConfig()
	cfg.URI, cfg.Database = uri, "auth_test_"+bson.NewObjectID().Hex()
	// Exercise configurable collection names in every transaction binding.
	cfg.UsersCollection, cfg.SessionsCollection = "identities", "auth_sessions"
	cfg.VerificationCollection, cfg.PasswordResetCollection, cfg.EmailChangeCollection = "verify_tokens", "reset_tokens", "change_tokens"
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	mongoMust(t, err)
	db := client.Database(cfg.Database)
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := db.Drop(cleanupCtx); err != nil {
			t.Error(err)
		}
		mongoMust(t, client.Disconnect(cleanupCtx))
	})
	svc, err := NewService(ctx, ServiceConfig{Mongo: cfg, Argon2: config.Argon2{Time: 1, Memory: 1024, Threads: 1, KeyLen: 32}})
	mongoMust(t, err)
	t.Cleanup(func() { mongoMust(t, svc.Close(context.Background())) })
	return &mongoFixture{svc: svc, client: client, db: db, cfg: cfg, ctx: ctx}
}

const mongoPassword = "correct-password-123"

func (f *mongoFixture) register(t *testing.T) core.AuthResult {
	t.Helper()
	name := "u_" + bson.NewObjectID().Hex()
	result, err := f.svc.Register(f.ctx, core.RegisterCommand{Email: name + "@example.com", Username: name, Password: mongoPassword})
	mongoMust(t, err)
	return result
}

type mongoSnapshot struct {
	User           models.User
	Sessions       int64
	ActiveSessions int64
}

func (f *mongoFixture) database(ctx context.Context) *mongo.Database {
	if session := mongo.SessionFromContext(ctx); session != nil {
		return session.Client().Database(f.cfg.Database)
	}
	return f.db
}

func (f *mongoFixture) snapshot(t *testing.T, ctx context.Context, userID core.ID) mongoSnapshot {
	t.Helper()
	oid := mongoID(t, userID)
	db := f.database(ctx)
	var result mongoSnapshot
	mongoMust(t, db.Collection(f.cfg.UsersCollection).FindOne(ctx, bson.M{"_id": oid}).Decode(&result.User))
	var err error
	result.Sessions, err = db.Collection(f.cfg.SessionsCollection).CountDocuments(ctx, bson.M{"user_id": oid})
	mongoMust(t, err)
	result.ActiveSessions, err = db.Collection(f.cfg.SessionsCollection).CountDocuments(ctx, bson.M{"user_id": oid, "revoked": false})
	mongoMust(t, err)
	return result
}

func assertMongoSnapshot(t *testing.T, before, after mongoSnapshot) {
	t.Helper()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("credentials, timestamps or sessions unexpectedly changed")
	}
}

func mongoMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mongoID(t *testing.T, id core.ID) bson.ObjectID {
	t.Helper()
	oid, err := bson.ObjectIDFromHex(string(id))
	mongoMust(t, err)
	return oid
}

func assertMongoRace(t *testing.T, a, b, conflict error) {
	t.Helper()
	if a == nil && errors.Is(b, conflict) {
		return
	}
	if b == nil && errors.Is(a, conflict) {
		return
	}
	t.Fatalf("expected one success and one %v, got %v / %v", conflict, a, b)
}

func TestMongoManagement(t *testing.T) {
	f := newMongoFixture(t, "AUTH_TEST_MONGO_URI")
	t.Run("sessionless_verification", func(t *testing.T) {
		user := f.register(t)
		for _, login := range []bool{false, true} {
			if login {
				_, err := f.svc.Login(f.ctx, core.LoginCommand{Email: user.User.Email, Password: mongoPassword})
				mongoMust(t, err)
			}
			before := f.snapshot(t, f.ctx, user.User.ID)
			if (before.User.LastLoginAt != nil) != login {
				t.Fatal("login timestamp fixture is wrong")
			}
			for _, tc := range []struct {
				id       core.ID
				password string
				want     error
			}{
				{user.User.ID, mongoPassword, nil}, {user.User.ID, "wrong", core.ErrInvalidCredentials},
				{core.ID(bson.NewObjectID().Hex()), mongoPassword, core.ErrInvalidCredentials},
				{"invalid-id", mongoPassword, core.ErrInvalidCredentials}, {user.User.ID, strings.Repeat("x", 1025), core.ErrInvalidCredentials},
			} {
				if err := f.svc.VerifyPassword(f.ctx, tc.id, tc.password); !errors.Is(err, tc.want) {
					t.Fatalf("VerifyPassword = %v, want %v", err, tc.want)
				}
			}
			assertMongoSnapshot(t, before, f.snapshot(t, f.ctx, user.User.ID))
		}
	})
	t.Run("idempotent_revocation", func(t *testing.T) {
		user, other := f.register(t), f.register(t)
		_, err := f.svc.Login(f.ctx, core.LoginCommand{Email: user.User.Email, Password: mongoPassword})
		mongoMust(t, err)
		for range 2 {
			mongoMust(t, f.svc.RevokeSessionsByUser(f.ctx, user.User.ID))
		}
		mongoMust(t, f.svc.RevokeSessionsByUser(f.ctx, core.ID(bson.NewObjectID().Hex())))
		if f.snapshot(t, f.ctx, user.User.ID).ActiveSessions != 0 {
			t.Fatal("sessions remained active")
		}
		_, _, err = f.svc.AuthenticateSession(f.ctx, user.Token)
		if !errors.Is(err, core.ErrSessionNotFound) {
			t.Fatalf("revoked session accepted: %v", err)
		}
		_, _, err = f.svc.AuthenticateSession(f.ctx, other.Token)
		mongoMust(t, err)
	})
	t.Run("username_validation", func(t *testing.T) {
		user, other := f.register(t), f.register(t)
		before := f.snapshot(t, f.ctx, user.User.ID)
		for _, name := range []string{"", "ab", " \t", strings.Repeat("a", 31), "space name", "has.dot", "Äbc", "line\nbreak"} {
			_, err := f.svc.UpdateUsername(f.ctx, user.User.ID, name)
			if !errors.Is(err, core.ErrInvalidInput) {
				t.Fatalf("UpdateUsername(%q) = %v", name, err)
			}
			_, err = f.svc.Register(f.ctx, core.RegisterCommand{Email: bson.NewObjectID().Hex() + "@example.com", Username: name, Password: mongoPassword})
			if !errors.Is(err, core.ErrInvalidInput) {
				t.Fatalf("Register(%q) = %v", name, err)
			}
		}
		assertMongoSnapshot(t, before, f.snapshot(t, f.ctx, user.User.ID))
		for _, name := range []string{user.User.Username, strings.ToUpper(user.User.Username), " \tAbc_-19\n", strings.Repeat("a", 30)} {
			updated, err := f.svc.UpdateUsername(f.ctx, user.User.ID, name)
			mongoMust(t, err)
			if updated.Username != strings.TrimSpace(name) {
				t.Fatal("wrong normalization")
			}
		}
		_, err := f.svc.UpdateUsername(f.ctx, user.User.ID, strings.ToUpper(other.User.Username))
		if !errors.Is(err, core.ErrUsernameExists) {
			t.Fatalf("case conflict: %v", err)
		}
		_, err = f.svc.UpdateUsername(f.ctx, core.ID(bson.NewObjectID().Hex()), "valid_name")
		if !errors.Is(err, core.ErrUserNotFound) {
			t.Fatalf("missing user: %v", err)
		}
		repo := repos.NewUserRepository(f.db.Collection(f.cfg.UsersCollection), time.Second*5)
		if err := repo.UpdateFields(f.ctx, mongoID(t, user.User.ID), bson.M{"username": strings.ToUpper(other.User.Username)}); !errors.Is(err, core.ErrUsernameExists) {
			t.Fatalf("final update constraint: %v", err)
		}
		for _, tc := range []struct {
			email, name string
			want        error
		}{
			{bson.NewObjectID().Hex() + "@example.com", strings.ToUpper(other.User.Username), core.ErrUsernameExists},
			{other.User.Email, "unused_username", core.ErrEmailExists},
		} {
			_, err := repo.Create(f.ctx, models.User{Email: tc.email, Username: tc.name, PasswordHash: "unused", Role: "user"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("final create constraint: %v", err)
			}
		}
	})
	t.Run("ASCII_case_and_punctuation", func(t *testing.T) {
		for _, name := range []string{"Irene", "user-a", "user_a", "user01", "user1"} {
			_, err := f.svc.Register(f.ctx, core.RegisterCommand{Email: bson.NewObjectID().Hex() + "@example.com", Username: name, Password: mongoPassword})
			mongoMust(t, err)
		}
		_, err := f.svc.Register(f.ctx, core.RegisterCommand{Email: "irene2@example.com", Username: "irene", Password: mongoPassword})
		if !errors.Is(err, core.ErrUsernameExists) {
			t.Fatalf("I/i must conflict: %v", err)
		}
	})
	t.Run("username_lookup_treats_input_as_literal", func(t *testing.T) {
		user := f.register(t)
		repo := repos.NewUserRepository(f.db.Collection(f.cfg.UsersCollection), 5*time.Second)
		for _, name := range []string{`{"$ne":null}`, "$ne", "$where", "/.*/", "^.*$", user.User.Username[:5]} {
			_, err := repo.FindByUsername(f.ctx, name)
			if !errors.Is(err, mongo.ErrNoDocuments) {
				t.Fatalf("lookup(%q) matched or interpreted query syntax: %v", name, err)
			}
		}
	})
	for _, mode := range []string{"service", "transaction", "repository"} {
		t.Run("concurrent_username_"+mode, func(t *testing.T) {
			users := []core.AuthResult{f.register(t), f.register(t)}
			name := "r_" + bson.NewObjectID().Hex()
			start, results := make(chan struct{}), make(chan error, 2)
			for i, user := range users {
				go func() {
					<-start
					newName := name
					if i == 1 {
						newName = strings.ToUpper(name)
					}
					var err error
					switch mode {
					case "transaction":
						err = f.svc.InTx(f.ctx, func(ctx context.Context, tx *Transaction) error {
							_, err := tx.UpdateUsername(ctx, user.User.ID, newName)
							return err
						})
					case "repository":
						err = repos.NewUserRepository(f.db.Collection(f.cfg.UsersCollection), time.Second*5).UpdateFields(f.ctx, mongoID(t, user.User.ID), bson.M{"username": newName})
					default:
						_, err = f.svc.UpdateUsername(f.ctx, user.User.ID, newName)
					}
					results <- err
				}()
			}
			close(start)
			assertMongoRace(t, <-results, <-results, core.ErrUsernameExists)
		})
	}
	t.Run("role_update", func(t *testing.T) {
		user := f.register(t)
		updated, err := f.svc.UpdateRole(f.ctx, user.User.ID, core.RoleAdmin)
		mongoMust(t, err)
		if updated.Role != core.RoleAdmin {
			t.Fatal("role not updated")
		}
		_, err = f.svc.UpdateRole(f.ctx, user.User.ID, "unknown")
		if !errors.Is(err, core.ErrInvalidInput) {
			t.Fatalf("invalid role accepted: %v", err)
		}
	})
}

func TestMongoStandaloneManagementAndTransactionDenial(t *testing.T) {
	f := newMongoFixture(t, "AUTH_TEST_MONGO_STANDALONE_URI")
	user := f.register(t)
	mongoMust(t, f.svc.VerifyPassword(f.ctx, user.User.ID, mongoPassword))
	_, err := f.svc.UpdateUsername(f.ctx, user.User.ID, "standalone_user")
	mongoMust(t, err)
	_, err = f.svc.UpdateRole(f.ctx, user.User.ID, core.RoleAdmin)
	mongoMust(t, err)
	mongoMust(t, f.svc.RevokeSessionsByUser(f.ctx, user.User.ID))
	mongoMust(t, f.svc.RevokeSessionsByUser(f.ctx, user.User.ID))
	before := f.snapshot(t, f.ctx, user.User.ID)
	called := false
	err = f.svc.InTx(f.ctx, func(ctx context.Context, tx *Transaction) error {
		called = true
		_, err := f.db.Collection("consumer").InsertOne(ctx, bson.M{"value": 1})
		return err
	})
	if !errors.Is(err, core.ErrTransactionsUnsupported) || called {
		t.Fatalf("standalone fallback or wrong error: %v, called=%v", err, called)
	}
	session, err := f.client.StartSession()
	mongoMust(t, err)
	defer session.EndSession(f.ctx)
	mongoMust(t, session.StartTransaction())
	_, err = f.svc.WithTx(mongo.NewSessionContext(f.ctx, session))
	if !errors.Is(err, core.ErrTransactionsUnsupported) {
		t.Fatalf("standalone binding: %v", err)
	}
	mongoMust(t, session.AbortTransaction(f.ctx))
	assertMongoSnapshot(t, before, f.snapshot(t, f.ctx, user.User.ID))
	n, err := f.db.Collection("consumer").CountDocuments(f.ctx, bson.M{})
	mongoMust(t, err)
	if n != 0 {
		t.Fatal("standalone callback wrote consumer data")
	}
}

func (f *mongoFixture) consumerCount(t *testing.T, collection string, userID core.ID) int64 {
	t.Helper()
	n, err := f.db.Collection(collection).CountDocuments(f.ctx, bson.M{"user_id": mongoID(t, userID)})
	mongoMust(t, err)
	return n
}

func (f *mongoFixture) insertConsumer(ctx context.Context, userID core.ID) error {
	oid, err := bson.ObjectIDFromHex(string(userID))
	if err != nil {
		return err
	}
	_, err = mongo.SessionFromContext(ctx).Client().Database(f.cfg.Database).Collection("consumer").InsertOne(ctx, bson.M{"user_id": oid, "kind": "change"})
	return err
}

func TestMongoManagementTransactionAtomicity(t *testing.T) {
	f := newMongoFixture(t, "AUTH_TEST_MONGO_URI")
	mongoMust(t, f.db.CreateCollection(f.ctx, "consumer"))
	for _, external := range []bool{false, true} {
		for _, commit := range []bool{false, true} {
			t.Run(fmt.Sprintf("external_%t_commit_%t", external, commit), func(t *testing.T) {
				user := f.register(t)
				before := f.snapshot(t, f.ctx, user.User.ID)
				aborted := errors.New("consumer failure")
				callback := func(ctx context.Context, tx *Transaction) error {
					_, err := tx.UpdateUsername(ctx, user.User.ID, "upd_"+user.User.Username)
					if err != nil {
						return err
					}
					_, err = tx.UpdateRole(ctx, user.User.ID, core.RoleAdmin)
					if err != nil {
						return err
					}
					if err = tx.VerifyPassword(ctx, user.User.ID, mongoPassword); err != nil {
						return err
					}
					if err = tx.RevokeSessionsByUser(ctx, user.User.ID); err != nil {
						return err
					}
					if err = f.insertConsumer(ctx, user.User.ID); err != nil {
						return err
					}
					if !commit {
						return aborted
					}
					return nil
				}
				var err error
				if external {
					session, e := f.client.StartSession()
					mongoMust(t, e)
					defer session.EndSession(f.ctx)
					_, err = session.WithTransaction(f.ctx, func(ctx context.Context) (any, error) {
						tx, e := f.svc.WithTx(ctx)
						if e != nil {
							return nil, e
						}
						return nil, callback(ctx, tx)
					})
				} else {
					err = f.svc.InTx(f.ctx, callback)
				}
				if commit {
					mongoMust(t, err)
					after := f.snapshot(t, f.ctx, user.User.ID)
					if after.User.Username != "upd_"+user.User.Username || after.User.Role != "admin" || after.ActiveSessions != 0 || f.consumerCount(t, "consumer", user.User.ID) != 1 {
						t.Fatal("auth and consumer changes did not commit together")
					}
				} else {
					if !errors.Is(err, aborted) {
						t.Fatalf("callback error: %v", err)
					}
					assertMongoSnapshot(t, before, f.snapshot(t, f.ctx, user.User.ID))
					if f.consumerCount(t, "consumer", user.User.ID) != 0 {
						t.Fatal("consumer change survived rollback")
					}
				}
			})
		}
	}
	t.Run("panic", func(t *testing.T) {
		user := f.register(t)
		before := f.snapshot(t, f.ctx, user.User.ID)
		func() {
			defer func() {
				if p := recover(); p != "stop" {
					t.Fatalf("unexpected panic: %v", p)
				}
			}()
			_ = f.svc.InTx(f.ctx, func(ctx context.Context, tx *Transaction) error {
				_, err := tx.UpdateRole(ctx, user.User.ID, core.RoleAdmin)
				mongoMust(t, err)
				mongoMust(t, f.insertConsumer(ctx, user.User.ID))
				panic("stop")
			})
		}()
		assertMongoSnapshot(t, before, f.snapshot(t, f.ctx, user.User.ID))
		if f.consumerCount(t, "consumer", user.User.ID) != 0 {
			t.Fatal("panic did not roll back consumer data")
		}
	})
}
