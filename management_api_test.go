package auth_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/deicod/auth"
	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestManagementFactory(t *testing.T) {
	for _, customMailer := range []bool{false, true} {
		cfg := auth.DefaultConfig()
		cfg.Backend = auth.BackendSQLite
		cfg.Sqlite.DSN = ":memory:"
		cfg.Sqlite.MaxOpenConns = 1
		cfg.Email.Host = ""
		cfg.Argon2 = config.Argon2{Time: 1, Memory: 1024, Threads: 1, KeyLen: 32}
		var svc auth.ManagementService
		var err error
		mailer := &captureMailer{}
		if customMailer {
			svc, err = auth.NewManagementServiceWithMailer(context.Background(), cfg, mailer)
		} else {
			svc, err = auth.NewManagementService(context.Background(), cfg)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = svc.Close(context.Background()) })
		user, err := svc.Register(context.Background(), core.RegisterCommand{Email: "user@example.com", Username: "user", Password: "password123"})
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.VerifyPassword(context.Background(), user.User.ID, "password123"); err != nil {
			t.Fatal(err)
		}
		if customMailer && mailer.verificationCount() != 1 {
			t.Fatal("management factory did not preserve custom mailer")
		}
	}
}

func TestManagementFactoryRejectsUnsupportedBackend(t *testing.T) {
	cfg := auth.DefaultConfig()
	cfg.Backend = "unsupported"
	if _, err := auth.NewManagementService(context.Background(), cfg); !errors.Is(err, core.ErrInvalidInput) {
		t.Fatal("unsupported backend must fail before connecting")
	}
}

func TestMongoManagementFactory(t *testing.T) {
	uri := os.Getenv("AUTH_TEST_MONGO_URI")
	if uri == "" {
		t.Skip("use scripts/test-mongo.sh for real PSMDB tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	for _, customMailer := range []bool{false, true} {
		cfg := auth.DefaultConfig()
		cfg.Mongo.URI, cfg.Mongo.Database = uri, "auth_factory_"+bson.NewObjectID().Hex()
		cfg.Email.Host = ""
		cfg.Argon2 = config.Argon2{Time: 1, Memory: 1024, Threads: 1, KeyLen: 32}
		mailer := &captureMailer{}
		var svc auth.ManagementService
		if customMailer {
			svc, err = auth.NewManagementServiceWithMailer(ctx, cfg, mailer)
		} else {
			svc, err = auth.NewManagementService(ctx, cfg)
		}
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				_ = svc.Close(context.Background())
				_ = client.Database(cfg.Mongo.Database).Drop(context.Background())
			}()
			user, err := svc.Register(ctx, core.RegisterCommand{Email: "user@example.com", Username: "user", Password: "password123"})
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.VerifyPassword(ctx, user.User.ID, "password123"); err != nil {
				t.Fatal(err)
			}
			if customMailer && mailer.verificationCount() != 1 {
				t.Fatal("Mongo management factory did not preserve custom mailer")
			}
		}()
	}
}
