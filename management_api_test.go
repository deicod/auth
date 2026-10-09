package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/deicod/auth"
	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
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
	if _, err := auth.NewManagementService(context.Background(), auth.DefaultConfig()); !errors.Is(err, core.ErrInvalidInput) {
		t.Fatalf("MongoDB management must fail before connecting: %v", err)
	}
}
