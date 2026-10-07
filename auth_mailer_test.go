package auth_test

import (
	"context"
	"sync"
	"testing"

	"github.com/deicod/auth"
	"github.com/deicod/auth/core"
)

type captureMailer struct {
	mu                sync.Mutex
	verificationCalls int
}

func (m *captureMailer) SendVerification(context.Context, core.User, string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verificationCalls++
	return nil
}

func (*captureMailer) SendPasswordReset(context.Context, core.User, string) error {
	return nil
}

func (*captureMailer) SendEmailChange(context.Context, core.User, string, string) error {
	return nil
}

func (*captureMailer) SendEmailChangeAlert(context.Context, core.User, string) error {
	return nil
}

func (m *captureMailer) verificationCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.verificationCalls
}

func TestNewServiceWithMailerUsesCustomSender(t *testing.T) {
	ctx := context.Background()
	cfg := auth.DefaultConfig()
	cfg.Backend = auth.BackendSQLite
	cfg.Sqlite.DSN = "file:custom-mailer?mode=memory&cache=shared"
	cfg.Sqlite.MaxOpenConns = 1

	mailer := &captureMailer{}
	svc, err := auth.NewServiceWithMailer(ctx, cfg, mailer)
	if err != nil {
		t.Fatalf("NewServiceWithMailer: %v", err)
	}
	if closer, ok := svc.(interface{ Close(context.Context) error }); ok {
		t.Cleanup(func() {
			if err := closer.Close(context.Background()); err != nil {
				t.Errorf("close service: %v", err)
			}
		})
	}

	if _, err := svc.Register(ctx, core.RegisterCommand{
		Email:    "custom@example.com",
		Username: "custom",
		Password: "password123",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if got := mailer.verificationCount(); got != 1 {
		t.Fatalf("verification calls = %d, want 1", got)
	}
}

func TestNewServiceBehaviorIsUnchangedWithoutCustomSender(t *testing.T) {
	ctx := context.Background()
	cfg := auth.DefaultConfig()
	cfg.Backend = auth.BackendSQLite
	cfg.Sqlite.DSN = "file:default-mailer?mode=memory&cache=shared"
	cfg.Sqlite.MaxOpenConns = 1
	cfg.Email.Host = ""

	svc, err := auth.NewService(ctx, cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if closer, ok := svc.(interface{ Close(context.Context) error }); ok {
		t.Cleanup(func() {
			if err := closer.Close(context.Background()); err != nil {
				t.Errorf("close service: %v", err)
			}
		})
	}

	if _, err := svc.Register(ctx, core.RegisterCommand{
		Email:    "default@example.com",
		Username: "default",
		Password: "password123",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
}
