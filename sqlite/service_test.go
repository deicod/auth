package sqlite

import (
	"context"
	"testing"

	"github.com/deicod/auth/core"
)

// TestServiceIntegration tests the SQLite service with in-memory database.
func TestServiceIntegration(t *testing.T) {
	ctx := context.Background()

	cfg := DefaultConfig()
	cfg.DSN = ":memory:?_foreign_keys=on"

	svc, err := NewService(ctx, ServiceConfig{
		Sqlite: cfg,
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	t.Cleanup(func() {
		if err := svc.Close(ctx); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})
}

func TestServiceRegisterAndLogin(t *testing.T) {
	ctx := context.Background()

	cfg := DefaultConfig()
	cfg.DSN = ":memory:?_foreign_keys=on"

	svc, err := NewService(ctx, ServiceConfig{
		Sqlite: cfg,
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	t.Cleanup(func() {
		if err := svc.Close(ctx); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})

	// Register a user
	regResult, err := svc.Register(ctx, core.RegisterCommand{
		Email:     "test@example.com",
		Username:  "testuser",
		Password:  "securepassword123",
		UserAgent: "test-agent",
		IP:        "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if regResult.User.Email != "test@example.com" {
		t.Fatalf("expected email 'test@example.com', got %q", regResult.User.Email)
	}
	if regResult.Token == "" {
		t.Fatal("expected non-empty token")
	}

	// Login with the registered user
	loginResult, err := svc.Login(ctx, core.LoginCommand{
		Email:     "test@example.com",
		Password:  "securepassword123",
		UserAgent: "test-agent",
		IP:        "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if loginResult.User.ID != regResult.User.ID {
		t.Fatalf("expected same user ID after login")
	}

	// Authenticate the session
	user, session, err := svc.AuthenticateSession(ctx, loginResult.Token)
	if err != nil {
		t.Fatalf("AuthenticateSession failed: %v", err)
	}
	if user.ID != regResult.User.ID {
		t.Fatalf("authenticated user ID mismatch")
	}
	if session.ID == "" {
		t.Fatal("expected non-empty session ID")
	}

	// Logout
	if err := svc.Logout(ctx, loginResult.Token); err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	// Session should be revoked after logout
	_, _, err = svc.AuthenticateSession(ctx, loginResult.Token)
	if err == nil {
		t.Fatal("expected error after logout")
	}
}

func TestServiceWrongPassword(t *testing.T) {
	ctx := context.Background()

	cfg := DefaultConfig()
	cfg.DSN = ":memory:?_foreign_keys=on"

	svc, err := NewService(ctx, ServiceConfig{
		Sqlite: cfg,
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	t.Cleanup(func() {
		if err := svc.Close(ctx); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})

	// Register a user
	_, err = svc.Register(ctx, core.RegisterCommand{
		Email:    "wrong@example.com",
		Username: "wronguser",
		Password: "correctpassword",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Login with wrong password
	_, err = svc.Login(ctx, core.LoginCommand{
		Email:    "wrong@example.com",
		Password: "wrongpassword",
	})
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if err != core.ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestServiceForgotAndResetPassword(t *testing.T) {
	ctx := context.Background()

	cfg := DefaultConfig()
	cfg.DSN = ":memory:?_foreign_keys=on"

	svc, err := NewService(ctx, ServiceConfig{
		Sqlite: cfg,
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	t.Cleanup(func() {
		if err := svc.Close(ctx); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})

	// Register a user
	_, err = svc.Register(ctx, core.RegisterCommand{
		Email:    "forgot@example.com",
		Username: "forgotuser",
		Password: "oldpassword",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Request password reset (will succeed even without actual email sending)
	err = svc.ForgotPassword(ctx, core.ForgotPasswordCommand{
		Email: "forgot@example.com",
	})
	if err != nil {
		t.Fatalf("ForgotPassword failed: %v", err)
	}
	// Note: In production, you'd capture the token from the mailer.
	// Here we just verify the flow doesn't error.
}
