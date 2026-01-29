package services

import (
	"context"
	"strings"
	"testing"

	"github.com/deicod/auth/core"
)

func TestRegisterDosProtection(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Test Long Password
	longPassword := strings.Repeat("a", 2000)
	_, err := svc.Register(ctx, core.RegisterCommand{
		Email:    "valid@example.com",
		Username: "validuser",
		Password: longPassword,
	})
	if err == nil {
		t.Error("expected error for long password, got nil")
	} else if !strings.Contains(err.Error(), "password too long") {
		// We expect a specific error message once implemented
		t.Logf("got error: %v (expected 'password too long' after fix)", err)
	}

	// Test Long Email
	longEmail := strings.Repeat("a", 300) + "@example.com"
	_, err = svc.Register(ctx, core.RegisterCommand{
		Email:    longEmail,
		Username: "validuser",
		Password: "validpassword",
	})
	if err == nil {
		t.Error("expected error for long email, got nil")
	}
}

func TestLoginDosProtection(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Create a user first
	if _, err := svc.Register(ctx, core.RegisterCommand{
		Email: "u@e.com", Username: "user1", Password: "password123",
	}); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	longPassword := strings.Repeat("a", 2000)
	_, err := svc.Login(ctx, core.LoginCommand{
		Email:    "u@e.com",
		Password: longPassword,
	})
	if err == nil {
		t.Error("expected error for long password login, got nil")
	}
}
