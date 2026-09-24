package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/deicod/auth/core"
)

// Oversized passwords must be rejected before any database work, so an
// unauthenticated caller cannot burn DB resources with ~1MB passwords.
// This test proves the ordering: with an already-taken email, the
// password-length error must win over ErrEmailExists.
func TestRegister_RejectsLongPasswordBeforeDBLookup(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Register(ctx, core.RegisterCommand{
		Email: "taken@example.com", Username: "takenuser", Password: "password123",
	}); err != nil {
		t.Fatalf("seed register failed: %v", err)
	}

	longPassword := strings.Repeat("a", maxPasswordLength+1)
	_, err := svc.Register(ctx, core.RegisterCommand{
		Email:    "taken@example.com",
		Username: "anotheruser",
		Password: longPassword,
	})
	if err == nil {
		t.Fatal("expected error for oversized password, got nil")
	}
	if !errors.Is(err, core.ErrInvalidInput) || !strings.Contains(err.Error(), "password too long") {
		t.Fatalf("expected password-too-long ErrInvalidInput, got %v", err)
	}
	if errors.Is(err, core.ErrEmailExists) {
		t.Fatalf("email-exists check ran before password-length check: %v", err)
	}
}
