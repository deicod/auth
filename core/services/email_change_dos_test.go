package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/deicod/auth/core"
)

type countingHasher struct {
	verifyCalls int
	maxSeenLen  int
}

func (h *countingHasher) Hash(password string) (string, error) { return "hash:" + password, nil }

func (h *countingHasher) Verify(encoded, password string) error {
	h.verifyCalls++
	if len(password) > h.maxSeenLen {
		h.maxSeenLen = len(password)
	}
	if encoded != "hash:"+password {
		return errors.New("mismatch")
	}
	return nil
}

func newCountingService(t *testing.T, hasher *countingHasher) (*AuthService, *testDeps) {
	t.Helper()
	deps := &testDeps{
		users:         newMemUserStore(),
		sessions:      newMemSessionStore(),
		verifications: newMemVerificationStore(),
		resets:        newMemPasswordResetStore(),
		changes:       newMemEmailChangeStore(),
		mailer:        &captureMailer{notifyReset: make(chan struct{}, 1), notifyChange: make(chan struct{}, 1)},
	}
	svc, err := New(Dependencies{
		Stores: Stores{
			Users:          deps.users,
			Sessions:       deps.sessions,
			Verifications:  deps.verifications,
			PasswordResets: deps.resets,
			EmailChanges:   deps.changes,
		},
		Hasher:         hasher,
		SessionTokens:  newFixedTokenGenerator("sess"),
		TokenGenerator: newFixedTokenGenerator("tok"),
		Mailer:         deps.mailer,
	})
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	return svc, deps
}

func TestInitiateEmailChange_RejectsLongPasswordBeforeVerify(t *testing.T) {
	hasher := &countingHasher{}
	svc, _ := newCountingService(t, hasher)
	ctx := context.Background()

	longPassword := strings.Repeat("a", 2000)

	// Non-existent user path (dummy-hash branch): must fail fast without Argon2 work.
	err := svc.InitiateEmailChange(ctx, core.ChangeEmailCommand{
		UserID:   "non-existent-user",
		Password: longPassword,
		NewEmail: "new@example.com",
	})
	if !errors.Is(err, core.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if hasher.verifyCalls != 0 {
		t.Fatalf("expected no password verification for oversized password (not-found path), got %d calls (max len %d)", hasher.verifyCalls, hasher.maxSeenLen)
	}

	// Existing user path: register with a normal password, then retry with oversized one.
	res, err := svc.Register(ctx, core.RegisterCommand{Email: "u@e.com", Username: "user1", Password: "password123"})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	hasher.verifyCalls = 0
	hasher.maxSeenLen = 0
	err = svc.InitiateEmailChange(ctx, core.ChangeEmailCommand{
		UserID:   res.User.ID,
		Password: longPassword,
		NewEmail: "new2@example.com",
	})
	if !errors.Is(err, core.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if hasher.verifyCalls != 0 {
		t.Fatalf("expected no password verification for oversized password (found path), got %d calls", hasher.verifyCalls)
	}
}
