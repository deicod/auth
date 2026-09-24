package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/deicod/auth/core"
)

type countingResetStore struct {
	*memPasswordResetStore
	findCalls int
}

func (c *countingResetStore) FindByHash(ctx context.Context, hash string) (core.PasswordResetToken, error) {
	c.findCalls++
	return c.memPasswordResetStore.FindByHash(ctx, hash)
}

type countingHashHasher struct {
	hashCalls int
}

func (h *countingHashHasher) Hash(password string) (string, error) {
	h.hashCalls++
	return "hash:" + password, nil
}

func (h *countingHashHasher) Verify(encoded, password string) error {
	if encoded != "hash:"+password {
		return errors.New("mismatch")
	}
	return nil
}

func TestResetPassword_RejectsLongPasswordBeforeDB(t *testing.T) {
	resets := &countingResetStore{memPasswordResetStore: newMemPasswordResetStore()}
	hasher := &countingHashHasher{}
	svc, err := New(Dependencies{
		Stores: Stores{
			Users:          newMemUserStore(),
			Sessions:       newMemSessionStore(),
			Verifications:  newMemVerificationStore(),
			PasswordResets: resets,
			EmailChanges:   newMemEmailChangeStore(),
		},
		Hasher:         hasher,
		SessionTokens:  newFixedTokenGenerator("sess"),
		TokenGenerator: newFixedTokenGenerator("tok"),
		Mailer:         &captureMailer{},
	})
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	// New() hashes a dummy password for timing protection; ignore it.
	hasher.hashCalls = 0

	longPassword := strings.Repeat("a", maxPasswordLength+1)
	_, err = svc.ResetPassword(context.Background(), core.ResetPasswordCommand{
		Token:       "some-token",
		NewPassword: longPassword,
	})
	if !errors.Is(err, core.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
	if !strings.Contains(err.Error(), "password too long") {
		t.Fatalf("expected 'password too long', got %v", err)
	}
	if resets.findCalls != 0 {
		t.Fatalf("expected no DB lookup for oversized password, got %d FindByHash calls", resets.findCalls)
	}
	if hasher.hashCalls != 0 {
		t.Fatalf("expected no hashing for oversized password, got %d Hash calls", hasher.hashCalls)
	}
}
