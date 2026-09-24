package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/deicod/auth/core"
)

type countingSessionStore struct {
	*memSessionStore
	findCalls int
}

func (c *countingSessionStore) FindByTokenHash(ctx context.Context, hash string) (core.Session, error) {
	c.findCalls++
	return c.memSessionStore.FindByTokenHash(ctx, hash)
}

func TestSessionToken_RejectsOversizedBeforeDB(t *testing.T) {
	sessions := &countingSessionStore{memSessionStore: newMemSessionStore()}
	svc, err := New(Dependencies{
		Stores: Stores{
			Users:          newMemUserStore(),
			Sessions:       sessions,
			Verifications:  newMemVerificationStore(),
			PasswordResets: newMemPasswordResetStore(),
			EmailChanges:   newMemEmailChangeStore(),
		},
		Hasher:         fakeHasher{},
		SessionTokens:  newFixedTokenGenerator("sess"),
		TokenGenerator: newFixedTokenGenerator("tok"),
		Mailer:         &captureMailer{},
	})
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	ctx := context.Background()

	// Legitimate token still works.
	reg, err := svc.Register(ctx, core.RegisterCommand{
		Email: "sessdos@example.com", Username: "sessdos", Password: "password123",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	sessions.findCalls = 0
	if _, _, err := svc.AuthenticateSession(ctx, reg.Token); err != nil {
		t.Fatalf("legitimate token rejected: %v", err)
	}
	if sessions.findCalls == 0 {
		t.Fatalf("expected DB lookup for legitimate token")
	}

	// Oversized tokens must fail fast without touching the store.
	oversized := strings.Repeat("a", maxTokenLength+1)
	sessions.findCalls = 0
	if _, _, err := svc.AuthenticateSession(ctx, oversized); !errors.Is(err, core.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for oversized session token, got %v", err)
	}
	if sessions.findCalls != 0 {
		t.Fatalf("expected no DB lookup for oversized session token, got %d calls", sessions.findCalls)
	}

	if err := svc.Logout(ctx, oversized); !errors.Is(err, core.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for oversized logout token, got %v", err)
	}
	if sessions.findCalls != 0 {
		t.Fatalf("expected no DB lookup for oversized logout token, got %d calls", sessions.findCalls)
	}

	// Whitespace-padded short values must also fail fast on raw length.
	padded := strings.Repeat(" ", maxTokenLength+1) + "x"
	sessions.findCalls = 0
	if _, _, err := svc.AuthenticateSession(ctx, padded); !errors.Is(err, core.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for padded session token, got %v", err)
	}
	if sessions.findCalls != 0 {
		t.Fatalf("expected no DB lookup for padded session token, got %d calls", sessions.findCalls)
	}
	if err := svc.Logout(ctx, padded); !errors.Is(err, core.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for padded logout token, got %v", err)
	}
	if sessions.findCalls != 0 {
		t.Fatalf("expected no DB lookup for padded logout token, got %d calls", sessions.findCalls)
	}
}
