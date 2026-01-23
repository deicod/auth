package services

import (
	"context"
	"testing"
	"time"

	"github.com/deicod/auth/core"
)

type slowMailer struct {
	captureMailer
}

func (s *slowMailer) SendPasswordReset(ctx context.Context, user core.User, token string) error {
	time.Sleep(50 * time.Millisecond)
	return s.captureMailer.SendPasswordReset(ctx, user, token)
}

func TestForgotPasswordTiming(t *testing.T) {
	svc, deps := newTestService(t)
	// Replace the mailer with a slow one
	slow := &slowMailer{captureMailer: *deps.mailer}

	// We need to re-create the service with the slow mailer
	// But newTestService returns a service with deps.mailer already injected.
	// We can just overwrite the mailer in the struct if it's exported?
	// No, it's private in AuthService.
	// So we need to reconstruct AuthService.

	// Let's just create a new one manually using the same deps but swapping mailer.
	var err error
	svc, err = New(Dependencies{
		Stores: Stores{
			Users:          deps.users,
			Sessions:       deps.sessions,
			Verifications:  deps.verifications,
			PasswordResets: deps.resets,
			EmailChanges:   deps.changes,
		},
		Hasher:         fakeHasher{},
		SessionTokens:  newFixedTokenGenerator("sess"),
		TokenGenerator: newFixedTokenGenerator("tok"),
		Mailer:         slow,
	})
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	ctx := context.Background()
	_, err = svc.Register(ctx, core.RegisterCommand{Email: "timing@example.com", Username: "timing", Password: "password123"})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	start := time.Now()
	err = svc.ForgotPassword(ctx, core.ForgotPasswordCommand{Email: "timing@example.com"})
	if err != nil {
		t.Fatalf("forgot password failed: %v", err)
	}
	duration := time.Since(start)

	// With the fix (async), it should take significantly less than 50ms.
	// We allow some overhead, but 20ms is a generous upper bound for a simple DB lookup + goroutine spawn.
	if duration > 20*time.Millisecond {
		t.Errorf("Expected duration < 20ms (async), got %v", duration)
	}
}
