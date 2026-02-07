package services

import (
	"context"
	"testing"
	"time"

	"github.com/deicod/auth/core"
)

// timeoutCheckingMailer is a mock that checks if the context has a deadline.
type timeoutCheckingMailer struct {
	hasDeadline bool
	notify      chan struct{}
}

func (m *timeoutCheckingMailer) SendVerification(_ context.Context, _ core.User, _ string) error {
	return nil
}

func (m *timeoutCheckingMailer) SendPasswordReset(ctx context.Context, _ core.User, _ string) error {
	_, m.hasDeadline = ctx.Deadline()
	close(m.notify)
	return nil
}

func (m *timeoutCheckingMailer) SendEmailChange(_ context.Context, _ core.User, _, _ string) error {
	return nil
}

func (m *timeoutCheckingMailer) SendEmailChangeAlert(_ context.Context, _ core.User, _ string) error {
	return nil
}

func TestForgotPasswordAsyncTimeout(t *testing.T) {
	// Setup stores and hasher
	stores := Stores{
		Users:          newMemUserStore(),
		Sessions:       newMemSessionStore(),
		Verifications:  newMemVerificationStore(),
		PasswordResets: newMemPasswordResetStore(),
		EmailChanges:   newMemEmailChangeStore(),
	}
	hasher := fakeHasher{}

	// Setup custom mailer
	mailer := &timeoutCheckingMailer{notify: make(chan struct{})}

	// Create service
	svc, err := New(Dependencies{
		Stores:         stores,
		Hasher:         hasher,
		SessionTokens:  newFixedTokenGenerator("sess"),
		TokenGenerator: newFixedTokenGenerator("tok"),
		Mailer:         mailer,
	})
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}

	ctx := context.Background()

	// Register a user first so ForgotPassword has something to find
	_, err = svc.Register(ctx, core.RegisterCommand{Email: "timeout@test.com", Username: "timeout", Password: "password123"})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Trigger forgot password
	if err := svc.ForgotPassword(ctx, core.ForgotPasswordCommand{Email: "timeout@test.com"}); err != nil {
		t.Fatalf("forgot password failed: %v", err)
	}

	// Wait for async email to be sent
	select {
	case <-mailer.notify:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for password reset email")
	}

	if !mailer.hasDeadline {
		t.Fatal("SendPasswordReset was called with a context without a deadline (infinite timeout)")
	}
}
