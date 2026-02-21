package services

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/deicod/auth/core"
)

type slowVerificationMailer struct {
	*captureMailer
	delay time.Duration
}

func (s *slowVerificationMailer) SendVerification(ctx context.Context, user core.User, token string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(s.delay):
		return nil
	}
}

func TestRegisterTimeout(t *testing.T) {
	// Temporarily reduce timeout for faster test
	origTimeout := syncTaskTimeout
	syncTaskTimeout = 100 * time.Millisecond
	defer func() { syncTaskTimeout = origTimeout }()

	svc, deps := newTestService(t)
	// Replace mailer with slow mailer that takes 200ms (longer than 100ms timeout)
	svc.mailer = &slowVerificationMailer{
		captureMailer: deps.mailer,
		delay:         200 * time.Millisecond,
	}

	ctx := context.Background()
	start := time.Now()

	// Register with a valid user
	_, err := svc.Register(ctx, core.RegisterCommand{
		Email:    "slow@example.com",
		Username: "slowuser",
		Password: "password123",
	})

	duration := time.Since(start)

	// We expect an error due to timeout
	if err == nil {
		t.Fatal("expected error due to timeout, got nil")
	}

	// The error should be related to context deadline exceeded.
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("expected deadline exceeded error, got: %v", err)
	}

	// We expect the operation to take around 100ms (timeout),
	// but definitely less than 200ms (hang duration).
	if duration >= 200*time.Millisecond {
		t.Fatalf("Register took too long: %v, expected ~100ms timeout", duration)
	}
	if duration < 50*time.Millisecond {
		t.Fatalf("Register returned too fast: %v, expected ~100ms timeout", duration)
	}

	// Verify cleanup: User should be deleted
	_, err = deps.users.FindByEmail(ctx, "slow@example.com")
	if err == nil {
		t.Fatal("expected user to be cleaned up after timeout, but found user")
	}
	if !strings.Contains(err.Error(), "user not found") && err != core.ErrUserNotFound {
		t.Errorf("expected user not found error, got: %v", err)
	}
}
