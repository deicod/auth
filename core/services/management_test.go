package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/deicod/auth/core"
)

type managementUserSpy struct {
	UserStore
	lookups int
	err     error
}

func (s *managementUserSpy) FindByID(ctx context.Context, id core.ID) (core.User, error) {
	s.lookups++
	if s.err != nil {
		return core.User{}, s.err
	}
	return s.UserStore.FindByID(ctx, id)
}

func TestVerifyPasswordTimingAndInputBound(t *testing.T) {
	hasher := &countingHasher{}
	auth, deps := newCountingService(t, hasher)
	ctx := context.Background()
	res, err := auth.Register(ctx, core.RegisterCommand{Email: "user@example.com", Username: "user", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	users := &managementUserSpy{UserStore: deps.users}
	auth.stores.Users = users
	svc := NewManagementService(auth)

	for _, tc := range []struct {
		name     string
		id       core.ID
		password string
		want     error
	}{
		{"correct", res.User.ID, "password123", nil},
		{"wrong", res.User.ID, "wrong", core.ErrInvalidCredentials},
		{"missing", "missing", "password123", core.ErrInvalidCredentials},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hasher.verifyCalls = 0
			if err := svc.VerifyPassword(ctx, tc.id, tc.password); !errors.Is(err, tc.want) {
				t.Fatalf("VerifyPassword = %v, want %v", err, tc.want)
			}
			if hasher.verifyCalls != 1 {
				t.Fatalf("expected one hash verification, got %d", hasher.verifyCalls)
			}
		})
	}
	for _, id := range []core.ID{res.User.ID, "missing"} {
		users.lookups, hasher.verifyCalls = 0, 0
		if err := svc.VerifyPassword(ctx, id, strings.Repeat("x", maxPasswordLength+1)); !errors.Is(err, core.ErrInvalidCredentials) {
			t.Fatalf("oversized password: %v", err)
		}
		if users.lookups != 0 || hasher.verifyCalls != 0 {
			t.Fatal("oversized password reached database or hasher")
		}
	}
	users.err = errors.New("database unavailable")
	if err := svc.VerifyPassword(ctx, res.User.ID, "password123"); !errors.Is(err, users.err) {
		t.Fatalf("database error must remain actionable, got %v", err)
	}
}

type hashSpy struct {
	fakeHasher
	hashes int
}

func (s *hashSpy) Hash(password string) (string, error) {
	s.hashes++
	return s.fakeHasher.Hash(password)
}

func TestTransactionBindingAndDeniedResetDoNotHash(t *testing.T) {
	auth, deps := newTestService(t)
	hasher := &hashSpy{}
	auth.hasher = hasher
	res, err := auth.Register(context.Background(), core.RegisterCommand{Email: "user@example.com", Username: "user", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.issuePasswordReset(context.Background(), deps.users.users[res.User.ID])
	if err != nil {
		t.Fatal(err)
	}
	hasher.hashes = 0
	bound := NewTransaction(auth, auth.stores)
	denied := errors.New("policy denied")
	_, err = bound.ResetPassword(context.Background(), core.ResetPasswordCommand{Token: token, NewPassword: "newpassword123"}, func(context.Context, core.Mutation) error {
		return denied
	})
	if !errors.Is(err, denied) {
		t.Fatalf("ResetPassword = %v, want policy denial", err)
	}
	if hasher.hashes != 0 {
		t.Fatalf("binding or denied reset performed %d hashes", hasher.hashes)
	}
}
