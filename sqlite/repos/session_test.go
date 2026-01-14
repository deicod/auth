package repos

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestSessionRepository_Create(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	sessionRepo := NewSessionRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "session@example.com",
		Username:     "sessionuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	session, err := sessionRepo.Create(ctx, CreateSessionParams{
		UserID:    user.ID,
		TokenHash: "tokenhash123",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if session.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if session.UserID != user.ID {
		t.Fatalf("expected UserID %q, got %q", user.ID, session.UserID)
	}
}

func TestSessionRepository_FindByTokenHash(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	sessionRepo := NewSessionRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "findtoken@example.com",
		Username:     "findtokenuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	created, _ := sessionRepo.Create(ctx, CreateSessionParams{
		UserID:    user.ID,
		TokenHash: "uniquetokenhash",
		UserAgent: "cli",
		IP:        "127.0.0.1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	found, err := sessionRepo.FindByTokenHash(ctx, "uniquetokenhash")
	if err != nil {
		t.Fatalf("FindByTokenHash failed: %v", err)
	}
	if found.ID != created.ID {
		t.Fatalf("expected ID %q, got %q", created.ID, found.ID)
	}
}

func TestSessionRepository_FindByTokenHash_NotFound(t *testing.T) {
	db := testDB(t)
	sessionRepo := NewSessionRepository(db, 5*time.Second)
	ctx := context.Background()

	_, err := sessionRepo.FindByTokenHash(ctx, "nonexistent")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestSessionRepository_Revoke(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	sessionRepo := NewSessionRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "revoke@example.com",
		Username:     "revokeuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	session, _ := sessionRepo.Create(ctx, CreateSessionParams{
		UserID:    user.ID,
		TokenHash: "revokeme",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	if err := sessionRepo.Revoke(ctx, session.ID); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	found, _ := sessionRepo.FindByTokenHash(ctx, "revokeme")
	if !found.Revoked {
		t.Fatal("expected session to be revoked")
	}
}

func TestSessionRepository_RevokeByUser(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	sessionRepo := NewSessionRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "revokeall@example.com",
		Username:     "revokealluser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	// Create multiple sessions
	sessionRepo.Create(ctx, CreateSessionParams{
		UserID:    user.ID,
		TokenHash: "session1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})
	sessionRepo.Create(ctx, CreateSessionParams{
		UserID:    user.ID,
		TokenHash: "session2",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	if err := sessionRepo.RevokeByUser(ctx, user.ID); err != nil {
		t.Fatalf("RevokeByUser failed: %v", err)
	}

	s1, _ := sessionRepo.FindByTokenHash(ctx, "session1")
	s2, _ := sessionRepo.FindByTokenHash(ctx, "session2")
	if !s1.Revoked || !s2.Revoked {
		t.Fatal("expected all user sessions to be revoked")
	}
}
