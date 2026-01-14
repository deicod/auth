package repos

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestVerificationRepository_Create(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	verRepo := NewVerificationRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "verify@example.com",
		Username:     "verifyuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	token, err := verRepo.Create(ctx, CreateVerificationParams{
		UserID:    user.ID,
		TokenHash: "verthash123",
		ExpiresAt: time.Now().Add(48 * time.Hour),
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if token.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if token.UserID != user.ID {
		t.Fatalf("expected UserID %q, got %q", user.ID, token.UserID)
	}
}

func TestVerificationRepository_FindByHash(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	verRepo := NewVerificationRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "findhash@example.com",
		Username:     "findhashuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	created, _ := verRepo.Create(ctx, CreateVerificationParams{
		UserID:    user.ID,
		TokenHash: "uniquehash",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	found, err := verRepo.FindByHash(ctx, "uniquehash")
	if err != nil {
		t.Fatalf("FindByHash failed: %v", err)
	}
	if found.ID != created.ID {
		t.Fatalf("expected ID %q, got %q", created.ID, found.ID)
	}
}

func TestVerificationRepository_FindByHash_NotFound(t *testing.T) {
	db := testDB(t)
	verRepo := NewVerificationRepository(db, 5*time.Second)
	ctx := context.Background()

	_, err := verRepo.FindByHash(ctx, "nonexistent")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestVerificationRepository_Consume(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	verRepo := NewVerificationRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "consume@example.com",
		Username:     "consumeuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	token, _ := verRepo.Create(ctx, CreateVerificationParams{
		UserID:    user.ID,
		TokenHash: "consumehash",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	consumedAt := time.Now()
	if err := verRepo.Consume(ctx, token.ID, consumedAt); err != nil {
		t.Fatalf("Consume failed: %v", err)
	}

	found, _ := verRepo.FindByHash(ctx, "consumehash")
	if found.ConsumedAt == nil {
		t.Fatal("expected ConsumedAt to be set")
	}
}

func TestVerificationRepository_DeleteByID(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	verRepo := NewVerificationRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "delete@example.com",
		Username:     "deleteveruser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	token, _ := verRepo.Create(ctx, CreateVerificationParams{
		UserID:    user.ID,
		TokenHash: "deletehash",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	if err := verRepo.DeleteByID(ctx, token.ID); err != nil {
		t.Fatalf("DeleteByID failed: %v", err)
	}

	_, err := verRepo.FindByHash(ctx, "deletehash")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows after delete, got %v", err)
	}
}
