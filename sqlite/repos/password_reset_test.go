package repos

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestPasswordResetRepository_Create(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	resetRepo := NewPasswordResetRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "reset@example.com",
		Username:     "resetuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	token, err := resetRepo.Create(ctx, CreatePasswordResetParams{
		UserID:    user.ID,
		TokenHash: "resethash123",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if token.ID == "" {
		t.Fatal("expected non-empty ID")
	}
}

func TestPasswordResetRepository_FindByHash(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	resetRepo := NewPasswordResetRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "findreset@example.com",
		Username:     "findresetuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	created, _ := resetRepo.Create(ctx, CreatePasswordResetParams{
		UserID:    user.ID,
		TokenHash: "findresethash",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	found, err := resetRepo.FindByHash(ctx, "findresethash")
	if err != nil {
		t.Fatalf("FindByHash failed: %v", err)
	}
	if found.ID != created.ID {
		t.Fatalf("expected ID %q, got %q", created.ID, found.ID)
	}
}

func TestPasswordResetRepository_FindByHash_NotFound(t *testing.T) {
	db := testDB(t)
	resetRepo := NewPasswordResetRepository(db, 5*time.Second)
	ctx := context.Background()

	_, err := resetRepo.FindByHash(ctx, "nonexistent")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestPasswordResetRepository_Consume(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	resetRepo := NewPasswordResetRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "consumereset@example.com",
		Username:     "consumeresetuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	token, _ := resetRepo.Create(ctx, CreatePasswordResetParams{
		UserID:    user.ID,
		TokenHash: "consumeresethash",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	consumedAt := time.Now()
	if err := resetRepo.Consume(ctx, token.ID, consumedAt); err != nil {
		t.Fatalf("Consume failed: %v", err)
	}

	found, _ := resetRepo.FindByHash(ctx, "consumeresethash")
	if found.ConsumedAt == nil {
		t.Fatal("expected ConsumedAt to be set")
	}
}
