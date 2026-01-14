package repos

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestEmailChangeRepository_Create(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	emailRepo := NewEmailChangeRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "original@example.com",
		Username:     "emailuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	request, err := emailRepo.Create(ctx, CreateEmailChangeParams{
		UserID:    user.ID,
		NewEmail:  "newemail@example.com",
		TokenHash: "emailhash123",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if request.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if request.NewEmail != "newemail@example.com" {
		t.Fatalf("expected NewEmail 'newemail@example.com', got %q", request.NewEmail)
	}
}

func TestEmailChangeRepository_FindByHash(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	emailRepo := NewEmailChangeRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "find@example.com",
		Username:     "findemailuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	created, _ := emailRepo.Create(ctx, CreateEmailChangeParams{
		UserID:    user.ID,
		NewEmail:  "findnew@example.com",
		TokenHash: "findhash",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	found, err := emailRepo.FindByHash(ctx, "findhash")
	if err != nil {
		t.Fatalf("FindByHash failed: %v", err)
	}
	if found.ID != created.ID {
		t.Fatalf("expected ID %q, got %q", created.ID, found.ID)
	}
}

func TestEmailChangeRepository_FindByHash_NotFound(t *testing.T) {
	db := testDB(t)
	emailRepo := NewEmailChangeRepository(db, 5*time.Second)
	ctx := context.Background()

	_, err := emailRepo.FindByHash(ctx, "nonexistent")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestEmailChangeRepository_Consume(t *testing.T) {
	db := testDB(t)
	userRepo := NewUserRepository(db, 5*time.Second)
	emailRepo := NewEmailChangeRepository(db, 5*time.Second)
	ctx := context.Background()

	user, _ := userRepo.Create(ctx, CreateUserParams{
		Email:        "consume@example.com",
		Username:     "consumeemailuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	request, _ := emailRepo.Create(ctx, CreateEmailChangeParams{
		UserID:    user.ID,
		NewEmail:  "consumed@example.com",
		TokenHash: "consumehash",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	consumedAt := time.Now()
	if err := emailRepo.Consume(ctx, request.ID, consumedAt); err != nil {
		t.Fatalf("Consume failed: %v", err)
	}

	found, _ := emailRepo.FindByHash(ctx, "consumehash")
	if found.ConsumedAt == nil {
		t.Fatal("expected ConsumedAt to be set")
	}
}
