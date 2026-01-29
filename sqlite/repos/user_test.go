package repos

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// testDB creates an in-memory SQLite database for testing with schema applied.
// Uses shared cache mode to support concurrent access from multiple goroutines.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", "file::memory:?cache=shared&_foreign_keys=on")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})

	schema := `
	CREATE TABLE users (
		id TEXT PRIMARY KEY,
		email TEXT NOT NULL UNIQUE,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL,
		is_verified INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		verified_at TEXT,
		last_login_at TEXT
	);
	CREATE TABLE sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL UNIQUE,
		user_agent TEXT,
		ip TEXT,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL,
		revoked INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE verification_tokens (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL UNIQUE,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL,
		consumed_at TEXT
	);
	CREATE TABLE password_reset_tokens (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL UNIQUE,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL,
		consumed_at TEXT
	);
	CREATE TABLE email_change_requests (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		new_email TEXT NOT NULL,
		token_hash TEXT NOT NULL UNIQUE,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL,
		consumed_at TEXT
	);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("failed to apply schema: %v", err)
	}
	return db
}

func TestUserRepository_Create(t *testing.T) {
	db := testDB(t)
	repo := NewUserRepository(db, 5*time.Second)
	ctx := context.Background()

	user, err := repo.Create(ctx, CreateUserParams{
		Email:        "test@example.com",
		Username:     "testuser",
		PasswordHash: "hash123",
		Role:         "user",
		IsVerified:   false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if user.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if user.Email != "test@example.com" {
		t.Fatalf("expected email 'test@example.com', got %q", user.Email)
	}
}

func TestUserRepository_FindByEmail(t *testing.T) {
	db := testDB(t)
	repo := NewUserRepository(db, 5*time.Second)
	ctx := context.Background()

	created, _ := repo.Create(ctx, CreateUserParams{
		Email:        "find@example.com",
		Username:     "finduser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	found, err := repo.FindByEmail(ctx, "find@example.com")
	if err != nil {
		t.Fatalf("FindByEmail failed: %v", err)
	}
	if found.ID != created.ID {
		t.Fatalf("expected ID %q, got %q", created.ID, found.ID)
	}
}

func TestUserRepository_FindByEmail_NotFound(t *testing.T) {
	db := testDB(t)
	repo := NewUserRepository(db, 5*time.Second)
	ctx := context.Background()

	_, err := repo.FindByEmail(ctx, "nonexistent@example.com")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestUserRepository_FindByUsername(t *testing.T) {
	db := testDB(t)
	repo := NewUserRepository(db, 5*time.Second)
	ctx := context.Background()

	created, _ := repo.Create(ctx, CreateUserParams{
		Email:        "user@example.com",
		Username:     "findbyname",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	found, err := repo.FindByUsername(ctx, "findbyname")
	if err != nil {
		t.Fatalf("FindByUsername failed: %v", err)
	}
	if found.ID != created.ID {
		t.Fatalf("expected ID %q, got %q", created.ID, found.ID)
	}
}

func TestUserRepository_FindByID(t *testing.T) {
	db := testDB(t)
	repo := NewUserRepository(db, 5*time.Second)
	ctx := context.Background()

	created, _ := repo.Create(ctx, CreateUserParams{
		Email:        "byid@example.com",
		Username:     "byiduser",
		PasswordHash: "hash",
		Role:         "admin",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	found, err := repo.FindByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("FindByID failed: %v", err)
	}
	if found.Email != created.Email {
		t.Fatalf("expected email %q, got %q", created.Email, found.Email)
	}
}

func TestUserRepository_UpdateFields(t *testing.T) {
	db := testDB(t)
	repo := NewUserRepository(db, 5*time.Second)
	ctx := context.Background()

	created, _ := repo.Create(ctx, CreateUserParams{
		Email:        "update@example.com",
		Username:     "updateuser",
		PasswordHash: "oldhash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	verifiedAt := time.Now()
	err := repo.UpdateFields(ctx, created.ID, map[string]interface{}{
		"is_verified": true,
		"verified_at": verifiedAt,
	})
	if err != nil {
		t.Fatalf("UpdateFields failed: %v", err)
	}

	updated, _ := repo.FindByID(ctx, created.ID)
	if !updated.IsVerified {
		t.Fatal("expected IsVerified to be true")
	}
	if updated.VerifiedAt == nil {
		t.Fatal("expected VerifiedAt to be set")
	}
}

func TestUserRepository_DeleteByID(t *testing.T) {
	db := testDB(t)
	repo := NewUserRepository(db, 5*time.Second)
	ctx := context.Background()

	created, _ := repo.Create(ctx, CreateUserParams{
		Email:        "delete@example.com",
		Username:     "deleteuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	if err := repo.DeleteByID(ctx, created.ID); err != nil {
		t.Fatalf("DeleteByID failed: %v", err)
	}

	_, err := repo.FindByID(ctx, created.ID)
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows after delete, got %v", err)
	}
}

func TestUserRepository_ConcurrentCreate(t *testing.T) {
	db := testDB(t)
	repo := NewUserRepository(db, 5*time.Second)
	ctx := context.Background()

	const workers = 10
	var wg sync.WaitGroup
	errors := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := repo.Create(ctx, CreateUserParams{
				Email:        fmt.Sprintf("concurrent%d@example.com", i),
				Username:     fmt.Sprintf("concurrentuser%d", i),
				PasswordHash: "hash",
				Role:         "user",
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			})
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent create error: %v", err)
	}
}

func TestUserRepository_DuplicateEmail(t *testing.T) {
	db := testDB(t)
	repo := NewUserRepository(db, 5*time.Second)
	ctx := context.Background()

	_, err := repo.Create(ctx, CreateUserParams{
		Email:        "duplicate@example.com",
		Username:     "user1",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("first Create failed: %v", err)
	}

	// Attempt to create user with duplicate email
	_, err = repo.Create(ctx, CreateUserParams{
		Email:        "duplicate@example.com",
		Username:     "user2",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}
}

func TestUserRepository_DuplicateUsername(t *testing.T) {
	db := testDB(t)
	repo := NewUserRepository(db, 5*time.Second)
	ctx := context.Background()

	_, err := repo.Create(ctx, CreateUserParams{
		Email:        "unique1@example.com",
		Username:     "duplicateuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("first Create failed: %v", err)
	}

	// Attempt to create user with duplicate username
	_, err = repo.Create(ctx, CreateUserParams{
		Email:        "unique2@example.com",
		Username:     "duplicateuser",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})
	if err == nil {
		t.Fatal("expected error for duplicate username")
	}
}

func TestUserRepository_UpdateFields_Injection(t *testing.T) {
	db := testDB(t)
	repo := NewUserRepository(db, 5*time.Second)
	ctx := context.Background()

	victim, _ := repo.Create(ctx, CreateUserParams{
		Email:        "victim@example.com",
		Username:     "victim",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	attacker, _ := repo.Create(ctx, CreateUserParams{
		Email:        "attacker@example.com",
		Username:     "attacker",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	// Inject SQL: "role = 'admin' --"
	// Query becomes: UPDATE users SET role = 'admin' -- = ? WHERE id = ?
	// This sets role='admin' for ALL rows because WHERE is commented out.
	err := repo.UpdateFields(ctx, attacker.ID, map[string]interface{}{
		"role = 'admin' --": true,
	})

	// Before fix, this might succeed or fail depending on DB quirks, but if it succeeds, it's bad.
	// If it fails with "no such column" that's also fine, but we want to ensure we prevent it explicitly.
	// Actually, SQLite executes this.

	if err == nil {
		t.Fatal("expected error for invalid column injection, got nil")
	}

	updatedVictim, _ := repo.FindByID(ctx, victim.ID)
	if updatedVictim.Role == "admin" {
		t.Fatal("SQL Injection successful! Victim role changed to admin.")
	}
}
