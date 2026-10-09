package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/sqlite/repos"
)

func TestMigrateLegacyUsernames(t *testing.T) {
	for _, collision := range []bool{false, true} {
		name := "clean"
		if collision {
			name = "collision"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "legacy.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			if _, err := db.ExecContext(ctx, initMigration); err != nil {
				t.Fatal(err)
			}
			repo := repos.NewUserRepository(db, time.Second*5)
			first, err := repo.Create(ctx, repos.CreateUserParams{Email: "alice@example.com", Username: "Alice", PasswordHash: "existing-hash", Role: "admin", CreatedAt: time.Now(), UpdatedAt: time.Now()})
			if err != nil {
				t.Fatal(err)
			}
			secondName := "Bob"
			if collision {
				secondName = "ALICE"
			}
			second, err := repo.Create(ctx, repos.CreateUserParams{Email: "other@example.com", Username: secondName, PasswordHash: "other-hash", Role: "user", CreatedAt: time.Now(), UpdatedAt: time.Now()})
			if err != nil {
				t.Fatal(err)
			}
			err = applyMigrations(ctx, db)
			if collision {
				if !errors.Is(err, core.ErrUsernameExists) {
					t.Fatalf("expected actionable legacy collision error, got %v", err)
				}
				var exists bool
				if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'users_username_nocase_unique')`).Scan(&exists); err != nil {
					t.Fatal(err)
				}
				if exists {
					t.Fatal("failed migration left an index behind")
				}
				unchanged, err := repo.FindByID(ctx, second.ID)
				if err != nil || unchanged.Username != "ALICE" || unchanged.PasswordHash != "other-hash" {
					t.Fatalf("failed migration modified legacy data: %v", err)
				}
				if err := repo.UpdateFields(ctx, second.ID, map[string]interface{}{"username": "Bob"}); err != nil {
					t.Fatal(err)
				}
				if err := applyMigrations(ctx, db); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if err := applyMigrations(ctx, db); err != nil {
				t.Fatalf("repeated migration: %v", err)
			}
			preserved, err := repo.FindByID(ctx, first.ID)
			if err != nil || preserved.Username != "Alice" || preserved.Role != "admin" || preserved.PasswordHash != "existing-hash" {
				t.Fatalf("migration modified legacy data: %v", err)
			}
			if err := repo.UpdateFields(ctx, second.ID, map[string]interface{}{"username": "aLiCe"}); !errors.Is(err, core.ErrUsernameExists) {
				t.Fatalf("migration did not enforce case-insensitive uniqueness: %v", err)
			}
		})
	}
}
