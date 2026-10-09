package pgx

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/pgx/models"
	"github.com/deicod/auth/pgx/repos"
)

func TestMigrateLegacyUsernames(t *testing.T) {
	for _, turkishCollation := range []bool{false, true} {
		for _, collision := range []bool{false, true} {
			name := "clean"
			if collision {
				name = "collision"
			}
			if turkishCollation {
				name += "_turkish"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				pool, _ := testPool(t)
				if _, err := pool.Exec(ctx, initMigration); err != nil {
					t.Fatal(err)
				}
				if turkishCollation {
					requireTurkishCollation(t, pool)
					if _, err := pool.Exec(ctx, `ALTER TABLE users ALTER COLUMN username TYPE text COLLATE "tr-x-icu"`); err != nil {
						t.Fatal(err)
					}
				}
				repo := repos.NewUserRepository(pool, time.Second*5)
				first, err := repo.Create(ctx, models.User{Email: "irene@example.com", Username: "Irene", PasswordHash: "existing-hash", Role: "admin", CreatedAt: time.Now(), UpdatedAt: time.Now()})
				if err != nil {
					t.Fatal(err)
				}
				secondName := "Bob"
				if collision {
					secondName = "irene"
				}
				second, err := repo.Create(ctx, models.User{Email: "other@example.com", Username: secondName, PasswordHash: "other-hash", Role: "user", CreatedAt: time.Now(), UpdatedAt: time.Now()})
				if err != nil {
					t.Fatal(err)
				}
				err = applyMigrations(ctx, pool)
				if collision {
					if !errors.Is(err, core.ErrUsernameExists) {
						t.Fatalf("expected actionable legacy collision error, got %v", err)
					}
					var exists bool
					if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'users_username_lower_unique')`).Scan(&exists); err != nil {
						t.Fatal(err)
					}
					if exists {
						t.Fatal("failed migration left an index behind")
					}
					unchanged, err := repo.FindByID(ctx, second.ID)
					if err != nil || unchanged.Username != "irene" || unchanged.PasswordHash != "other-hash" {
						t.Fatalf("failed migration modified legacy data: %v", err)
					}
					// Simulate an operator resolving the collision, then restart.
					if err := repo.UpdateFields(ctx, second.ID, map[string]interface{}{"username": "Bob"}); err != nil {
						t.Fatal(err)
					}
					if err := applyMigrations(ctx, pool); err != nil {
						t.Fatal(err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if err := applyMigrations(ctx, pool); err != nil {
					t.Fatalf("repeated migration: %v", err)
				}
				preserved, err := repo.FindByID(ctx, first.ID)
				if err != nil || preserved.Username != "Irene" || preserved.Role != "admin" || preserved.PasswordHash != "existing-hash" {
					t.Fatalf("migration modified legacy data: %v", err)
				}
				if err := repo.UpdateFields(ctx, second.ID, map[string]interface{}{"username": "iReNe"}); !errors.Is(err, core.ErrUsernameExists) {
					t.Fatalf("migration did not enforce case-insensitive uniqueness: %v", err)
				}
			})
		}
	}
}
