package pgx

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	"github.com/deicod/auth/internal/authtest"
	"github.com/deicod/auth/pgx/models"
	"github.com/deicod/auth/pgx/repos"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("AUTH_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set AUTH_TEST_POSTGRES_DSN to run PostgreSQL 18 integration tests")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "auth_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
		if err != nil {
			t.Error(err)
		}
	})
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		query := u.Query()
		query.Set("search_path", schema)
		u.RawQuery = query.Encode()
		dsn = u.String()
	} else {
		dsn += " search_path=" + schema
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, dsn
}

func testManagementService(t *testing.T) (*Service, *pgxpool.Pool) {
	t.Helper()
	external, dsn := testPool(t)
	cfg := DefaultConfig()
	cfg.DSN = dsn
	svc, err := NewService(context.Background(), ServiceConfig{
		Pgx:    cfg,
		Argon2: config.Argon2{Time: 1, Memory: 1024, Threads: 1, KeyLen: 32},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	return svc, external
}

func testDB(db repos.DBTX) authtest.DB {
	return authtest.DB{
		Exec: func(ctx context.Context, query string, args ...any) error {
			_, err := db.Exec(ctx, replacePlaceholders(query), args...)
			return err
		},
		QueryRow: func(ctx context.Context, query string, args ...any) authtest.Scanner {
			return db.QueryRow(ctx, replacePlaceholders(query), args...)
		},
	}
}

func replacePlaceholders(query string) string {
	var out strings.Builder
	i := 0
	for _, ch := range query {
		if ch == '?' {
			i++
			fmt.Fprintf(&out, "$%d", i)
		} else {
			out.WriteRune(ch)
		}
	}
	return out.String()
}

func TestManagementContract(t *testing.T) {
	svc, external := testManagementService(t)
	repo := repos.NewUserRepository(external, time.Second*5)
	authtest.Run(t, authtest.Backend{
		Service:   svc,
		DB:        testDB(external),
		ForUpdate: " FOR UPDATE",
		InTx: func(ctx context.Context, fn func(authtest.DB, *Transaction) error) error {
			return svc.InTx(ctx, func(tx pgx.Tx, auth *Transaction) error { return fn(testDB(tx), auth) })
		},
		Begin: func(ctx context.Context) (*authtest.Tx, error) {
			tx, err := external.Begin(ctx)
			if err != nil {
				return nil, err
			}
			auth, err := svc.WithTx(ctx, tx)
			if err != nil {
				_ = tx.Rollback(ctx)
				return nil, err
			}
			return &authtest.Tx{DB: testDB(tx), Auth: auth, Commit: func() error { return tx.Commit(ctx) }, Rollback: func() error { return tx.Rollback(ctx) }}, nil
		},
		UpdateRaw: func(ctx context.Context, id core.ID, name string) error {
			return repo.UpdateFields(ctx, uuid.MustParse(string(id)), map[string]interface{}{"username": name})
		},
		CreateRaw: func(ctx context.Context, email, name string) error {
			_, err := repo.Create(ctx, models.User{Email: email, Username: name, PasswordHash: "unused", Role: "user", CreatedAt: time.Now(), UpdatedAt: time.Now()})
			return err
		},
	})
}

func TestTransactionArguments(t *testing.T) {
	svc, _ := testManagementService(t)
	if _, err := svc.WithTx(context.Background(), nil); !errors.Is(err, core.ErrInvalidInput) {
		t.Fatalf("nil transaction: %v", err)
	}
	if err := svc.InTx(context.Background(), nil); !errors.Is(err, core.ErrInvalidInput) {
		t.Fatalf("nil callback: %v", err)
	}
}

func TestUsernameASCIIFolding(t *testing.T) {
	svc, external := testManagementService(t)
	requireTurkishCollation(t, external)
	ctx := context.Background()
	if _, err := external.Exec(ctx, `ALTER TABLE users ALTER COLUMN username TYPE text COLLATE "tr-x-icu"`); err != nil {
		t.Fatal(err)
	}
	user, err := svc.Register(ctx, core.RegisterCommand{Email: "irene@example.com", Username: "Irene", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	repo := repos.NewUserRepository(external, time.Second*5)
	found, err := repo.FindByUsername(ctx, "irene")
	if err != nil || found.ID.String() != string(user.User.ID) {
		t.Fatalf("lookup must fold ASCII I/i independently of locale: %v", err)
	}
	_, err = svc.Register(ctx, core.RegisterCommand{Email: "other@example.com", Username: "irene", Password: "password123"})
	if !errors.Is(err, core.ErrUsernameExists) {
		t.Fatalf("registration accepted ASCII case conflict: %v", err)
	}
	updated, err := svc.UpdateUsername(ctx, user.User.ID, "irene")
	if err != nil || updated.Username != "irene" {
		t.Fatalf("case-only update failed: %v", err)
	}
}

func requireTurkishCollation(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM pg_collation WHERE collname = 'tr-x-icu')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Skip("PostgreSQL was built without Turkish ICU collation")
	}
}
