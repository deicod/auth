package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	"github.com/deicod/auth/internal/authtest"
	"github.com/deicod/auth/sqlite/repos"
	modernsqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func testManagementService(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	cfg := DefaultConfig()
	cfg.DSN = "file:" + filepath.Join(t.TempDir(), "auth.db") + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	cfg.MaxOpenConns, cfg.MaxIdleConns = 4, 4
	external, err := sql.Open("sqlite", cfg.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = external.Close() })
	if _, err := external.ExecContext(ctx, `PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(ctx, ServiceConfig{
		Sqlite: cfg,
		Argon2: config.Argon2{Time: 1, Memory: 1024, Threads: 1, KeyLen: 32},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(ctx) })
	return svc, external
}

func testDB(db repos.DBTX) authtest.DB {
	convert := func(args []any) []any {
		out := append([]any(nil), args...)
		for i, arg := range out {
			if tm, ok := arg.(time.Time); ok {
				out[i] = tm.Format(time.RFC3339Nano)
			}
		}
		return out
	}
	return authtest.DB{
		Exec: func(ctx context.Context, query string, args ...any) error {
			_, err := db.ExecContext(ctx, query, convert(args)...)
			return err
		},
		QueryRow: func(ctx context.Context, query string, args ...any) authtest.Scanner {
			return db.QueryRowContext(ctx, query, convert(args)...)
		},
	}
}

func TestManagementContract(t *testing.T) {
	svc, external := testManagementService(t)
	repo := repos.NewUserRepository(external, time.Second*5)
	authtest.Run(t, authtest.Backend{
		Service: svc,
		DB:      testDB(external),
		InTx: func(ctx context.Context, fn func(authtest.DB, *Transaction) error) error {
			return svc.InTx(ctx, func(tx *sql.Tx, auth *Transaction) error { return fn(testDB(tx), auth) })
		},
		Begin: func(ctx context.Context) (*authtest.Tx, error) {
			tx, err := external.BeginTx(ctx, nil)
			if err != nil {
				return nil, err
			}
			auth, err := svc.WithTx(ctx, tx)
			if err != nil {
				_ = tx.Rollback()
				return nil, err
			}
			return &authtest.Tx{DB: testDB(tx), Auth: auth, Commit: tx.Commit, Rollback: tx.Rollback}, nil
		},
		UpdateRaw: func(ctx context.Context, id core.ID, name string) error {
			return repo.UpdateFields(ctx, string(id), map[string]interface{}{"username": name})
		},
		CreateRaw: func(ctx context.Context, email, name string) error {
			_, err := repo.Create(ctx, repos.CreateUserParams{Email: email, Username: name, PasswordHash: "unused", Role: "user", CreatedAt: time.Now(), UpdatedAt: time.Now()})
			return err
		},
	})
}

func TestWithTxRejectsStaleSnapshot(t *testing.T) {
	svc, external := testManagementService(t)
	ctx := context.Background()
	user, err := svc.Register(ctx, core.RegisterCommand{Email: "user@example.com", Username: "user", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := external.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	var name string
	if err := tx.QueryRowContext(ctx, `SELECT username FROM users WHERE id = ?`, string(user.User.ID)).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateUsername(ctx, user.User.ID, "updated"); err != nil {
		t.Fatal(err)
	}
	_, err = svc.WithTx(ctx, tx)
	var sqliteErr *modernsqlite.Error
	if !errors.As(err, &sqliteErr) || sqliteErr.Code() != sqlite3.SQLITE_BUSY_SNAPSHOT {
		t.Fatalf("expected stale snapshot rejection, got %v", err)
	}
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
