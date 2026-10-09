package pgx

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/deicod/auth/core"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/0001_init.sql
var initMigration string

//go:embed migrations/0002_username_unique.sql
var usernameMigration string

func applyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	for _, migration := range []string{initMigration, usernameMigration} {
		for stmt := range strings.SplitSeq(migration, ";") {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := tx.Exec(ctx, stmt); err != nil {
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "users_username_lower_unique" {
					return fmt.Errorf("%w: resolve existing case-insensitive username collisions before restarting auth", core.ErrUsernameExists)
				}
				return err
			}
		}
	}
	return tx.Commit(ctx)
}
