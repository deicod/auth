package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/deicod/auth/core"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

//go:embed migrations/0001_init.sql
var initMigration string

//go:embed migrations/0002_username_unique.sql
var usernameMigration string

// applyMigrations executes the DDL statements to set up the database schema.
func applyMigrations(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, migration := range []string{initMigration, usernameMigration} {
		for stmt := range strings.SplitSeq(migration, ";") {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				var sqliteErr *sqlite.Error
				if migration == usernameMigration && errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
					return fmt.Errorf("%w: resolve existing case-insensitive username collisions before restarting auth", core.ErrUsernameExists)
				}
				return err
			}
		}
	}
	return tx.Commit()
}
