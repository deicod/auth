package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"strings"
)

//go:embed migrations/0001_init.sql
var initMigration string

// applyMigrations executes the DDL statements to set up the database schema.
func applyMigrations(ctx context.Context, db *sql.DB) error {
	statements := strings.Split(initMigration, ";")
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}
