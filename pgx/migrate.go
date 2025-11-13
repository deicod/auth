package pgx

import (
	"context"
	_ "embed"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/0001_init.sql
var initMigration string

func applyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	statements := strings.Split(initMigration, ";")
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}
