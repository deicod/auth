package repos

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DBTX is the database surface shared by pgx pools, connections and transactions.
type DBTX interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func tokenLock(db DBTX) string {
	if _, ok := db.(pgx.Tx); ok {
		return " FOR UPDATE"
	}
	return ""
}
