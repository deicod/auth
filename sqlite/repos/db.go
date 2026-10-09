package repos

import (
	"context"
	"database/sql"
)

// DBTX is the database surface shared by *sql.DB, *sql.Conn and *sql.Tx.
type DBTX interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
