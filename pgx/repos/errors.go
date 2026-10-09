package repos

import (
	"errors"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/internal/ctxutil"
	"github.com/jackc/pgx/v5/pgconn"
)

func userError(err error, op string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		switch pgErr.ConstraintName {
		case "users_username_key", "users_username_lower_unique":
			return core.ErrUsernameExists
		case "users_email_key":
			return core.ErrEmailExists
		}
	}
	return ctxutil.NormalizeError(err, op)
}
