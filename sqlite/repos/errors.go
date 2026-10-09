package repos

import (
	"errors"
	"strings"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/internal/ctxutil"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func userError(err error, op string) error {
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
		switch {
		case strings.Contains(sqliteErr.Error(), "users.username"):
			return core.ErrUsernameExists
		case strings.Contains(sqliteErr.Error(), "users.email"):
			return core.ErrEmailExists
		}
	}
	return ctxutil.NormalizeError(err, op)
}
