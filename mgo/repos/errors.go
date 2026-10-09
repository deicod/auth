package repos

import (
	"errors"
	"strings"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/internal/ctxutil"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func userError(err error, op string) error {
	var writeErr mongo.WriteException
	if errors.As(err, &writeErr) {
		for _, e := range writeErr.WriteErrors {
			if e.Code != 11000 {
				continue
			}
			// The server includes the index name even when keyPattern is absent
			// from a driver/server version's structured write error.
			switch {
			case strings.Contains(e.Message, "index: users_username_unique "), strings.Contains(e.Message, "index: users_username_nocase_unique "):
				return core.ErrUsernameExists
			case strings.Contains(e.Message, "index: users_email_unique "):
				return core.ErrEmailExists
			}
		}
	}
	return ctxutil.NormalizeError(err, op)
}
