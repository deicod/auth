package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/deicod/auth/core"
)

type SessionAuthenticator interface {
	AuthenticateSession(ctx context.Context, token string) (core.UserPublic, core.SessionPublic, error)
}

type contextKey string

const (
	userKey    contextKey = "auth.user"
	sessionKey contextKey = "auth.session"
)

func RequireAuth(authenticator SessionAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}

			user, session, err := authenticator.AuthenticateSession(r.Context(), token)
			if err != nil {
				http.Error(w, "invalid or expired session", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), userKey, user)
			ctx = context.WithValue(ctx, sessionKey, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func UserFromContext(ctx context.Context) (core.UserPublic, bool) {
	user, ok := ctx.Value(userKey).(core.UserPublic)
	return user, ok
}

func SessionFromContext(ctx context.Context) (core.SessionPublic, bool) {
	session, ok := ctx.Value(sessionKey).(core.SessionPublic)
	return session, ok
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 {
		return "", false
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", false
	}
	return token, true
}
