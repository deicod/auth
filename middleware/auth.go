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

// bearerToken extracts the bearer token from the Authorization header.
// It is optimized for zero allocations by avoiding strings.Fields.
func bearerToken(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if len(header) < 7 {
		return "", false
	}
	if !strings.EqualFold(header[:6], "Bearer") {
		return "", false
	}

	// The character immediately following "Bearer" MUST be whitespace (separator).
	// We strictly require ASCII whitespace (SP, HTAB, LF, VT, FF, CR)
	// which covers standard HTTP header usage and strings.Fields delimiters.
	c := header[6]
	if c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\v' && c != '\f' {
		return "", false
	}

	token := strings.TrimSpace(header[7:])
	if token == "" {
		return "", false
	}

	// Ensure no internal whitespace in the token to match strict 2-part format
	for i := 0; i < len(token); i++ {
		c := token[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' {
			return "", false
		}
	}
	return token, true
}
