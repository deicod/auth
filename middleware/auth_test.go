package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deicod/auth/core"
)

type fakeAuthenticator struct {
	token   string
	user    core.UserPublic
	session core.SessionPublic
	err     error
}

func (f *fakeAuthenticator) AuthenticateSession(_ context.Context, token string) (core.UserPublic, core.SessionPublic, error) {
	f.token = token
	return f.user, f.session, f.err
}

func TestRequireAuthSuccess(t *testing.T) {
	user := core.UserPublic{ID: "123", Email: "test@example.com"}
	session := core.SessionPublic{ID: "sess", UserID: "123"}
	auth := &fakeAuthenticator{user: user, session: session}

	called := false
	handler := RequireAuth(auth)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		gotUser, ok := UserFromContext(r.Context())
		if !ok || gotUser.ID != user.ID {
			t.Fatalf("expected user in context")
		}
		gotSession, ok := SessionFromContext(r.Context())
		if !ok || gotSession.ID != session.ID {
			t.Fatalf("expected session in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer token123")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 got %d", rr.Code)
	}
	if auth.token != "token123" {
		t.Fatalf("expected authenticator to get token, got %s", auth.token)
	}
	if !called {
		t.Fatalf("expected handler to be called")
	}
}

func TestRequireAuthMissingToken(t *testing.T) {
	auth := &fakeAuthenticator{}
	handler := RequireAuth(auth)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", rr.Code)
	}
	if auth.token != "" {
		t.Fatalf("authenticator should not be called")
	}
}

func TestRequireAuthInvalidSession(t *testing.T) {
	auth := &fakeAuthenticator{err: errors.New("invalid")}
	handler := RequireAuth(auth)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when authenticator fails, got %d", rr.Code)
	}
}
