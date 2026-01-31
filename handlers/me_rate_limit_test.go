package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deicod/auth/core"
)

func TestMeEndpointRateLimit(t *testing.T) {
	// Setup a mock service that always returns success for AuthenticateSession
	svc := &fakeService{
		meUser:    core.UserPublic{ID: "1", Email: "me@example.com"},
		meSession: core.SessionPublic{ID: "sess", UserID: "1"},
	}
	h := New(svc)

	// Me endpoint has a limit of 60 requests per minute
	// We will send 65 requests. First 60 should succeed. 61st should fail.
	limit := 60
	for i := 0; i < limit+5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer token123")
		req.RemoteAddr = "10.0.0.1:1234"
		rr := httptest.NewRecorder()

		h.Me().ServeHTTP(rr, req)

		if i < limit {
			if rr.Code != http.StatusOK {
				t.Fatalf("Request %d failed with status %d (expected 200)", i+1, rr.Code)
			}
		} else {
			if rr.Code != http.StatusTooManyRequests {
				t.Fatalf("Request %d succeeded with status %d (expected 429)", i+1, rr.Code)
			}
		}
	}
}
