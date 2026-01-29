package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deicod/auth/core"
)

func TestLargeBodyRejection(t *testing.T) {
	svc := &fakeService{}
	h := New(svc)

	// Create a body larger than 1MB (1048576 bytes)
	// We use a valid field "password" to avoid "unknown field" error before the size check
	largePassword := strings.Repeat("a", int(maxBodySize)+100)
	body := map[string]string{
		"email":    "u@example.com",
		"password": largePassword,
	}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(data))
	rr := httptest.NewRecorder()

	h.Login().ServeHTTP(rr, req)

	// We expect 400 Bad Request because the body is too large.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for large body, got %d", rr.Code)
	}
}

func TestUserAgentTruncation(t *testing.T) {
	svc := &fakeService{
		registerRes: core.AuthResult{User: core.UserPublic{ID: "1"}},
	}
	h := New(svc)

	// Create a massive User-Agent string (e.g. 10KB)
	massiveUA := strings.Repeat("a", 10240)

	body := map[string]string{"email": "u@example.com", "username": "user", "password": "pass"}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(data))
	req.Header.Set("User-Agent", massiveUA)
	rr := httptest.NewRecorder()

	h.Register().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr.Code)
	}

	// Verify the UA passed to the service is truncated to 512
	if len(svc.registerCmd.UserAgent) != 512 {
		t.Errorf("Expected UA length 512, got %d", len(svc.registerCmd.UserAgent))
	}
}
