package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	svc := &fakeService{}
	h := New(svc)

	// Test Login endpoint as a representative of JSON responses
	body := map[string]string{"email": "u@example.com", "password": "pass"}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(string(data)))
	rr := httptest.NewRecorder()

	h.Login().ServeHTTP(rr, req)

	// Check for security headers
	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-Xss-Protection":       "1; mode=block",
		"Cache-Control":          "no-store",
		"Pragma":                 "no-cache",
	}

	for key, expectedValue := range expectedHeaders {
		if got := rr.Header().Get(key); got != expectedValue {
			t.Errorf("Header %s: expected %q, got %q", key, expectedValue, got)
		}
	}
}
