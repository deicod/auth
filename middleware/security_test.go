package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	// Create a simple handler that the middleware will wrap
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap the handler with the SecurityHeaders middleware
	handler := SecurityHeaders(nextHandler)

	// Create a test request
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()

	// Execute the request
	handler.ServeHTTP(w, req)

	// Check the response headers
	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}

	for header, expectedValue := range expectedHeaders {
		if value := w.Header().Get(header); value != expectedValue {
			t.Errorf("Expected header %s to be %q, but got %q", header, expectedValue, value)
		}
	}

	// Ensure CSP is NOT set (as we removed it)
	if value := w.Header().Get("Content-Security-Policy"); value != "" {
		t.Errorf("Expected Content-Security-Policy to be empty, but got %q", value)
	}
}
