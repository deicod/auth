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

	// Create a test request with a non-localhost host
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()

	// Execute the request
	handler.ServeHTTP(w, req)

	// Check the response headers
	expectedHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'",
		"Permissions-Policy":        "geolocation=(), camera=(), microphone=(), payment=(), usb=(), vr=()",
	}

	for header, expectedValue := range expectedHeaders {
		if value := w.Header().Get(header); value != expectedValue {
			t.Errorf("Expected header %s to be %q, but got %q", header, expectedValue, value)
		}
	}
}

func TestSecurityHeaders_Localhost(t *testing.T) {
	// Create a simple handler that the middleware will wrap
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap the handler with the SecurityHeaders middleware
	handler := SecurityHeaders(nextHandler)

	// Test cases for localhost addresses
	localhosts := []string{
		"http://localhost:8080/foo",
		"http://127.0.0.1/foo",
		"http://[::1]/foo",
	}

	for _, url := range localhosts {
		req := httptest.NewRequest("GET", url, nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// HSTS should be MISSING for localhost
		if value := w.Header().Get("Strict-Transport-Security"); value != "" {
			t.Errorf("Expected Strict-Transport-Security to be empty for %s, but got %q", url, value)
		}

		// Other headers should still be present
		if value := w.Header().Get("X-Frame-Options"); value != "DENY" {
			t.Errorf("Expected X-Frame-Options to be DENY for %s, but got %q", url, value)
		}
	}
}
