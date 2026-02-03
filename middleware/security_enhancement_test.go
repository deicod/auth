package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders_Enhancements(t *testing.T) {
	// Create a simple handler that the middleware will wrap
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap the handler with the SecurityHeaders middleware
	handler := SecurityHeaders(nextHandler)

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// New headers to verify
	expectedHeaders := map[string]string{
		"X-Permitted-Cross-Domain-Policies": "none",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"Cross-Origin-Resource-Policy":        "same-origin",
		"X-Download-Options":                "noopen",
	}

	for header, expectedValue := range expectedHeaders {
		if value := w.Header().Get(header); value != expectedValue {
			t.Errorf("Expected header %s to be %q, but got %q", header, expectedValue, value)
		}
	}
}
