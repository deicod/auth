package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLargeBodyRejection(t *testing.T) {
	svc := &fakeService{}
	h := New(svc)

	// Create a body larger than 1MB (1048576 bytes)
	// We use a valid field "password" to avoid "unknown field" error before the size check
	largePassword := strings.Repeat("a", 1048576+100)
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
