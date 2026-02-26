package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestContentType_SimpleRequest(t *testing.T) {
	// Re-use fakeService from auth_test.go
	h := New(&fakeService{})

	// Scenario: An attacker tricks a browser into sending a "Simple Request" (e.g. text/plain)
	// which bypasses CORS preflight. If the server accepts it and processes it as JSON,
	// it's vulnerable to CSRF if authentication was cookie-based (though here it's Bearer token).
	// However, stricter Content-Type validation is a good defense-in-depth practice for APIs.

	body := map[string]string{"email": "test@example.com", "password": "pass"}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "text/plain") // Simple request content-type

	rr := httptest.NewRecorder()
	h.Login().ServeHTTP(rr, req)

	// We expect 400 Bad Request for invalid or unexpected Content-Type
	if rr.Code == http.StatusOK {
		t.Fatal("VULNERABLE: Accepted text/plain Content-Type")
	} else if rr.Code == http.StatusBadRequest {
		// Expected behavior: request rejected as bad JSON / unsupported media type
	} else {
		t.Logf("Got unexpected status %d", rr.Code)
	}
}

func TestContentType_ValidJSON(t *testing.T) {
	h := New(&fakeService{})
	body := map[string]string{"email": "test@example.com", "password": "pass"}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	h.Login().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for application/json, got %d", rr.Code)
	}
}

func TestContentType_ValidJSON_WithCharset(t *testing.T) {
	h := New(&fakeService{})
	body := map[string]string{"email": "test@example.com", "password": "pass"}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	rr := httptest.NewRecorder()
	h.Login().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for application/json; charset=utf-8, got %d", rr.Code)
	}
}
