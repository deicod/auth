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

func TestHugeIPDoS(t *testing.T) {
	svc := &fakeService{registerRes: core.AuthResult{User: core.UserPublic{ID: "1"}}}
	h := New(svc)

	body := map[string]string{"email": "u@example.com", "username": "user", "password": "pass"}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(data))
	// Simulate a massive X-Forwarded-For header (1MB)
	hugeIP := strings.Repeat("A", 1024*1024)
	req.Header.Set("X-Forwarded-For", hugeIP)

	// Set a known remote addr
	req.RemoteAddr = "1.2.3.4:1234"

	rr := httptest.NewRecorder()
	h.Register().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr.Code)
	}

	// Vulnerability Check: If vulnerability exists, svc.registerCmd.IP will be hugeIP.
	// We expect it to be filtered and fallback to RemoteAddr (or at least NOT be 1MB).
	if len(svc.registerCmd.IP) > 64 {
		t.Errorf("Expected IP length <= 64, got %d. The service accepted the huge header.", len(svc.registerCmd.IP))
	}
	if svc.registerCmd.IP != "1.2.3.4" {
		t.Errorf("Expected IP '1.2.3.4' (fallback), got '%s'", svc.registerCmd.IP)
	}
}
