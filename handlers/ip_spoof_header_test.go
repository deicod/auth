package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deicod/auth/core"
)

func TestClientIP_MultipleHeaders(t *testing.T) {
	// Setup: Service behind a trusted proxy (1.2.3.4)
	svc := &fakeService{registerRes: core.AuthResult{User: core.UserPublic{ID: "1"}}}
	h := New(svc)
	h.TrustedProxies = []string{"1.2.3.4"}

	// Attack Scenario:
	// Attacker (Real IP 10.0.0.1) wants to spoof IP 5.6.7.8
	// Attacker sends request with header: "X-Forwarded-For: 5.6.7.8"
	// Trusted Proxy (1.2.3.4) receives it, and ADDS the real IP.
	// Some proxies/configs might add it as a separate header line instead of appending to the string.
	// So the backend receives:
	// X-Forwarded-For: 5.6.7.8
	// X-Forwarded-For: 10.0.0.1

	body := map[string]string{"email": "u@example.com", "username": "user", "password": "pass"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(data))

	// Simulate multiple header lines
	req.Header.Add("X-Forwarded-For", "5.6.7.8")  // Attacker provided
	req.Header.Add("X-Forwarded-For", "10.0.0.1") // Added by Proxy (Real IP)

	req.RemoteAddr = "1.2.3.4:1234" // From Trusted Proxy

	rr := httptest.NewRecorder()
	h.Register().ServeHTTP(rr, req)

	// If vulnerable, it picks the first header "5.6.7.8"
	// If fixed, it joins them "5.6.7.8, 10.0.0.1", parses from right, finds "10.0.0.1" (untrusted) and returns it.

	if svc.registerCmd.IP == "5.6.7.8" {
		t.Errorf("VULNERABILITY: IP spoofing successful! Got spoofed IP '5.6.7.8', expected real IP '10.0.0.1'")
	}

	if svc.registerCmd.IP != "10.0.0.1" {
		t.Errorf("Expected IP '10.0.0.1', got '%s'", svc.registerCmd.IP)
	}
}
