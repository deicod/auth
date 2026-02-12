package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIP_MultipleHeaders(t *testing.T) {
	// Setup a fake service and handler
	svc := &fakeService{}
	h := New(svc)
	// Trust the "proxy" IP
	h.TrustedProxies = []string{"10.0.0.1"}

	// Construct a request with multiple X-Forwarded-For headers
	// This simulates an attacker sending a header, and the proxy appending a NEW header instead of merging
	body, _ := json.Marshal(map[string]string{
		"email": "test@example.com", "username": "test", "password": "password",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.1:1234" // Request comes from trusted proxy

	// Add the headers directly to the Header map to ensure they are separate
	req.Header.Add("X-Forwarded-For", "1.2.3.4") // Spoofed IP (attacker)
	req.Header.Add("X-Forwarded-For", "5.6.7.8") // Real IP (added by proxy)

	// In a vulnerable implementation using Header.Get(), it will return "1.2.3.4".
	// Since "1.2.3.4" is not trusted, it will be returned as the client IP.
	// But the TRUE client IP (closest to the proxy) is "5.6.7.8".
	// The correct logic should see "1.2.3.4, 5.6.7.8", parse right-to-left:
	// 1. "5.6.7.8" (Untrusted) -> Return "5.6.7.8".

	rr := httptest.NewRecorder()
	h.Register().ServeHTTP(rr, req)

	// Check what IP was captured
	if svc.registerCmd.IP != "5.6.7.8" {
		t.Errorf("IP Spoofing Vulnerability: got IP %q, want %q (Real IP)", svc.registerCmd.IP, "5.6.7.8")
	}
}
