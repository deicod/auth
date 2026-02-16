package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIP_MultipleHeaders(t *testing.T) {
	svc := &fakeService{}
	h := New(svc)
	// Trust 1.2.3.4 (the proxy)
	h.TrustedProxies = []string{"1.2.3.4"}

	body, _ := json.Marshal(map[string]string{
		"email": "test@example.com", "username": "test", "password": "password",
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.RemoteAddr = "1.2.3.4:1234"

	// Simulate:
	// Attacker sends: X-Forwarded-For: 192.0.2.1
	// Proxy receives it, and ADDS a new header line: X-Forwarded-For: 192.0.2.2
	// So the request has two X-Forwarded-For headers.
	req.Header.Add("X-Forwarded-For", "192.0.2.1")
	req.Header.Add("X-Forwarded-For", "192.0.2.2")

	rr := httptest.NewRecorder()
	h.Register().ServeHTTP(rr, req)

	// Current vulnerable behavior: Get() returns "192.0.2.1".
	// It is checked. It is not trusted. So it is returned.
	// So attacker spoofs IP.

	// Desired behavior: Headers are joined -> "192.0.2.1, 192.0.2.2".
	// Parse right to left. "192.0.2.2" is checked. It is untrusted. It is returned.

	if svc.registerCmd.IP == "192.0.2.1" {
		t.Fatalf("VULNERABILITY CONFIRMED: IP spoofing successful with multiple headers. Got %q", svc.registerCmd.IP)
	}

	if svc.registerCmd.IP != "192.0.2.2" {
		t.Errorf("Expected IP %q, got %q", "192.0.2.2", svc.registerCmd.IP)
	}
}
