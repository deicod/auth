package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIP_HeaderInjection(t *testing.T) {
	// Vulnerability Reproduction:
	// A trusted proxy sends a request with X-Forwarded-For: spoofed, garbage.
	// The current code skips "garbage" (invalid IP) and returns "spoofed".
	// The desired secure code should stop at "garbage" and return the last trusted IP (the proxy itself).

	svc := &fakeService{}
	h := New(svc)
	h.TrustedProxies = []string{"1.2.3.4"} // Configure trusted proxy

	body, _ := json.Marshal(map[string]string{
		"email": "test@example.com", "username": "test", "password": "password",
	})

	// Scenario: Request from trusted proxy (1.2.3.4) with injected garbage
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.RemoteAddr = "1.2.3.4:1234"
	// Header crafted by attacker -> trusted proxy appends real IP (1.2.3.4) -> App receives request from 1.2.3.4
	// But wait, the app receives the header as sent by the proxy.
	// If the proxy received "spoofed, garbage" from the attacker, and the proxy is configured to append,
	// the header becomes "spoofed, garbage, <real_client_ip>".
	// If the attacker is the client, real_client_ip is the attacker's IP.
	// BUT if the attacker is seemingly coming from "garbage" (which is invalid),
	// or if the proxy forwards garbage...

	// Let's simulate the header as seen by the application.
	// We want to test the parsing logic.
	// If the header is "10.0.0.1, garbage, 1.2.3.4" (where 1.2.3.4 is the trusted proxy itself? No).
	// The header contains IPs *before* the immediate peer.
	// If immediate peer is 1.2.3.4 (trusted).
	// And header is "spoofed-ip, garbage".
	// The parser iterates:
	// 1. "garbage". Invalid. Skipped (Current) -> Break (Desired).
	// 2. "spoofed-ip". Valid. Untrusted. Returns "spoofed-ip" (Current).

	req.Header.Set("X-Forwarded-For", "192.0.2.1, garbage")
	// 192.0.2.1 is the spoofed IP.

	rr := httptest.NewRecorder()
	h.Register().ServeHTTP(rr, req)

	// Current Vulnerable Behavior: returns "192.0.2.1"
	// Desired Secure Behavior: returns "1.2.3.4" (the last trusted peer) because the chain is broken.

	if svc.registerCmd.IP == "192.0.2.1" {
		t.Fatalf("VULNERABILITY CONFIRMED: IP spoofing successful. Got spoofed IP %q instead of trusted proxy IP.", svc.registerCmd.IP)
	}

	if svc.registerCmd.IP != "1.2.3.4" {
		t.Errorf("Expected IP %q (trusted proxy), got %q", "1.2.3.4", svc.registerCmd.IP)
	}
}
