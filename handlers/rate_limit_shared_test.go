package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimit_SharedBucketVulnerability(t *testing.T) {
	svc := &fakeService{}
	h := New(svc)

	// Simulate spamming ForgotPassword to exhaust the shared "strict" bucket
	// Default limit is 5 requests per minute
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/forgot", bytes.NewBufferString(`{"email":"spam@example.com"}`))
		req.RemoteAddr = "192.0.2.1:1234"
		rr := httptest.NewRecorder()
		h.ForgotPassword().ServeHTTP(rr, req)

		if rr.Code == http.StatusTooManyRequests {
			t.Fatalf("Request %d to ForgotPassword was blocked unexpectedly", i+1)
		}
	}

	// Now try to Login from the same IP
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString(`{"email":"user@example.com","password":"password"}`))
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()
	h.Login().ServeHTTP(rr, req)

	// After the fix, this should SUCCEED (not 429).
	// We check for NOT 429 to confirm the fix.
	if rr.Code == http.StatusTooManyRequests {
		t.Error("Login was blocked by rate limit! The fix did not work or buckets are still shared.")
	} else {
		t.Logf("Login was NOT blocked (status %d). Fix verified.", rr.Code)
	}
}
