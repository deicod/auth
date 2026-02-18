package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDoS_RateLimit_Cleanup verifies that the rate limit cleanup doesn't cause a denial of service
// by iterating too many items when the map is large.
func TestDoS_RateLimit_Cleanup(t *testing.T) {
	// Create a handler with a mock service
	svc := &fakeService{}
	h := New(svc)

	// Pre-fill the visitors map with a large number of "active" visitors
	// They are NOT expired, so the cleanup loop will visit them but not delete them.
	// We use 100,000 items.
	initialSize := 100000
	future := time.Now().Add(time.Hour)
	for i := 0; i < initialSize; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		h.visitors[rateLimitKey{ip: ip, action: "strict"}] = visitor{count: 1, resetAt: future}
	}

	// Now make ONE request from a new IP
	// This should trigger the cleanup check (len > 1000)
	// And since none are expired, it will iterate all 100,000 items.

	start := time.Now()

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()

	// We just test the rate limit check part, but we can call the handler
	// The handler calls checkRateLimit at the beginning.
	h.Login().ServeHTTP(rr, req)

	duration := time.Since(start)

	// On a fast machine, 100k iteration is fast (~5-10ms).
	// But if we had 1M, it would be worse.
	// We just want to ensure we don't regress or that we fix the behavior.
	// For "Sentinel", we want to change the behavior to NOT iterate all.

	t.Logf("Time taken for request with %d visitors: %v", initialSize, duration)

	// With the fix, we expect this to be very fast (O(1) or O(limited)).
	// Without the fix, it is O(N).
	// We can't easily assert "too slow" in a generic environment, but we can check correctness of the fix later.
}

func TestDoS_RateLimit_MapGrowth(t *testing.T) {
	// Verify that the map stops growing at some point (Hard Limit)
	// The new implementation limits to 50,000.

	svc := &fakeService{}
	h := New(svc)

	// Fill to 50500 (above hard limit 50000)
	const maxLimit = 50000
	limit := maxLimit + 500
	future := time.Now().Add(time.Hour)
	for i := 0; i < limit; i++ {
		// Use a simple string generation to avoid excessive allocs in test setup
		// We use a prefix to ensure uniqueness
		ip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		h.visitors[rateLimitKey{ip: ip, action: "strict"}] = visitor{count: 1, resetAt: future}
	}

	// Add one more
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	h.Login().ServeHTTP(rr, req)

	if len(h.visitors) > maxLimit {
		t.Errorf("Map size %d exceeded hard limit %d", len(h.visitors), maxLimit)
	}
}
