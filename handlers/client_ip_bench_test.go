package handlers

import (
	"net/http/httptest"
	"testing"
)

func BenchmarkClientIP_MultipleHeaders(b *testing.B) {
	h := &AuthHandlers{
		TrustedProxies: []string{"1.2.3.4"},
	}
	// Trigger lazy initialization of trusted proxies
	reqInit := httptest.NewRequest("GET", "/", nil)
	reqInit.RemoteAddr = "1.2.3.4:1234"
	h.clientIP(reqInit)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	// Simulate multiple headers as added by a chain of proxies
	// The current implementation joins these into "10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4"
	req.Header.Add("X-Forwarded-For", "10.0.0.1")
	req.Header.Add("X-Forwarded-For", "10.0.0.2, 10.0.0.3")
	req.Header.Add("X-Forwarded-For", "10.0.0.4")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = h.clientIP(req)
	}
}
