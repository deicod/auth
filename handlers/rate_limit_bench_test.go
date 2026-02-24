package handlers

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkCheckRateLimit_Cleanup(b *testing.B) {
	svc := &fakeService{}
	h := New(svc)

	// Pre-fill map to trigger cleanup path (> 1000)
	future := time.Now().Add(time.Hour)
	for i := 0; i < 2000; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		h.visitors[rateLimitKey{ip: parseIPKey(ip), action: hashString("strict")}] = visitor{count: 1, resetAt: future.UnixNano()}
	}

	// Pre-generate IPs to avoid allocation during benchmark loop
	// Limit to reasonable number to avoid OOM if N is huge, but reuse them.
	// If we reuse, we might hit existing entry.
	// But if we cycle through 10000 IPs, we likely evict them before reusing.
	count := 10000
	ips := make([]string, count)
	for i := 0; i < count; i++ {
		ips[i] = fmt.Sprintf("10.1.%d.%d", i/256, i%256)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.checkRateLimit(ips[i%count], "strict", 5, time.Minute)
	}
}
