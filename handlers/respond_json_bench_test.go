package handlers

import (
	"net/http"
	"testing"
)

// mockWriter is a lightweight http.ResponseWriter for benchmarking.
// It allows reusing the header map to avoid allocations during benchmarks.
type mockWriter struct {
	h http.Header
}

func (m *mockWriter) Header() http.Header {
	return m.h
}

func (m *mockWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (m *mockWriter) WriteHeader(statusCode int) {
	// No-op
}

func BenchmarkRespondJSON(b *testing.B) {
	// Pre-allocate payload
	payload := struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}{
		ID:    "12345",
		Email: "test@example.com",
	}

	// Initialize with pre-allocated map
	w := &mockWriter{
		h: make(http.Header),
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Reset headers by deleting keys, preserving map allocation
		for k := range w.h {
			delete(w.h, k)
		}

		respondJSON(w, http.StatusOK, payload)
	}
}
