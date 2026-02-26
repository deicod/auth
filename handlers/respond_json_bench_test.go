package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkRespondJSON(b *testing.B) {
	// Pre-allocate payload
	payload := struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}{
		ID:    "12345",
		Email: "test@example.com",
	}

	w := httptest.NewRecorder()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Reset recorder
		header := w.Header()
		for k := range header {
			delete(header, k)
		}
		w.Body.Reset()

		respondJSON(w, http.StatusOK, payload)
	}
}
