package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimiting_AllEndpoints(t *testing.T) {
	endpoints := []struct {
		name   string
		path   string
		method string
		body   string
	}{
		{"ForgotPassword", "/auth/forgot", http.MethodPost, `{"email":"t@e.com"}`},
		{"VerifyEmail", "/auth/verify", http.MethodPost, `{"token":"t"}`},
		{"ResetPassword", "/auth/reset", http.MethodPost, `{"token":"t","new_password":"p"}`},
		{"InitiateEmailChange", "/auth/email-change", http.MethodPost, `{"user_id":"1","password":"p","new_email":"n@e.com"}`},
		{"ConfirmEmailChange", "/auth/email-confirm", http.MethodPost, `{"token":"t"}`},
	}

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			svc := &fakeService{}
			h := New(svc)

			// Make 5 requests (allowed)
			for i := 0; i < 5; i++ {
				req := httptest.NewRequest(ep.method, ep.path, bytes.NewBufferString(ep.body))
				req.RemoteAddr = "192.0.2.1:1234"
				rr := httptest.NewRecorder()

				switch ep.name {
				case "ForgotPassword":
					h.ForgotPassword().ServeHTTP(rr, req)
				case "VerifyEmail":
					h.VerifyEmail().ServeHTTP(rr, req)
				case "ResetPassword":
					h.ResetPassword().ServeHTTP(rr, req)
				case "InitiateEmailChange":
					h.InitiateEmailChange().ServeHTTP(rr, req)
				case "ConfirmEmailChange":
					h.ConfirmEmailChange().ServeHTTP(rr, req)
				}

				if rr.Code == http.StatusTooManyRequests {
					t.Fatalf("Request %d was rate limited unexpectedly", i+1)
				}
			}

			// 6th request should be blocked
			req := httptest.NewRequest(ep.method, ep.path, bytes.NewBufferString(ep.body))
			req.RemoteAddr = "192.0.2.1:1234"
			rr := httptest.NewRecorder()

			switch ep.name {
			case "ForgotPassword":
				h.ForgotPassword().ServeHTTP(rr, req)
			case "VerifyEmail":
				h.VerifyEmail().ServeHTTP(rr, req)
			case "ResetPassword":
				h.ResetPassword().ServeHTTP(rr, req)
			case "InitiateEmailChange":
				h.InitiateEmailChange().ServeHTTP(rr, req)
			case "ConfirmEmailChange":
				h.ConfirmEmailChange().ServeHTTP(rr, req)
			}

			if rr.Code != http.StatusTooManyRequests {
				t.Errorf("Expected 429 Too Many Requests, got %d", rr.Code)
			}
		})
	}
}
