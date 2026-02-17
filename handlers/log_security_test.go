package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientIP_LogDoS(t *testing.T) {
	// Setup capture
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, nil)
	logger := slog.New(handler)
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	svc := &fakeService{}
	h := New(svc)
	h.TrustedProxies = []string{"127.0.0.1"}

	// Create a huge header value
	hugeString := strings.Repeat("a", 1024*10) // 10KB
	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", hugeString) // No commas, so it's treated as one IP

	rr := httptest.NewRecorder()
	h.Login().ServeHTTP(rr, req) // Login calls clientIP

	// Check log output
	logOutput := buf.String()
	if !strings.Contains(logOutput, "ip_verification_failed") {
		t.Fatal("expected log to contain ip_verification_failed")
	}

	if !strings.Contains(logOutput, "...(truncated)") {
		t.Error("expected log to contain truncated suffix")
	}

	// 128 chars + suffix + surrounding log structure should be << 2000
	if len(logOutput) > 2000 {
		t.Errorf("log output too large: %d bytes", len(logOutput))
	}
}

func TestRegister_LogDoS(t *testing.T) {
	// Setup capture
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, nil)
	logger := slog.New(handler)
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	// Make service return error so it logs
	svc := &fakeService{registerErr: errors.New("some error")}
	h := New(svc)

	hugeUsername := strings.Repeat("a", 1024*10) // 10KB
	body := map[string]string{
		"email":    "test@example.com",
		"username": hugeUsername,
		"password": "password",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/auth/register", bytes.NewReader(bodyBytes))
	rr := httptest.NewRecorder()
	h.Register().ServeHTTP(rr, req)

	// Check log output
	logOutput := buf.String()
	if !strings.Contains(logOutput, "register_failed") {
		t.Fatal("expected log to contain register_failed")
	}

	if !strings.Contains(logOutput, "...(truncated)") {
		t.Error("expected log to contain truncated suffix")
	}

	// 128 chars + suffix + surrounding log structure should be << 2000
	if len(logOutput) > 2000 {
		t.Errorf("log output too large: %d bytes", len(logOutput))
	}
}
