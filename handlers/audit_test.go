package handlers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deicod/auth/core"
)

func TestAuditLogging(t *testing.T) {
	// Capture slog output
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	// Save old default logger to restore later
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)

	slog.SetDefault(logger)

	t.Run("LoginSuccess", func(t *testing.T) {
		buf.Reset()
		svc := &fakeService{
			loginRes: core.AuthResult{User: core.UserPublic{ID: "user123"}},
		}
		h := New(svc)

		body := map[string]string{"email": "test@example.com", "password": "pass"}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(jsonBody))
		req.RemoteAddr = "1.2.3.4:1234"
		rr := httptest.NewRecorder()

		h.Login().ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, "login_success") {
			t.Errorf("expected log to contain 'login_success', got: %s", logOutput)
		}
		if !strings.Contains(logOutput, "user123") {
			t.Errorf("expected log to contain user ID, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, "1.2.3.4") {
			t.Errorf("expected log to contain IP, got: %s", logOutput)
		}
	})

	t.Run("LoginFailure", func(t *testing.T) {
		buf.Reset()
		svc := &fakeService{
			loginErr: core.ErrInvalidCredentials,
		}
		h := New(svc)

		body := map[string]string{"email": "fail@example.com", "password": "pass"}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(jsonBody))
		req.RemoteAddr = "5.6.7.8:1234"
		rr := httptest.NewRecorder()

		h.Login().ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, "login_failed") {
			t.Errorf("expected log to contain 'login_failed', got: %s", logOutput)
		}
		if !strings.Contains(logOutput, "fail@example.com") {
			t.Errorf("expected log to contain email, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, "5.6.7.8") {
			t.Errorf("expected log to contain IP, got: %s", logOutput)
		}
	})

	t.Run("RegisterSuccess", func(t *testing.T) {
		buf.Reset()
		svc := &fakeService{
			registerRes: core.AuthResult{User: core.UserPublic{ID: "reg_user"}},
		}
		h := New(svc)

		body := map[string]string{"email": "new@example.com", "username": "newuser", "password": "pass"}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(jsonBody))
		req.RemoteAddr = "10.0.0.1:1234"
		rr := httptest.NewRecorder()

		h.Register().ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d", rr.Code)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, "register_success") {
			t.Errorf("expected log to contain 'register_success', got: %s", logOutput)
		}
		if !strings.Contains(logOutput, "reg_user") {
			t.Errorf("expected log to contain user ID, got: %s", logOutput)
		}
	})

	t.Run("ResetPasswordSuccess", func(t *testing.T) {
		buf.Reset()
		svc := &fakeService{
			resetPwdRes: core.UserPublic{ID: "reset_user"},
		}
		h := New(svc)

		body := map[string]string{"token": "token123", "new_password": "pass"}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/auth/reset", bytes.NewReader(jsonBody))
		req.RemoteAddr = "10.0.0.2:1234"
		rr := httptest.NewRecorder()

		h.ResetPassword().ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, "reset_password_success") {
			t.Errorf("expected log to contain 'reset_password_success', got: %s", logOutput)
		}
		if !strings.Contains(logOutput, "reset_user") {
			t.Errorf("expected log to contain user ID, got: %s", logOutput)
		}
	})
}
