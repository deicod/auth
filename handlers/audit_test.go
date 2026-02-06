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

	t.Run("InitiateEmailChangeSuccess", func(t *testing.T) {
		buf.Reset()
		svc := &fakeService{} // Returns nil error by default
		h := New(svc)

		body := map[string]string{"user_id": "user123", "password": "password", "new_email": "new@example.com"}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/auth/email-change", bytes.NewReader(jsonBody))
		req.RemoteAddr = "10.0.0.3:1234"
		rr := httptest.NewRecorder()

		h.InitiateEmailChange().ServeHTTP(rr, req)

		if rr.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d", rr.Code)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, "initiate_email_change_success") {
			t.Errorf("expected log to contain 'initiate_email_change_success', got: %s", logOutput)
		}
		if !strings.Contains(logOutput, "user123") {
			t.Errorf("expected log to contain user ID, got: %s", logOutput)
		}
	})

	t.Run("ConfirmEmailChangeSuccess", func(t *testing.T) {
		buf.Reset()
		svc := &fakeService{
			confirmEmailChangeRes: core.ChangeEmailResult{User: core.UserPublic{ID: "confirmed_user"}},
		}
		h := New(svc)

		body := map[string]string{"token": "valid_token"}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/auth/email-confirm", bytes.NewReader(jsonBody))
		req.RemoteAddr = "10.0.0.4:1234"
		rr := httptest.NewRecorder()

		h.ConfirmEmailChange().ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, "confirm_email_change_success") {
			t.Errorf("expected log to contain 'confirm_email_change_success', got: %s", logOutput)
		}
		if !strings.Contains(logOutput, "confirmed_user") {
			t.Errorf("expected log to contain user ID, got: %s", logOutput)
		}
	})

	t.Run("VerifyEmailSuccess", func(t *testing.T) {
		buf.Reset()
		svc := &fakeService{
			verifyEmailRes: core.VerifyEmailResult{User: core.UserPublic{ID: "verified_user"}},
		}
		h := New(svc)

		body := map[string]string{"token": "valid_token"}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/auth/verify", bytes.NewReader(jsonBody))
		req.RemoteAddr = "10.0.0.5:1234"
		rr := httptest.NewRecorder()

		h.VerifyEmail().ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, "verify_email_success") {
			t.Errorf("expected log to contain 'verify_email_success', got: %s", logOutput)
		}
		if !strings.Contains(logOutput, "verified_user") {
			t.Errorf("expected log to contain user ID, got: %s", logOutput)
		}
	})

	t.Run("VerifyEmailFailure", func(t *testing.T) {
		buf.Reset()
		svc := &fakeService{
			verifyEmailErr: core.ErrTokenNotFound,
		}
		h := New(svc)

		body := map[string]string{"token": "bad_token"}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/auth/verify", bytes.NewReader(jsonBody))
		req.RemoteAddr = "10.0.0.6:1234"
		rr := httptest.NewRecorder()

		h.VerifyEmail().ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, "verify_email_failed") {
			t.Errorf("expected log to contain 'verify_email_failed', got: %s", logOutput)
		}
		if !strings.Contains(logOutput, "10.0.0.6") {
			t.Errorf("expected log to contain IP, got: %s", logOutput)
		}
	})
}
