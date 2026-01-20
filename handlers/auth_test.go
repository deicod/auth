package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authpkg "github.com/deicod/auth"
	"github.com/deicod/auth/core"
)

type fakeService struct {
	registerCmd           core.RegisterCommand
	logoutToken           string
	meToken               string
	registerRes           core.AuthResult
	registerErr           error
	logoutErr             error
	meErr                 error
	meUser                core.UserPublic
	meSession             core.SessionPublic
	loginErr              error
	loginRes              core.AuthResult
	verifyEmailErr        error
	verifyEmailRes        core.VerifyEmailResult
	forgotPwdErr          error
	resetPwdErr           error
	resetPwdRes           core.UserPublic
	initEmailChangeErr    error
	confirmEmailChangeErr error
	confirmEmailChangeRes core.ChangeEmailResult
}

func (f *fakeService) Register(ctx context.Context, cmd core.RegisterCommand) (core.AuthResult, error) {
	f.registerCmd = cmd
	return f.registerRes, f.registerErr
}
func (f *fakeService) Login(context.Context, core.LoginCommand) (core.AuthResult, error) {
	return f.loginRes, f.loginErr
}
func (f *fakeService) VerifyEmail(context.Context, core.VerifyEmailCommand) (core.VerifyEmailResult, error) {
	return f.verifyEmailRes, f.verifyEmailErr
}
func (f *fakeService) ForgotPassword(context.Context, core.ForgotPasswordCommand) error {
	return f.forgotPwdErr
}
func (f *fakeService) ResetPassword(context.Context, core.ResetPasswordCommand) (core.UserPublic, error) {
	return f.resetPwdRes, f.resetPwdErr
}
func (f *fakeService) InitiateEmailChange(context.Context, core.ChangeEmailCommand) error {
	return f.initEmailChangeErr
}
func (f *fakeService) ConfirmEmailChange(context.Context, core.ConfirmEmailChangeCommand) (core.ChangeEmailResult, error) {
	return f.confirmEmailChangeRes, f.confirmEmailChangeErr
}
func (f *fakeService) AuthenticateSession(ctx context.Context, token string) (core.UserPublic, core.SessionPublic, error) {
	f.meToken = token
	return f.meUser, f.meSession, f.meErr
}
func (f *fakeService) Logout(ctx context.Context, token string) error {
	f.logoutToken = token
	return f.logoutErr
}

func TestRegisterHandlerSuccess(t *testing.T) {
	svc := &fakeService{registerRes: core.AuthResult{User: core.UserPublic{ID: "1", Email: "u@example.com"}}}
	h := New(svc)

	body := map[string]string{"email": "u@example.com", "username": "user", "password": "pass"}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(data))
	rr := httptest.NewRecorder()

	h.Register().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr.Code)
	}
	if svc.registerCmd.Email != "u@example.com" {
		t.Fatalf("expected service to receive email")
	}
}

func TestRegisterHandlerBadJSON(t *testing.T) {
	svc := &fakeService{}
	h := New(svc)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString("not-json"))
	rr := httptest.NewRecorder()
	h.Register().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestLogoutHandlerUnauthorized(t *testing.T) {
	svc := &fakeService{}
	h := New(svc)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	rr := httptest.NewRecorder()
	h.Logout().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMeHandlerSuccess(t *testing.T) {
	svc := &fakeService{
		meUser:    core.UserPublic{ID: "1", Email: "me@example.com"},
		meSession: core.SessionPublic{ID: "sess", UserID: "1"},
	}
	h := New(svc)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer token123")
	rr := httptest.NewRecorder()

	h.Me().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if svc.meToken != "token123" {
		t.Fatalf("expected AuthenticateSession to receive token")
	}
}

func TestMeHandlerUnauthorized(t *testing.T) {
	svc := &fakeService{meErr: core.ErrSessionNotFound}
	h := New(svc)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer bad")
	rr := httptest.NewRecorder()

	h.Me().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestLoginHandler(t *testing.T) {
	tests := []struct {
		name       string
		body       interface{}
		mockSetup  func(*fakeService)
		wantStatus int
	}{
		{
			name: "Success",
			body: map[string]string{"email": "u@example.com", "password": "pass"},
			mockSetup: func(f *fakeService) {
				f.loginRes = core.AuthResult{User: core.UserPublic{ID: "1"}}
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "InvalidJSON",
			body:       "not-json",
			mockSetup:  func(f *fakeService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "InvalidCredentials",
			body: map[string]string{"email": "u@example.com", "password": "wrong"},
			mockSetup: func(f *fakeService) {
				f.loginErr = core.ErrInvalidCredentials
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeService{}
			tt.mockSetup(svc)
			h := New(svc)

			var body []byte
			if s, ok := tt.body.(string); ok && s == "not-json" {
				body = []byte(s)
			} else {
				body, _ = json.Marshal(tt.body)
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
			rr := httptest.NewRecorder()

			h.Login().ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestVerifyEmailHandler(t *testing.T) {
	tests := []struct {
		name       string
		body       interface{}
		mockSetup  func(*fakeService)
		wantStatus int
	}{
		{
			name: "Success",
			body: map[string]string{"token": "valid-token"},
			mockSetup: func(f *fakeService) {
				f.verifyEmailRes = core.VerifyEmailResult{User: core.UserPublic{ID: "1", IsVerified: true}}
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "InvalidToken",
			body: map[string]string{"token": "invalid"},
			mockSetup: func(f *fakeService) {
				f.verifyEmailErr = core.ErrTokenNotFound
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeService{}
			tt.mockSetup(svc)
			h := New(svc)

			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/auth/verify", bytes.NewReader(body))
			rr := httptest.NewRecorder()

			h.VerifyEmail().ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestForgotPasswordHandler(t *testing.T) {
	tests := []struct {
		name       string
		body       interface{}
		mockSetup  func(*fakeService)
		wantStatus int
	}{
		{
			name: "Success",
			body: map[string]string{"email": "u@example.com"},
			mockSetup: func(f *fakeService) {
			},
			wantStatus: http.StatusAccepted,
		},
		{
			name: "ServiceError",
			body: map[string]string{"email": "u@example.com"},
			mockSetup: func(f *fakeService) {
				f.forgotPwdErr = errors.New("db error")
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeService{}
			tt.mockSetup(svc)
			h := New(svc)

			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/auth/forgot", bytes.NewReader(body))
			rr := httptest.NewRecorder()

			h.ForgotPassword().ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestResetPasswordHandler(t *testing.T) {
	tests := []struct {
		name       string
		body       interface{}
		mockSetup  func(*fakeService)
		wantStatus int
	}{
		{
			name: "Success",
			body: map[string]string{"token": "t", "new_password": "p"},
			mockSetup: func(f *fakeService) {
				f.resetPwdRes = core.UserPublic{ID: "1"}
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "TokenExpired",
			body: map[string]string{"token": "t", "new_password": "p"},
			mockSetup: func(f *fakeService) {
				f.resetPwdErr = core.ErrTokenExpired
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeService{}
			tt.mockSetup(svc)
			h := New(svc)

			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/auth/reset", bytes.NewReader(body))
			rr := httptest.NewRecorder()

			h.ResetPassword().ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestInitiateEmailChangeHandler(t *testing.T) {
	tests := []struct {
		name       string
		body       interface{}
		mockSetup  func(*fakeService)
		wantStatus int
	}{
		{
			name: "Success",
			body: map[string]string{"user_id": "1", "password": "p", "new_email": "n@e.com"},
			mockSetup: func(f *fakeService) {
			},
			wantStatus: http.StatusAccepted,
		},
		{
			name: "InvalidCredentials",
			body: map[string]string{"user_id": "1", "password": "wrong", "new_email": "n@e.com"},
			mockSetup: func(f *fakeService) {
				f.initEmailChangeErr = core.ErrInvalidCredentials
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeService{}
			tt.mockSetup(svc)
			h := New(svc)

			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/auth/email-change", bytes.NewReader(body))
			rr := httptest.NewRecorder()

			h.InitiateEmailChange().ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestConfirmEmailChangeHandler(t *testing.T) {
	tests := []struct {
		name       string
		body       interface{}
		mockSetup  func(*fakeService)
		wantStatus int
	}{
		{
			name: "Success",
			body: map[string]string{"token": "valid"},
			mockSetup: func(f *fakeService) {
				f.confirmEmailChangeRes = core.ChangeEmailResult{User: core.UserPublic{ID: "1"}}
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "TokenExpired",
			body: map[string]string{"token": "expired"},
			mockSetup: func(f *fakeService) {
				f.confirmEmailChangeErr = core.ErrTokenExpired
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeService{}
			tt.mockSetup(svc)
			h := New(svc)

			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/auth/email-confirm", bytes.NewReader(body))
			rr := httptest.NewRecorder()

			h.ConfirmEmailChange().ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		headerKey      string
		headerVal      string
		trustedProxies []string
		wantIP         string
	}{
		{
			name:       "DefaultAllow_NoConfig",
			remoteAddr: "1.2.3.4:1234",
			headerKey:  "X-Forwarded-For",
			headerVal:  "5.6.7.8",
			wantIP:     "5.6.7.8",
		},
		{
			name:           "TrustedProxy_ExplicitConfig_UntrustedSource",
			remoteAddr:     "1.2.3.4:1234",
			headerKey:      "X-Forwarded-For",
			headerVal:      "5.6.7.8",
			trustedProxies: []string{"9.9.9.9"}, // Doesn't match remoteAddr
			wantIP:         "1.2.3.4",
		},
		{
			name:           "TrustedProxy_ExactMatch",
			remoteAddr:     "1.2.3.4:1234",
			headerKey:      "X-Forwarded-For",
			headerVal:      "5.6.7.8",
			trustedProxies: []string{"1.2.3.4"},
			wantIP:         "5.6.7.8",
		},
		{
			name:           "TrustedProxy_CIDRMatch",
			remoteAddr:     "10.0.0.5:1234",
			headerKey:      "X-Forwarded-For",
			headerVal:      "5.6.7.8",
			trustedProxies: []string{"10.0.0.0/8"},
			wantIP:         "5.6.7.8",
		},
		{
			name:           "UntrustedProxy_CIDRMismatch",
			remoteAddr:     "192.168.1.1:1234",
			headerKey:      "X-Forwarded-For",
			headerVal:      "5.6.7.8",
			trustedProxies: []string{"10.0.0.0/8"},
			wantIP:         "192.168.1.1",
		},
		{
			name:       "DirectConnection_NoHeaders",
			remoteAddr: "1.2.3.4:1234",
			wantIP:     "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeService{}
			h := New(svc)
			h.TrustedProxies = tt.trustedProxies

			body, _ := json.Marshal(map[string]string{
				"email": "test@example.com", "username": "test", "password": "password",
			})
			req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
			req.RemoteAddr = tt.remoteAddr
			if tt.headerKey != "" {
				req.Header.Set(tt.headerKey, tt.headerVal)
			}
			rr := httptest.NewRecorder()

			h.Register().ServeHTTP(rr, req)

			if svc.registerCmd.IP != tt.wantIP {
				t.Errorf("got IP %q, want %q", svc.registerCmd.IP, tt.wantIP)
			}
		})
	}
}

var _ authpkg.Service = (*fakeService)(nil)
