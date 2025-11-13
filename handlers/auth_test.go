package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	authpkg "github.com/deicod/auth"
	"github.com/deicod/auth/core"
)

type fakeService struct {
	registerCmd core.RegisterCommand
	logoutToken string
	meToken     string
	registerRes core.AuthResult
	registerErr error
	logoutErr   error
	meErr       error
	meUser      core.UserPublic
	meSession   core.SessionPublic
}

func (f *fakeService) Register(ctx context.Context, cmd core.RegisterCommand) (core.AuthResult, error) {
	f.registerCmd = cmd
	return f.registerRes, f.registerErr
}
func (f *fakeService) Login(context.Context, core.LoginCommand) (core.AuthResult, error) {
	return core.AuthResult{}, nil
}
func (f *fakeService) VerifyEmail(context.Context, core.VerifyEmailCommand) (core.VerifyEmailResult, error) {
	return core.VerifyEmailResult{}, nil
}
func (f *fakeService) ForgotPassword(context.Context, core.ForgotPasswordCommand) error { return nil }
func (f *fakeService) ResetPassword(context.Context, core.ResetPasswordCommand) (core.UserPublic, error) {
	return core.UserPublic{}, nil
}
func (f *fakeService) InitiateEmailChange(context.Context, core.ChangeEmailCommand) error { return nil }
func (f *fakeService) ConfirmEmailChange(context.Context, core.ConfirmEmailChangeCommand) (core.ChangeEmailResult, error) {
	return core.ChangeEmailResult{}, nil
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

var _ authpkg.Service = (*fakeService)(nil)
