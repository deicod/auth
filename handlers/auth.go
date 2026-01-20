package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	authpkg "github.com/deicod/auth"
	"github.com/deicod/auth/core"
)

type AuthHandlers struct {
	svc authpkg.Service
	// TrustedProxies is a list of trusted IP addresses or CIDR ranges.
	// If empty, X-Forwarded-For and X-Real-IP headers are TRUSTED (default-allow).
	// To secure the application, you must configure this list.
	TrustedProxies []string
}

func New(svc authpkg.Service) *AuthHandlers {
	return &AuthHandlers{svc: svc}
}

func (h *AuthHandlers) Register() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string `json:"email"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err)
			return
		}

		cmd := core.RegisterCommand{
			Email:     req.Email,
			Username:  req.Username,
			Password:  req.Password,
			UserAgent: r.UserAgent(),
			IP:        h.clientIP(r),
		}

		result, err := h.svc.Register(r.Context(), cmd)
		if err != nil {
			h.writeServiceError(w, err)
			return
		}
		respondJSON(w, http.StatusCreated, result)
	}
}

func (h *AuthHandlers) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err)
			return
		}

		cmd := core.LoginCommand{
			Email:     req.Email,
			Password:  req.Password,
			UserAgent: r.UserAgent(),
			IP:        h.clientIP(r),
		}

		result, err := h.svc.Login(r.Context(), cmd)
		if err != nil {
			h.writeServiceError(w, err)
			return
		}
		respondJSON(w, http.StatusOK, result)
	}
}

func (h *AuthHandlers) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, errors.New("missing bearer token"))
			return
		}
		if err := h.svc.Logout(r.Context(), token); err != nil {
			h.writeServiceError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *AuthHandlers) Me() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, errors.New("missing bearer token"))
			return
		}
		user, session, err := h.svc.AuthenticateSession(r.Context(), token)
		if err != nil {
			h.writeServiceError(w, err)
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"user":    user,
			"session": session,
		})
	}
}

func (h *AuthHandlers) VerifyEmail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err)
			return
		}
		result, err := h.svc.VerifyEmail(r.Context(), core.VerifyEmailCommand{Token: req.Token})
		if err != nil {
			h.writeServiceError(w, err)
			return
		}
		respondJSON(w, http.StatusOK, result)
	}
}

func (h *AuthHandlers) ForgotPassword() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string `json:"email"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.svc.ForgotPassword(r.Context(), core.ForgotPasswordCommand{Email: req.Email}); err != nil {
			h.writeServiceError(w, err)
			return
		}
		respondJSON(w, http.StatusAccepted, map[string]string{"status": "email_sent"})
	}
}

func (h *AuthHandlers) ResetPassword() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token       string `json:"token"`
			NewPassword string `json:"new_password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err)
			return
		}
		result, err := h.svc.ResetPassword(r.Context(), core.ResetPasswordCommand{Token: req.Token, NewPassword: req.NewPassword})
		if err != nil {
			h.writeServiceError(w, err)
			return
		}
		respondJSON(w, http.StatusOK, result)
	}
}

func (h *AuthHandlers) InitiateEmailChange() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserID   string `json:"user_id"`
			Password string `json:"password"`
			NewEmail string `json:"new_email"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err)
			return
		}
		cmd := core.ChangeEmailCommand{
			UserID:   core.ID(req.UserID),
			Password: req.Password,
			NewEmail: req.NewEmail,
		}
		if err := h.svc.InitiateEmailChange(r.Context(), cmd); err != nil {
			h.writeServiceError(w, err)
			return
		}
		respondJSON(w, http.StatusAccepted, map[string]string{"status": "email_sent"})
	}
}

func (h *AuthHandlers) ConfirmEmailChange() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err)
			return
		}
		result, err := h.svc.ConfirmEmailChange(r.Context(), core.ConfirmEmailChangeCommand{Token: req.Token})
		if err != nil {
			h.writeServiceError(w, err)
			return
		}
		respondJSON(w, http.StatusOK, result)
	}
}

func (h *AuthHandlers) writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, core.ErrEmailExists), errors.Is(err, core.ErrUsernameExists):
		writeJSONError(w, http.StatusConflict, err)
	case errors.Is(err, core.ErrInvalidInput):
		writeJSONError(w, http.StatusBadRequest, err)
	case errors.Is(err, core.ErrInvalidCredentials):
		writeJSONError(w, http.StatusUnauthorized, err)
	case errors.Is(err, core.ErrSessionNotFound):
		writeJSONError(w, http.StatusUnauthorized, err)
	case errors.Is(err, core.ErrUserNotFound):
		writeJSONError(w, http.StatusNotFound, err)
	case errors.Is(err, core.ErrTokenNotFound), errors.Is(err, core.ErrTokenConsumed), errors.Is(err, core.ErrTokenExpired):
		writeJSONError(w, http.StatusBadRequest, err)
	default:
		log.Printf("auth handler internal error: %v", err)
		writeJSONError(w, http.StatusInternalServerError, errors.New("internal server error"))
	}
}

func decodeJSON(r *http.Request, dst interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("request body required")
		}
		return err
	}
	return nil
}

func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, err error) {
	type errorResponse struct {
		Error string `json:"error"`
	}
	respondJSON(w, status, errorResponse{Error: err.Error()})
}

func (h *AuthHandlers) clientIP(r *http.Request) string {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	trusted := false
	// If no trusted proxies are configured, we default to trusting headers (default-allow).
	// This is necessary because in many environments (like K8s) we can't easily know the proxy IP.
	// Users should configure TrustedProxies to enable IP validation.
	if len(h.TrustedProxies) == 0 {
		trusted = true
	} else {
		for _, proxy := range h.TrustedProxies {
			if proxy == remoteIP {
				trusted = true
				break
			}
			_, ipNet, err := net.ParseCIDR(proxy)
			if err == nil {
				if ip := net.ParseIP(remoteIP); ip != nil && ipNet.Contains(ip) {
					trusted = true
					break
				}
			}
		}
	}

	if trusted {
		if header := r.Header.Get("X-Forwarded-For"); header != "" {
			parts := strings.Split(header, ",")
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return ip
			}
		}
		if header := strings.TrimSpace(r.Header.Get("X-Real-IP")); header != "" {
			return header
		}
	}

	return remoteIP
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 {
		return "", false
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", false
	}
	return token, true
}
