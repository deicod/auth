package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	authpkg "github.com/deicod/auth"
	"github.com/deicod/auth/core"
)

const (
	maxBodySize     = 1048576 // 1MB
	loginRateLimit  = 5
	loginRateWindow = time.Minute
)

var insecureProxyWarningOnce sync.Once

type visitor struct {
	count   int
	resetAt time.Time
}

type AuthHandlers struct {
	svc authpkg.Service
	// TrustedProxies is a list of trusted IP addresses or CIDR ranges.
	// If empty, X-Forwarded-For and X-Real-IP headers are TRUSTED (default-allow).
	// To secure the application, you must configure this list.
	TrustedProxies []string

	mu       sync.Mutex
	visitors map[string]*visitor
}

func New(svc authpkg.Service) *AuthHandlers {
	return &AuthHandlers{
		svc:      svc,
		visitors: make(map[string]*visitor),
	}
}

func (h *AuthHandlers) Register() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.checkRateLimit(h.clientIP(r), "strict", loginRateLimit, loginRateWindow) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

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
			UserAgent: sanitizeUserAgent(r.UserAgent()),
			IP:        h.clientIP(r),
		}

		result, err := h.svc.Register(r.Context(), cmd)
		if err != nil {
			slog.Warn("security_event", "action", "register_failed", "ip", cmd.IP, "email", cmd.Email, "username", cmd.Username, "error", err.Error())
			h.writeServiceError(w, err)
			return
		}
		slog.Info("security_event", "action", "register_success", "user_id", result.User.ID, "ip", cmd.IP)
		respondJSON(w, http.StatusCreated, result)
	}
}

func (h *AuthHandlers) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.checkRateLimit(h.clientIP(r), "strict", loginRateLimit, loginRateWindow) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

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
			UserAgent: sanitizeUserAgent(r.UserAgent()),
			IP:        h.clientIP(r),
		}

		result, err := h.svc.Login(r.Context(), cmd)
		if err != nil {
			slog.Warn("security_event", "action", "login_failed", "ip", cmd.IP, "email", cmd.Email, "error", err.Error())
			h.writeServiceError(w, err)
			return
		}
		slog.Info("security_event", "action", "login_success", "user_id", result.User.ID, "ip", cmd.IP)
		respondJSON(w, http.StatusOK, result)
	}
}

func (h *AuthHandlers) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.checkRateLimit(h.clientIP(r), "logout", 20, time.Minute) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
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
		// Use a higher rate limit for Me endpoint (60/min) to allow frequent checks but prevent DoS
		if !h.checkRateLimit(h.clientIP(r), "me", 60, time.Minute) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

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
		if !h.checkRateLimit(h.clientIP(r), "strict", loginRateLimit, loginRateWindow) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

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
		if !h.checkRateLimit(h.clientIP(r), "strict", loginRateLimit, loginRateWindow) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

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
		if !h.checkRateLimit(h.clientIP(r), "strict", loginRateLimit, loginRateWindow) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

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
			slog.Warn("security_event", "action", "reset_password_failed", "ip", h.clientIP(r), "error", err.Error())
			h.writeServiceError(w, err)
			return
		}
		slog.Info("security_event", "action", "reset_password_success", "user_id", result.ID, "ip", h.clientIP(r))
		respondJSON(w, http.StatusOK, result)
	}
}

func (h *AuthHandlers) InitiateEmailChange() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.checkRateLimit(h.clientIP(r), "strict", loginRateLimit, loginRateWindow) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

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
		if !h.checkRateLimit(h.clientIP(r), "strict", loginRateLimit, loginRateWindow) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

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
	// Limit request body to 1MB to prevent DoS
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodySize)
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Printf("auth handler failed to close request body: %v", err)
		}
	}()
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
	// Prevent caching of sensitive authentication data
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
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
		if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-IP") != "" {
			insecureProxyWarningOnce.Do(func() {
				log.Println("WARNING: AuthHandlers.TrustedProxies is empty. Trusting X-Forwarded-For/X-Real-IP headers. This allows IP spoofing and bypass of rate limits. Please configure TrustedProxies.")
			})
		}
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
			// Avoid strings.Split to prevent large slice allocation if header contains many commas
			ip := header
			if idx := strings.IndexByte(header, ','); idx >= 0 {
				ip = header[:idx]
			}
			if ip = strings.TrimSpace(ip); ip != "" {
				// Prevent DoS via excessive IP length (max IPv6 mapped is ~45 chars)
				if len(ip) > 64 || net.ParseIP(ip) == nil {
					return remoteIP
				}
				return ip
			}
		}
		if header := strings.TrimSpace(r.Header.Get("X-Real-IP")); header != "" {
			// Prevent DoS via excessive IP length
			if len(header) > 64 || net.ParseIP(header) == nil {
				return remoteIP
			}
			return header
		}
	}

	return remoteIP
}

func bearerToken(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if len(header) < 7 {
		return "", false
	}
	if !strings.EqualFold(header[:6], "Bearer") {
		return "", false
	}

	// The character immediately following "Bearer" MUST be whitespace (separator).
	// We strictly require ASCII whitespace (SP, HTAB, LF, VT, FF, CR)
	// which covers standard HTTP header usage and strings.Fields delimiters.
	c := header[6]
	if c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\v' && c != '\f' {
		return "", false
	}

	token := strings.TrimSpace(header[7:])
	if token == "" {
		return "", false
	}

	// Ensure no internal whitespace in the token to match strict 2-part format
	for i := 0; i < len(token); i++ {
		c := token[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' {
			return "", false
		}
	}
	return token, true
}

func (h *AuthHandlers) checkRateLimit(ip, action string, limit int, window time.Duration) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	key := ip + ":" + action
	v, exists := h.visitors[key]
	if !exists || time.Now().After(v.resetAt) {
		h.visitors[key] = &visitor{count: 1, resetAt: time.Now().Add(window)}
		// Simple cleanup: if map is too big, purge expired
		if len(h.visitors) > 1000 {
			// Only check a fixed number of items to prevent DoS (O(N) scan)
			// Go map iteration is random, so this is a random sample.
			checked := 0
			for k, val := range h.visitors {
				if time.Now().After(val.resetAt) {
					delete(h.visitors, k)
				}
				checked++
				if checked >= 50 {
					break
				}
			}

			// Hard limit to prevent memory exhaustion
			if len(h.visitors) > 5000 {
				// Evict random items until we are back under the limit
				for k := range h.visitors {
					delete(h.visitors, k)
					if len(h.visitors) <= 5000 {
						break
					}
				}
			}
		}
		return true
	}

	if v.count >= limit {
		return false
	}
	v.count++
	return true
}

func sanitizeUserAgent(ua string) string {
	// Truncate to 512 characters to prevent DB issues or potential excessive logging/DoS
	const maxUserAgentLen = 512
	if len(ua) <= maxUserAgentLen {
		return ua
	}

	// Simply slicing the byte string might split a multi-byte character.
	// We need to ensure valid UTF-8.

	// Check if the byte at the cutoff point is a rune start.
	// utf8.RuneStart returns true if the byte is a start byte or ASCII (0xxxxxxx or 11xxxxxx).
	// It returns false if it is a continuation byte (10xxxxxx).
	if utf8.RuneStart(ua[maxUserAgentLen]) {
		return ua[:maxUserAgentLen]
	}

	// We are in the middle of a sequence (ua[maxUserAgentLen] is a continuation byte).
	// Backtrack to find the start of the incomplete rune and cut before it.
	for i := maxUserAgentLen - 1; i >= 0; i-- {
		if utf8.RuneStart(ua[i]) {
			return ua[:i]
		}
	}

	return ""
}
