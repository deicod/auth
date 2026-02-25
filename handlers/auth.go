package handlers

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/netip"
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
	resetAt int64 // UnixNano
}

type rateLimitKey struct {
	ip     [16]byte
	action uint64
}

type AuthHandlers struct {
	svc authpkg.Service
	// TrustedProxies is a list of trusted IP addresses or CIDR ranges.
	// If empty, X-Forwarded-For and X-Real-IP headers are TRUSTED (default-allow).
	// To secure the application, you must configure this list.
	TrustedProxies []string

	trustedCIDRs   []netip.Prefix
	trustedIPs     []netip.Addr
	trustedStrings []string
	initProxies    sync.Once

	mu sync.Mutex
	// visitors map stores values instead of pointers to reduce GC pressure and allocations
	visitors    map[rateLimitKey]visitor
	cleanupIter uint64
}

func New(svc authpkg.Service) *AuthHandlers {
	return &AuthHandlers{
		svc:      svc,
		visitors: make(map[rateLimitKey]visitor),
	}
}

func (h *AuthHandlers) Register() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := h.clientIP(r)
		if !h.checkRateLimit(ip, "register", loginRateLimit, loginRateWindow) {
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
			IP:        ip,
		}

		result, err := h.svc.Register(r.Context(), cmd)
		if err != nil {
			slog.Warn("security_event", "action", "register_failed", "ip", cmd.IP, "email", truncateLog(cmd.Email), "username", truncateLog(cmd.Username), "error", err.Error())
			h.writeServiceError(w, err)
			return
		}
		slog.Info("security_event", "action", "register_success", "user_id", result.User.ID, "ip", cmd.IP)
		respondJSON(w, http.StatusCreated, result)
	}
}

func (h *AuthHandlers) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := h.clientIP(r)
		if !h.checkRateLimit(ip, "login", loginRateLimit, loginRateWindow) {
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
			IP:        ip,
		}

		result, err := h.svc.Login(r.Context(), cmd)
		if err != nil {
			slog.Warn("security_event", "action", "login_failed", "ip", cmd.IP, "email", truncateLog(cmd.Email), "error", err.Error())
			h.writeServiceError(w, err)
			return
		}
		slog.Info("security_event", "action", "login_success", "user_id", result.User.ID, "ip", cmd.IP)
		respondJSON(w, http.StatusOK, result)
	}
}

func (h *AuthHandlers) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := h.clientIP(r)
		if !h.checkRateLimit(ip, "logout", 20, time.Minute) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, errors.New("missing bearer token"))
			return
		}
		if err := h.svc.Logout(r.Context(), token); err != nil {
			slog.Warn("security_event", "action", "logout_failed", "ip", ip, "error", err.Error())
			h.writeServiceError(w, err)
			return
		}
		slog.Info("security_event", "action", "logout_success", "ip", ip)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *AuthHandlers) Me() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Use a higher rate limit for Me endpoint (60/min) to allow frequent checks but prevent DoS
		ip := h.clientIP(r)
		if !h.checkRateLimit(ip, "me", 60, time.Minute) {
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
		ip := h.clientIP(r)
		if !h.checkRateLimit(ip, "verify_email", loginRateLimit, loginRateWindow) {
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
			slog.Warn("security_event", "action", "verify_email_failed", "ip", ip, "error", err.Error())
			h.writeServiceError(w, err)
			return
		}
		slog.Info("security_event", "action", "verify_email_success", "user_id", result.User.ID, "ip", ip)
		respondJSON(w, http.StatusOK, result)
	}
}

func (h *AuthHandlers) ForgotPassword() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := h.clientIP(r)
		if !h.checkRateLimit(ip, "forgot_password", loginRateLimit, loginRateWindow) {
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
			slog.Warn("security_event", "action", "forgot_password_failed", "ip", ip, "email", truncateLog(req.Email), "error", err.Error())
			h.writeServiceError(w, err)
			return
		}
		slog.Info("security_event", "action", "forgot_password_requested", "ip", ip, "email", truncateLog(req.Email))
		respondJSON(w, http.StatusAccepted, map[string]string{"status": "email_sent"})
	}
}

func (h *AuthHandlers) ResetPassword() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := h.clientIP(r)
		if !h.checkRateLimit(ip, "reset_password", loginRateLimit, loginRateWindow) {
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
			slog.Warn("security_event", "action", "reset_password_failed", "ip", ip, "error", err.Error())
			h.writeServiceError(w, err)
			return
		}
		slog.Info("security_event", "action", "reset_password_success", "user_id", result.ID, "ip", ip)
		respondJSON(w, http.StatusOK, result)
	}
}

func (h *AuthHandlers) InitiateEmailChange() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := h.clientIP(r)
		if !h.checkRateLimit(ip, "initiate_email_change", loginRateLimit, loginRateWindow) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		// Security: Require active session to initiate email change.
		// This prevents unauthorized users (even with a stolen password) from initiating
		// an email change without first logging in (which triggers its own checks/alerts).
		// It also ensures the action is associated with a verified session.
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, errors.New("missing bearer token"))
			return
		}
		user, _, err := h.svc.AuthenticateSession(r.Context(), token)
		if err != nil {
			// Log authentication failure for this sensitive action
			slog.Warn("security_event", "action", "initiate_email_change_auth_failed", "ip", ip, "error", err.Error())
			h.writeServiceError(w, err)
			return
		}

		var req struct {
			// UserID is intentionally ignored from the body to prevent ID spoofing.
			// The user can only change the email for the authenticated session.
			UserID   string `json:"user_id"`
			Password string `json:"password"`
			NewEmail string `json:"new_email"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err)
			return
		}
		cmd := core.ChangeEmailCommand{
			UserID:   user.ID, // Use ID from session
			Password: req.Password,
			NewEmail: req.NewEmail,
		}
		if err := h.svc.InitiateEmailChange(r.Context(), cmd); err != nil {
			slog.Warn("security_event", "action", "initiate_email_change_failed", "ip", ip, "user_id", truncateLog(string(cmd.UserID)), "error", err.Error())
			h.writeServiceError(w, err)
			return
		}
		slog.Info("security_event", "action", "initiate_email_change_success", "user_id", cmd.UserID, "ip", ip)
		respondJSON(w, http.StatusAccepted, map[string]string{"status": "email_sent"})
	}
}

func (h *AuthHandlers) ConfirmEmailChange() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := h.clientIP(r)
		if !h.checkRateLimit(ip, "confirm_email_change", loginRateLimit, loginRateWindow) {
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
			slog.Warn("security_event", "action", "confirm_email_change_failed", "ip", ip, "error", err.Error())
			h.writeServiceError(w, err)
			return
		}
		slog.Info("security_event", "action", "confirm_email_change_success", "user_id", result.User.ID, "ip", ip)
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
	// Add security headers to API responses
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Xss-Protection", "1; mode=block")
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
	remoteIP := extractIP(r.RemoteAddr)

	// Initialize trusted proxies
	if len(h.TrustedProxies) > 0 {
		h.initProxies.Do(func() {
			for _, proxy := range h.TrustedProxies {
				if prefix, err := netip.ParsePrefix(proxy); err == nil {
					h.trustedCIDRs = append(h.trustedCIDRs, prefix)
				} else if addr, err := netip.ParseAddr(proxy); err == nil {
					h.trustedIPs = append(h.trustedIPs, addr)
				} else {
					h.trustedStrings = append(h.trustedStrings, proxy)
				}
			}
		})
	} else {
		// Optimization: Check map directly to avoid CanonicalMIMEHeaderKey overhead.
		// Go's http.Header keys are canonicalized.
		// X-Forwarded-For -> X-Forwarded-For
		// X-Real-IP -> X-Real-Ip
		if len(r.Header["X-Forwarded-For"]) > 0 || len(r.Header["X-Real-Ip"]) > 0 {
			insecureProxyWarningOnce.Do(func() {
				log.Println("WARNING: AuthHandlers.TrustedProxies is empty. Trusting X-Forwarded-For/X-Real-IP headers. This allows IP spoofing and bypass of rate limits. Please configure TrustedProxies.")
			})
		}
	}

	isTrusted := false
	if len(h.TrustedProxies) == 0 {
		isTrusted = true
	} else {
		// Only parse remoteIP if we need to check trust against configured proxies.
		// This saves an allocation and parsing cost (~35ns) when TrustedProxies is empty (default).
		remoteAddr, err := netip.ParseAddr(remoteIP)
		if err == nil {
			isTrusted = h.isTrustedAddr(remoteAddr)
		} else {
			isTrusted = h.isTrustedString(remoteIP)
		}
	}

	// First check if the immediate peer is trusted
	if !isTrusted {
		return remoteIP
	}

	// Peer is trusted, check headers.
	// We prefer X-Forwarded-For (standard), but fall back to X-Real-IP.
	// SECURITY: Iterate from RIGHT to LEFT to find the first untrusted IP.
	// This prevents IP spoofing where a client appends a fake IP to the header.
	// Instead of joining multiple headers (which causes allocation), we iterate backwards.
	if xff := r.Header["X-Forwarded-For"]; len(xff) > 0 {
		var lastValidIP string
		// Iterate over headers in reverse (proxies append new headers to the end)
		for i := len(xff) - 1; i >= 0; i-- {
			header := xff[i]
			end := len(header)
			// Iterate over IPs in this header in reverse
			for end > 0 {
				start := strings.LastIndexByte(header[:end], ',')
				var part string
				if start == -1 {
					part = header[:end]
					end = 0
				} else {
					part = header[start+1 : end]
					end = start
				}

				ip := strings.TrimSpace(part)
				if ip == "" {
					continue
				}

				// Validate IP format
				addr, err := netip.ParseAddr(ip)
				if len(ip) > 64 || err != nil {
					// SECURITY: If we encounter an invalid IP, the chain of trust is broken.
					// We must STOP traversing. Skipping it would allow an attacker to "bridge"
					// the gap between a trusted proxy and a spoofed IP by injecting garbage.
					// We fall back to the last successfully verified trusted IP (or the immediate peer).
					slog.Warn("security_event", "action", "ip_verification_failed", "reason", "invalid_ip_in_header", "invalid_part", truncateLog(ip))
					goto Done
				}

				// Store the last valid IP encountered (which is the leftmost valid IP so far because we iterate backward)
				lastValidIP = ip

				if !h.isTrustedAddr(addr) {
					return ip
				}
			}
		}
	Done:
		// If we reach here, all IPs in the chain are trusted.
		// Return the leftmost valid IP (the original client according to the chain).
		if lastValidIP != "" {
			return lastValidIP
		}
	}

	if header := strings.TrimSpace(r.Header.Get("X-Real-IP")); header != "" {
		// Use ParseAddr to validate IP format (no allocation)
		if _, err := netip.ParseAddr(header); err == nil && len(header) <= 64 {
			return header
		}
	}

	return remoteIP
}

func (h *AuthHandlers) isTrustedAddr(addr netip.Addr) bool {
	// If no trusted proxies configured, we default to trusting ALL (default-allow).
	if len(h.TrustedProxies) == 0 {
		return true
	}
	for _, trustedAddr := range h.trustedIPs {
		if trustedAddr == addr {
			return true
		}
	}
	for _, prefix := range h.trustedCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (h *AuthHandlers) isTrustedString(ip string) bool {
	if len(h.TrustedProxies) == 0 {
		return true
	}
	for _, trusted := range h.trustedStrings {
		if trusted == ip {
			return true
		}
	}
	return false
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

// hashString calculates FNV-1a 64-bit hash of a string.
// Inline implementation to avoid allocation (fnv.Write([]byte(s))).
func hashString(s string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	hash := uint64(offset64)
	for i := 0; i < len(s); i++ {
		hash ^= uint64(s[i])
		hash *= prime64
	}
	return hash
}

// parseIPKey converts an IP string to [16]byte key for rate limiting.
// It uses netip.ParseAddr for valid IPs (zero-allocation).
// For invalid IPs (e.g. "localhost"), it falls back to FNV-1a hashing.
func parseIPKey(s string) [16]byte {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.As16()
	}
	// Fallback for non-IP strings (e.g. localhost or unparseable headers).
	// We use FNV-1a (64-bit) to avoid allocation and CPU cost of MD5.
	// We pad the 16-byte key with the hash. Collisions mean shared rate limits,
	// which is acceptable for invalid inputs.
	h := hashString(s)
	var key [16]byte
	binary.BigEndian.PutUint64(key[:8], h)
	return key
}

func (h *AuthHandlers) checkRateLimit(ip, action string, limit int, window time.Duration) bool {
	// Hoist time.Now() out of the lock to reduce critical section size
	now := time.Now()
	nowUnix := now.UnixNano()

	ipKey := parseIPKey(ip)
	actionKey := hashString(action)
	key := rateLimitKey{ipKey, actionKey}

	h.mu.Lock()
	defer h.mu.Unlock()

	v, exists := h.visitors[key]
	if !exists || nowUnix > v.resetAt {
		h.visitors[key] = visitor{count: 1, resetAt: now.Add(window).UnixNano()}
		// Simple cleanup: if map is too big, purge expired.
		// Optimization: Check only every 64th request to amortize the cost of map iteration.
		// This prevents the cleanup loop from running on every request when the map is full.
		if len(h.visitors) > 1000 {
			h.cleanupIter++
			if h.cleanupIter&0x3F == 0 {
				// Only check a fixed number of items to prevent DoS (O(N) scan)
				// Go map iteration is random, so this is a random sample.
				checked := 0
				for k, val := range h.visitors {
					if nowUnix > val.resetAt {
						delete(h.visitors, k)
					}
					checked++
					if checked >= 50 {
						break
					}
				}
			}

			// Hard limit to prevent memory exhaustion.
			// Increased to 50,000 to better handle distributed attacks.
			const maxVisitors = 50000
			if len(h.visitors) > maxVisitors {
				// First pass: Prioritize evicting expired items to preserve active users.
				// Limit the scan to avoid O(N) latency spikes when the map is full of active users.
				// Under attack, this prevents the loop from iterating 50k+ items without finding anything to delete.
				scanned := 0
				for k, val := range h.visitors {
					if nowUnix > val.resetAt {
						delete(h.visitors, k)
					}
					scanned++
					// If we've cleared enough space OR scanned too many items, stop.
					if len(h.visitors) <= maxVisitors || scanned >= 100 {
						break
					}
				}

				// Second pass: If still over limit, evict random items
				if len(h.visitors) > maxVisitors {
					for k := range h.visitors {
						delete(h.visitors, k)
						if len(h.visitors) <= maxVisitors {
							break
						}
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
	h.visitors[key] = v
	return true
}

// sanitizeUserAgent truncates the user agent string to 512 bytes
// and ensures it is valid UTF-8.
func sanitizeUserAgent(ua string) string {
	// Prevent excessive memory allocation by capping input size early.
	// We use a larger buffer (2048) than the final limit (512) to account for
	// bytes that might be removed (like NULLs) or multi-byte characters.
	if len(ua) > 2048 {
		ua = ua[:2048]
	}

	// Remove NULL bytes first to prevent DB issues (Postgres text fields reject \0)
	// and potential logging issues.
	ua = strings.ReplaceAll(ua, "\x00", "")

	// Truncate to 512 characters to prevent DB issues or potential excessive logging/DoS
	const maxUserAgentLen = 512
	if len(ua) > maxUserAgentLen {
		// Simply slicing the byte string might split a multi-byte character.
		// We need to ensure valid UTF-8.

		// Check if the byte at the cutoff point is a rune start.
		// utf8.RuneStart returns true if the byte is a start byte or ASCII (0xxxxxxx or 11xxxxxx).
		// It returns false if it is a continuation byte (10xxxxxx).
		if utf8.RuneStart(ua[maxUserAgentLen]) {
			ua = ua[:maxUserAgentLen]
		} else {
			// We are in the middle of a sequence (ua[maxUserAgentLen] is a continuation byte).
			// Backtrack to find the start of the incomplete rune and cut before it.
			found := false
			for i := maxUserAgentLen - 1; i >= 0; i-- {
				if utf8.RuneStart(ua[i]) {
					ua = ua[:i]
					found = true
					break
				}
			}
			if !found {
				ua = ""
			}
		}
	}

	// Ensure valid UTF-8 after truncation.
	// This removes any invalid byte sequences (replacing them with empty string).
	// This prevents database errors (like Postgres "invalid byte sequence for encoding UTF8")
	// and potential logging issues.
	return strings.ToValidUTF8(ua, "")
}

// extractIP extracts the IP address from a "IP:Port" string.
// It avoids allocation by slicing the input string.
func truncateLog(s string) string {
	const maxLogLen = 128
	if len(s) <= maxLogLen {
		return s
	}
	// Check for UTF-8 boundary to avoid cutting in the middle of a character
	truncated := s[:maxLogLen]
	if !utf8.RuneStart(s[maxLogLen]) {
		// Backtrack to find the start of the incomplete rune
		for i := maxLogLen - 1; i >= 0; i-- {
			if utf8.RuneStart(s[i]) {
				truncated = s[:i]
				break
			}
		}
	}
	return truncated + "...(truncated)"
}

func extractIP(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	if remoteAddr[0] == '[' {
		// IPv6 with brackets
		endBracket := strings.IndexByte(remoteAddr, ']')
		if endBracket != -1 {
			return remoteAddr[1:endBracket]
		}
		return remoteAddr
	}

	colon := strings.LastIndexByte(remoteAddr, ':')
	if colon != -1 {
		// If there is another colon before the last one, it's IPv6 without brackets (no port).
		if strings.IndexByte(remoteAddr, ':') < colon {
			return remoteAddr
		}
		return remoteAddr[:colon]
	}
	return remoteAddr
}
