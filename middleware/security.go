package middleware

import (
	"net"
	"net/http"
	"strings"
)

// SecurityHeaders adds standard security headers to the response.
// This middleware should be applied to all routes to improve defense-in-depth.
//
// Usage:
//
//	router := http.NewServeMux()
//	// ... register handlers ...
//	srv := &http.Server{
//		Handler: middleware.SecurityHeaders(router),
//	}
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME-sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		// Enable XSS filtering in browsers that support it
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// Control referrer information
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Prevent XSS and data injection (strict CSP for API)
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';")
		// Enforce HTTPS, but skip on localhost to avoid locking dev environments
		if !isLocalhost(r.Host) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

func isLocalhost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Strip brackets from IPv6 literals if present (e.g. "[::1]" -> "::1")
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
