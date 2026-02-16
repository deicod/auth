package middleware

import (
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
		// Content Security Policy
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		// Prevent other sites from opening the app in a way that allows cross-origin interactions
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		// Prevent other sites from loading resources from the app
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		// Prevent Flash/PDF from loading data from the domain
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		// Prevent IE from executing downloads in site context
		w.Header().Set("X-Download-Options", "noopen")
		// Permissions Policy (formerly Feature Policy) to disable sensitive features
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
		// Enforce HTTPS, but skip on localhost to avoid locking dev environments
		if !isLocalhost(r.Host) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

func isLocalhost(host string) bool {
	host = strings.TrimSpace(host)
	if len(host) == 0 {
		return false
	}

	// Fast path for exact matches
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}

	// Handle IPv6 with brackets [::1]:8080 or [::1]
	if host[0] == '[' {
		if end := strings.LastIndexByte(host, ']'); end != -1 {
			host = host[1:end]
		} else {
			host = host[1:]
		}
	} else {
		// Handle host:port (IPv4 or hostname)
		// If multiple colons, it's likely IPv6 without brackets (e.g. ::1)
		if lastColon := strings.LastIndexByte(host, ':'); lastColon != -1 {
			if strings.IndexByte(host, ':') == lastColon {
				host = host[:lastColon]
			}
		}
	}

	return host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost")
}
