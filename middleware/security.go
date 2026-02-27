package middleware

import (
	"net/http"
	"strings"
)

// Pre-allocate header value slices to avoid allocation on every request.
var (
	HeaderXContentOptions         = []string{"nosniff"}
	HeaderXFrameOptions           = []string{"DENY"}
	HeaderXXssProtection          = []string{"1; mode=block"} // Canonical key is X-Xss-Protection
	headerReferrerPolicy          = []string{"strict-origin-when-cross-origin"}
	HeaderCSP                     = []string{"default-src 'none'; frame-ancestors 'none'"}
	headerCOOP                    = []string{"same-origin"}
	headerCORP                    = []string{"same-origin"}
	headerXPermittedPolicies      = []string{"none"}
	headerXDownloadOptions        = []string{"noopen"}
	headerPermissionsPolicy       = []string{"accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"}
	headerStrictTransportSecurity = []string{"max-age=63072000; includeSubDomains"}
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
		h := w.Header()

		// Prevent MIME-sniffing
		h["X-Content-Type-Options"] = HeaderXContentOptions
		// Prevent clickjacking
		h["X-Frame-Options"] = HeaderXFrameOptions
		// Enable XSS filtering in browsers that support it
		// Note: We use the canonical key "X-Xss-Protection" because direct map assignment bypasses canonicalization.
		h["X-Xss-Protection"] = HeaderXXssProtection
		// Control referrer information
		h["Referrer-Policy"] = headerReferrerPolicy
		// Content Security Policy
		h["Content-Security-Policy"] = HeaderCSP
		// Prevent other sites from opening the app in a way that allows cross-origin interactions
		h["Cross-Origin-Opener-Policy"] = headerCOOP
		// Prevent other sites from loading resources from the app
		h["Cross-Origin-Resource-Policy"] = headerCORP
		// Prevent Flash/PDF from loading data from the domain
		h["X-Permitted-Cross-Domain-Policies"] = headerXPermittedPolicies
		// Prevent IE from executing downloads in site context
		h["X-Download-Options"] = headerXDownloadOptions
		// Permissions Policy (formerly Feature Policy) to disable sensitive features
		h["Permissions-Policy"] = headerPermissionsPolicy

		// Enforce HTTPS, but skip on localhost to avoid locking dev environments
		if !isLocalhost(r.Host) {
			h["Strict-Transport-Security"] = headerStrictTransportSecurity
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
