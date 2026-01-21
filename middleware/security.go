package middleware

import (
	"net/http"
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

		next.ServeHTTP(w, r)
	})
}
