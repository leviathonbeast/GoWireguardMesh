package httpx

import "net/http"

// SecurityHeaders hardens every response. The CSP is the backstop for
// the admin UI: script execution is limited to same-origin resources,
// so a stray XSS cannot load an exfiltration payload from elsewhere.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")

		// HSTS only over TLS: advertising it on plain HTTP is wrong
		// (dev mode) and it is the proxy's job when TLS terminates
		// upstream.
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}

		next.ServeHTTP(w, r)
	})
}
