package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// newHTTPServer wraps handler in a server with explicit limits. The
// zero-value http.Server has none: header reads, body reads, and
// writes can all stall forever, so a handful of slow-drip connections
// (slowloris) pins goroutines and file descriptors indefinitely.
//
// The read/write deadlines apply per request. Long-lived WebSocket
// relay sessions survive them because net/http clears the connection
// deadlines when the websocket upgrade hijacks the connection
// (pinned by TestRelayWSSurvivesServerTimeouts).
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
		// TLS 1.3 only: every client is either our own Go agent or a
		// modern browser hitting the admin UI. Ignored on plain HTTP.
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
}

// runHTTPServer serves until SIGINT/SIGTERM, then shuts down
// gracefully so runServe's deferred cleanup (closing the store,
// removing firewall rules the server opened) actually executes —
// without this, Ctrl+C leaks the opened ports and only the next
// start's reconciliation cleans them up.
func runHTTPServer(srv *http.Server, serveTLS bool, certFile, keyFile string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)

	go func() {
		if serveTLS {
			errCh <- srv.ListenAndServeTLS(certFile, keyFile)
		} else {
			errCh <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server: %w", err)
		}

		return nil
	case <-ctx.Done():
		slog.Info("shutting down", "reason", "signal")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Hijacked connections (active WebSocket relays) are not waited
		// on; they die with the process, and agents re-establish.
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}

		return nil
	}
}

// securityHeaders hardens every response. The CSP is the backstop for
// the admin UI, whose token sits in sessionStorage: script injection
// is limited to same-origin resources, so a stray XSS cannot load an
// exfiltration payload from elsewhere. 'unsafe-inline' is granted to
// styles only (React style attributes); scripts stay 'self' — the
// built UI loads one external module script and nothing inline.
func securityHeaders(next http.Handler) http.Handler {
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

// decodeJSON decodes a JSON request body of at most maxBytes into v.
// On failure it writes the error response (413 for oversized bodies,
// 400 otherwise) and returns false. Every handler that reads a body
// goes through this: an unbounded json.Decode on a public endpoint is
// a memory-exhaustion vector.
func decodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, v any) bool {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes)).Decode(v)
	if err == nil {
		return true
	}

	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", tooLarge.Limit))
		return false
	}

	writeError(w, http.StatusBadRequest, "invalid JSON")

	return false
}

// setupLogging installs the process-wide slog handler at the given
// level. Everything human-oriented goes through slog on stderr; the
// JSONL access log (stdout mode) is a separate machine stream and
// stays independent of the level.
func setupLogging(level string) error {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return fmt.Errorf(`log-level must be "debug", "info", "warn", or "error", got %q`, level)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))

	return nil
}
