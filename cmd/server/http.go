package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"gowireguard/internal/httpx"
)

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

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return httpx.NewServer(addr, handler)
}

func runHTTPServer(srv *http.Server, serveTLS bool, certFile, keyFile string) error {
	return httpx.RunServer(srv, serveTLS, certFile, keyFile)
}

func securityHeaders(next http.Handler) http.Handler {
	return httpx.SecurityHeaders(next)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, v any) bool {
	return httpx.DecodeJSON(w, r, maxBytes, v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	httpx.WriteJSON(w, status, v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	httpx.WriteError(w, status, msg)
}
