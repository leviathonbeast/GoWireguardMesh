package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// NewServer wraps handler in a server with explicit limits. The
// zero-value http.Server has none: header reads, body reads, and
// writes can all stall forever, so a handful of slow-drip connections
// can pin goroutines and file descriptors indefinitely.
func NewServer(addr string, handler http.Handler) *http.Server {
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

// RunServer serves until SIGINT/SIGTERM, then shuts down gracefully so
// caller-owned deferred cleanup can run. Hijacked connections (active
// WebSocket relays) are not waited on; agents re-establish them.
func RunServer(srv *http.Server, serveTLS bool, certFile, keyFile string) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", srv.Addr, err)
	}

	return RunServerListener(srv, ln, serveTLS, certFile, keyFile)
}

// RunServerListener is RunServer over a caller-built listener — the
// seam for wrapping the accept path (PROXY protocol). With serveTLS,
// empty cert paths serve from TLSConfig (GetCertificate/Certificates).
func RunServerListener(srv *http.Server, ln net.Listener, serveTLS bool, certFile, keyFile string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)

	go func() {
		if serveTLS {
			errCh <- srv.ServeTLS(ln, certFile, keyFile)
		} else {
			errCh <- srv.Serve(ln)
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

		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}

		return nil
	}
}
