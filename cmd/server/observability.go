package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gowireguard/internal/store"
)

// accessLogMu serializes access-log writes: concurrent requests must
// not interleave partial JSON lines on stdout.
var accessLogMu sync.Mutex

// writeAccessLog emits one JSON line (no log-package prefix) so a log
// shipper can parse each line as one object. The record carries its
// own "time" field.
func writeAccessLog(line accessLogLine) {
	b, err := json.Marshal(line)
	if err != nil {
		return
	}

	b = append(b, '\n')

	accessLogMu.Lock()
	os.Stdout.Write(b)
	accessLogMu.Unlock()
}

// isLoopback reports whether a listen address binds only the loopback
// interface, so plain HTTP / trusted XFF is safe there.
func isLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

// handleHealthz is an unauthenticated liveness probe for orchestration.
func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

type auditRowJSON struct {
	ID           int64  `json:"id"`
	At           string `json:"at"`
	Event        string `json:"event"`
	PeerID       int64  `json:"peer_id,omitempty"`
	PeerHostname string `json:"peer_hostname,omitempty"`
	OverlayIP    string `json:"overlay_ip,omitempty"`
	RemoteIP     string `json:"remote_ip,omitempty"`
	ForwardedFor string `json:"forwarded_for,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
	Method       string `json:"method,omitempty"`
	Path         string `json:"path,omitempty"`
	Status       int    `json:"status,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

func (s *server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200

	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 || n > 2000 {
			writeError(w, http.StatusBadRequest, "limit must be 1-2000")
			return
		}

		limit = n
	}

	rows, err := s.store.ListAuditLog(r.Context(), limit)
	if err != nil {
		log.Printf("list audit log: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := make([]auditRowJSON, 0, len(rows))
	for _, a := range rows {
		out = append(out, auditRowJSON(a))
	}

	writeJSON(w, http.StatusOK, out)
}

// pruneAuditLoop trims the audit log to the retention window daily.
func (s *server) pruneAuditLoop(ctx context.Context, retention time.Duration) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		n, err := s.store.PruneAuditLog(ctx, retention)
		if err != nil {
			log.Printf("prune audit log: %v", err)
		} else if n > 0 {
			log.Printf("pruned %d audit rows older than %s", n, retention)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// reqContext carries per-request identity that middleware records but
// only handlers can resolve (which peer authenticated, its overlay
// IP). Handlers enrich it via enrichRequest; the logging middleware
// reads it after the handler returns.
type reqContext struct {
	peerID    int64
	overlayIP string
}

type reqCtxKey struct{}

// enrichRequest lets an authenticated handler attach the peer it
// resolved, so the access log and audit trail can name it.
func enrichRequest(r *http.Request, peerID int64, overlayIP string) {
	if rc, ok := r.Context().Value(reqCtxKey{}).(*reqContext); ok {
		rc.peerID = peerID
		rc.overlayIP = overlayIP
	}
}

// statusRecorder captures the status code for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}

	n, err := s.ResponseWriter.Write(b)
	s.bytes += n

	return n, err
}

// Hijack lets the websocket upgrade work through the recorder.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// accessLogLine is one structured request record. It carries the
// original client IP, the proxy hop chain, the authenticated peer's
// overlay (WireGuard) IP, and a redacted view of request headers —
// the fields NetBird-style tracing wants. Emitted as one JSON line to
// stdout so a log shipper can index it.
type accessLogLine struct {
	Time         string            `json:"time"`
	Event        string            `json:"event"`
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	Status       int               `json:"status"`
	DurationMS   int64             `json:"duration_ms"`
	RemoteIP     string            `json:"remote_ip"`
	ForwardedFor string            `json:"forwarded_for,omitempty"`
	OverlayIP    string            `json:"overlay_ip,omitempty"`
	PeerID       int64             `json:"peer_id,omitempty"`
	UserAgent    string            `json:"user_agent,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
}

// safeHeaders returns a copy of the request headers with secrets
// redacted. Authorization (bearer tokens) and Cookie are never
// logged; everything else is kept for tracing.
func safeHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))

	for k, v := range h {
		switch http.CanonicalHeaderKey(k) {
		case "Authorization", "Cookie", "Sec-Websocket-Key":
			out[k] = "[redacted]"
		default:
			out[k] = strings.Join(v, ",")
		}
	}

	return out
}

// logRequests wraps the mux: it injects a reqContext, times the
// request, and emits one structured access-log line per request with
// the original IP, proxy chain, overlay IP, and redacted headers.
func (s *server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rc := &reqContext{}
		r = r.WithContext(context.WithValue(r.Context(), reqCtxKey{}, rc))

		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)

		if rec.status == 0 {
			rec.status = http.StatusOK
		}

		line := accessLogLine{
			Time:         start.UTC().Format(time.RFC3339),
			Event:        "http_request",
			Method:       r.Method,
			Path:         r.URL.Path,
			Status:       rec.status,
			DurationMS:   time.Since(start).Milliseconds(),
			RemoteIP:     s.clientIP(r),
			ForwardedFor: r.Header.Get("X-Forwarded-For"),
			OverlayIP:    rc.overlayIP,
			PeerID:       rc.peerID,
			UserAgent:    r.Header.Get("User-Agent"),
			Headers:      safeHeaders(r.Header),
		}

		writeAccessLog(line)
	})
}

// audit records a security event, filling the request-derived fields
// (original IP, proxy chain, user agent, method, path) automatically.
// Never fails the request: audit errors are logged and swallowed.
func (s *server) audit(r *http.Request, event string, status int, detail string) {
	rc, _ := r.Context().Value(reqCtxKey{}).(*reqContext)

	e := store.AuditEntry{
		Event:        event,
		RemoteIP:     s.clientIP(r),
		ForwardedFor: r.Header.Get("X-Forwarded-For"),
		UserAgent:    r.Header.Get("User-Agent"),
		Method:       r.Method,
		Path:         r.URL.Path,
		Status:       status,
		Detail:       detail,
	}

	if rc != nil {
		e.PeerID = rc.peerID
		e.OverlayIP = rc.overlayIP
	}

	if err := s.store.Audit(r.Context(), e); err != nil {
		log.Printf("audit(%s): %v", event, err)
	}
}
