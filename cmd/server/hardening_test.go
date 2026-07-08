package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gowireguard "gowireguard"

	"github.com/gorilla/websocket"
)

// TestClientIPUsesRightmostForwardedFor: with a trusted proxy in
// front, only the RIGHTMOST X-Forwarded-For entry was appended by the
// proxy; everything left of it is client-controlled. Taking the first
// entry let clients choose their own rate-limit key and audit
// identity.
func TestClientIPUsesRightmostForwardedFor(t *testing.T) {
	newReq := func(xff string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.0.0.9:41234"
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	trusted := &server{trustProxy: true}

	if got := trusted.clientIP(newReq("1.2.3.4, 5.6.7.8")); got != "5.6.7.8" {
		t.Fatalf("clientIP(spoofed chain) = %q, want rightmost 5.6.7.8", got)
	}
	if got := trusted.clientIP(newReq(" 9.9.9.9 ")); got != "9.9.9.9" {
		t.Fatalf("clientIP(single entry) = %q, want 9.9.9.9", got)
	}
	if got := trusted.clientIP(newReq("")); got != "10.0.0.9" {
		t.Fatalf("clientIP(no header) = %q, want RemoteAddr host", got)
	}

	direct := &server{trustProxy: false}
	if got := direct.clientIP(newReq("1.2.3.4")); got != "10.0.0.9" {
		t.Fatalf("clientIP(untrusted proxy header) = %q, want RemoteAddr host", got)
	}
}

// TestEnrollBodyCapReturns413: /enroll is public; an unbounded decode
// there is a memory-DoS vector. Oversized bodies must be refused with
// 413, not read to completion.
func TestEnrollBodyCapReturns413(t *testing.T) {
	_, ts := newTestServer(t)

	huge, _ := json.Marshal(map[string]string{
		"setup_key":  strings.Repeat("a", 128<<10), // > the 64KB cap
		"public_key": "irrelevant",
	})

	resp, err := http.Post(ts.URL+"/enroll", "application/json", bytes.NewReader(huge))
	if err != nil {
		t.Fatalf("POST /enroll: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized enroll: status %d, want 413", resp.StatusCode)
	}
}

// TestSecurityHeadersPresent: every response must carry the CSP and
// friends. The dashboard bundle itself is also server-gated by
// TestWebUIStructureHiddenUntilSessionCookie below.
func TestSecurityHeadersPresent(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("Content-Security-Policy = %q, want same-origin policy", csp)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want DENY", got)
	}
	if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q, want no-referrer", got)
	}
	// Plain-HTTP test server: HSTS must NOT be advertised without TLS.
	if got := resp.Header.Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("Strict-Transport-Security = %q on plain HTTP, want unset", got)
	}
}

func TestWebUIStructureHiddenUntilSessionCookie(t *testing.T) {
	ui, err := fs.Sub(gowireguard.WebUI, "web/dist")
	if err != nil {
		t.Fatalf("locate embedded ui: %v", err)
	}

	srv := &server{adminToken: "test-admin"}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ui-login", srv.handleUILogin)
	mux.Handle("GET /", srv.uiHandler(ui))
	mux.HandleFunc("GET /api/peers", srv.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, []peerJSON{})
	}))
	ts := httptest.NewServer(securityHeaders(mux))
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("anonymous / status = %d, want 200", resp.StatusCode)
	}
	if strings.Contains(string(body), "/assets/") || strings.Contains(string(body), "Overview") {
		t.Fatalf("anonymous login page exposed app structure: %s", body)
	}

	resp, err = http.Get(ts.URL + "/assets/index-does-not-matter.js")
	if err != nil {
		t.Fatalf("GET anonymous asset: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("anonymous asset status = %d, want 404", resp.StatusCode)
	}

	resp, err = http.PostForm(ts.URL+"/ui-login", url.Values{"token": {"wrong"}})
	if err != nil {
		t.Fatalf("POST bad /ui-login: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login status = %d, want 401", resp.StatusCode)
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err = client.PostForm(ts.URL+"/ui-login", url.Values{"token": {"test-admin"}})
	if err != nil {
		t.Fatalf("POST good /ui-login: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("good login status = %d, want 303", resp.StatusCode)
	}
	var session *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == uiSessionCookie {
			session = cookie
			break
		}
	}
	if session == nil || !session.HttpOnly {
		t.Fatalf("login did not set HttpOnly %s cookie: %#v", uiSessionCookie, resp.Cookies())
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	if err != nil {
		t.Fatalf("build authenticated ui request: %v", err)
	}
	req.AddCookie(session)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET authenticated /: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated / status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "/assets/") {
		t.Fatalf("authenticated / did not serve built app index: %s", body)
	}

	req, err = http.NewRequest(http.MethodGet, ts.URL+"/api/peers", nil)
	if err != nil {
		t.Fatalf("build cookie API request: %v", err)
	}
	req.AddCookie(session)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/peers with UI cookie: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cookie-authenticated API status = %d, want 200", resp.StatusCode)
	}
}

// dialRelayWS opens an authenticated relay websocket to the test
// server, targeting the given peer public key.
func dialRelayWS(t *testing.T, ctx context.Context, ts *httptest.Server, authToken, targetPubKey string) *websocket.Conn {
	t.Helper()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/relay-ws?peer=" + url.QueryEscape(targetPubKey)

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, http.Header{"Authorization": []string{"Bearer " + authToken}})
	if err != nil {
		t.Fatalf("dial %s: %v", wsURL, err)
	}

	return conn
}

// TestRelayWSSurvivesServerTimeouts pins the deadline interaction the
// relay depends on: the http.Server arms Read/WriteTimeout deadlines
// per request, and a long-lived relay session only survives because
// net/http clears both deadlines when the upgrade hijacks the
// connection (hijackLocked does SetDeadline(time.Time{}) — an
// implementation detail, hence this test). The test runs a server
// with 250ms timeouts, idles a relay session well past them, and
// proves frames still flow.
func TestRelayWSSurvivesServerTimeouts(t *testing.T) {
	srv, ts := newTestServer(t)

	// Rebuild the listener with aggressive per-request deadlines. The
	// handler chain (logRequests → securityHeaders → mux) is the same
	// production chain, so the websocket Hijack must also reach the
	// real connection through statusRecorder's Unwrap.
	ts.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll", srv.handleEnroll)
	mux.HandleFunc("GET /relay-ws", srv.handleRelayWS)

	tight := httptest.NewUnstartedServer(srv.logRequests(securityHeaders(mux)))
	tight.Config.ReadTimeout = 250 * time.Millisecond
	tight.Config.WriteTimeout = 250 * time.Millisecond
	tight.Start()
	defer tight.Close()

	setupKey, err := srv.store.CreateSetupKey(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}

	a, keyA := enrollPeerKey(t, tight, setupKey, "ws-a")
	b, keyB := enrollPeerKey(t, tight, setupKey, "ws-b")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	connA := dialRelayWS(t, ctx, tight, a.AuthToken, keyB.PublicKey().String())
	defer connA.Close()
	connB := dialRelayWS(t, ctx, tight, b.AuthToken, keyA.PublicKey().String())
	defer connB.Close()

	// The hub drops frames until BOTH members have joined (by design —
	// WireGuard keepalives retransmit), and a dial returning only
	// proves the 101, not the join. Wait for both joins so the strict
	// exchange below cannot race the second one.
	pairID := relayPairID(keyA.PublicKey().String(), keyB.PublicKey().String())
	for start := time.Now(); srv.wsHub.MemberCount(pairID) != 2; {
		if time.Since(start) > 2*time.Second {
			t.Fatalf("pair never reached 2 members (have %d)", srv.wsHub.MemberCount(pairID))
		}

		time.Sleep(5 * time.Millisecond)
	}

	exchange := func(stage string) {
		if err := connA.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("%s: A write deadline: %v", stage, err)
		}
		if err := connA.WriteMessage(websocket.BinaryMessage, []byte("ping-"+stage)); err != nil {
			t.Fatalf("%s: A write: %v", stage, err)
		}

		if err := connB.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("%s: B read deadline: %v", stage, err)
		}
		_, data, err := connB.ReadMessage()
		if err != nil {
			t.Fatalf("%s: B read: %v", stage, err)
		}
		if string(data) != "ping-"+stage {
			t.Fatalf("%s: B got %q", stage, data)
		}

		if err := connB.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("%s: B write deadline: %v", stage, err)
		}
		if err := connB.WriteMessage(websocket.BinaryMessage, []byte("pong-"+stage)); err != nil {
			t.Fatalf("%s: B write: %v", stage, err)
		}

		if err := connA.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("%s: A read deadline: %v", stage, err)
		}
		_, data, err = connA.ReadMessage()
		if err != nil {
			t.Fatalf("%s: A read: %v", stage, err)
		}
		if string(data) != "pong-"+stage {
			t.Fatalf("%s: A got %q", stage, data)
		}
	}

	exchange("before")

	// Idle 3x past both server timeouts. If hijacking ever stopped
	// clearing the armed Read/WriteTimeout deadlines, they fire during
	// this sleep and the next exchange errors out.
	time.Sleep(750 * time.Millisecond)

	exchange("after")

	// Shut the sessions down and wait for both handlers to write their
	// final relay_ws_close audit row. httptest.Server.Close does not
	// wait for hijacked connections, so without this the handlers'
	// last DB writes race the store close and TempDir cleanup.
	connA.Close()
	connB.Close()

	deadline := time.Now().Add(3 * time.Second)

	for {
		rows, err := srv.store.ListAuditLog(context.Background(), 100)
		if err != nil {
			t.Fatalf("ListAuditLog: %v", err)
		}

		closes := 0
		for _, row := range rows {
			if row.Event == "relay_ws_close" {
				closes++
			}
		}

		if closes >= 2 {
			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("relay handlers never finished: %d relay_ws_close audit rows", closes)
		}

		time.Sleep(10 * time.Millisecond)
	}
}
