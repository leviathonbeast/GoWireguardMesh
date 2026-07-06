package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	uiSessionCookie = "wgmesh_ui"
	uiSessionTTL    = 12 * time.Hour
)

func (s *server) handleUILogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		writeUILogin(w, http.StatusBadRequest, "invalid request")
		return
	}

	token := strings.TrimSpace(r.Form.Get("token"))
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.adminToken)) != 1 {
		writeUILogin(w, http.StatusUnauthorized, "admin token rejected")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     uiSessionCookie,
		Value:    s.signUISession(time.Now().UTC()),
		Path:     "/",
		MaxAge:   int(uiSessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) uiHandler(ui fs.FS) http.Handler {
	files := http.FileServerFS(ui)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.validUISession(r) {
			files.ServeHTTP(w, r)
			return
		}

		if r.URL.Path == "/" {
			writeUILogin(w, http.StatusOK, "")
			return
		}

		http.NotFound(w, r)
	})
}

func (s *server) validUISession(r *http.Request) bool {
	cookie, err := r.Cookie(uiSessionCookie)
	if err != nil {
		return false
	}

	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return false
	}

	tsRaw, macRaw, ok := strings.Cut(string(raw), ".")
	if !ok {
		return false
	}

	issued, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return false
	}

	issuedAt := time.Unix(issued, 0)
	now := time.Now()
	if issuedAt.After(now.Add(1*time.Minute)) || now.Sub(issuedAt) > uiSessionTTL {
		return false
	}

	want := s.uiSessionMAC(tsRaw)
	got, err := base64.RawURLEncoding.DecodeString(macRaw)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(got, want) == 1
}

func (s *server) signUISession(t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	mac := base64.RawURLEncoding.EncodeToString(s.uiSessionMAC(ts))
	return base64.RawURLEncoding.EncodeToString([]byte(ts + "." + mac))
}

func (s *server) uiSessionMAC(ts string) []byte {
	mac := hmac.New(sha256.New, []byte(s.adminToken))
	_, _ = io.WriteString(mac, "wgmesh-ui-session.")
	_, _ = io.WriteString(mac, ts)
	return mac.Sum(nil)
}

func writeUILogin(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	errHTML := ""
	if message != "" {
		errHTML = fmt.Sprintf(`<div class="error">%s</div>`, htmlEscape(message))
	}

	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>wgmesh</title>
  <style>
    :root { color-scheme: dark; --bg:#101317; --panel:#1a1f26; --border:#2d3541; --text:#e4e8ee; --muted:#9aa5b3; --accent:#2382e8; --bad:#e46767; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 18px; background: var(--bg); color: var(--text); font: 14px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    main { width: min(100%%, 420px); border: 1px solid var(--border); border-radius: 8px; background: var(--panel); padding: 18px; }
    .brand { display: flex; align-items: center; gap: 10px; padding-bottom: 16px; margin-bottom: 16px; border-bottom: 1px solid var(--border); }
    .mark { display: grid; place-items: center; width: 34px; height: 34px; border: 1px solid rgba(69,163,255,.55); border-radius: 8px; color: #45a3ff; font-weight: 700; }
    .name { font-weight: 700; line-height: 1.1; }
    .sub, label { color: var(--muted); }
    form { display: grid; gap: 12px; }
    label { display: grid; gap: 6px; }
    input, button { width: 100%%; font: inherit; color: var(--text); background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; }
    input:focus { outline: none; border-color: #45a3ff; }
    button { cursor: pointer; background: var(--accent); border-color: var(--accent); color: white; }
    .error { margin-top: 12px; color: var(--bad); min-height: 1.5em; }
  </style>
</head>
<body>
  <main>
    <div class="brand"><div class="mark">wg</div><div><div class="name">wgmesh</div><div class="sub">control plane</div></div></div>
    <form method="post" action="/ui-login">
      <label>Admin token<input type="password" name="token" autocomplete="current-password" autofocus></label>
      <button type="submit">connect</button>
    </form>
    %s
  </main>
</body>
</html>`, errHTML)
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;")
	return replacer.Replace(s)
}
