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

	"gowireguard/internal/store"
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

	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")

	user, err := s.store.Authenticate(r.Context(), username, password)
	if err != nil {
		s.audit(r, "ui_login_failed", http.StatusUnauthorized, "user="+username)
		writeUILogin(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     uiSessionCookie,
		Value:    s.signUISession(user, time.Now().UTC()),
		Path:     "/",
		MaxAge:   int(uiSessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.requestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
	s.audit(r, "ui_login", http.StatusOK, "user="+user.Username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleLogout clears the session cookie.
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     uiSessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.requestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (s *server) requestIsHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
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

// sessionUser returns the authenticated user for a request's session
// cookie, or ok=false. It validates the HMAC (keyed by the server session
// key, not the admin token), the TTL, and that the user still exists with a
// matching session epoch — so a password change or user deletion revokes
// outstanding cookies.
func (s *server) sessionUser(r *http.Request) (store.User, bool) {
	cookie, err := r.Cookie(uiSessionCookie)
	if err != nil {
		return store.User{}, false
	}

	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return store.User{}, false
	}

	payload, macRaw, ok := strings.Cut(string(raw), "|")
	if !ok {
		return store.User{}, false
	}

	// payload = userID.epoch.issued
	fields := strings.Split(payload, ".")
	if len(fields) != 3 {
		return store.User{}, false
	}
	userID, err1 := strconv.ParseInt(fields[0], 10, 64)
	epoch, err2 := strconv.ParseInt(fields[1], 10, 64)
	issued, err3 := strconv.ParseInt(fields[2], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return store.User{}, false
	}

	got, err := base64.RawURLEncoding.DecodeString(macRaw)
	if err != nil || subtle.ConstantTimeCompare(got, s.uiSessionMAC(payload)) != 1 {
		return store.User{}, false
	}

	issuedAt := time.Unix(issued, 0)
	now := time.Now()
	if issuedAt.After(now.Add(1*time.Minute)) || now.Sub(issuedAt) > uiSessionTTL {
		return store.User{}, false
	}

	user, err := s.store.UserByID(r.Context(), userID)
	if err != nil || user.SessionEpoch != epoch {
		return store.User{}, false
	}
	return user, true
}

func (s *server) validUISession(r *http.Request) bool {
	_, ok := s.sessionUser(r)
	return ok
}

func (s *server) signUISession(user store.User, t time.Time) string {
	payload := fmt.Sprintf("%d.%d.%d", user.ID, user.SessionEpoch, t.Unix())
	mac := base64.RawURLEncoding.EncodeToString(s.uiSessionMAC(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + mac))
}

func (s *server) uiSessionMAC(payload string) []byte {
	mac := hmac.New(sha256.New, s.sessionKey)
	_, _ = io.WriteString(mac, "wgmesh-ui-session.")
	_, _ = io.WriteString(mac, payload)
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
      <label>Username<input type="text" name="username" autocomplete="username" autofocus value="admin"></label>
      <label>Password<input type="password" name="password" autocomplete="current-password"></label>
      <button type="submit">sign in</button>
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
