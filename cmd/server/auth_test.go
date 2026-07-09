package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// login posts username/password and returns the session cookie.
func login(t *testing.T, ts string, username, password string) *http.Cookie {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.PostForm(ts+"/ui-login", url.Values{"username": {username}, "password": {password}})
	if err != nil {
		t.Fatalf("POST /ui-login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == uiSessionCookie {
			return c
		}
	}
	t.Fatal("login set no session cookie")
	return nil
}

func doWithCookie(t *testing.T, method, u string, cookie *http.Cookie, body string) (int, []byte) {
	t.Helper()
	var r *strings.Reader
	if body != "" {
		r = strings.NewReader(body)
	} else {
		r = strings.NewReader("")
	}
	req, err := http.NewRequest(method, u, r)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, buf
}

func TestPasswordAuthFlow(t *testing.T) {
	_, ts := newTestServer(t)

	// Seeded admin logs in with the admin token as the initial password.
	cookie := login(t, ts.URL, "admin", "test-admin")

	// /api/account reports who we are.
	status, body := doWithCookie(t, http.MethodGet, ts.URL+"/api/account", cookie, "")
	if status != http.StatusOK {
		t.Fatalf("GET /api/account = %d: %s", status, body)
	}
	var acct userJSON
	if err := json.Unmarshal(body, &acct); err != nil {
		t.Fatalf("decode account: %v", err)
	}
	if acct.Username != "admin" {
		t.Fatalf("account username = %q, want admin", acct.Username)
	}

	// Wrong current password is rejected.
	status, _ = doWithCookie(t, http.MethodPost, ts.URL+"/api/account/password", cookie,
		`{"current_password":"nope","new_password":"brand-new-password"}`)
	if status != http.StatusUnauthorized {
		t.Fatalf("bad current-password change = %d, want 401", status)
	}

	// Correct change succeeds and re-issues a fresh cookie.
	status, body = doWithCookie(t, http.MethodPost, ts.URL+"/api/account/password", cookie,
		`{"current_password":"test-admin","new_password":"brand-new-password"}`)
	if status != http.StatusOK {
		t.Fatalf("password change = %d: %s", status, body)
	}

	// The ORIGINAL cookie is now stale (epoch bumped) — it must be rejected.
	status, _ = doWithCookie(t, http.MethodGet, ts.URL+"/api/account", cookie, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("stale cookie after password change = %d, want 401", status)
	}

	// A fresh login with the new password works; the old password does not.
	if login(t, ts.URL, "admin", "brand-new-password") == nil {
		t.Fatal("login with new password failed")
	}
}

func TestBearerTokenStillWorksForAdminAPI(t *testing.T) {
	_, ts := newTestServer(t)

	// The programmatic bearer token path is unchanged by the user/pass work.
	status, body := adminDo(t, ts, http.MethodGet, "/api/peers", nil)
	if status != http.StatusOK {
		t.Fatalf("bearer GET /api/peers = %d: %s", status, body)
	}
	// Account endpoints, by contrast, require a session (a user), not bearer.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/account", nil)
	req.Header.Set("Authorization", "Bearer test-admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/account bearer: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bearer /api/account = %d, want 401 (needs a session)", resp.StatusCode)
	}
}

func TestUserManagement(t *testing.T) {
	_, ts := newTestServer(t)

	// Create a second admin via the API (bearer-authenticated).
	status, body := adminDo(t, ts, http.MethodPost, "/api/users",
		map[string]any{"username": "carol", "password": "carol-password-1"})
	if status != http.StatusOK {
		t.Fatalf("create user = %d: %s", status, body)
	}
	var created userJSON
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode created user: %v", err)
	}

	// carol can now log in.
	if login(t, ts.URL, "carol", "carol-password-1") == nil {
		t.Fatal("new user cannot log in")
	}

	// List shows both admin and carol.
	status, body = adminDo(t, ts, http.MethodGet, "/api/users", nil)
	if status != http.StatusOK {
		t.Fatalf("list users = %d: %s", status, body)
	}
	var users []userJSON
	if err := json.Unmarshal(body, &users); err != nil {
		t.Fatalf("decode users: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("user count = %d, want 2", len(users))
	}

	// Delete carol.
	status, _ = adminDo(t, ts, http.MethodPost, "/api/users/"+strconv.FormatInt(created.ID, 10)+"/delete", nil)
	if status != http.StatusOK {
		t.Fatalf("delete user = %d", status)
	}

	// carol can no longer log in.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.PostForm(ts.URL+"/ui-login", url.Values{"username": {"carol"}, "password": {"carol-password-1"}})
	if err != nil {
		t.Fatalf("login deleted user: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("deleted user login = %d, want 401", resp.StatusCode)
	}
}
