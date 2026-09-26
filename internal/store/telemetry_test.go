package store

import (
	"strings"
	"testing"
)

// TestAgentVersionRejectsJunk: the reporting agent is authenticated but
// not trusted, and this string is rendered in the admin UI, so anything
// outside a plain printable token is dropped rather than stored.
func TestAgentVersionRejectsJunk(t *testing.T) {
	for _, ok := range []string{"v0.9.1", "a34d586", "a34d586-dirty", "v1.2.3-rc1+build.5"} {
		if got := agentVersion(ok); got != ok {
			t.Errorf("agentVersion(%q) = %q, want it kept", ok, got)
		}
	}

	junk := map[string]string{
		"empty":     "",
		"space":     "v0.9.1 rm -rf",
		"newline":   "v0.9.1\ninjected",
		"tab":       "v0.9.1\tx",
		"nonascii":  "v0.9.1é",
		"controlch": "v0.9.1\x00",
		"toolong":   strings.Repeat("v", 65),
	}
	for name, v := range junk {
		if got := agentVersion(v); got != "" {
			t.Errorf("agentVersion(%s) = %q, want dropped", name, got)
		}
	}
}
