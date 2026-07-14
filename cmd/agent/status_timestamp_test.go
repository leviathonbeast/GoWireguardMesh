package main

import (
	"regexp"
	"strings"
	"testing"
)

func TestTimestampLine(t *testing.T) {
	re := regexp.MustCompile(`^\[\d{2}:\d{2}:\d{2}\] `)

	got := timestampLine("[agent] relay: leaving relay\n")
	if !re.MatchString(got) {
		t.Fatalf("missing/invalid timestamp prefix: %q", got)
	}
	if !strings.HasSuffix(got, "[agent] relay: leaving relay\n") {
		t.Fatalf("message mangled: %q", got)
	}

	// Leading newlines (blank-line separators) stay ahead of the stamp.
	got = timestampLine("\n\nReceived signal: interrupt\n")
	if !strings.HasPrefix(got, "\n\n[") {
		t.Fatalf("leading newlines not preserved: %q", got)
	}

	// Empty / newline-only input is passed through untouched.
	if got := timestampLine("\n"); got != "\n" {
		t.Fatalf("newline-only input changed: %q", got)
	}
	if got := timestampLine(""); got != "" {
		t.Fatalf("empty input changed: %q", got)
	}
}
