package main

import (
	"strings"
	"testing"
)

func TestStatusHubDisabledDropsUpdates(t *testing.T) {
	hub := &statusHub{}

	hub.update(func(s *agentStatus) { s.State = stateRunning })

	got, version := hub.snapshot()
	if got.State != "" || version != 0 {
		t.Fatalf("disabled hub accepted update: state=%q version=%d", got.State, version)
	}
}

func TestStatusHubSnapshotIsDeepCopy(t *testing.T) {
	hub := &statusHub{}
	hub.enable()

	hub.update(func(s *agentStatus) {
		s.State = stateRunning
		s.Peers = []peerStatus{{PublicKey: "a"}}
	})

	first, v1 := hub.snapshot()
	first.Peers[0].PublicKey = "mutated"

	second, v2 := hub.snapshot()
	if second.Peers[0].PublicKey != "a" {
		t.Fatalf("snapshot shares peer memory with the hub")
	}
	if v1 != v2 || v1 == 0 {
		t.Fatalf("versions: first=%d second=%d, want equal and nonzero", v1, v2)
	}

	hub.update(func(s *agentStatus) { s.State = stateStopped })
	if _, v3 := hub.snapshot(); v3 != v2+1 {
		t.Fatalf("version after update = %d, want %d", v3, v2+1)
	}
}

func TestLogRingSplitsAndVersions(t *testing.T) {
	ring := &logRing{}

	if _, err := ring.Write([]byte("one\ntwo\npart")); err != nil {
		t.Fatal(err)
	}

	text, v1 := ring.snapshot()
	if text != "one\ntwo" {
		t.Fatalf("snapshot = %q, want %q (partial line must not appear)", text, "one\ntwo")
	}
	if v1 == 0 {
		t.Fatal("version did not advance on complete lines")
	}

	// Completing the partial line keeps the earlier fragment intact.
	if _, err := ring.Write([]byte("ial\n")); err != nil {
		t.Fatal(err)
	}

	text, v2 := ring.snapshot()
	if text != "one\ntwo\npartial" {
		t.Fatalf("snapshot = %q, want %q", text, "one\ntwo\npartial")
	}
	if v2 == v1 {
		t.Fatal("version did not advance when the partial line completed")
	}

	// A write with no newline must not bump the version.
	if _, err := ring.Write([]byte("pend")); err != nil {
		t.Fatal(err)
	}
	if _, v3 := ring.snapshot(); v3 != v2 {
		t.Fatalf("version advanced on a partial-only write: %d -> %d", v2, v3)
	}
}

func TestLogRingCapsLines(t *testing.T) {
	ring := &logRing{}

	var b strings.Builder
	for i := 0; i < logRingMax+50; i++ {
		b.WriteString("line\n")
	}
	if _, err := ring.Write([]byte(b.String())); err != nil {
		t.Fatal(err)
	}

	text, _ := ring.snapshot()
	if got := strings.Count(text, "\n") + 1; got != logRingMax {
		t.Fatalf("ring holds %d lines, want %d", got, logRingMax)
	}

	ring.clear()
	if text, _ := ring.snapshot(); text != "" {
		t.Fatalf("clear left %q", text)
	}
}
