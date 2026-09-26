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

// TestSortPeerStatusPutsNamedPeersFirst: the GUI list is scanned by
// hostname, so named peers lead and sort alphabetically. Unnamed peers
// (enrolled without a name, or before the first sync lands) fall to the
// bottom ordered by key, which keeps the list stable rather than
// reshuffling as names arrive.
func TestSortPeerStatusPutsNamedPeersFirst(t *testing.T) {
	peers := []peerStatus{
		{PublicKey: "aaa"},
		{PublicKey: "zzz", Hostname: "nas-3"},
		{PublicKey: "bbb"},
		{PublicKey: "mmm", Hostname: "homelab-2"},
		{PublicKey: "ccc", Hostname: "vps-1"},
	}

	sortPeerStatus(peers)

	want := []string{"homelab-2", "nas-3", "vps-1", "", ""}
	for i, w := range want {
		if peers[i].Hostname != w {
			t.Fatalf("peers[%d].Hostname = %q, want %q (order: %v)", i, peers[i].Hostname, w, hostnamesOf(peers))
		}
	}

	// Unnamed tail ordered by key, so the list does not jitter.
	if peers[3].PublicKey != "aaa" || peers[4].PublicKey != "bbb" {
		t.Fatalf("unnamed peers not key-ordered: %q, %q", peers[3].PublicKey, peers[4].PublicKey)
	}
}

// TestSortPeerStatusStableForDuplicateNames: two hosts can share a
// name; the key breaks the tie so the order does not flip between
// refreshes.
func TestSortPeerStatusStableForDuplicateNames(t *testing.T) {
	peers := []peerStatus{
		{PublicKey: "zzz", Hostname: "dup"},
		{PublicKey: "aaa", Hostname: "dup"},
	}

	sortPeerStatus(peers)

	if peers[0].PublicKey != "aaa" || peers[1].PublicKey != "zzz" {
		t.Fatalf("duplicate names not key-ordered: %q, %q", peers[0].PublicKey, peers[1].PublicKey)
	}
}

func hostnamesOf(peers []peerStatus) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.Hostname)
	}
	return out
}
