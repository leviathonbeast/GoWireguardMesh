package main

import (
	"net/netip"
	"strings"
	"testing"
)

func TestCandidateAddrFilters(t *testing.T) {
	overlay4 := netip.MustParsePrefix("100.64.0.0/16")
	overlay6 := netip.MustParsePrefix("fd00:100:64::/64")

	tests := []struct {
		addr string
		want bool
	}{
		{"192.168.1.10", true},    // private LAN: the whole point
		{"10.0.40.7", true},       // private LAN
		{"203.0.113.9", true},     // public v4
		{"127.0.0.1", false},      // loopback
		{"169.254.10.1", false},   // link-local
		{"100.64.0.5", false},     // overlay itself
		{"100.65.1.1", false},     // CGNAT space outside the overlay
		{"2001:db8::1", true},     // global v6
		{"fd00:100:64::2", false}, // overlay v6
		{"fdab::1", false},        // foreign ULA: unknowable reachability
		{"fe80::1", false},        // link-local v6
		{"::1", false},            // loopback v6
	}

	for _, tt := range tests {
		got := candidateAddr(netip.MustParseAddr(tt.addr), []netip.Prefix{overlay4, overlay6})
		if got != tt.want {
			t.Errorf("candidateAddr(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestGatherLocalCandidatesExcludesAndFormats(t *testing.T) {
	// Excluding all of v4 and v6 space proves the overlay filter is
	// honored regardless of what interfaces this test host has.
	all4 := netip.MustParsePrefix("0.0.0.0/0")
	all6 := netip.MustParsePrefix("::/0")

	if got := gatherLocalCandidates(51820, true, all4, all6); len(got) != 0 {
		t.Fatalf("gatherLocalCandidates with everything excluded = %v, want none", got)
	}

	// Unfiltered: whatever comes back must be well-formed, carry the
	// listen port, and never be loopback/link-local.
	for _, c := range gatherLocalCandidates(51820, true) {
		if c.Type != "host" && c.Type != "host6" {
			t.Errorf("candidate type = %q, want host/host6", c.Type)
		}
		ap, err := netip.ParseAddrPort(c.Endpoint)
		if err != nil {
			t.Errorf("candidate endpoint %q not addr:port: %v", c.Endpoint, err)
			continue
		}
		if ap.Port() != 51820 {
			t.Errorf("candidate port = %d, want 51820", ap.Port())
		}
		if ap.Addr().IsLoopback() || ap.Addr().IsLinkLocalUnicast() {
			t.Errorf("candidate %q should have been filtered", c.Endpoint)
		}
		if strings.Contains(c.Endpoint, "%") {
			t.Errorf("candidate %q carries a zone", c.Endpoint)
		}
	}
}

// With advertiseV6 off (the --manage-firewall=false case), no host6
// candidate may ever be produced, whatever v6 addresses this host has.
func TestGatherLocalCandidatesSuppressesV6WhenNotAdvertising(t *testing.T) {
	for _, c := range gatherLocalCandidates(51820, false) {
		if c.Type == "host6" {
			t.Errorf("host6 candidate %q emitted with advertiseV6=false", c.Endpoint)
		}
	}
}

// A cached reflexive v6 endpoint is emitted as a stun6 candidate, and
// suppressed when withdrawn (v6 stopped answering STUN).
func TestSelfCandidatesIncludesV6Endpoint(t *testing.T) {
	tel := &telemetryReporter{
		listenPort:      51820,
		publicEndpoint6: "[2001:db8::7]:51820",
	}

	found := false
	for _, c := range tel.selfCandidates() {
		if c.Type == "stun6" && c.Endpoint == "[2001:db8::7]:51820" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stun6 candidate not present: %+v", tel.selfCandidates())
	}

	tel.publicEndpoint6 = ""
	for _, c := range tel.selfCandidates() {
		if c.Type == "stun6" {
			t.Fatalf("stun6 candidate emitted after withdrawal: %+v", tel.selfCandidates())
		}
	}
}

// A pinned endpoint (--advertise-endpoint) is emitted as a typed
// candidate so the server can rank the operator's guarantee above
// discovered guesses; an unpinned public endpoint must not be.
func TestSelfCandidatesIncludesPinnedEndpoint(t *testing.T) {
	tel := &telemetryReporter{
		listenPort:     51820,
		publicEndpoint: "203.0.113.9:51820",
		endpointPinned: true,
	}

	found := false
	for _, c := range tel.selfCandidates() {
		if c.Type == "pinned" && c.Endpoint == "203.0.113.9:51820" {
			found = true
		}
	}
	if !found {
		t.Fatalf("pinned candidate not present: %+v", tel.selfCandidates())
	}

	tel.endpointPinned = false
	for _, c := range tel.selfCandidates() {
		if c.Type == "pinned" {
			t.Fatalf("pinned candidate emitted for STUN-discovered endpoint: %+v", tel.selfCandidates())
		}
	}
}
