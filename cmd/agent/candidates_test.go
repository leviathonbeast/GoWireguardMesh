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

	if got := gatherLocalCandidates(51820, all4, all6); len(got) != 0 {
		t.Fatalf("gatherLocalCandidates with everything excluded = %v, want none", got)
	}

	// Unfiltered: whatever comes back must be well-formed, carry the
	// listen port, and never be loopback/link-local.
	for _, c := range gatherLocalCandidates(51820) {
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
