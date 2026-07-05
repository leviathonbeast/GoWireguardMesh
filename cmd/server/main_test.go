package main

import (
	"testing"
	"time"

	"gowireguard/internal/store"
)

func TestAllowedIPsForPeerIncludesIPv6WhenPresent(t *testing.T) {
	got := allowedIPsForPeer(store.PeerRow{
		AssignedIP:  "100.64.0.2",
		AssignedIP6: "fd00:100:64::2",
	})
	want := []string{"100.64.0.2/32", "fd00:100:64::2/128"}

	if len(got) != len(want) {
		t.Fatalf("allowedIPsForPeer() = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("allowedIPsForPeer()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDefaultNetwork6CIDRParsesAsIPv6(t *testing.T) {
	prefix, err := parseNetwork6(defaultNetwork6CIDR)
	if err != nil {
		t.Fatalf("parseNetwork6(defaultNetwork6CIDR) returned error: %v", err)
	}
	if got := prefix.String(); got != "fd00:100:64::/64" {
		t.Fatalf("default network6 = %q, want fd00:100:64::/64", got)
	}
}

func TestParseNetwork6RejectsIPv4(t *testing.T) {
	if _, err := parseNetwork6("100.64.0.0/16"); err == nil {
		t.Fatal("parseNetwork6 accepted an IPv4 CIDR")
	}
}

func TestFlowDirectionUsesIPv6PeerIP(t *testing.T) {
	dir, ingress, egress := flowDirection(
		"100.64.0.2",
		"fd00:100:64::2",
		"fd00:100:64::2",
		12345,
		"fd00:100:64::3",
		443,
	)

	if dir != "egress" || ingress != 12345 || egress != 443 {
		t.Fatalf("flowDirection() = (%q, %d, %d), want (egress, 12345, 443)", dir, ingress, egress)
	}
}

func TestAccessLogMemoryRingNewestFirst(t *testing.T) {
	sink := newAccessLogSink(accessLogMemory, 2)
	sink.write(accessLogLine{Path: "/one"})
	sink.write(accessLogLine{Path: "/two"})
	sink.write(accessLogLine{Path: "/three"})

	got := sink.list(10)
	if len(got) != 2 {
		t.Fatalf("list() returned %d rows, want 2", len(got))
	}
	if got[0].Path != "/three" || got[1].Path != "/two" {
		t.Fatalf("list() paths = %q, %q; want /three, /two", got[0].Path, got[1].Path)
	}
}

func TestPeerHealthClassifiesLastSeen(t *testing.T) {
	online, age := peerHealth(time.Now().UTC().Add(-30*time.Second).Format(time.RFC3339Nano), "")
	if online != "online" || age < 0 {
		t.Fatalf("peerHealth(30s ago) = %q, %d; want online", online, age)
	}

	stale, _ := peerHealth(time.Now().UTC().Add(-2*time.Minute).Format(time.RFC3339Nano), "")
	if stale != "stale" {
		t.Fatalf("peerHealth(2m ago) = %q, want stale", stale)
	}

	offline, _ := peerHealth(time.Now().UTC().Add(-10*time.Minute).Format(time.RFC3339Nano), "")
	if offline != "offline" {
		t.Fatalf("peerHealth(10m ago) = %q, want offline", offline)
	}

	revoked, _ := peerHealth(time.Now().UTC().Format(time.RFC3339Nano), "revoked")
	if revoked != "revoked" {
		t.Fatalf("peerHealth(revoked) = %q, want revoked", revoked)
	}
}
