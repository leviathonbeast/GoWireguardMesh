package main

import (
	"testing"

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
