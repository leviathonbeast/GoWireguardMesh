package store

import (
	"context"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gowireguard/internal/proto"
)

func TestConnectionEventKind(t *testing.T) {
	cases := []struct {
		prev, next string
		wantKind   string
		wantOK     bool
	}{
		{"", "direct", "direct", true},
		{"", "ws-relay", "relay", true},
		{"", "quic-relay", "relay", true},
		{"", "udp-relay", "relay", true},
		{"", "probing-direct", "", false},
		{"ws-relay", "direct", "direct", true},
		{"direct", "ws-relay", "relay", true},
		{"ws-relay", "udp-relay", "", false}, // relay transport churn, not a new event
		{"quic-relay", "ws-relay", "", false},
		{"direct", "direct", "", false}, // unchanged
		{"direct", "probing-direct", "", false},
	}

	for _, c := range cases {
		kind, ok := connectionEventKind(c.prev, c.next)
		if kind != c.wantKind || ok != c.wantOK {
			t.Fatalf("connectionEventKind(%q,%q) = %q,%v; want %q,%v",
				c.prev, c.next, kind, ok, c.wantKind, c.wantOK)
		}
	}
}

func TestConnectionEventsFromPathTransitions(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}

	reporterKey, _ := wgtypes.GeneratePrivateKey()
	remoteKey, _ := wgtypes.GeneratePrivateKey()

	reporter, err := st.Enroll(ctx, setupKey, reporterKey.PublicKey().String(), "node-a", 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("enroll reporter: %v", err)
	}
	if _, err := st.Enroll(ctx, setupKey, remoteKey.PublicKey().String(), "node-b", 51820, "192.0.2.11", ""); err != nil {
		t.Fatalf("enroll remote: %v", err)
	}

	report := func(state string) {
		t.Helper()
		if err := st.ApplyReport(ctx, reporter.Peer.ID, "192.0.2.10", &proto.ReportRequest{
			PathStates: []proto.PeerPathState{{PeerPublicKey: remoteKey.PublicKey().String(), State: state}},
		}); err != nil {
			t.Fatalf("ApplyReport(%s): %v", state, err)
		}
	}

	report("ws-relay")       // first observation -> relay event
	report("direct")         // upgrade -> direct event
	report("direct")         // unchanged -> no event
	report("probing-direct") // intermediate -> no event

	events, err := st.ListConnectionEvents(ctx, 50)
	if err != nil {
		t.Fatalf("ListConnectionEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d connection events, want 2: %+v", len(events), events)
	}

	// Newest first.
	if events[0].Kind != "direct" || events[0].ToState != "direct" || events[0].FromState != "ws-relay" {
		t.Fatalf("event[0] = %+v, want direct from ws-relay", events[0])
	}
	if events[1].Kind != "relay" || events[1].ToState != "ws-relay" || events[1].FromState != "" {
		t.Fatalf("event[1] = %+v, want relay first-seen", events[1])
	}
	if events[0].ReporterHostname != "node-a" || events[0].RemoteHostname != "node-b" {
		t.Fatalf("hostnames = %s -> %s, want node-a -> node-b",
			events[0].ReporterHostname, events[0].RemoteHostname)
	}
}
