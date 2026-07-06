package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"gowireguard/internal/proto"
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

func TestEndpointCandidatesPreferLANForSamePublicEndpoint(t *testing.T) {
	self := store.PeerRow{PublicEndpoint: "203.0.113.1:51820"}
	peer := store.PeerRow{
		PublicEndpoint: "203.0.113.1:51821",
		ObservedIP:     "192.168.1.20",
		ListenPort:     51820,
	}

	got := endpointCandidates(self, peer)
	if len(got) != 2 {
		t.Fatalf("endpointCandidates returned %d candidates, want 2", len(got))
	}
	if got[0].Type != "lan" || got[0].Endpoint != "192.168.1.20:51820" {
		t.Fatalf("first candidate = %#v, want LAN candidate", got[0])
	}
	if got[1].Type != "stun" {
		t.Fatalf("second candidate = %#v, want STUN candidate", got[1])
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

func TestShouldBumpPunchEpoch(t *testing.T) {
	tests := []struct {
		name string
		in   punchDecision
		want bool
	}{
		{
			name: "relayed online with candidates",
			in: punchDecision{
				state:            "ws-relay",
				remoteOnline:     true,
				selfCandidates:   1,
				remoteCandidates: 1,
			},
			want: true,
		},
		{
			name: "direct",
			in: punchDecision{
				state:            "direct",
				remoteOnline:     true,
				selfCandidates:   1,
				remoteCandidates: 1,
			},
		},
		{
			name: "offline remote",
			in: punchDecision{
				state:            "udp-relay",
				remoteOnline:     false,
				selfCandidates:   1,
				remoteCandidates: 1,
			},
		},
		{
			name: "missing candidate",
			in: punchDecision{
				state:            "ws-relay",
				remoteOnline:     true,
				selfCandidates:   1,
				remoteCandidates: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldBumpPunchEpoch(tt.in); got != tt.want {
				t.Fatalf("shouldBumpPunchEpoch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPunchEpochBackoffAndCap(t *testing.T) {
	srv := &server{punchEpochs: make(map[string]punchEpoch)}
	keyA, keyB := "a", "b"
	t0 := time.Now()

	// First bump lands immediately (no prior bumpedAt).
	srv.bumpPunchEpoch(keyA, keyB, t0)
	if got := srv.punchEpoch(keyA, keyB); got != 1 {
		t.Fatalf("epoch after first bump = %d, want 1", got)
	}

	// After attempt 1 the cooldown grows to 4m; a bump inside it is ignored.
	srv.bumpPunchEpoch(keyA, keyB, t0.Add(3*time.Minute))
	if got := srv.punchEpoch(keyA, keyB); got != 1 {
		t.Fatalf("epoch inside 4m cooldown = %d, want 1", got)
	}

	// Past 4m it bumps to 2 (next cooldown grows to 8m).
	srv.bumpPunchEpoch(keyA, keyB, t0.Add(5*time.Minute))
	if got := srv.punchEpoch(keyA, keyB); got != 2 {
		t.Fatalf("epoch after 4m cooldown = %d, want 2", got)
	}

	// Past 8m more it bumps to 3, spending the attempt budget.
	srv.bumpPunchEpoch(keyA, keyB, t0.Add(14*time.Minute))
	if got := srv.punchEpoch(keyA, keyB); got != 3 {
		t.Fatalf("epoch after third attempt = %d, want 3", got)
	}

	// Further bumps are refused once maxPunchAttempts is reached, however
	// long we wait — the pair settles on relay.
	srv.bumpPunchEpoch(keyA, keyB, t0.Add(1*time.Hour))
	if got := srv.punchEpoch(keyA, keyB); got != 3 {
		t.Fatalf("epoch past attempt cap = %d, want 3 (capped)", got)
	}

	// Reaching direct re-arms the budget; the epoch stays monotonic so a
	// stale high-water mark on an agent never suppresses the next signal.
	srv.resetPunchAttempts(keyA, keyB)
	srv.bumpPunchEpoch(keyA, keyB, t0.Add(2*time.Hour))
	if got := srv.punchEpoch(keyA, keyB); got != 4 {
		t.Fatalf("epoch after reset = %d, want 4", got)
	}
}

func TestRelayedReportEmitsPunchEpoch(t *testing.T) {
	srv, ts := newTestServer(t)
	setupKey, err := srv.store.CreateSetupKey(t.Context(), 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}
	self, _ := enrollPeerKey(t, ts, setupKey, "self")
	remote, remoteKey := enrollPeerKey(t, ts, setupKey, "remote")

	reportAs(t, ts, remote.AuthToken)

	report := proto.ReportRequest{
		PathStates: []proto.PeerPathState{{
			PeerPublicKey: remoteKey.PublicKey().String(),
			State:         "ws-relay",
		}},
	}
	body, _ := json.Marshal(report)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/report", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build report: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+self.AuthToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /report: %v", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("report status %d: %s", resp.StatusCode, raw)
	}

	var out proto.ReportResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode report response: %v", err)
	}
	if len(out.Peers) != 1 {
		t.Fatalf("sync peers = %d, want 1", len(out.Peers))
	}
	if out.Peers[0].PunchEpoch == 0 {
		t.Fatalf("PunchEpoch = 0, want nonzero in peer config: %+v", out.Peers[0])
	}
}
