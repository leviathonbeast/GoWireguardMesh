package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
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

func TestEndpointCandidatesSameNATPrefersHostAddresses(t *testing.T) {
	self := store.PeerRow{PublicEndpoint: "203.0.113.1:51820"}
	peer := store.PeerRow{
		PublicEndpoint: "203.0.113.1:51821",
		ObservedIP:     "203.0.113.1", // VPS control plane: observed = shared WAN
		ListenPort:     51820,
		CandidatesJSON: `[{"endpoint":"192.168.1.20:51820","type":"host"},` +
			`{"endpoint":"[2001:db8::20]:51820","type":"host6"},` +
			`{"endpoint":"203.0.113.1:60000","type":"upnp"}]`,
	}

	got := endpointCandidates(self, peer)

	wantOrder := []string{"host", "lan", "host6", "stun", "upnp"}
	if len(got) != len(wantOrder) {
		t.Fatalf("candidates = %+v, want %d entries", got, len(wantOrder))
	}
	for i, typ := range wantOrder {
		if got[i].Type != typ {
			t.Fatalf("candidate[%d].Type = %q, want %q (%+v)", i, got[i].Type, typ, got)
		}
	}
	if got[0].Endpoint != "192.168.1.20:51820" {
		t.Fatalf("first candidate = %q, want the host address", got[0].Endpoint)
	}
}

func TestEndpointCandidatesCrossNAT(t *testing.T) {
	self := store.PeerRow{
		PublicEndpoint: "198.51.100.7:51820",
		CandidatesJSON: `[{"endpoint":"10.9.8.7:51820","type":"host"}]`,
	}
	peer := store.PeerRow{
		PublicEndpoint: "203.0.113.1:51821",
		ObservedIP:     "203.0.113.1",
		ListenPort:     51820,
		CandidatesJSON: `[{"endpoint":"192.168.1.20:51820","type":"host"},` +
			`{"endpoint":"[2001:db8::20]:51820","type":"host6"},` +
			`{"endpoint":"203.0.113.1:60000","type":"upnp"}]`,
	}

	got := endpointCandidates(self, peer)

	// Private host addresses on a DIFFERENT subnet than self never make
	// the list across NATs; the rest ranks upnp > stun > host6 > lan.
	wantOrder := []string{"upnp", "stun", "host6", "lan"}
	if len(got) != len(wantOrder) {
		t.Fatalf("candidates = %+v, want %d entries", got, len(wantOrder))
	}
	for i, typ := range wantOrder {
		if got[i].Type != typ {
			t.Fatalf("candidate[%d].Type = %q, want %q (%+v)", i, got[i].Type, typ, got)
		}
	}
}

func TestEndpointCandidatesCrossNATSameSubnetKeepsHost(t *testing.T) {
	self := store.PeerRow{
		PublicEndpoint: "198.51.100.7:51820",
		CandidatesJSON: `[{"endpoint":"192.168.1.9:51820","type":"host"}]`,
	}
	peer := store.PeerRow{
		PublicEndpoint: "203.0.113.1:51821",
		CandidatesJSON: `[{"endpoint":"192.168.1.20:51820","type":"host"}]`,
	}

	got := endpointCandidates(self, peer)
	if len(got) != 2 {
		t.Fatalf("candidates = %+v, want host + stun", got)
	}
	// Shared /24 despite different WAN IPs: the host address wins.
	if got[0].Type != "host" || got[0].Endpoint != "192.168.1.20:51820" {
		t.Fatalf("first candidate = %+v, want same-subnet host", got[0])
	}
}

func TestEncodeAgentCandidatesValidates(t *testing.T) {
	in := []proto.AgentCandidate{
		{Endpoint: "192.168.1.20:51820", Type: "host"},
		{Endpoint: "not an endpoint", Type: "host"},   // unparseable: dropped
		{Endpoint: "192.168.1.21:51820", Type: "lan"}, // server-owned type: dropped
		{Endpoint: "[2001:db8::1]:51820", Type: "host6"},
	}

	out := encodeAgentCandidates(in)
	got := agentCandidates(store.PeerRow{CandidatesJSON: out})
	if len(got) != 2 {
		t.Fatalf("kept %d candidates (%s), want 2", len(got), out)
	}
	if got[0].Endpoint != "192.168.1.20:51820" || got[1].Type != "host6" {
		t.Fatalf("kept = %+v", got)
	}

	if encodeAgentCandidates(nil) != "" {
		t.Fatal("empty input should encode to empty string")
	}

	var many []proto.AgentCandidate
	for i := 0; i < 20; i++ {
		many = append(many, proto.AgentCandidate{Endpoint: "10.0.0.1:1", Type: "host"})
	}
	if got := agentCandidates(store.PeerRow{CandidatesJSON: encodeAgentCandidates(many)}); len(got) > maxAgentCandidates {
		t.Fatalf("kept %d candidates, want <= %d", len(got), maxAgentCandidates)
	}
}

// fakeRelay implements relayAllocator with canned observed mappings.
type fakeRelay struct {
	srcA, srcB netip.AddrPort
	ok         bool
}

func (f fakeRelay) allocate(string) (int, int, error) { return 1, 2, nil }
func (f fakeRelay) observed(string) (netip.AddrPort, netip.AddrPort, bool) {
	return f.srcA, f.srcB, f.ok
}

func TestPairCandidatesIncludesRelayObserved(t *testing.T) {
	srv := &server{relay: fakeRelay{
		srcA: netip.MustParseAddrPort("198.51.100.7:41000"),
		srcB: netip.MustParseAddrPort("203.0.113.1:42000"),
		ok:   true,
	}}

	// Keys: self="a" < p="b", so p's packets latch on leg B.
	self := store.PeerRow{PublicKey: "a", PublicEndpoint: "198.51.100.7:51820"}
	p := store.PeerRow{PublicKey: "b", PublicEndpoint: "203.0.113.1:51821"}

	got := srv.pairCandidates(self, p)
	if len(got) != 2 {
		t.Fatalf("candidates = %+v, want stun + relay", got)
	}
	if got[0].Type != "relay" || got[0].Endpoint != "203.0.113.1:42000" {
		t.Fatalf("first candidate = %+v, want relay-observed leg B first (fresher than stun)", got[0])
	}
	if got[1].Type != "stun" {
		t.Fatalf("second candidate = %+v, want stun", got[1])
	}

	// Dedupe: when the relay sees exactly the STUN endpoint, no extra
	// candidate appears.
	p2 := store.PeerRow{PublicKey: "b", PublicEndpoint: "203.0.113.1:42000"}
	if got := srv.pairCandidates(self, p2); len(got) != 1 {
		t.Fatalf("candidates = %+v, want deduped single entry", got)
	}

	// No relay configured: plain endpointCandidates result.
	bare := &server{}
	if got := bare.pairCandidates(self, p); len(got) != 1 || got[0].Type != "stun" {
		t.Fatalf("bare candidates = %+v, want stun only", got)
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
	online, age := peerHealth(time.Now().UTC().Add(-30*time.Second).Format(time.RFC3339Nano), "", "agent")
	if online != "online" || age < 0 {
		t.Fatalf("peerHealth(30s ago) = %q, %d; want online", online, age)
	}

	stale, _ := peerHealth(time.Now().UTC().Add(-2*time.Minute).Format(time.RFC3339Nano), "", "agent")
	if stale != "stale" {
		t.Fatalf("peerHealth(2m ago) = %q, want stale", stale)
	}

	offline, _ := peerHealth(time.Now().UTC().Add(-10*time.Minute).Format(time.RFC3339Nano), "", "agent")
	if offline != "offline" {
		t.Fatalf("peerHealth(10m ago) = %q, want offline", offline)
	}

	revoked, _ := peerHealth(time.Now().UTC().Format(time.RFC3339Nano), "revoked", "static")
	if revoked != "revoked" {
		t.Fatalf("peerHealth(revoked) = %q, want revoked", revoked)
	}

	static, _ := peerHealth("", "", "static")
	if static != "static" {
		t.Fatalf("peerHealth(static) = %q, want static", static)
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
		{
			name: "hard-hard cannot punch",
			in: punchDecision{
				state:            "ws-relay",
				remoteOnline:     true,
				selfCandidates:   1,
				remoteCandidates: 1,
				selfNAT:          "hard",
				remoteNAT:        "hard",
			},
		},
		{
			name: "hard-easy still tries",
			in: punchDecision{
				state:            "ws-relay",
				remoteOnline:     true,
				selfCandidates:   1,
				remoteCandidates: 1,
				selfNAT:          "hard",
				remoteNAT:        "easy",
			},
			want: true,
		},
		{
			name: "hard-unknown gets benefit of the doubt",
			in: punchDecision{
				state:            "ws-relay",
				remoteOnline:     true,
				selfCandidates:   1,
				remoteCandidates: 1,
				selfNAT:          "hard",
			},
			want: true,
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
