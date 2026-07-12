package main

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gowireguard/internal/proto"
)

type fakeWGBackend struct {
	device     *wgtypes.Device
	configured []wgtypes.Config
	err        error
}

func (f *fakeWGBackend) Device() (*wgtypes.Device, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.device == nil {
		return &wgtypes.Device{}, nil
	}
	return f.device, nil
}

func (f *fakeWGBackend) ConfigureDevice(cfg wgtypes.Config) error {
	if f.err != nil {
		return f.err
	}
	f.configured = append(f.configured, cfg)
	return nil
}

func (f *fakeWGBackend) Close() error { return nil }

func TestMaybeRetryDirectIgnoresFreshRelay(t *testing.T) {
	key := wgtypes.Key{1}
	tel := &telemetryReporter{
		relayed:   map[wgtypes.Key]bool{key: true},
		relayedAt: map[wgtypes.Key]time.Time{key: time.Now()},
	}

	tel.maybeRetryDirect(key, []*net.UDPAddr{{IP: net.ParseIP("192.0.2.1"), Port: 51820}}, 0)

	if !tel.relayed[key] {
		t.Fatal("maybeRetryDirect cleared a fresh relayed peer")
	}
}

func TestMaybeRetryDirectIgnoresMissingEndpoint(t *testing.T) {
	key := wgtypes.Key{1}
	tel := &telemetryReporter{
		relayed:   map[wgtypes.Key]bool{key: true},
		relayedAt: map[wgtypes.Key]time.Time{key: time.Now().Add(-directRetryAfter - time.Second)},
	}

	tel.maybeRetryDirect(key, nil, 0)

	if !tel.relayed[key] {
		t.Fatal("maybeRetryDirect cleared relayed peer without an endpoint")
	}
}

func TestMaybeRetryDirectDisabledKeepsRelayStable(t *testing.T) {
	key := wgtypes.Key{1}
	backend := &fakeWGBackend{}
	tel := &telemetryReporter{
		wg:             backend,
		relayed:        map[wgtypes.Key]bool{key: true},
		relayedAt:      map[wgtypes.Key]time.Time{key: time.Now().Add(-directRetryAfter - time.Second)},
		relayEndpoints: map[wgtypes.Key]*net.UDPAddr{key: {IP: net.ParseIP("127.0.0.1"), Port: 40000}},
		directProbes:   map[wgtypes.Key]directProbe{},
		directProbeOff: true,
	}

	tel.maybeRetryDirect(key, []*net.UDPAddr{{IP: net.ParseIP("192.0.2.1"), Port: 51820}}, 99)

	if _, ok := tel.directProbes[key]; ok {
		t.Fatal("direct probe started even though direct probing is disabled")
	}
	if len(backend.configured) != 0 {
		t.Fatalf("ConfigureDevice called %d times, want 0", len(backend.configured))
	}
}

func TestEndpointCandidatesFromProtoKeepsOrderAndDedupes(t *testing.T) {
	fallback := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 51820}

	got := endpointCandidatesFromProto(proto.PeerConfigResponse{
		EndpointCandidates: []proto.EndpointCandidate{
			{Endpoint: "203.0.113.10:51820", Type: "stun", Priority: 100},
			{Endpoint: "203.0.113.10:51820", Type: "stun", Priority: 100},
			{Endpoint: "192.0.2.10:51820", Type: "lan", Priority: 80},
		},
	}, fallback)

	if len(got) != 2 {
		t.Fatalf("endpointCandidatesFromProto returned %d candidates, want 2", len(got))
	}
	if got[0].String() != "203.0.113.10:51820" || got[1].String() != "192.0.2.10:51820" {
		t.Fatalf("candidate order = %v, want stun then lan", got)
	}
}

func TestDirectSilentForUsesRecentInbound(t *testing.T) {
	key := wgtypes.Key{1}
	now := time.Now()
	tel := &telemetryReporter{
		firstSeen:   map[wgtypes.Key]time.Time{key: now.Add(-10 * time.Minute)},
		lastInbound: map[wgtypes.Key]time.Time{key: now.Add(-10 * time.Second)},
	}

	peer := wgtypes.Peer{
		PublicKey:         key,
		LastHandshakeTime: now.Add(-200 * time.Second),
	}

	if got := tel.directSilentFor(peer, now); got >= directStaleAfter {
		t.Fatalf("directSilentFor with recent inbound = %s, want under %s", got, directStaleAfter)
	}
}

func TestDirectSilentForDetectsSilentEstablishedPeer(t *testing.T) {
	key := wgtypes.Key{1}
	now := time.Now()
	tel := &telemetryReporter{
		firstSeen:   map[wgtypes.Key]time.Time{key: now.Add(-10 * time.Minute)},
		lastInbound: map[wgtypes.Key]time.Time{key: now.Add(-200 * time.Second)},
	}

	peer := wgtypes.Peer{
		PublicKey:         key,
		LastHandshakeTime: now.Add(-200 * time.Second),
	}

	if got := tel.directSilentFor(peer, now); got < directStaleAfter {
		t.Fatalf("directSilentFor silent established peer = %s, want at least %s", got, directStaleAfter)
	}
}

func TestDirectSilentForEstablishingPeer(t *testing.T) {
	key := wgtypes.Key{1}
	now := time.Now()
	tel := &telemetryReporter{
		firstSeen:   map[wgtypes.Key]time.Time{key: now.Add(-directStaleAfter - time.Second)},
		lastInbound: map[wgtypes.Key]time.Time{},
	}

	if got := tel.directSilentFor(wgtypes.Peer{PublicKey: key}, now); got < directStaleAfter {
		t.Fatalf("directSilentFor old establishing peer = %s, want at least %s", got, directStaleAfter)
	}

	tel.firstSeen[key] = now.Add(-directStaleAfter + time.Second)
	if got := tel.directSilentFor(wgtypes.Peer{PublicKey: key}, now); got >= directStaleAfter {
		t.Fatalf("directSilentFor fresh establishing peer = %s, want under %s", got, directStaleAfter)
	}
}

func TestDirectProbeRequiresLaterInboundBeforePromotion(t *testing.T) {
	key := wgtypes.Key{1}
	started := time.Now().Add(-5 * time.Second)
	direct := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51820}
	relay := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	tel := &telemetryReporter{
		wg:              &fakeWGBackend{},
		directProbes:    map[wgtypes.Key]directProbe{key: {started: started, relayEndpoint: relay, interval: time.Minute}},
		relayed:         map[wgtypes.Key]bool{key: true},
		relayedAt:       map[wgtypes.Key]time.Time{key: started},
		relayEndpoints:  map[wgtypes.Key]*net.UDPAddr{key: relay},
		lastInbound:     map[wgtypes.Key]time.Time{key: started},
		firstSeen:       map[wgtypes.Key]time.Time{},
		directFailures:  map[wgtypes.Key]int{},
		lastCandidates:  map[wgtypes.Key]string{},
		pathKinds:       map[wgtypes.Key]string{key: "quic-relay"},
		quicUnavailable: map[wgtypes.Key]bool{},
		wsProxies:       map[wgtypes.Key]*wsRelayProxy{},
		quicProxies:     map[wgtypes.Key]*quicRelayProxy{},
	}
	peer := wgtypes.Peer{PublicKey: key, Endpoint: direct, LastHandshakeTime: started.Add(time.Second)}

	confirmed := time.Now()
	tel.checkDirectProbe(peer, confirmed)
	probe := tel.directProbes[key]
	if probe.confirmedAt.IsZero() {
		t.Fatal("direct handshake did not start probation")
	}
	if !tel.relayed[key] {
		t.Fatal("single handshake prematurely left relay")
	}

	stableAt := confirmed.Add(directProbationMin + time.Second)
	tel.lastInbound[key] = stableAt
	tel.checkDirectProbe(peer, stableAt)
	if tel.relayed[key] {
		t.Fatal("later inbound traffic did not promote stable direct path")
	}
	if _, probing := tel.directProbes[key]; probing {
		t.Fatal("stable direct path remained in probation")
	}
}

func TestDirectProbationTimeoutRestoresRelay(t *testing.T) {
	key := wgtypes.Key{1}
	relay := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	confirmed := time.Now().Add(-directProbationTimeout - time.Second)
	backend := &fakeWGBackend{}
	tel := &telemetryReporter{
		wg:             backend,
		directProbes:   map[wgtypes.Key]directProbe{key: {started: confirmed, confirmedAt: confirmed, relayEndpoint: relay}},
		relayed:        map[wgtypes.Key]bool{key: true},
		relayedAt:      map[wgtypes.Key]time.Time{},
		lastInbound:    map[wgtypes.Key]time.Time{key: confirmed},
		directFailures: map[wgtypes.Key]int{},
	}

	tel.checkDirectProbe(wgtypes.Peer{
		PublicKey: key,
		Endpoint:  &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51820},
	}, time.Now())

	if len(backend.configured) != 1 || backend.configured[0].Peers[0].Endpoint.String() != relay.String() {
		t.Fatalf("probation timeout did not restore relay endpoint: %+v", backend.configured)
	}
	if _, probing := tel.directProbes[key]; probing {
		t.Fatal("timed-out probation remained active")
	}
}

func TestPunchEpochStartsFastProbe(t *testing.T) {
	key := wgtypes.Key{1}
	relay := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	candidate := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51820}
	backend := &fakeWGBackend{}
	tel := &telemetryReporter{
		wg:             backend,
		relayed:        map[wgtypes.Key]bool{key: true},
		relayedAt:      map[wgtypes.Key]time.Time{key: time.Now()},
		relayEndpoints: map[wgtypes.Key]*net.UDPAddr{key: relay},
		directProbes:   map[wgtypes.Key]directProbe{},
		lastPunchEpoch: map[wgtypes.Key]int{},
	}

	tel.maybeRetryDirect(key, []*net.UDPAddr{candidate}, 7)

	probe, ok := tel.directProbes[key]
	if !ok {
		t.Fatal("expected punch epoch to start a direct probe")
	}
	if probe.interval != coordinatedProbeInterval {
		t.Fatalf("probe interval = %s, want %s", probe.interval, coordinatedProbeInterval)
	}
	if probe.interval < 5*time.Second {
		t.Fatalf("probe interval = %s, want at least WireGuard handshake retry", probe.interval)
	}
	if time.Until(probe.deadline) > coordinatedProbeWindow || probe.deadline.IsZero() {
		t.Fatalf("probe deadline = %v, want bounded window around %s", probe.deadline, coordinatedProbeWindow)
	}
	if len(backend.configured) != 1 {
		t.Fatalf("ConfigureDevice called %d times, want 1", len(backend.configured))
	}
	if got := backend.configured[0].Peers[0].Endpoint.String(); got != candidate.String() {
		t.Fatalf("configured endpoint = %s, want %s", got, candidate)
	}
}

func TestPunchEpochDoesNotStartWithoutBackendApply(t *testing.T) {
	key := wgtypes.Key{1}
	tel := &telemetryReporter{
		wg:             &fakeWGBackend{err: errors.New("boom")},
		relayed:        map[wgtypes.Key]bool{key: true},
		relayedAt:      map[wgtypes.Key]time.Time{key: time.Now()},
		relayEndpoints: map[wgtypes.Key]*net.UDPAddr{key: {IP: net.ParseIP("127.0.0.1"), Port: 40000}},
		directProbes:   map[wgtypes.Key]directProbe{},
		lastPunchEpoch: map[wgtypes.Key]int{},
	}

	tel.maybeRetryDirect(key, []*net.UDPAddr{{IP: net.ParseIP("192.0.2.1"), Port: 51820}}, 1)

	if _, ok := tel.directProbes[key]; ok {
		t.Fatal("direct probe was stored even though endpoint apply failed")
	}
}

func TestDirectRetryIntervalBacksOff(t *testing.T) {
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{0, directRetryAfter},
		{1, 10 * time.Minute},
		{2, 20 * time.Minute},
		{3, 30 * time.Minute},
		{9, 30 * time.Minute},
	}

	for _, c := range cases {
		if got := directRetryInterval(c.failures); got != c.want {
			t.Fatalf("directRetryInterval(%d) = %s, want %s", c.failures, got, c.want)
		}
	}
}

func TestMaybeRetryDirectBackoffAndCandidateReset(t *testing.T) {
	key := wgtypes.Key{1}
	cand := []*net.UDPAddr{{IP: net.ParseIP("192.0.2.1"), Port: 51820}}

	// Two prior failures back the retry interval off to 20m; a peer relayed
	// only 6m ago must therefore NOT be probed yet (the thrash fix).
	tel := &telemetryReporter{
		relayed:        map[wgtypes.Key]bool{key: true},
		relayedAt:      map[wgtypes.Key]time.Time{key: time.Now().Add(-6 * time.Minute)},
		directProbes:   map[wgtypes.Key]directProbe{},
		directFailures: map[wgtypes.Key]int{key: 2},
		lastCandidates: map[wgtypes.Key]string{key: candidateDigest(cand)},
	}

	tel.maybeRetryDirect(key, cand, 0)
	if _, probing := tel.directProbes[key]; probing {
		t.Fatal("backed-off peer was probed before its interval elapsed")
	}

	// A new candidate set clears the failure count, re-arming a prompt retry
	// even though the relay is still recent.
	tel.wg = &fakeWGBackend{}
	tel.relayEndpoints = map[wgtypes.Key]*net.UDPAddr{key: {IP: net.ParseIP("127.0.0.1"), Port: 40000}}
	newCand := []*net.UDPAddr{{IP: net.ParseIP("198.51.100.9"), Port: 51820}}

	tel.maybeRetryDirect(key, newCand, 0)
	if tel.directFailures[key] != 0 {
		t.Fatalf("candidate change did not reset failures: got %d", tel.directFailures[key])
	}
	if _, probing := tel.directProbes[key]; !probing {
		t.Fatal("new candidate set did not re-arm a prompt direct probe")
	}
}
