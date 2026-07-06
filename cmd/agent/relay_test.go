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
