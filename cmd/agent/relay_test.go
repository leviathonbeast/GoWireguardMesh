package main

import (
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gowireguard/internal/proto"
)

func TestMaybeRetryDirectIgnoresFreshRelay(t *testing.T) {
	key := wgtypes.Key{1}
	tel := &telemetryReporter{
		relayed:   map[wgtypes.Key]bool{key: true},
		relayedAt: map[wgtypes.Key]time.Time{key: time.Now()},
	}

	tel.maybeRetryDirect(key, []*net.UDPAddr{{IP: net.ParseIP("192.0.2.1"), Port: 51820}})

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

	tel.maybeRetryDirect(key, nil)

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
