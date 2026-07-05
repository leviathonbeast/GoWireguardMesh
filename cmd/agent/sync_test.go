package main

import (
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPeerNeedsUpdateWhenEndpointMissingAndNoHandshake(t *testing.T) {
	cur := wgtypes.Peer{}
	want := wgtypes.PeerConfig{PublicKey: wgtypes.Key{}, AllowedIPs: []net.IPNet{{IP: net.ParseIP("100.64.0.2"), Mask: net.CIDRMask(32, 32)}}}

	if !peerNeedsUpdate(cur, want) {
		t.Fatal("peerNeedsUpdate() should request an update when the peer has no endpoint and no handshake")
	}
}

func TestPeerNeedsUpdateWhenHandshakeRecorded(t *testing.T) {
	cur := wgtypes.Peer{LastHandshakeTime: time.Now(), AllowedIPs: []net.IPNet{{IP: net.ParseIP("100.64.0.2"), Mask: net.CIDRMask(32, 32)}}}
	want := wgtypes.PeerConfig{PublicKey: wgtypes.Key{}, AllowedIPs: []net.IPNet{{IP: net.ParseIP("100.64.0.2"), Mask: net.CIDRMask(32, 32)}}}

	if peerNeedsUpdate(cur, want) {
		t.Fatal("peerNeedsUpdate() should not request an update for a peer that already completed a handshake")
	}
}
