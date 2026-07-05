package main

import (
	"net"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The interface address must carry the NETWORK prefix, not /32: its
// connected route is the only thing steering overlay traffic into
// wg-int. A /32 here left the kernel with no route to other peers,
// so pings to 100.64.0.x leaked out the LAN with an underlay source
// address and the tunnel never carried a packet.
func TestOverlayAddressUsesNetworkPrefix(t *testing.T) {
	network := netip.MustParsePrefix("100.64.0.0/16")

	got, err := overlayAddress("100.64.0.7", network)
	if err != nil {
		t.Fatalf("overlayAddress returned error: %v", err)
	}

	want := "100.64.0.7/16"
	if got != want {
		t.Fatalf("overlayAddress() = %q, want %q", got, want)
	}
}

func TestOverlayAddressRejectsGarbage(t *testing.T) {
	network := netip.MustParsePrefix("100.64.0.0/16")

	if _, err := overlayAddress("not-an-ip", network); err == nil {
		t.Fatal("overlayAddress accepted a non-IP address")
	}
}

func TestResolveListenPortAutoSelectsFreePort(t *testing.T) {
	port, err := resolveListenPort(0, "")
	if err != nil {
		t.Fatalf("resolveListenPort(0) returned error: %v", err)
	}
	if port <= 0 || port > 65535 {
		t.Fatalf("resolveListenPort(0) returned invalid port %d", port)
	}
}

func TestEffectiveListenPortUsesResolvedPort(t *testing.T) {
	if got := effectiveListenPort(0, 51820); got != 51820 {
		t.Fatalf("effectiveListenPort(0, 51820) = %d, want 51820", got)
	}
}

func TestEffectiveListenPortFallsBackToFlagPort(t *testing.T) {
	if got := effectiveListenPort(51821, 0); got != 51821 {
		t.Fatalf("effectiveListenPort(51821, 0) = %d, want 51821", got)
	}
}

func TestBuildPeerConfigAcceptsIPv6AllowedIP(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() returned error: %v", err)
	}

	cfg, err := buildPeerConfig(
		key.PublicKey().String(),
		"",
		"100.64.0.2/32",
		"fd00:100:64::2/128",
		"",
	)
	if err != nil {
		t.Fatalf("buildPeerConfig() returned error: %v", err)
	}

	want := []net.IPNet{
		{IP: net.ParseIP("100.64.0.2"), Mask: net.CIDRMask(32, 32)},
		{IP: net.ParseIP("fd00:100:64::2"), Mask: net.CIDRMask(128, 128)},
	}

	if len(cfg.AllowedIPs) != len(want) {
		t.Fatalf("AllowedIPs = %#v, want %#v", cfg.AllowedIPs, want)
	}
	for i := range want {
		if cfg.AllowedIPs[i].String() != want[i].String() {
			t.Fatalf("AllowedIPs[%d] = %q, want %q", i, cfg.AllowedIPs[i].String(), want[i].String())
		}
	}
}
