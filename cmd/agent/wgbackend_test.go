package main

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustKey(t *testing.T, b []byte) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.NewKey(b)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

// fixedKey returns a deterministic key filled with byte v, plus its hex.
func fixedKey(t *testing.T, v byte) (wgtypes.Key, string) {
	t.Helper()
	b := make([]byte, 32)
	for i := range b {
		b[i] = v
	}
	return mustKey(t, b), hex.EncodeToString(b)
}

// TestBuildIPCSetNeverEmitsBlankLine is the guard for the bug that made
// the old buildIPCConfig configure only the first peer: IpcSetOperation
// stops at the first blank line, so a multi-peer config must contain
// none.
func TestBuildIPCSetNeverEmitsBlankLine(t *testing.T) {
	k1, _ := fixedKey(t, 0x11)
	k2, _ := fixedKey(t, 0x22)
	priv, _ := fixedKey(t, 0x01)
	port := 51820
	ka := 25 * time.Second

	_, ipnet, _ := net.ParseCIDR("100.64.0.2/32")

	out := buildIPCSet(wgtypes.Config{
		PrivateKey:   &priv,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{PublicKey: k1, Endpoint: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 51820}, PersistentKeepaliveInterval: &ka, AllowedIPs: []net.IPNet{*ipnet}},
			{PublicKey: k2, AllowedIPs: []net.IPNet{*ipnet}},
		},
	})

	if strings.Contains(out, "\n\n") {
		t.Fatalf("buildIPCSet emitted a blank line (terminates IpcSet):\n%q", out)
	}
	if strings.Count(out, "public_key=") != 2 {
		t.Fatalf("expected 2 peers in output, got:\n%s", out)
	}
	// Device directives must precede the first peer.
	if strings.Index(out, "listen_port=") > strings.Index(out, "public_key=") {
		t.Fatalf("device directives must come before peers:\n%s", out)
	}
}

func TestBuildIPCSetIncrementalEndpointOnly(t *testing.T) {
	k, _ := fixedKey(t, 0x33)

	out := buildIPCSet(wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  k,
			UpdateOnly: true,
			Endpoint:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
		}},
	})

	for _, want := range []string{"update_only=true", "endpoint=127.0.0.1:40000"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"replace_peers", "allowed_ip", "private_key"} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("unexpected %q in incremental update:\n%s", unwanted, out)
		}
	}
}

func TestBuildIPCSetRemove(t *testing.T) {
	k, _ := fixedKey(t, 0x44)

	out := buildIPCSet(wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey: k,
			Remove:    true,
			Endpoint:  &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 1}, // must be ignored
		}},
	})

	if !strings.Contains(out, "remove=true") {
		t.Fatalf("missing remove=true:\n%s", out)
	}
	if strings.Contains(out, "endpoint=") {
		t.Fatalf("a removed peer must carry no other attributes:\n%s", out)
	}
}

// TestParseUAPIHandshakeZeroStaysZero pins the behavior relay fallback
// depends on: a peer that never handshook has LastHandshakeTime.IsZero()
// == true. time.Unix(0,0) is NOT zero, so the parser must special-case it.
func TestParseUAPIHandshakeZeroStaysZero(t *testing.T) {
	_, hexNever := fixedKey(t, 0x55)
	_, hexLive := fixedKey(t, 0x66)

	conf := strings.Join([]string{
		"private_key=" + strings.Repeat("00", 32),
		"listen_port=51820",
		"public_key=" + hexNever,
		"last_handshake_time_sec=0",
		"last_handshake_time_nsec=0",
		"rx_bytes=0",
		"tx_bytes=0",
		"public_key=" + hexLive,
		"last_handshake_time_sec=1700000000",
		"last_handshake_time_nsec=500",
		"rx_bytes=2048",
		"tx_bytes=1024",
		"",
	}, "\n")

	dev, err := parseUAPI(conf)
	if err != nil {
		t.Fatalf("parseUAPI: %v", err)
	}
	if len(dev.Peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(dev.Peers))
	}
	if !dev.Peers[0].LastHandshakeTime.IsZero() {
		t.Fatalf("never-handshook peer has non-zero handshake %v", dev.Peers[0].LastHandshakeTime)
	}
	if dev.Peers[1].LastHandshakeTime.IsZero() {
		t.Fatal("handshook peer reported zero handshake")
	}
	if dev.Peers[1].ReceiveBytes != 2048 || dev.Peers[1].TransmitBytes != 1024 {
		t.Fatalf("counters = rx %d tx %d, want 2048/1024", dev.Peers[1].ReceiveBytes, dev.Peers[1].TransmitBytes)
	}
	if dev.ListenPort != 51820 {
		t.Fatalf("listen_port = %d, want 51820", dev.ListenPort)
	}
}

// TestUAPIRoundTripThroughRealDevice is the strongest check: it drives a
// real in-process wireguard-go device (the same one the Windows agent
// embeds) with buildIPCSet, reads it back with IpcGet, and parses it —
// exercising the actual UAPI, not assumptions about its format.
func TestUAPIRoundTripThroughRealDevice(t *testing.T) {
	tun := tuntest.NewChannelTUN()
	dev := device.NewDevice(tun.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "test: "))
	t.Cleanup(dev.Close)

	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	peer1, _ := wgtypes.GeneratePrivateKey()
	peer2, _ := wgtypes.GeneratePrivateKey()
	psk, _ := wgtypes.GenerateKey()

	port := 0
	ka := 25 * time.Second
	_, ip1, _ := net.ParseCIDR("100.64.0.2/32")
	_, ip1b, _ := net.ParseCIDR("fd00:100:64::2/128")
	_, ip2, _ := net.ParseCIDR("100.64.0.3/32")

	cfg := wgtypes.Config{
		PrivateKey:   &priv,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:                   peer1.PublicKey(),
				PresharedKey:                &psk,
				Endpoint:                    &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51820},
				PersistentKeepaliveInterval: &ka,
				AllowedIPs:                  []net.IPNet{*ip1, *ip1b},
			},
			{
				PublicKey:  peer2.PublicKey(),
				AllowedIPs: []net.IPNet{*ip2},
			},
		},
	}

	if err := dev.IpcSet(buildIPCSet(cfg)); err != nil {
		t.Fatalf("IpcSet(buildIPCSet): %v", err)
	}

	raw, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}

	got, err := parseUAPI(raw)
	if err != nil {
		t.Fatalf("parseUAPI: %v", err)
	}

	// Both peers must survive (the multi-peer regression).
	if len(got.Peers) != 2 {
		t.Fatalf("round-trip yielded %d peers, want 2:\n%s", len(got.Peers), raw)
	}

	byKey := map[wgtypes.Key]wgtypes.Peer{}
	for _, p := range got.Peers {
		byKey[p.PublicKey] = p
	}

	p1, ok := byKey[peer1.PublicKey()]
	if !ok {
		t.Fatal("peer1 missing after round-trip")
	}
	if p1.Endpoint == nil || p1.Endpoint.String() != "203.0.113.7:51820" {
		t.Fatalf("peer1 endpoint = %v, want 203.0.113.7:51820", p1.Endpoint)
	}
	if p1.PresharedKey != psk {
		t.Fatal("peer1 preshared key did not round-trip")
	}
	if p1.PersistentKeepaliveInterval != ka {
		t.Fatalf("peer1 keepalive = %v, want %v", p1.PersistentKeepaliveInterval, ka)
	}
	if len(p1.AllowedIPs) != 2 {
		t.Fatalf("peer1 allowed IPs = %d, want 2 (dual-stack)", len(p1.AllowedIPs))
	}

	if _, ok := byKey[peer2.PublicKey()]; !ok {
		t.Fatal("peer2 missing after round-trip")
	}
}
