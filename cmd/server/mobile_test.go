package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gowireguard/internal/proto"
	"gowireguard/internal/store"
)

func TestCreateMobilePeerReturnsImportableConfig(t *testing.T) {
	srv, ts := newTestServer(t)

	setupKey, err := srv.store.CreateSetupKey(context.Background(), 1, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}
	_, gatewayKey := enrollPeerKey(t, ts, setupKey, "gateway")

	if _, err := srv.store.UpdateDNSConfig(context.Background(), store.DNSConfig{
		Enabled:     true,
		MagicDNS:    true,
		Domain:      "vpn",
		Nameservers: []string{"100.64.0.7", "fd00:100:64::7"},
	}); err != nil {
		t.Fatalf("UpdateDNSConfig: %v", err)
	}

	mobileKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}

	status, body := adminDo(t, ts, http.MethodPost, "/api/mobile-peers", map[string]any{
		"name":               "iphone",
		"private_key":        mobileKey.String(),
		"gateway_public_key": gatewayKey.PublicKey().String(),
		"gateway_endpoint":   "mesh.example.com:51820",
	})
	if status != http.StatusOK {
		t.Fatalf("POST /api/mobile-peers status = %d: %s", status, body)
	}

	var out mobilePeerResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode mobile response: %v", err)
	}

	if out.Peer.Hostname != "iphone" {
		t.Fatalf("hostname = %q, want iphone", out.Peer.Hostname)
	}
	if out.Peer.PeerType != "static" || out.Peer.HealthStatus != "static" {
		t.Fatalf("peer type/status = %q/%q, want static/static", out.Peer.PeerType, out.Peer.HealthStatus)
	}
	for _, want := range []string{
		"[Interface]",
		"PrivateKey = " + mobileKey.String(),
		"Address = 100.64.0.2/32, fd00:100:64::2/128",
		"DNS = 100.64.0.7, fd00:100:64::7",
		"[Peer]",
		"PublicKey = " + gatewayKey.PublicKey().String(),
		"Endpoint = mesh.example.com:51820",
		"AllowedIPs = 100.64.0.0/16, fd00:100:64::/64",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(out.Config, want) {
			t.Fatalf("mobile config missing %q:\n%s", want, out.Config)
		}
	}
	if out.PresharedKey == "" || !strings.Contains(out.Config, "PresharedKey = "+out.PresharedKey) {
		t.Fatalf("response/config did not include pair PSK")
	}
}

// TestMobilePeerRoutedViaGateway verifies the route-based (no-NAT) data
// plane: every other agent learns the mobile's /32 folded into its gateway
// peer's AllowedIPs, while the gateway itself gets the mobile as a real
// WireGuard peer plus a GatewayRoutes forwarding hint. This is what keeps
// the mobile's overlay source IP intact end-to-end.
func TestMobilePeerRoutedViaGateway(t *testing.T) {
	srv, ts := newTestServer(t)

	setupKey, err := srv.store.CreateSetupKey(context.Background(), 3, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}
	gwEnroll, gatewayKey := enrollPeerKey(t, ts, setupKey, "gateway")
	otherEnroll, _ := enrollPeerKey(t, ts, setupKey, "other")

	status, body := adminDo(t, ts, http.MethodPost, "/api/mobile-peers", map[string]any{
		"name":               "iphone",
		"gateway_public_key": gatewayKey.PublicKey().String(),
		"gateway_endpoint":   "mesh.example.com:51820",
	})
	if status != http.StatusOK {
		t.Fatalf("POST /api/mobile-peers status = %d: %s", status, body)
	}
	var mobile mobilePeerResponse
	if err := json.Unmarshal(body, &mobile); err != nil {
		t.Fatalf("decode mobile response: %v", err)
	}
	mobile32 := mobile.Peer.AssignedIP + "/32"
	mobile128 := mobile.Peer.AssignedIP6 + "/128"

	// The gateway agent: mobile is its own WireGuard peer (no endpoint),
	// and GatewayRoutes tells it to forward the mobile's /32 without NAT.
	gwSync := reportAs(t, ts, gwEnroll.AuthToken)
	if !containsAll(gwSync.GatewayRoutes, mobile32, mobile128) {
		t.Fatalf("gateway GatewayRoutes = %v, want %s and %s", gwSync.GatewayRoutes, mobile32, mobile128)
	}
	mobileEntry := findPeer(gwSync.Peers, mobile.Peer.PublicKey)
	if mobileEntry == nil {
		t.Fatalf("gateway sync missing mobile peer %s: %+v", mobile.Peer.PublicKey, gwSync.Peers)
	}
	if mobileEntry.Endpoint != nil || len(mobileEntry.EndpointCandidates) > 0 {
		t.Fatalf("mobile peer should have no endpoint hint (it roams in), got %+v", mobileEntry)
	}
	if !containsAll(mobileEntry.AllowedIPs, mobile32, mobile128) {
		t.Fatalf("mobile peer AllowedIPs = %v, want %s and %s", mobileEntry.AllowedIPs, mobile32, mobile128)
	}

	// Any other agent: the mobile is NOT a standalone peer; its /32 rides
	// the gateway peer's AllowedIPs, and this agent is not a gateway.
	otherSync := reportAs(t, ts, otherEnroll.AuthToken)
	if len(otherSync.GatewayRoutes) != 0 {
		t.Fatalf("non-gateway agent GatewayRoutes = %v, want empty", otherSync.GatewayRoutes)
	}
	if findPeer(otherSync.Peers, mobile.Peer.PublicKey) != nil {
		t.Fatalf("non-gateway agent should not see the mobile as its own peer")
	}
	gwPeer := findPeer(otherSync.Peers, gatewayKey.PublicKey().String())
	if gwPeer == nil {
		t.Fatalf("non-gateway agent missing the gateway peer")
	}
	if !containsAll(gwPeer.AllowedIPs, mobile32, mobile128) {
		t.Fatalf("gateway peer AllowedIPs = %v, must include the routed mobile %s and %s", gwPeer.AllowedIPs, mobile32, mobile128)
	}
}

func findPeer(peers []proto.PeerConfigResponse, publicKey string) *proto.PeerConfigResponse {
	for i := range peers {
		if peers[i].PublicKey == publicKey {
			return &peers[i]
		}
	}
	return nil
}

func containsAll(haystack []string, needles ...string) bool {
	for _, n := range needles {
		found := false
		for _, h := range haystack {
			if h == n {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestCreateMobilePeerCanGeneratePrivateKey(t *testing.T) {
	srv, ts := newTestServer(t)

	setupKey, err := srv.store.CreateSetupKey(context.Background(), 1, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}
	_, gatewayKey := enrollPeerKey(t, ts, setupKey, "gateway")

	status, body := adminDo(t, ts, http.MethodPost, "/api/mobile-peers", map[string]any{
		"name":               "android",
		"gateway_public_key": gatewayKey.PublicKey().String(),
		"gateway_endpoint":   "mesh.example.com:51820",
	})
	if status != http.StatusOK {
		t.Fatalf("POST /api/mobile-peers status = %d: %s", status, body)
	}

	var out mobilePeerResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode mobile response: %v", err)
	}
	if out.PrivateKey == "" || !strings.Contains(out.Config, "PrivateKey = "+out.PrivateKey) {
		t.Fatalf("generated private key missing from response/config")
	}
	if len(out.Warnings) == 0 {
		t.Fatal("generated-key response has no warnings")
	}
}
