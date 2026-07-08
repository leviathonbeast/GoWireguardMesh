package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

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
