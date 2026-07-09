package store

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// enrollAgent is a small helper: create+enroll an agent peer, returning its row.
func enrollAgent(t *testing.T, st *Store, setupKey, hostname string) PeerRow {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	res, err := st.Enroll(context.Background(), setupKey, key.PublicKey().String(), hostname, 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("Enroll(%s): %v", hostname, err)
	}
	return res.Peer
}

func TestCreateStaticPeerPersistsGateway(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")
	st.Network6 = netip.MustParsePrefix("fd00:100:64::/64")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}
	gateway := enrollAgent(t, st, setupKey, "gateway")

	mobKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	peer, err := st.CreateStaticPeer(ctx, StaticPeer{PublicKey: mobKey.PublicKey().String(), Hostname: "iphone", GatewayPeerID: gateway.ID})
	if err != nil {
		t.Fatalf("CreateStaticPeer: %v", err)
	}
	if peer.PeerType != "static" {
		t.Fatalf("peer_type = %q, want static", peer.PeerType)
	}
	if peer.GatewayPeerID != gateway.ID {
		t.Fatalf("gateway_peer_id = %d, want %d", peer.GatewayPeerID, gateway.ID)
	}
}

// The sealed key and endpoint are what let the admin UI rebuild a config
// later; a peer created without a sealed key must report that it has none.
func TestCreateStaticPeerPersistsSealedKeyAndEndpoint(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}
	gateway := enrollAgent(t, st, setupKey, "gateway")

	sealedKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	sealed, err := st.CreateStaticPeer(ctx, StaticPeer{
		PublicKey:       sealedKey.PublicKey().String(),
		Hostname:        "iphone",
		GatewayPeerID:   gateway.ID,
		PrivateKeyEnc:   "sealed-blob",
		GatewayEndpoint: "mesh.example.com:51820",
	})
	if err != nil {
		t.Fatalf("CreateStaticPeer: %v", err)
	}
	if !sealed.HasStoredConfig {
		t.Fatal("HasStoredConfig = false, want true")
	}
	if sealed.GatewayEndpoint != "mesh.example.com:51820" {
		t.Fatalf("gateway_endpoint = %q, want mesh.example.com:51820", sealed.GatewayEndpoint)
	}

	got, err := st.SealedPrivateKey(ctx, sealed.ID)
	if err != nil {
		t.Fatalf("SealedPrivateKey: %v", err)
	}
	if got != "sealed-blob" {
		t.Fatalf("SealedPrivateKey = %q, want sealed-blob", got)
	}

	// A peer whose key the operator supplied stores nothing to unseal.
	byoKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	byo, err := st.CreateStaticPeer(ctx, StaticPeer{
		PublicKey:       byoKey.PublicKey().String(),
		Hostname:        "byo",
		GatewayPeerID:   gateway.ID,
		GatewayEndpoint: "mesh.example.com:51820",
	})
	if err != nil {
		t.Fatalf("CreateStaticPeer: %v", err)
	}
	if byo.HasStoredConfig {
		t.Fatal("HasStoredConfig = true for an operator-supplied key")
	}
	if _, err := st.SealedPrivateKey(ctx, byo.ID); !errors.Is(err, ErrNoStoredConfig) {
		t.Fatalf("SealedPrivateKey: err = %v, want ErrNoStoredConfig", err)
	}

	// Agents never have one either, and must not be reachable by peer id.
	if _, err := st.SealedPrivateKey(ctx, gateway.ID); !errors.Is(err, ErrNoStoredConfig) {
		t.Fatalf("SealedPrivateKey(agent): err = %v, want ErrNoStoredConfig", err)
	}
}

func TestCreateStaticPeerRejectsBadGateway(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}
	gateway := enrollAgent(t, st, setupKey, "gateway")

	mobKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}

	// Missing gateway id.
	if _, err := st.CreateStaticPeer(ctx, StaticPeer{PublicKey: mobKey.PublicKey().String(), Hostname: "iphone", GatewayPeerID: 0}); err == nil {
		t.Fatal("CreateStaticPeer with gateway 0 should fail")
	}

	// Nonexistent gateway.
	if _, err := st.CreateStaticPeer(ctx, StaticPeer{PublicKey: mobKey.PublicKey().String(), Hostname: "iphone", GatewayPeerID: 999999}); err == nil {
		t.Fatal("CreateStaticPeer with unknown gateway should fail")
	}

	// A static peer cannot be another static peer's gateway.
	firstMobile, err := st.CreateStaticPeer(ctx, StaticPeer{PublicKey: mobKey.PublicKey().String(), Hostname: "iphone", GatewayPeerID: gateway.ID})
	if err != nil {
		t.Fatalf("CreateStaticPeer: %v", err)
	}
	secondKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	_, err = st.CreateStaticPeer(ctx, StaticPeer{PublicKey: secondKey.PublicKey().String(), Hostname: "ipad", GatewayPeerID: firstMobile.ID})
	if err == nil || !strings.Contains(err.Error(), "must be a wgmesh agent") {
		t.Fatalf("static-peer-as-gateway error = %v, want 'must be a wgmesh agent'", err)
	}
}

// TestGatewaySeesOwnMobileUnderDeny checks that a gateway agent can always
// reach its routed mobiles even under default-deny, without an explicit ACL
// rule — it has to, to route them.
func TestGatewaySeesOwnMobileUnderDeny(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")
	st.DefaultAllow = false

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}
	gateway := enrollAgent(t, st, setupKey, "gateway")
	other := enrollAgent(t, st, setupKey, "other")

	mobKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	mobile, err := st.CreateStaticPeer(ctx, StaticPeer{PublicKey: mobKey.PublicKey().String(), Hostname: "iphone", GatewayPeerID: gateway.ID})
	if err != nil {
		t.Fatalf("CreateStaticPeer: %v", err)
	}

	_, gwOthers, err := st.PeersForID(ctx, gateway.ID)
	if err != nil {
		t.Fatalf("PeersForID(gateway): %v", err)
	}
	if !hasPeerID(gwOthers, mobile.ID) {
		t.Fatalf("gateway should see its mobile under default-deny; got %+v", gwOthers)
	}

	// The unrelated agent must NOT see the mobile (no ACL rule connects them).
	_, otherOthers, err := st.PeersForID(ctx, other.ID)
	if err != nil {
		t.Fatalf("PeersForID(other): %v", err)
	}
	if hasPeerID(otherOthers, mobile.ID) {
		t.Fatalf("unrelated agent must not see the mobile under default-deny")
	}
}

func hasPeerID(rows []PeerRow, id int64) bool {
	for _, r := range rows {
		if r.ID == id {
			return true
		}
	}
	return false
}
