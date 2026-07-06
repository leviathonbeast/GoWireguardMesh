package store

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	gowireguard "gowireguard"
)

func openTestStore(t *testing.T, network string) *Store {
	t.Helper()

	st, err := Open(
		filepath.Join(t.TempDir(), "mesh.db"),
		netip.MustParsePrefix(network),
		gowireguard.SchemaSQL,
	)
	if err != nil {
		t.Fatalf("Open() returned error: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	return st
}

func TestEnrollAssignsIPv6WhenEnabled(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")
	st.Network6 = netip.MustParsePrefix("fd00:100:64::/64")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey() returned error: %v", err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() returned error: %v", err)
	}

	res, err := st.Enroll(ctx, setupKey, key.PublicKey().String(), "node-a", 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("Enroll() returned error: %v", err)
	}

	if res.Peer.AssignedIP != "100.64.0.1" {
		t.Fatalf("AssignedIP = %q, want 100.64.0.1", res.Peer.AssignedIP)
	}
	if res.Peer.AssignedIP6 != "fd00:100:64::1" {
		t.Fatalf("AssignedIP6 = %q, want fd00:100:64::1", res.Peer.AssignedIP6)
	}
}

func TestReEnrollBackfillsIPv6WhenEnabledLater(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey() returned error: %v", err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() returned error: %v", err)
	}

	first, err := st.Enroll(ctx, setupKey, key.PublicKey().String(), "node-a", 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("first Enroll() returned error: %v", err)
	}
	if first.Peer.AssignedIP6 != "" {
		t.Fatalf("first AssignedIP6 = %q, want empty", first.Peer.AssignedIP6)
	}

	st.Network6 = netip.MustParsePrefix("fd00:100:64::/64")

	second, err := st.Enroll(ctx, setupKey, key.PublicKey().String(), "node-a", 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("second Enroll() returned error: %v", err)
	}
	if second.Created {
		t.Fatal("second Enroll() created a new peer, want re-enroll")
	}
	if second.Peer.AssignedIP6 != "fd00:100:64::1" {
		t.Fatalf("backfilled AssignedIP6 = %q, want fd00:100:64::1", second.Peer.AssignedIP6)
	}
}

func TestReEnrollUpdatesHostname(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey() returned error: %v", err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() returned error: %v", err)
	}

	if _, err := st.Enroll(ctx, setupKey, key.PublicKey().String(), "docker-id", 51820, "192.0.2.10", ""); err != nil {
		t.Fatalf("first Enroll() returned error: %v", err)
	}

	second, err := st.Enroll(ctx, setupKey, key.PublicKey().String(), "muse", 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("second Enroll() returned error: %v", err)
	}
	if second.Created {
		t.Fatal("second Enroll() created a new peer, want re-enroll")
	}

	peers, err := st.ListPeers(ctx)
	if err != nil {
		t.Fatalf("ListPeers() returned error: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("ListPeers() returned %d peers, want 1", len(peers))
	}
	if peers[0].Hostname != "muse" {
		t.Fatalf("hostname after re-enroll = %q, want muse", peers[0].Hostname)
	}
}

func TestUpdatePeerAddressValidatesOverlayAndCollisions(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")
	st.Network6 = netip.MustParsePrefix("fd00:100:64::/64")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey() returned error: %v", err)
	}

	key1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() returned error: %v", err)
	}
	key2, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() returned error: %v", err)
	}

	p1, err := st.Enroll(ctx, setupKey, key1.PublicKey().String(), "node-a", 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("first Enroll() returned error: %v", err)
	}
	p2, err := st.Enroll(ctx, setupKey, key2.PublicKey().String(), "node-b", 51820, "192.0.2.11", "")
	if err != nil {
		t.Fatalf("second Enroll() returned error: %v", err)
	}

	updated, err := st.UpdatePeerAddress(ctx, p1.Peer.ID, "100.64.0.44", "fd00:100:64::44")
	if err != nil {
		t.Fatalf("UpdatePeerAddress() returned error: %v", err)
	}
	if updated.AssignedIP != "100.64.0.44" || updated.AssignedIP6 != "fd00:100:64::44" {
		t.Fatalf("updated addresses = %s/%s, want 100.64.0.44/fd00:100:64::44", updated.AssignedIP, updated.AssignedIP6)
	}

	if _, err := st.UpdatePeerAddress(ctx, p1.Peer.ID, p2.Peer.AssignedIP, "fd00:100:64::45"); !errors.Is(err, ErrAddressInUse) {
		t.Fatalf("collision error = %v, want ErrAddressInUse", err)
	}
	if _, err := st.UpdatePeerAddress(ctx, p1.Peer.ID, "192.0.2.44", "fd00:100:64::46"); err == nil {
		t.Fatal("UpdatePeerAddress() accepted IPv4 outside the overlay")
	}
	if _, err := st.UpdatePeerAddress(ctx, p1.Peer.ID, "100.64.0.45", "2001:db8::1"); err == nil {
		t.Fatal("UpdatePeerAddress() accepted IPv6 outside the overlay")
	}
}

func TestRemovePeerRequiresRevokedPeerAndFreesAddress(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey() returned error: %v", err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() returned error: %v", err)
	}

	first, err := st.Enroll(ctx, setupKey, key.PublicKey().String(), "old", 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("Enroll() returned error: %v", err)
	}

	if err := st.RemovePeer(ctx, first.Peer.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RemovePeer(active) = %v, want ErrNotFound", err)
	}
	if err := st.RevokePeer(ctx, first.Peer.ID); err != nil {
		t.Fatalf("RevokePeer() returned error: %v", err)
	}
	if err := st.RemovePeer(ctx, first.Peer.ID); err != nil {
		t.Fatalf("RemovePeer(revoked) returned error: %v", err)
	}

	nextKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() returned error: %v", err)
	}
	next, err := st.Enroll(ctx, setupKey, nextKey.PublicKey().String(), "new", 51820, "192.0.2.11", "")
	if err != nil {
		t.Fatalf("Enroll() after remove returned error: %v", err)
	}
	if next.Peer.AssignedIP != first.Peer.AssignedIP {
		t.Fatalf("next assigned IP = %s, want freed %s", next.Peer.AssignedIP, first.Peer.AssignedIP)
	}
}
