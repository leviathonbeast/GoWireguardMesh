package store

import (
	"context"
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
