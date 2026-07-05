package store

import (
	"context"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestApplyNetworkMigrationReassignsPeersAndReEnrollReturnsNewIP(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")
	if _, err := st.LoadOrInitNetworkConfig(ctx,
		netip.MustParsePrefix("100.64.0.0/16"),
		netip.MustParsePrefix("fd00:100:64::/64"),
	); err != nil {
		t.Fatalf("LoadOrInitNetworkConfig() returned error: %v", err)
	}

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
	if first.Peer.AssignedIP != "100.64.0.1" || first.Peer.AssignedIP6 != "fd00:100:64::1" {
		t.Fatalf("first assignment = %s / %s", first.Peer.AssignedIP, first.Peer.AssignedIP6)
	}

	plan, err := st.ApplyNetworkMigration(ctx,
		netip.MustParsePrefix("100.99.0.0/16"),
		netip.MustParsePrefix("fd00:99::/64"),
	)
	if err != nil {
		t.Fatalf("ApplyNetworkMigration() returned error: %v", err)
	}
	if len(plan.Changes) != 1 {
		t.Fatalf("migration changes = %d, want 1", len(plan.Changes))
	}
	if plan.Changes[0].NewIP != "100.99.0.1" || plan.Changes[0].NewIP6 != "fd00:99::1" {
		t.Fatalf("new assignment = %s / %s", plan.Changes[0].NewIP, plan.Changes[0].NewIP6)
	}

	second, err := st.Enroll(ctx, setupKey, key.PublicKey().String(), "node-a", 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("second Enroll() returned error: %v", err)
	}
	if second.Created {
		t.Fatal("second Enroll() created a new peer, want re-enroll")
	}
	if second.Peer.ID != first.Peer.ID {
		t.Fatalf("re-enroll peer ID = %d, want %d", second.Peer.ID, first.Peer.ID)
	}
	if second.Peer.AssignedIP != "100.99.0.1" || second.Peer.AssignedIP6 != "fd00:99::1" {
		t.Fatalf("re-enroll assignment = %s / %s, want migrated IPs", second.Peer.AssignedIP, second.Peer.AssignedIP6)
	}
}

func TestPreviewNetworkMigrationRejectsTooSmallNetwork(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")
	if _, err := st.LoadOrInitNetworkConfig(ctx,
		netip.MustParsePrefix("100.64.0.0/16"),
		netip.MustParsePrefix("fd00:100:64::/64"),
	); err != nil {
		t.Fatalf("LoadOrInitNetworkConfig() returned error: %v", err)
	}

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey() returned error: %v", err)
	}

	for i := 0; i < 2; i++ {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("GeneratePrivateKey() returned error: %v", err)
		}
		if _, err := st.Enroll(ctx, setupKey, key.PublicKey().String(), "node", 51820, "192.0.2.10", ""); err != nil {
			t.Fatalf("Enroll() returned error: %v", err)
		}
	}

	if _, err := st.PreviewNetworkMigration(ctx,
		netip.MustParsePrefix("100.99.0.0/31"),
		netip.MustParsePrefix("fd00:99::/64"),
	); err == nil {
		t.Fatal("PreviewNetworkMigration accepted an IPv4 network without enough host addresses")
	}
}
