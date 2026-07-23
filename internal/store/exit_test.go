package store

import (
	"context"
	"errors"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gowireguard/internal/proto"
)

// enrollTestAgent enrolls a fresh agent peer and returns its row.
func enrollTestAgent(t *testing.T, st *Store, hostname string) PeerRow {
	t.Helper()
	ctx := context.Background()

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey() returned error: %v", err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() returned error: %v", err)
	}
	res, err := st.Enroll(ctx, setupKey, key.PublicKey().String(), hostname, 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("Enroll(%s) returned error: %v", hostname, err)
	}

	return res.Peer
}

func TestSetExitNodeValidation(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")
	st.DefaultAllow = true

	a := enrollTestAgent(t, st, "node-a")
	b := enrollTestAgent(t, st, "node-b")
	c := enrollTestAgent(t, st, "node-c")

	// Self-assignment.
	if _, err := st.SetExitNode(ctx, a.ID, a.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("self-assignment: err = %v, want ErrInvalid", err)
	}

	// Target does not advertise.
	if _, err := st.SetExitNode(ctx, a.ID, b.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-advertising target: err = %v, want ErrInvalid", err)
	}

	// Unknown target.
	if _, err := st.SetExitNode(ctx, a.ID, 999); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown target: err = %v, want ErrInvalid", err)
	}

	if err := st.SetAdvertiseExitNode(ctx, b.ID, true); err != nil {
		t.Fatalf("SetAdvertiseExitNode() returned error: %v", err)
	}

	assignment, err := st.SetExitNode(ctx, a.ID, b.ID)
	if err != nil {
		t.Fatalf("SetExitNode(a via b) returned error: %v", err)
	}
	if assignment.PeerPublicKey != a.PublicKey || assignment.ExitPublicKey != b.PublicKey {
		t.Fatalf("assignment keys = %+v, want a/b public keys", assignment)
	}
	if assignment.PeerHostname != "node-a" || assignment.ExitHostname != "node-b" {
		t.Fatalf("assignment hostnames = %+v, want node-a/node-b", assignment)
	}

	// A static peer cannot be an exit target even if the column is set.
	if _, err := st.db.ExecContext(ctx, `UPDATE peers SET peer_type = 'static' WHERE id = ?`, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAdvertiseExitNode(ctx, c.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetExitNode(ctx, a.ID, c.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("static target: err = %v, want ErrInvalid", err)
	}
	// Nor can a static peer be a client.
	if _, err := st.SetExitNode(ctx, c.ID, b.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("static client: err = %v, want ErrInvalid", err)
	}

	// Chains are rejected in both directions: b serves a, so b cannot
	// route through anyone...
	d := enrollTestAgent(t, st, "node-d")
	if err := st.SetAdvertiseExitNode(ctx, d.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetExitNode(ctx, b.ID, d.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("exit with clients chaining out: err = %v, want ErrInvalid", err)
	}
	// ...and a (which routes through b) cannot serve as an exit target.
	if err := st.SetAdvertiseExitNode(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetExitNode(ctx, d.ID, a.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("target routing through an exit: err = %v, want ErrInvalid", err)
	}

	// Clearing frees b to route through d.
	if _, err := st.SetExitNode(ctx, a.ID, 0); err != nil {
		t.Fatalf("clear returned error: %v", err)
	}
	if _, err := st.SetExitNode(ctx, b.ID, d.ID); err != nil {
		t.Fatalf("SetExitNode(b via d) after clear returned error: %v", err)
	}
}

// An exit-node pairing must be mutually visible under default-deny even
// with no ACL rule connecting the pair — without that neither side can
// configure the other as a WireGuard peer.
func TestExitNodeVisibilityDefaultDeny(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	a := enrollTestAgent(t, st, "node-a")
	b := enrollTestAgent(t, st, "node-b")

	_, others, err := st.PeersForID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(others) != 0 {
		t.Fatalf("default-deny baseline: a sees %d peers, want 0", len(others))
	}

	if err := st.SetAdvertiseExitNode(ctx, b.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetExitNode(ctx, a.ID, b.ID); err != nil {
		t.Fatal(err)
	}

	self, others, err := st.PeersForID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if self.ExitNodePeerID != b.ID {
		t.Fatalf("a.ExitNodePeerID = %d, want %d", self.ExitNodePeerID, b.ID)
	}
	if len(others) != 1 || others[0].ID != b.ID {
		t.Fatalf("a should see exactly its exit node, got %+v", others)
	}
	if !others[0].AdvertiseExitNode {
		t.Fatalf("exit node row should carry AdvertiseExitNode")
	}

	_, others, err = st.PeersForID(ctx, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(others) != 1 || others[0].ID != a.ID {
		t.Fatalf("b should see exactly its exit client, got %+v", others)
	}
	if others[0].ExitNodePeerID != b.ID {
		t.Fatalf("client row ExitNodePeerID = %d, want %d", others[0].ExitNodePeerID, b.ID)
	}
}

// The reported flag is authoritative in both directions: reporting true
// stores the offer, reporting false withdraws it.
func TestApplyReportAdvertiseExitNode(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	a := enrollTestAgent(t, st, "node-a")

	advertised := func() bool {
		t.Helper()
		peers, err := st.ListPeers(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range peers {
			if p.ID == a.ID {
				return p.AdvertiseExitNode
			}
		}
		t.Fatalf("peer %d missing from ListPeers", a.ID)
		return false
	}

	if advertised() {
		t.Fatal("fresh enroll should not advertise")
	}

	if err := st.ApplyReport(ctx, a.ID, "192.0.2.10", &proto.ReportRequest{AdvertiseExitNode: true}); err != nil {
		t.Fatal(err)
	}
	if !advertised() {
		t.Fatal("report with advertise_exit_node=true should store the offer")
	}

	if err := st.ApplyReport(ctx, a.ID, "192.0.2.10", &proto.ReportRequest{}); err != nil {
		t.Fatal(err)
	}
	if advertised() {
		t.Fatal("report without the flag should withdraw the offer")
	}
}
