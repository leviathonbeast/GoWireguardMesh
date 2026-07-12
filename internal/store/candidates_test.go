package store

import (
	"context"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gowireguard/internal/proto"
)

func TestApplyReportStoresCandidatesAndNATType(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}

	res, err := st.Enroll(ctx, setupKey, key.PublicKey().String(), "node-a", 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	report := &proto.ReportRequest{
		Candidates: []proto.AgentCandidate{
			{Endpoint: "192.168.1.20:51820", Type: "host"},
		},
		NATType: "easy",
	}
	if err := st.ApplyReport(ctx, res.Peer.ID, "192.0.2.10", report); err != nil {
		t.Fatalf("ApplyReport: %v", err)
	}

	self, _, err := st.PeersForID(ctx, res.Peer.ID)
	if err != nil {
		t.Fatalf("PeersForID: %v", err)
	}
	if self.NATType != "easy" {
		t.Fatalf("NATType = %q, want easy", self.NATType)
	}
	if self.CandidatesJSON == "" {
		t.Fatal("CandidatesJSON empty after report")
	}

	// An empty follow-up report must not clobber either value.
	if err := st.ApplyReport(ctx, res.Peer.ID, "192.0.2.10", &proto.ReportRequest{}); err != nil {
		t.Fatalf("ApplyReport (empty): %v", err)
	}

	self, _, err = st.PeersForID(ctx, res.Peer.ID)
	if err != nil {
		t.Fatalf("PeersForID: %v", err)
	}
	if self.NATType != "easy" || self.CandidatesJSON == "" {
		t.Fatalf("empty report clobbered stored values: nat=%q candidates=%q", self.NATType, self.CandidatesJSON)
	}

	// A junk NAT classification is treated as "not reported".
	if err := st.ApplyReport(ctx, res.Peer.ID, "", &proto.ReportRequest{NATType: "weird"}); err != nil {
		t.Fatalf("ApplyReport (junk nat): %v", err)
	}
	self, _, _ = st.PeersForID(ctx, res.Peer.ID)
	if self.NATType != "easy" {
		t.Fatalf("junk NATType overwrote stored value: %q", self.NATType)
	}
}

func TestUpdatePeerCandidates(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}

	res, err := st.Enroll(ctx, setupKey, key.PublicKey().String(), "node-a", 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	want := `[{"endpoint":"192.168.1.20:51820","type":"host"}]`
	if err := st.UpdatePeerCandidates(ctx, res.Peer.ID, want); err != nil {
		t.Fatalf("UpdatePeerCandidates: %v", err)
	}

	self, _, err := st.PeersForID(ctx, res.Peer.ID)
	if err != nil {
		t.Fatalf("PeersForID: %v", err)
	}
	if self.CandidatesJSON != want {
		t.Fatalf("CandidatesJSON = %q, want %q", self.CandidatesJSON, want)
	}

	// "" means no update, not a wipe.
	if err := st.UpdatePeerCandidates(ctx, res.Peer.ID, ""); err != nil {
		t.Fatalf("UpdatePeerCandidates(\"\"): %v", err)
	}
	self, _, _ = st.PeersForID(ctx, res.Peer.ID)
	if self.CandidatesJSON != want {
		t.Fatalf("empty update wiped candidates: %q", self.CandidatesJSON)
	}
}
