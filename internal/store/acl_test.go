package store

import (
	"context"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func enrollTestPeer(t *testing.T, ctx context.Context, st *Store, setupKey, hostname string) PeerRow {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() returned error: %v", err)
	}

	res, err := st.Enroll(ctx, setupKey, key.PublicKey().String(), hostname, 51820, "192.0.2.10", "")
	if err != nil {
		t.Fatalf("Enroll() returned error: %v", err)
	}

	return res.Peer
}

func TestCreateNamedSetupKeyListsName(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	key, err := st.CreateNamedSetupKey(ctx, "jellyfin sidecar", 1, 0)
	if err != nil {
		t.Fatalf("CreateNamedSetupKey() returned error: %v", err)
	}
	if key == "" {
		t.Fatal("CreateNamedSetupKey() returned an empty key")
	}

	keys, err := st.ListSetupKeys(ctx)
	if err != nil {
		t.Fatalf("ListSetupKeys() returned error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("ListSetupKeys() returned %d keys, want 1", len(keys))
	}
	if keys[0].Name != "jellyfin sidecar" {
		t.Fatalf("setup key name = %q, want %q", keys[0].Name, "jellyfin sidecar")
	}
}

func TestCreateACLRuleDetailedStoresServiceFields(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey() returned error: %v", err)
	}
	src := enrollTestPeer(t, ctx, st, setupKey, "laptop")
	dst := enrollTestPeer(t, ctx, st, setupKey, "jellyfin")
	port := int64(8096)

	id, err := st.CreateACLRuleDetailed(ctx, ACLRule{
		SrcPeerID: &src.ID,
		DstPeerID: &dst.ID,
		Name:      "Jellyfin web",
		Protocol:  "tcp",
		PortMin:   &port,
	})
	if err != nil {
		t.Fatalf("CreateACLRuleDetailed() returned error: %v", err)
	}

	rules, err := st.ListACLRules(ctx)
	if err != nil {
		t.Fatalf("ListACLRules() returned error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("ListACLRules() returned %d rules, want 1", len(rules))
	}

	rule := rules[0]
	if rule.ID != id || rule.Name != "Jellyfin web" || rule.Protocol != "tcp" {
		t.Fatalf("rule = %#v, want id/name/protocol to round-trip", rule)
	}
	if rule.PortMin == nil || rule.PortMax == nil || *rule.PortMin != port || *rule.PortMax != port {
		t.Fatalf("ports = %v-%v, want %d-%d", rule.PortMin, rule.PortMax, port, port)
	}
}

func TestCreateACLRuleDetailedRejectsInvalidService(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")
	port := int64(443)

	if _, err := st.CreateACLRuleDetailed(ctx, ACLRule{Protocol: "icmp", PortMin: &port}); err == nil {
		t.Fatal("CreateACLRuleDetailed accepted an ICMP rule with a port")
	}

	low, high := int64(9000), int64(8000)
	if _, err := st.CreateACLRuleDetailed(ctx, ACLRule{Protocol: "udp", PortMin: &low, PortMax: &high}); err == nil {
		t.Fatal("CreateACLRuleDetailed accepted an inverted port range")
	}
}

func TestImportACLRulesReplacesExistingRules(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey() returned error: %v", err)
	}
	src := enrollTestPeer(t, ctx, st, setupKey, "laptop")
	dst := enrollTestPeer(t, ctx, st, setupKey, "jellyfin")
	oldPort := int64(80)
	newPort := int64(8096)

	if _, err := st.CreateACLRuleDetailed(ctx, ACLRule{
		SrcPeerID: &src.ID,
		DstPeerID: &dst.ID,
		Name:      "old",
		Protocol:  "tcp",
		PortMin:   &oldPort,
	}); err != nil {
		t.Fatalf("CreateACLRuleDetailed() returned error: %v", err)
	}

	n, err := st.ImportACLRules(ctx, []ACLRule{{
		SrcPeerID: &src.ID,
		DstPeerID: &dst.ID,
		Name:      "restored",
		Protocol:  "tcp",
		PortMin:   &newPort,
	}}, true)
	if err != nil {
		t.Fatalf("ImportACLRules() returned error: %v", err)
	}
	if n != 1 {
		t.Fatalf("ImportACLRules() imported %d rules, want 1", n)
	}

	rules, err := st.ListACLRules(ctx)
	if err != nil {
		t.Fatalf("ListACLRules() returned error: %v", err)
	}
	if len(rules) != 1 || rules[0].Name != "restored" {
		t.Fatalf("rules after replace = %#v, want one restored rule", rules)
	}
	if rules[0].PortMin == nil || *rules[0].PortMin != newPort {
		t.Fatalf("restored port = %v, want %d", rules[0].PortMin, newPort)
	}
}

func TestImportACLRulesRollsBackOnInvalidRule(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	setupKey, err := st.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey() returned error: %v", err)
	}
	src := enrollTestPeer(t, ctx, st, setupKey, "laptop")
	dst := enrollTestPeer(t, ctx, st, setupKey, "jellyfin")

	if _, err := st.CreateACLRuleDetailed(ctx, ACLRule{
		SrcPeerID: &src.ID,
		DstPeerID: &dst.ID,
		Name:      "existing",
		Protocol:  "any",
	}); err != nil {
		t.Fatalf("CreateACLRuleDetailed() returned error: %v", err)
	}

	missingPeer := int64(99999)
	if _, err := st.ImportACLRules(ctx, []ACLRule{{
		SrcPeerID: &src.ID,
		DstPeerID: &missingPeer,
		Name:      "bad",
		Protocol:  "any",
	}}, true); err == nil {
		t.Fatal("ImportACLRules() accepted a missing peer")
	}

	rules, err := st.ListACLRules(ctx)
	if err != nil {
		t.Fatalf("ListACLRules() returned error: %v", err)
	}
	if len(rules) != 1 || rules[0].Name != "existing" {
		t.Fatalf("rules after failed import = %#v, want original rule preserved", rules)
	}
}
