package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"gowireguard/internal/store"
)

func TestACLExportImportRoundTrip(t *testing.T) {
	srv, ts := newTestServer(t)
	ctx := context.Background()

	setupKey, err := srv.store.CreateSetupKey(ctx, 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}
	src := enrollPeer(t, ts, setupKey, "laptop")
	dst := enrollPeer(t, ts, setupKey, "jellyfin")
	port := int64(8096)

	if _, err := srv.store.CreateACLRuleDetailed(ctx, store.ACLRule{
		SrcPeerID: int64Ptr(int64(src.PeerID)),
		DstPeerID: int64Ptr(int64(dst.PeerID)),
		Name:      "Jellyfin web",
		Protocol:  "tcp",
		PortMin:   &port,
	}); err != nil {
		t.Fatalf("CreateACLRuleDetailed: %v", err)
	}

	code, body := adminDo(t, ts, http.MethodGet, "/api/acl/export", nil)
	if code != http.StatusOK {
		t.Fatalf("export acl: status %d (%s)", code, body)
	}

	var exported aclExportJSON
	if err := json.Unmarshal(body, &exported); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if exported.Version != 1 || exported.RuleCount != 1 || len(exported.Rules) != 1 {
		t.Fatalf("export = %#v, want version 1 with one rule", exported)
	}
	if exported.Rules[0].Name != "Jellyfin web" || exported.Rules[0].SrcLabel != "laptop" || exported.Rules[0].DstLabel != "jellyfin" {
		t.Fatalf("exported rule = %#v, want readable labels and name", exported.Rules[0])
	}

	if _, err := srv.store.ImportACLRules(ctx, nil, true); err != nil {
		t.Fatalf("clear acl: %v", err)
	}

	replace := true
	code, body = adminDo(t, ts, http.MethodPost, "/api/acl/import", aclImportRequest{
		Replace: &replace,
		Rules:   exported.Rules,
	})
	if code != http.StatusOK {
		t.Fatalf("import acl: status %d (%s)", code, body)
	}

	var imported struct {
		DefaultPolicy string        `json:"default_policy"`
		Rules         []aclRuleJSON `json:"rules"`
	}
	if err := json.Unmarshal(body, &imported); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if len(imported.Rules) != 1 || imported.Rules[0].Name != "Jellyfin web" || imported.Rules[0].Protocol != "tcp" {
		t.Fatalf("import response = %#v, want restored Jellyfin TCP rule", imported)
	}
	if imported.Rules[0].PortMin == nil || *imported.Rules[0].PortMin != port {
		t.Fatalf("imported port = %v, want %d", imported.Rules[0].PortMin, port)
	}
}

func int64Ptr(v int64) *int64 {
	return &v
}
