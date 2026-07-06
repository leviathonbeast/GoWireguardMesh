package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	gowireguard "gowireguard"
	"gowireguard/internal/proto"
	"gowireguard/internal/relay"
	"gowireguard/internal/store"
)

// newTestServer builds a control plane backed by a temp DB with the
// default dual-stack overlay, wired to the same handlers runServe uses.
// It exercises the real HTTP path (enroll, report, network migration)
// so cache/store consistency is tested end to end, not just the store.
func newTestServer(t *testing.T) (*server, *httptest.Server) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "mesh.db")
	prefix := netip.MustParsePrefix("100.64.0.0/16")
	prefix6 := netip.MustParsePrefix(defaultNetwork6CIDR)

	st, err := store.Open(dbPath, prefix, gowireguard.SchemaSQL)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg, err := st.LoadOrInitNetworkConfig(context.Background(), prefix, prefix6)
	if err != nil {
		t.Fatalf("LoadOrInitNetworkConfig: %v", err)
	}
	st.DefaultAllow = true

	pskMaster, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate psk master: %v", err)
	}

	srv := &server{
		store:        st,
		networkCIDR:  cfg.NetworkCIDR,
		network6CIDR: cfg.NetworkCIDR6,
		pskMaster:    pskMaster,
		adminToken:   "test-admin",
		accessLog:    newAccessLogSink(accessLogMemory, 100),
		wsHub:        relay.NewWSHub(),
		punchEpochs:  make(map[string]punchEpoch),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll", srv.handleEnroll)
	mux.HandleFunc("POST /report", srv.handleReport)
	mux.HandleFunc("GET /relay-ws", srv.handleRelayWS)
	mux.HandleFunc("GET /healthz", srv.handleHealthz)
	mux.HandleFunc("GET /api/peers", srv.requireAdmin(srv.handleListPeers))
	mux.HandleFunc("POST /api/peers/{id}/address", srv.requireAdmin(srv.handleUpdatePeerAddress))
	mux.HandleFunc("POST /api/peers/{id}/remove", srv.requireAdmin(srv.handleRemovePeer))
	mux.HandleFunc("GET /api/network", srv.requireAdmin(srv.handleGetNetwork))
	mux.HandleFunc("POST /api/network/preview", srv.requireAdmin(srv.handlePreviewNetworkMigration))
	mux.HandleFunc("POST /api/network/apply", srv.requireAdmin(srv.handleApplyNetworkMigration))
	mux.HandleFunc("GET /api/acl", srv.requireAdmin(srv.handleListACL))
	mux.HandleFunc("GET /api/acl/export", srv.requireAdmin(srv.handleExportACL))
	mux.HandleFunc("POST /api/acl/import", srv.requireAdmin(srv.handleImportACL))

	// Mirror the production middleware chain (logRequests wrapping
	// securityHeaders) AND the production server limits, so tests
	// exercise what actually ships — including the WS relay's deadline
	// exemption, which only matters when Read/WriteTimeout are armed.
	ts := httptest.NewUnstartedServer(srv.logRequests(securityHeaders(mux)))
	ts.Config.ReadTimeout = 60 * time.Second
	ts.Config.WriteTimeout = 60 * time.Second
	ts.Start()
	t.Cleanup(ts.Close)

	return srv, ts
}

func enrollPeer(t *testing.T, ts *httptest.Server, setupKey, hostname string) proto.EnrollResponse {
	t.Helper()

	resp, _ := enrollPeerKey(t, ts, setupKey, hostname)
	return resp
}

// enrollPeerKey enrolls a fresh peer and also returns its private key,
// for tests that need to reference the peer's public key afterwards.
func enrollPeerKey(t *testing.T, ts *httptest.Server, setupKey, hostname string) (proto.EnrollResponse, wgtypes.Key) {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate peer key: %v", err)
	}

	body, _ := json.Marshal(proto.EnrollRequest{
		SetupKey:   setupKey,
		PublicKey:  key.PublicKey().String(),
		Hostname:   hostname,
		ListenPort: 51820,
	})

	resp, err := http.Post(ts.URL+"/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /enroll: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("enroll %s: status %d: %s", hostname, resp.StatusCode, raw)
	}

	var out proto.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode enroll response: %v", err)
	}

	return out, key
}

func adminDo(t *testing.T, ts *httptest.Server, method, path string, payload any) (int, []byte) {
	t.Helper()

	var reader io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, ts.URL+path, reader)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer test-admin")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// reportAs posts an empty telemetry report authenticated by the peer's
// auth token and returns the sync response (which carries the peer's
// current self-IP — the value a running agent adopts without restart).
func reportAs(t *testing.T, ts *httptest.Server, authToken string) proto.ReportResponse {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/report", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatalf("build report: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /report: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("report: status %d: %s", resp.StatusCode, raw)
	}

	var out proto.ReportResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode report response: %v", err)
	}

	return out
}

// assertHasAllowedIPs checks that every wanted CIDR appears in some
// peer's AllowedIPs across the sync payload.
func assertHasAllowedIPs(t *testing.T, peers []proto.PeerConfigResponse, want ...string) {
	t.Helper()

	have := map[string]bool{}
	for _, p := range peers {
		for _, cidr := range p.AllowedIPs {
			have[cidr] = true
		}
	}

	for _, w := range want {
		if !have[w] {
			t.Fatalf("expected AllowedIP %q among peers %+v", w, peers)
		}
	}
}

// TestNetworkMigrationReservesRevokedPeerSlots checks that a revoked
// peer is still re-IP'd by the migration and keeps its address reserved
// afterward, so a fresh enrollment can't be handed the revoked peer's
// slot. Revoked rows counting toward capacity is deliberate.
func TestNetworkMigrationReservesRevokedPeerSlots(t *testing.T) {
	srv, ts := newTestServer(t)

	setupKey, err := srv.store.CreateSetupKey(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}

	p1 := enrollPeer(t, ts, setupKey, "p1") // 100.64.0.1
	p2 := enrollPeer(t, ts, setupKey, "p2") // 100.64.0.2
	enrollPeer(t, ts, setupKey, "p3")       // 100.64.0.3

	if err := srv.store.RevokePeer(context.Background(), int64(p2.PeerID)); err != nil {
		t.Fatalf("RevokePeer: %v", err)
	}

	confirmed := map[string]any{"network_cidr": "100.99.0.0/16", "network_cidr6": "fd00:99::/64", "confirm": networkMigrationConfirm}
	code, body := adminDo(t, ts, "POST", "/api/network/apply", confirmed)
	if code != http.StatusOK {
		t.Fatalf("apply: status %d (%s)", code, body)
	}

	var plan store.NetworkMigrationPlan
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatalf("decode apply plan: %v", err)
	}
	if len(plan.Changes) != 3 {
		t.Fatalf("migration re-IP'd %d peers, want 3 (revoked included)", len(plan.Changes))
	}

	// p1 (active) adopts its new IP; the revoked p2's slot (.2) stays
	// reserved, so a new peer must skip to .4, not reuse .2 or .3.
	if got := reportAs(t, ts, p1.AuthToken); got.AssignedIP != "100.99.0.1" {
		t.Fatalf("p1 self-IP after migration = %s, want 100.99.0.1", got.AssignedIP)
	}

	fresh := enrollPeer(t, ts, setupKey, "p4")
	if fresh.AssignedIP != "100.99.0.4" {
		t.Fatalf("new peer after migration got %s, want 100.99.0.4 (revoked .2 stays reserved)", fresh.AssignedIP)
	}
}

// TestNetworkMigrationSameNetworkIsNoOp guards the two-phase staging:
// reassigning every peer to the address it already holds must not trip
// the assigned_ip UNIQUE constraint.
func TestNetworkMigrationSameNetworkIsNoOp(t *testing.T) {
	srv, ts := newTestServer(t)

	setupKey, err := srv.store.CreateSetupKey(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}

	p1 := enrollPeer(t, ts, setupKey, "p1")
	enrollPeer(t, ts, setupKey, "p2")

	same := map[string]any{"network_cidr": "100.64.0.0/16", "network_cidr6": defaultNetwork6CIDR, "confirm": networkMigrationConfirm}
	if code, body := adminDo(t, ts, "POST", "/api/network/apply", same); code != http.StatusOK {
		t.Fatalf("same-network apply: status %d (%s)", code, body)
	}

	if got := reportAs(t, ts, p1.AuthToken); got.AssignedIP != "100.64.0.1" || got.AssignedIP6 != "fd00:100:64::1" {
		t.Fatalf("p1 after no-op migration = %s / %s, want unchanged", got.AssignedIP, got.AssignedIP6)
	}
}

func TestNetworkMigrationEndToEnd(t *testing.T) {
	srv, ts := newTestServer(t)

	setupKey, err := srv.store.CreateSetupKey(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}

	a := enrollPeer(t, ts, setupKey, "node-a")
	b := enrollPeer(t, ts, setupKey, "node-b")

	if a.AssignedIP != "100.64.0.1" || a.AssignedIP6 != "fd00:100:64::1" {
		t.Fatalf("peer a assignment = %s / %s", a.AssignedIP, a.AssignedIP6)
	}
	if b.AssignedIP != "100.64.0.2" || b.AssignedIP6 != "fd00:100:64::2" {
		t.Fatalf("peer b assignment = %s / %s", b.AssignedIP, b.AssignedIP6)
	}

	// Peer a learns about peer b through config sync on its next report
	// (b enrolled after a, so a's own enroll response predates b). Both
	// address families must appear in AllowedIPs.
	pre := reportAs(t, ts, a.AuthToken)
	assertHasAllowedIPs(t, pre.Peers, "100.64.0.2/32", "fd00:100:64::2/128")

	target := map[string]any{"network_cidr": "100.99.0.0/16", "network_cidr6": "fd00:99::/64"}

	// Apply must be gated by the confirm phrase.
	if code, body := adminDo(t, ts, "POST", "/api/network/apply", target); code != http.StatusBadRequest {
		t.Fatalf("apply without confirm: status %d (%s), want 400", code, body)
	}

	// Preview should describe the reassignment without changing anything.
	code, body := adminDo(t, ts, "POST", "/api/network/preview", target)
	if code != http.StatusOK {
		t.Fatalf("preview: status %d (%s)", code, body)
	}
	var plan store.NetworkMigrationPlan
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if len(plan.Changes) != 2 {
		t.Fatalf("preview changes = %d, want 2", len(plan.Changes))
	}
	// Preview must not have mutated live state: a report still returns the old IP.
	if got := reportAs(t, ts, a.AuthToken); got.AssignedIP != "100.64.0.1" {
		t.Fatalf("after preview, peer a self-IP = %s, want unchanged 100.64.0.1", got.AssignedIP)
	}

	// A network too small to hold every peer must be rejected (via HTTP).
	tooSmall := map[string]any{"network_cidr": "100.99.0.0/31", "network_cidr6": "fd00:99::/64", "confirm": networkMigrationConfirm}
	if code, body := adminDo(t, ts, "POST", "/api/network/apply", tooSmall); code != http.StatusBadRequest {
		t.Fatalf("apply too-small network: status %d (%s), want 400", code, body)
	}

	// Apply for real.
	confirmed := map[string]any{"network_cidr": "100.99.0.0/16", "network_cidr6": "fd00:99::/64", "confirm": networkMigrationConfirm}
	if code, body := adminDo(t, ts, "POST", "/api/network/apply", confirmed); code != http.StatusOK {
		t.Fatalf("apply: status %d (%s)", code, body)
	}

	// The server's advertised network config must now reflect the target.
	code, body = adminDo(t, ts, "GET", "/api/network", nil)
	if code != http.StatusOK {
		t.Fatalf("get network: status %d (%s)", code, body)
	}
	var netCfg store.NetworkConfig
	if err := json.Unmarshal(body, &netCfg); err != nil {
		t.Fatalf("decode network config: %v", err)
	}
	if netCfg.NetworkCIDR != "100.99.0.0/16" || netCfg.NetworkCIDR6 != "fd00:99::/64" {
		t.Fatalf("network config after apply = %s / %s", netCfg.NetworkCIDR, netCfg.NetworkCIDR6)
	}

	// The running agent adopts its new self-IP from the next report — no
	// restart, no re-enroll. This is the crux: token unchanged, IP moved.
	got := reportAs(t, ts, a.AuthToken)
	if got.AssignedIP != "100.99.0.1" || got.AssignedIP6 != "fd00:99::1" {
		t.Fatalf("post-migration self-IP = %s / %s, want 100.99.0.1 / fd00:99::1", got.AssignedIP, got.AssignedIP6)
	}
	if got.NetworkCIDR != "100.99.0.0/16" || got.NetworkCIDR6 != "fd00:99::/64" {
		t.Fatalf("post-migration network = %s / %s", got.NetworkCIDR, got.NetworkCIDR6)
	}
	// And peer a's view of peer b must be re-IP'd in AllowedIPs too,
	// both families.
	assertHasAllowedIPs(t, got.Peers, "100.99.0.2/32", "fd00:99::2/128")

	// A brand-new enrollment after migration must allocate from the new
	// network, not collide, and land at the next free host.
	c := enrollPeer(t, ts, setupKey, "node-c")
	if c.AssignedIP != "100.99.0.3" || c.AssignedIP6 != "fd00:99::3" {
		t.Fatalf("post-migration new peer assignment = %s / %s, want 100.99.0.3 / fd00:99::3", c.AssignedIP, c.AssignedIP6)
	}
}

func TestPeerAddressUpdateUpdatesRunningAgentViaReport(t *testing.T) {
	srv, ts := newTestServer(t)

	setupKey, err := srv.store.CreateSetupKey(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}

	a := enrollPeer(t, ts, setupKey, "node-a")
	b := enrollPeer(t, ts, setupKey, "node-b")

	update := map[string]any{"assigned_ip": "100.64.0.77", "assigned_ip6": "fd00:100:64::77"}
	code, body := adminDo(t, ts, "POST", fmt.Sprintf("/api/peers/%d/address", a.PeerID), update)
	if code != http.StatusOK {
		t.Fatalf("address update: status %d (%s)", code, body)
	}

	var peer peerJSON
	if err := json.Unmarshal(body, &peer); err != nil {
		t.Fatalf("decode address update response: %v", err)
	}
	if peer.AssignedIP != "100.64.0.77" || peer.AssignedIP6 != "fd00:100:64::77" {
		t.Fatalf("updated peer = %s / %s, want 100.64.0.77 / fd00:100:64::77", peer.AssignedIP, peer.AssignedIP6)
	}

	got := reportAs(t, ts, a.AuthToken)
	if got.AssignedIP != "100.64.0.77" || got.AssignedIP6 != "fd00:100:64::77" {
		t.Fatalf("post-update self-IP = %s / %s, want 100.64.0.77 / fd00:100:64::77", got.AssignedIP, got.AssignedIP6)
	}

	collide := map[string]any{"assigned_ip": b.AssignedIP, "assigned_ip6": "fd00:100:64::78"}
	if code, body := adminDo(t, ts, "POST", fmt.Sprintf("/api/peers/%d/address", a.PeerID), collide); code != http.StatusConflict {
		t.Fatalf("collision update: status %d (%s), want 409", code, body)
	}

	outside := map[string]any{"assigned_ip": "192.0.2.77", "assigned_ip6": "fd00:100:64::79"}
	if code, body := adminDo(t, ts, "POST", fmt.Sprintf("/api/peers/%d/address", a.PeerID), outside); code != http.StatusBadRequest {
		t.Fatalf("outside update: status %d (%s), want 400", code, body)
	}
}

func TestRemovePeerRequiresRevocation(t *testing.T) {
	srv, ts := newTestServer(t)

	setupKey, err := srv.store.CreateSetupKey(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}

	peer := enrollPeer(t, ts, setupKey, "stale-node")
	path := fmt.Sprintf("/api/peers/%d/remove", peer.PeerID)

	if code, body := adminDo(t, ts, "POST", path, nil); code != http.StatusNotFound {
		t.Fatalf("remove active peer: status %d (%s), want 404", code, body)
	}
	if err := srv.store.RevokePeer(context.Background(), int64(peer.PeerID)); err != nil {
		t.Fatalf("RevokePeer: %v", err)
	}
	if code, body := adminDo(t, ts, "POST", path, nil); code != http.StatusOK {
		t.Fatalf("remove revoked peer: status %d (%s)", code, body)
	}

	code, body := adminDo(t, ts, "GET", "/api/peers", nil)
	if code != http.StatusOK {
		t.Fatalf("list peers: status %d (%s)", code, body)
	}
	var peers []peerJSON
	if err := json.Unmarshal(body, &peers); err != nil {
		t.Fatalf("decode peers: %v", err)
	}
	if len(peers) != 0 {
		t.Fatalf("peers after remove = %#v, want empty", peers)
	}
}

func TestBuildACLPolicyUsesOverlayIPsAndService(t *testing.T) {
	srv, ts := newTestServer(t)
	srv.store.DefaultAllow = false

	setupKey, err := srv.store.CreateSetupKey(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("CreateSetupKey: %v", err)
	}
	src := enrollPeer(t, ts, setupKey, "traefik")
	dst := enrollPeer(t, ts, setupKey, "muse")
	port := int64(4040)
	if _, err := srv.store.CreateACLRuleDetailed(context.Background(), store.ACLRule{
		SrcPeerID: int64Ptr(int64(src.PeerID)),
		DstPeerID: int64Ptr(int64(dst.PeerID)),
		Name:      "Muse",
		Protocol:  "tcp",
		PortMin:   &port,
	}); err != nil {
		t.Fatalf("CreateACLRuleDetailed: %v", err)
	}

	policy, err := srv.buildACLPolicy(context.Background())
	if err != nil {
		t.Fatalf("buildACLPolicy: %v", err)
	}
	if policy.DefaultPolicy != "deny" || len(policy.Rules) != 1 {
		t.Fatalf("policy = %#v, want deny with one rule", policy)
	}
	rule := policy.Rules[0]
	if rule.SrcIP != "100.64.0.1" || rule.DstIP != "100.64.0.2" || rule.Protocol != "tcp" || rule.PortMin != 4040 {
		t.Fatalf("rule = %#v, want traefik->muse tcp/4040 overlay IPs", rule)
	}
}
