// Command server is the wgmesh control plane: it issues setup keys
// and enrolls peers over HTTP.
//
// Usage:
//
//	server [flags]                     run the control plane
//	server newkey [flags]              mint a setup key and print it
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	iofs "io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	gowireguard "gowireguard"
	"gowireguard/internal/firewall"
	"gowireguard/internal/httpx"
	"gowireguard/internal/proto"
	"gowireguard/internal/psk"
	"gowireguard/internal/relay"
	"gowireguard/internal/store"
	"gowireguard/internal/tlsutil"
)

// keepaliveSeconds is handed to every peer. The control plane decides
// this, not the agent — resolves the old agent-side TODO.
const keepaliveSeconds = 25

const defaultNetwork6CIDR = "fd00:100:64::/64"

const punchCooldown = 2 * time.Minute

// maxPunchAttempts caps how many coordinated hole-punch epochs the control
// plane emits for one continuous relay episode. A pair that cannot punch
// (e.g. firewall-blocked inbound) then rests on relay instead of being told
// to tear it down forever; the count resets once the pair reaches direct.
const maxPunchAttempts = 3

type server struct {
	store        *store.Store
	networkMu    sync.RWMutex
	networkCIDR  string
	network6CIDR string
	pskMaster    wgtypes.Key // never distributed; per-pair PSKs derive from it
	adminToken   string
	trustProxy   bool
	relay        relayAllocator // nil when no relay is configured
	relayHost    string         // public data-plane address agents dial
	wsHub        *relay.WSHub   // nil unless the embedded WS relay is enabled
	signalHub    *signalHub
	accessLog    *accessLogSink
	punchMu      sync.Mutex
	punchEpochs  map[string]punchEpoch
}

type punchEpoch struct {
	epoch    int
	bumpedAt time.Time
	attempts int // coordinated tries this relay episode; reset on reaching direct
}

// clientIP is the peer's underlay address as seen by the control
// plane. Behind a TLS-terminating proxy (Traefik) every request comes
// from the proxy, so --trust-proxy switches to X-Forwarded-For —
// trusting that header from direct clients would let them spoof it.
//
// The RIGHTMOST X-Forwarded-For entry is used, never the first: a
// proxy APPENDS the address it observed to whatever the client sent,
// so the last entry is the only one the trusted proxy vouches for.
// Taking the first would let any client choose its own logged and
// rate-limited identity by sending a forged X-Forwarded-For. This
// assumes exactly one trusted proxy in front (the supported
// topology); the full header chain is still recorded in the access
// and audit logs for forensics.
func (s *server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}

	return host
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "newkey" {
		return runNewKey(os.Args[2:])
	}

	return runServe(os.Args[1:])
}

func runNewKey(args []string) error {
	fs := flag.NewFlagSet("newkey", flag.ExitOnError)
	dbPath := fs.String("db", "mesh.db", "path to sqlite database")
	network := fs.String("network", "100.64.0.0/16", "overlay network (CIDR)")
	name := fs.String("name", "", "human-readable setup key name")
	maxUses := fs.Int("max-uses", 0, "maximum enrollments (0 = unlimited)")
	expiresIn := fs.Duration("expires-in", 0, "time until expiry (0 = never; negative mints an already-expired key, for testing)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	prefix, err := netip.ParsePrefix(*network)
	if err != nil {
		return fmt.Errorf("parse network %q: %w", *network, err)
	}

	st, err := store.Open(*dbPath, prefix, gowireguard.SchemaSQL)
	if err != nil {
		return err
	}
	defer st.Close()

	key, err := st.CreateNamedSetupKey(context.Background(), *name, *maxUses, *expiresIn)
	if err != nil {
		return err
	}

	fmt.Println(key)

	return nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	dbPath := fs.String("db", "mesh.db", "path to sqlite database")
	listen := fs.String("listen", "127.0.0.1:8080", "listen address")
	network := fs.String("network", "100.64.0.0/16", "overlay network (CIDR)")
	network6 := fs.String("network6", defaultNetwork6CIDR, "IPv6 overlay network (CIDR)")
	pskFile := fs.String("psk-file", "mesh-psk.key", "path to network preshared key file")
	noTLS := fs.Bool("no-tls", false, "serve plain HTTP: for dev, or production behind a TLS-terminating reverse proxy (e.g. Traefik)")
	tlsCert := fs.String("tls-cert", "cert.pem", "path to TLS certificate (self-signed generated if missing)")
	tlsKey := fs.String("tls-key", "key.pem", "path to TLS private key (generated if missing)")
	tlsHosts := fs.String("tls-hosts", "localhost,127.0.0.1", "comma-separated SANs for a generated certificate; include the address agents will dial")
	adminTokenFile := fs.String("admin-token-file", "admin-token", "path to admin API token file (generated if missing)")
	flowRetention := fs.Duration("flow-retention", 7*24*time.Hour, "how long to keep flow log rows")
	trustProxy := fs.Bool("trust-proxy", false, "trust X-Forwarded-For for client addresses (only behind a reverse proxy)")
	relayHost := fs.String("relay-host", "", "address agents dial for relayed traffic (enables relay fallback)")
	relayEmbedded := fs.Bool("relay-embedded", false, "run the relay inside this process (NetBird-style single binary; no relay-control/secret needed)")
	relayPortMin := fs.Int("relay-port-min", 51900, "embedded relay: lowest forwarding UDP port")
	relayPortMax := fs.Int("relay-port-max", 51999, "embedded relay: highest forwarding UDP port")
	relayControl := fs.String("relay-control", "http://127.0.0.1:8081", "standalone relay: control API URL")
	relaySecretFile := fs.String("relay-secret-file", "relay-secret", "standalone relay: path to the control shared secret")
	defaultPolicy := fs.String("default-policy", "allow", "ACL default: \"allow\" (open mesh) or \"deny\" (only rule-connected pairs see each other)")
	dnsEnabled := fs.Bool("dns-enabled", false, "push DNS settings to agents")
	dnsNameservers := fs.String("dns-nameservers", "", "comma-separated DNS server IPs to push to agents (for example your CoreDNS overlay IP)")
	dnsDomain := fs.String("dns-domain", "vpn", "mesh DNS domain/search suffix to push to agents")
	dnsSearchDomains := fs.String("dns-search-domains", "", "comma-separated DNS search domains to push to agents (default: --dns-domain when DNS is enabled)")
	dnsMagic := fs.Bool("dns-magic", true, "enable peer-name style DNS search behavior for the mesh domain")
	manageFirewall := fs.Bool("manage-firewall", true, "open the API port on the host firewall (removed again on shutdown)")
	tokenTTL := fs.Duration("token-ttl", 0, "peer auth token lifetime (0 = never expires); agents re-enroll to refresh")
	auditRetention := fs.Duration("audit-retention", 90*24*time.Hour, "how long to keep audit-log rows")
	rateLimit := fs.Float64("rate-limit", 20, "per-source requests/second on public endpoints (0 = disabled)")
	rateBurst := fs.Float64("rate-burst", 40, "per-source burst allowance on public endpoints")
	accessLogRaw := fs.String("access-log", "memory", "request access log mode: memory, stdout, or off")
	accessLogSize := fs.Int("access-log-size", 1000, "request access log ring size when --access-log=memory")
	logLevel := fs.String("log-level", "info", "minimum log level: debug, info, warn, or error")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := setupLogging(*logLevel); err != nil {
		return err
	}

	if *trustProxy && !isLoopback(*listen) {
		// XFF from a direct client is attacker-controlled; only trust
		// it when a proxy terminates in front. Binding non-loopback
		// with trust-proxy means the proxy MUST be the only reachable
		// front door — warn loudly so a misconfig is visible.
		slog.Warn("--trust-proxy is set on a non-loopback listener: ensure a reverse proxy is the ONLY thing that can reach this port, or clients can spoof X-Forwarded-For", "listen", *listen)
	}

	accessMode, err := parseAccessLogMode(*accessLogRaw)
	if err != nil {
		return err
	}

	prefix, err := parseNetwork4(*network)
	if err != nil {
		return err
	}

	prefix6, err := parseNetwork6(*network6)
	if err != nil {
		return err
	}

	st, err := store.Open(*dbPath, prefix, gowireguard.SchemaSQL)
	if err != nil {
		return err
	}
	defer st.Close()

	networkCfg, err := st.LoadOrInitNetworkConfig(context.Background(), prefix, prefix6)
	if err != nil {
		return err
	}

	switch *defaultPolicy {
	case "allow":
		st.DefaultAllow = true
	case "deny":
		st.DefaultAllow = false
	default:
		return fmt.Errorf("default-policy must be \"allow\" or \"deny\", got %q", *defaultPolicy)
	}

	st.TokenTTL = *tokenTTL

	searchDomains := splitCSV(*dnsSearchDomains)
	if *dnsEnabled && len(searchDomains) == 0 && strings.TrimSpace(*dnsDomain) != "" {
		searchDomains = []string{*dnsDomain}
	}
	dnsCfg, err := st.LoadOrInitDNSConfig(context.Background(), store.DNSConfig{
		Enabled:       *dnsEnabled,
		MagicDNS:      *dnsMagic,
		Domain:        *dnsDomain,
		Nameservers:   splitCSV(*dnsNameservers),
		SearchDomains: searchDomains,
	})
	if err != nil {
		return err
	}

	networkPSK, err := psk.LoadOrGenerate(*pskFile)
	if err != nil {
		return err
	}

	adminToken, err := loadOrGenerateAdminToken(*adminTokenFile)
	if err != nil {
		return err
	}

	if *manageFirewall {
		if _, portStr, err := net.SplitHostPort(*listen); err == nil {
			if port, err := strconv.Atoi(portStr); err == nil {
				fw, ferr := firewall.OpenWithReconcile("wgmesh-server", *dbPath+".server.fw")
				if ferr != nil {
					slog.Warn("firewall unavailable; open the API port yourself if needed", "error", ferr, "tcp", port)
				} else if err := fw.AllowTCP(port); err != nil {
					// Common when running unprivileged; the API port
					// then needs opening by hand.
					slog.Warn("firewall rule failed", "backend", fw.Backend(), "error", err)
				} else {
					slog.Info("firewall opened api port", "backend", fw.Backend(), "tcp", port)
					defer func() {
						if err := fw.Close(); err != nil {
							slog.Warn("firewall cleanup failed", "error", err)
						}
					}()
				}
			}
		}
	}

	srv := &server{
		store:        st,
		networkCIDR:  networkCfg.NetworkCIDR,
		network6CIDR: networkCfg.NetworkCIDR6,
		pskMaster:    networkPSK,
		adminToken:   adminToken,
		trustProxy:   *trustProxy,
		accessLog:    newAccessLogSink(accessMode, *accessLogSize),
		signalHub:    newSignalHub(),
		punchEpochs:  make(map[string]punchEpoch),
	}

	switch {
	case *relayEmbedded:
		// NetBird-style single binary: the relay runs in-process, the
		// allocator is a function call, and no shared secret exists.
		if *relayHost == "" {
			return errors.New("--relay-embedded requires --relay-host (the address agents dial, e.g. this host's LAN or public IP)")
		}

		rs, err := relay.New(relay.Config{PortMin: *relayPortMin, PortMax: *relayPortMax})
		if err != nil {
			return err
		}
		defer rs.Close()

		srv.relay = embeddedRelay{rs: rs}
		srv.relayHost = *relayHost

		// The WebSocket relay rides this process's own port, so it
		// works over the same 443 as the API — no extra firewall
		// holes. Only the embedded relay offers it (it needs the
		// store for auth); a standalone relay stays UDP-only.
		srv.wsHub = relay.NewWSHub()

		if *manageFirewall {
			fw, ferr := firewall.OpenWithReconcile("wgmesh-server-relay", *dbPath+".relay.fw")
			if ferr != nil {
				slog.Warn("firewall unavailable; open the relay range yourself if needed", "error", ferr, "udp_min", *relayPortMin, "udp_max", *relayPortMax)
			} else if err := fw.AllowUDPRange(*relayPortMin, *relayPortMax); err != nil {
				slog.Warn("firewall rule failed", "backend", fw.Backend(), "error", err)
			} else {
				slog.Info("firewall opened relay range", "backend", fw.Backend(), "udp_min", *relayPortMin, "udp_max", *relayPortMax)
				defer func() {
					if err := fw.Close(); err != nil {
						slog.Warn("firewall cleanup failed", "error", err)
					}
				}()
			}
		}

		slog.Info("embedded relay enabled", "udp_min", *relayPortMin, "udp_max", *relayPortMax, "relay_host", *relayHost)

	case *relayHost != "":
		rc, err := newRelayClient(*relayControl, *relaySecretFile)
		if err != nil {
			return err
		}

		srv.relay = rc
		srv.relayHost = *relayHost

		slog.Info("standalone relay fallback enabled", "relay_host", *relayHost, "control", *relayControl)
	}

	ui, err := iofs.Sub(gowireguard.WebUI, "web/dist")
	if err != nil {
		return fmt.Errorf("locate embedded web ui: %w", err)
	}

	// publicLimit throttles the unauthenticated / peer-facing routes,
	// which are the ones exposed to the internet on a VPS control
	// plane. Admin routes are already gated by the admin token.
	publicLimit := func(h http.HandlerFunc) http.HandlerFunc {
		if *rateLimit <= 0 {
			return h
		}

		return httpx.NewRateLimiter(*rateLimit, *rateBurst).Middleware(srv.clientIP, h)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll", publicLimit(srv.handleEnroll))
	mux.HandleFunc("POST /report", publicLimit(srv.handleReport))
	mux.HandleFunc("GET /signal", publicLimit(srv.handleSignalWS))
	mux.HandleFunc("POST /relay-pair", publicLimit(srv.handleRelayPair))
	mux.HandleFunc("GET /relay-ws", publicLimit(srv.handleRelayWS))
	mux.HandleFunc("POST /ui-login", publicLimit(srv.handleUILogin))
	mux.Handle("GET /", srv.uiHandler(ui))
	mux.HandleFunc("GET /api/peers", srv.requireAdmin(srv.handleListPeers))
	mux.HandleFunc("POST /api/mobile-peers", srv.requireAdmin(srv.handleCreateMobilePeer))
	mux.HandleFunc("GET /api/peers/{id}/ping", srv.requireAdmin(srv.handlePingPeer))
	mux.HandleFunc("POST /api/peers/{id}/address", srv.requireAdmin(srv.handleUpdatePeerAddress))
	mux.HandleFunc("POST /api/peers/{id}/revoke", srv.requireAdmin(srv.handleRevokePeer))
	mux.HandleFunc("POST /api/peers/{id}/remove", srv.requireAdmin(srv.handleRemovePeer))
	mux.HandleFunc("GET /api/setup-keys", srv.requireAdmin(srv.handleListSetupKeys))
	mux.HandleFunc("POST /api/setup-keys", srv.requireAdmin(srv.handleCreateSetupKey))
	mux.HandleFunc("POST /api/setup-keys/{id}/revoke", srv.requireAdmin(srv.handleRevokeSetupKey))
	mux.HandleFunc("GET /api/link-stats", srv.requireAdmin(srv.handleListLinkStats))
	mux.HandleFunc("GET /api/flows", srv.requireAdmin(srv.handleListFlows))
	mux.HandleFunc("GET /api/access-log", srv.requireAdmin(srv.handleListAccessLog))
	mux.HandleFunc("GET /api/network", srv.requireAdmin(srv.handleGetNetwork))
	mux.HandleFunc("POST /api/network/preview", srv.requireAdmin(srv.handlePreviewNetworkMigration))
	mux.HandleFunc("POST /api/network/apply", srv.requireAdmin(srv.handleApplyNetworkMigration))
	mux.HandleFunc("GET /api/dns", srv.requireAdmin(srv.handleGetDNS))
	mux.HandleFunc("POST /api/dns", srv.requireAdmin(srv.handleUpdateDNS))
	mux.HandleFunc("GET /api/acl", srv.requireAdmin(srv.handleListACL))
	mux.HandleFunc("GET /api/acl/export", srv.requireAdmin(srv.handleExportACL))
	mux.HandleFunc("POST /api/acl/import", srv.requireAdmin(srv.handleImportACL))
	mux.HandleFunc("POST /api/acl", srv.requireAdmin(srv.handleCreateACL))
	mux.HandleFunc("POST /api/acl/{id}/delete", srv.requireAdmin(srv.handleDeleteACL))
	mux.HandleFunc("GET /api/audit", srv.requireAdmin(srv.handleListAudit))
	mux.HandleFunc("GET /api/connection-events", srv.requireAdmin(srv.handleListConnectionEvents))
	mux.HandleFunc("GET /api/proxy-events", srv.requireAdmin(srv.handleListProxyEvents))
	mux.HandleFunc("GET /healthz", srv.handleHealthz)

	// Every request gets security headers and a structured access-log
	// line with the original IP, proxy chain, overlay IP, and redacted
	// headers.
	handler := srv.logRequests(securityHeaders(mux))

	pruneCtx, cancelPrune := context.WithCancel(context.Background())
	defer cancelPrune()

	go srv.pruneFlowsLoop(pruneCtx, *flowRetention)
	go srv.pruneAuditLoop(pruneCtx, *auditRetention)

	if srv.relay == nil {
		slog.Info("relay fallback disabled; direct UDP connectivity between peers is required")
	}
	if dnsCfg.Enabled {
		slog.Info("dns settings enabled", "nameservers", strings.Join(dnsCfg.Nameservers, ","), "domain", dnsCfg.Domain, "search_domains", strings.Join(dnsCfg.SearchDomains, ","))
	}

	httpSrv := newHTTPServer(*listen, handler)

	if *noTLS {
		if !isLoopback(*listen) && !*trustProxy {
			slog.Warn("serving plain HTTP with no TLS: setup keys, the admin token, and peer tokens cross the wire in cleartext; use only on a trusted network, or put TLS in front (Traefik) and set --trust-proxy", "listen", *listen)
		}

		slog.Info("control plane up (plain HTTP; terminate TLS upstream or use for dev only)",
			"url", "http://"+*listen, "network", srv.networkCIDR+srv.network6LogSuffix(), "db", *dbPath)
		slog.Info("web ui ready", "url", "http://"+*listen+"/", "token_file", *adminTokenFile)

		return runHTTPServer(httpSrv, false, "", "")
	}

	hosts := strings.Split(*tlsHosts, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}

	if err := tlsutil.LoadOrGenerateCert(*tlsCert, *tlsKey, hosts); err != nil {
		return err
	}

	slog.Info("control plane up",
		"url", "https://"+*listen, "network", srv.networkCIDR+srv.network6LogSuffix(), "db", *dbPath)
	slog.Info("web ui ready", "url", "https://"+*listen+"/", "token_file", *adminTokenFile)
	slog.Info("agents should pin the certificate", "server_ca", *tlsCert)

	return runHTTPServer(httpSrv, true, *tlsCert, *tlsKey)
}

func network6CIDR(prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return ""
	}

	return prefix.String()
}

func parseNetwork4(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse network %q: %w", raw, err)
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("--network must be an IPv4 CIDR, got %q", raw)
	}

	return prefix.Masked(), nil
}

func parseNetwork6(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse network6 %q: %w", raw, err)
	}
	if !prefix.Addr().Is6() {
		return netip.Prefix{}, fmt.Errorf("--network6 must be an IPv6 CIDR, got %q", raw)
	}

	return prefix.Masked(), nil
}

func splitCSV(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (s *server) network6LogSuffix() string {
	cfg := s.currentNetworkConfig()
	if cfg.NetworkCIDR6 == "" {
		return ""
	}

	return ", " + cfg.NetworkCIDR6
}

func (s *server) currentNetworkConfig() store.NetworkConfig {
	s.networkMu.RLock()
	defer s.networkMu.RUnlock()

	return store.NetworkConfig{
		NetworkCIDR:  s.networkCIDR,
		NetworkCIDR6: s.network6CIDR,
	}
}

func (s *server) setNetworkConfig(cfg store.NetworkConfig) {
	s.networkMu.Lock()
	defer s.networkMu.Unlock()

	s.networkCIDR = cfg.NetworkCIDR
	s.network6CIDR = cfg.NetworkCIDR6
}

func (s *server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req proto.EnrollRequest

	// 64KB is generous for a key + hostname + endpoint; /enroll is
	// public, so an unbounded decode here would be a memory-DoS vector.
	if !decodeJSON(w, r, 64<<10, &req) {
		return
	}

	if req.SetupKey == "" {
		writeError(w, http.StatusBadRequest, "setup_key is required")
		return
	}

	if _, err := wgtypes.ParseKey(req.PublicKey); err != nil {
		writeError(w, http.StatusBadRequest, "public_key is not a valid WireGuard key")
		return
	}

	if req.ListenPort < 0 || req.ListenPort > 65535 {
		writeError(w, http.StatusBadRequest, "listen_port out of range")
		return
	}

	res, err := s.store.Enroll(r.Context(), req.SetupKey, req.PublicKey, req.Hostname, req.ListenPort, s.clientIP(r), req.PublicEndpoint)

	switch {
	case errors.Is(err, store.ErrUnauthorized):
		// Uniform 401: invalid, expired, revoked, and exhausted are
		// indistinguishable on the wire. The real reason goes to the
		// server log and audit trail only.
		slog.Warn("enroll rejected", "public_key", req.PublicKey, "listen_port", req.ListenPort, "error", err)
		s.audit(r, "enroll_rejected", http.StatusUnauthorized, err.Error())
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	case err != nil:
		slog.Error("enroll failed", "public_key", req.PublicKey, "listen_port", req.ListenPort, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	enrichRequest(r, res.Peer.ID, res.Peer.AssignedIP)

	if res.Created {
		slog.Info("enrolled peer", "peer_id", res.Peer.ID, "public_key", req.PublicKey, "assigned_ip", res.Peer.AssignedIP, "listen_port", req.ListenPort, "endpoint", req.PublicEndpoint)
		s.audit(r, "enroll", http.StatusOK, fmt.Sprintf("new peer %s (%s)", res.Peer.AssignedIP, req.Hostname))
	} else {
		slog.Info("idempotent re-enroll", "peer_id", res.Peer.ID, "public_key", req.PublicKey, "listen_port", req.ListenPort, "endpoint", req.PublicEndpoint)
		s.audit(r, "re_enroll", http.StatusOK, fmt.Sprintf("peer %s (%s)", res.Peer.AssignedIP, req.Hostname))
	}

	out, err := s.buildResponse(r.Context(), res)
	if err != nil {
		slog.Error("build enroll response failed", "public_key", req.PublicKey, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")

		return
	}

	writeJSON(w, http.StatusOK, out)
}

// lanEndpoint is the address the control plane observed the peer at,
// paired with its listen port — the path that works when both sides
// share a network with the server.
func lanEndpoint(p store.PeerRow) *string {
	if p.ObservedIP != "" && p.ListenPort > 0 {
		ep := net.JoinHostPort(p.ObservedIP, strconv.Itoa(p.ListenPort))
		return &ep
	}

	return nil
}

// sameHost reports whether two "host:port" endpoints share a host.
func sameHost(a, b string) bool {
	ha, _, errA := net.SplitHostPort(a)
	hb, _, errB := net.SplitHostPort(b)

	return errA == nil && errB == nil && ha == hb
}

// endpointHint picks the best-known underlay endpoint for the peer p,
// as seen from the peer self requesting the list.
//
// Normally p's own STUN discovery wins. But when BOTH sides
// discovered the same public IP, they sit behind the same NAT — the
// STUN address would have to hairpin through their shared router,
// which most consumer NATs refuse. The address the control plane
// observed p at is the path that actually routes in that topology.
//
// Hints are exactly that — WireGuard roaming overrides them the
// moment authenticated traffic arrives from somewhere else.
func endpointHint(self, p store.PeerRow) *string {
	candidates := endpointCandidates(self, p)
	if len(candidates) == 0 {
		return nil
	}

	return &candidates[0].Endpoint
}

func endpointCandidates(self, p store.PeerRow) []proto.EndpointCandidate {
	var out []proto.EndpointCandidate
	seen := map[string]bool{}

	add := func(endpoint, typ string, priority int) {
		if endpoint == "" || seen[endpoint] {
			return
		}
		seen[endpoint] = true
		out = append(out, proto.EndpointCandidate{
			Endpoint: endpoint,
			Type:     typ,
			Priority: priority,
		})
	}

	lan := lanEndpoint(p)
	if p.PublicEndpoint != "" && self.PublicEndpoint != "" && sameHost(self.PublicEndpoint, p.PublicEndpoint) && lan != nil {
		add(*lan, "lan", 100)
		add(p.PublicEndpoint, "stun", 80)
		return out
	}

	if p.PublicEndpoint != "" {
		add(p.PublicEndpoint, "stun", 100)
	}
	if lan != nil {
		add(*lan, "lan", 80)
	}

	return out
}

func (s *server) buildPeerEntries(self store.PeerRow, others []store.PeerRow) ([]proto.PeerConfigResponse, error) {
	keepalive := keepaliveSeconds

	peers := make([]proto.PeerConfigResponse, 0, len(others))

	for _, o := range others {
		pairKey, err := psk.DerivePairKey(s.pskMaster, self.PublicKey, o.PublicKey)
		if err != nil {
			return nil, err
		}

		pairPSK := pairKey.String()

		peers = append(peers, proto.PeerConfigResponse{
			PublicKey:                   o.PublicKey,
			PresharedKey:                &pairPSK,
			Endpoint:                    endpointHint(self, o),
			EndpointCandidates:          endpointCandidates(self, o),
			PunchEpoch:                  s.punchEpoch(self.PublicKey, o.PublicKey),
			PersistentKeepaliveInterval: &keepalive,
			AllowedIPs:                  allowedIPsForPeer(o),
		})
	}

	return peers, nil
}

func (s *server) buildACLPolicy(ctx context.Context) (*proto.ACLPolicy, error) {
	policy := "deny"
	if s.store.DefaultAllow {
		policy = "allow"
	}

	out := &proto.ACLPolicy{DefaultPolicy: policy}
	if s.store.DefaultAllow {
		return out, nil
	}

	peers, err := s.store.ListPeers(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]store.PeerInfo, len(peers))
	for _, p := range peers {
		if p.RevokedAt == "" {
			byID[p.ID] = p
		}
	}

	rules, err := s.store.ListACLRules(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		pr := proto.ACLRule{Protocol: r.Protocol}
		if r.PortMin != nil {
			pr.PortMin = int(*r.PortMin)
		}
		if r.PortMax != nil {
			pr.PortMax = int(*r.PortMax)
		}
		if r.SrcPeerID != nil {
			p, ok := byID[*r.SrcPeerID]
			if !ok {
				continue
			}
			pr.SrcIP = p.AssignedIP
			pr.SrcIP6 = p.AssignedIP6
		}
		if r.DstPeerID != nil {
			p, ok := byID[*r.DstPeerID]
			if !ok {
				continue
			}
			pr.DstIP = p.AssignedIP
			pr.DstIP6 = p.AssignedIP6
		}
		out.Rules = append(out.Rules, pr)
	}

	return out, nil
}

func (s *server) punchEpoch(keyA, keyB string) int {
	if s == nil {
		return 0
	}

	s.punchMu.Lock()
	defer s.punchMu.Unlock()

	return s.punchEpochs[relayPairID(keyA, keyB)].epoch
}

func allowedIPsForPeer(p store.PeerRow) []string {
	allowed := []string{p.AssignedIP + "/32"}
	if p.AssignedIP6 != "" {
		allowed = append(allowed, p.AssignedIP6+"/128")
	}

	return allowed
}

func (s *server) buildResponse(ctx context.Context, res *store.EnrollResult) (proto.EnrollResponse, error) {
	peers, err := s.buildPeerEntries(res.Peer, res.Others)
	if err != nil {
		return proto.EnrollResponse{}, err
	}

	cfg := s.currentNetworkConfig()
	dnsCfg, err := s.store.CurrentDNSConfig(ctx)
	if err != nil {
		return proto.EnrollResponse{}, err
	}
	acl, err := s.buildACLPolicy(ctx)
	if err != nil {
		return proto.EnrollResponse{}, err
	}

	return proto.EnrollResponse{
		PeerID:       int(res.Peer.ID),
		AssignedIP:   res.Peer.AssignedIP,
		AssignedIP6:  res.Peer.AssignedIP6,
		NetworkCIDR:  cfg.NetworkCIDR,
		NetworkCIDR6: cfg.NetworkCIDR6,
		DNS:          dnsConfigProto(dnsCfg),
		Peers:        peers,
		ACL:          acl,
		AuthToken:    res.AuthToken,
	}, nil
}

func dnsConfigProto(cfg store.DNSConfig) proto.DNSConfig {
	return proto.DNSConfig{
		Enabled:       cfg.Enabled,
		MagicDNS:      cfg.MagicDNS,
		Domain:        cfg.Domain,
		Nameservers:   append([]string(nil), cfg.Nameservers...),
		SearchDomains: append([]string(nil), cfg.SearchDomains...),
	}
}
