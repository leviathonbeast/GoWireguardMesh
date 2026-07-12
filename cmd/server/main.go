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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	iofs "io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	gowireguard "gowireguard"
	"gowireguard/internal/buildinfo"
	"gowireguard/internal/firewall"
	"gowireguard/internal/httpx"
	"gowireguard/internal/keyseal"
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
	pskMaster    wgtypes.Key     // never distributed; per-pair PSKs derive from it
	deviceKeys   *keyseal.Sealer // seals static peers' private keys at rest
	adminToken   string
	sessionKey   []byte // HMAC key for UI session cookies; independent of adminToken
	trustProxy   bool
	relay        relayAllocator // nil when no relay is configured
	relayHost    string         // public data-plane address agents dial
	wsHub        *relay.WSHub   // nil unless the embedded WS relay is enabled
	quicHub      *relay.WSHub   // nil unless the embedded QUIC relay is enabled
	quicEndpoint string         // public host:port agents dial for QUIC relay
	stunServers  []string       // mesh STUN endpoints advertised to agents; empty when disabled
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
	sessionKeyFile := fs.String("session-key-file", "session.key", "path to the web-UI session signing key (generated if missing)")
	adminUser := fs.String("admin-user", "admin", "username seeded on first boot with the admin token as its initial password")
	flowRetention := fs.Duration("flow-retention", 7*24*time.Hour, "how long to keep flow log rows")
	trustProxy := fs.Bool("trust-proxy", false, "trust X-Forwarded-For for client addresses (only behind a reverse proxy)")
	relayHost := fs.String("relay-host", "", "address agents dial for relayed traffic (enables relay fallback)")
	relayEmbedded := fs.Bool("relay-embedded", false, "run the relay inside this process (NetBird-style single binary; no relay-control/secret needed)")
	relayPortMin := fs.Int("relay-port-min", 51900, "embedded relay: lowest forwarding UDP port")
	relayPortMax := fs.Int("relay-port-max", 51999, "embedded relay: highest forwarding UDP port")
	relayQUICPort := fs.Int("relay-quic-port", 51890, "embedded relay: QUIC datagram forwarding port (0 disables)")
	stunPort := fs.Int("stun-port", 3478, "embedded relay: serve mesh STUN on this UDP port and the next (0 disables); agents use the pair to refresh endpoints and classify their NAT")
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
	slog.Info("wgmesh server starting", "git_commit", buildinfo.Commit())

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

	sessionKey, err := loadOrGenerateSessionKey(*sessionKeyFile)
	if err != nil {
		return err
	}

	// Seed the initial admin account on first boot so existing deployments
	// keep working: sign in as --admin-user with the admin token, then set
	// a real password from the UI. No-op once any user exists.
	if seeded, err := st.EnsureSeedUser(context.Background(), *adminUser, adminToken); err != nil {
		return fmt.Errorf("seed admin user: %w", err)
	} else if seeded {
		slog.Info("seeded initial admin user; log in with the admin token as the password and change it", "user", *adminUser)
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

	deviceKeys, err := keyseal.New(networkPSK)
	if err != nil {
		return err
	}

	srv := &server{
		store:        st,
		networkCIDR:  networkCfg.NetworkCIDR,
		network6CIDR: networkCfg.NetworkCIDR6,
		pskMaster:    networkPSK,
		deviceKeys:   deviceKeys,
		adminToken:   adminToken,
		sessionKey:   sessionKey,
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
		if *relayQUICPort > 0 {
			srv.quicHub = relay.NewWSHub()
			srv.quicEndpoint = net.JoinHostPort(relayEndpointHost(*relayHost), strconv.Itoa(*relayQUICPort))
		}

		// Mesh STUN: two ports on the relay host so agents can refresh
		// their public endpoint and classify their NAT without any
		// third-party STUN dependency.
		if *stunPort > 0 {
			stun, err := relay.NewSTUNResponder(nil, *stunPort)
			if err != nil {
				slog.Warn("mesh stun disabled", "error", err)
			} else {
				defer stun.Close()
				srv.stunServers = []string{
					net.JoinHostPort(*relayHost, strconv.Itoa(*stunPort)),
					net.JoinHostPort(*relayHost, strconv.Itoa(*stunPort+1)),
				}
				slog.Info("mesh stun enabled", "ports", []int{*stunPort, *stunPort + 1}, "host", *relayHost)
			}
		}

		if *manageFirewall {
			fw, ferr := firewall.OpenWithReconcile("wgmesh-server-relay", *dbPath+".relay.fw")
			if ferr != nil {
				slog.Warn("firewall unavailable; open the relay range yourself if needed", "error", ferr, "udp_min", *relayPortMin, "udp_max", *relayPortMax)
			} else if err := fw.AllowUDPRange(*relayPortMin, *relayPortMax); err != nil {
				slog.Warn("firewall rule failed", "backend", fw.Backend(), "error", err)
			} else {
				slog.Info("firewall opened relay range", "backend", fw.Backend(), "udp_min", *relayPortMin, "udp_max", *relayPortMax)
				if *relayQUICPort > 0 {
					if err := fw.AllowUDPRange(*relayQUICPort, *relayQUICPort); err != nil {
						slog.Warn("firewall quic rule failed", "backend", fw.Backend(), "error", err)
					}
				}
				if len(srv.stunServers) > 0 {
					if err := fw.AllowUDPRange(*stunPort, *stunPort+1); err != nil {
						slog.Warn("firewall stun rule failed", "backend", fw.Backend(), "error", err)
					}
				}
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

		// The standalone relay serves STUN itself (its --stun-port,
		// default 3478); the control plane just advertises where. Agents
		// degrade gracefully if the relay build predates STUN.
		if *stunPort > 0 {
			srv.stunServers = []string{
				net.JoinHostPort(*relayHost, strconv.Itoa(*stunPort)),
				net.JoinHostPort(*relayHost, strconv.Itoa(*stunPort+1)),
			}
		}

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
	mux.HandleFunc("POST /relay-quic", publicLimit(srv.handleRelayQUICInfo))
	mux.HandleFunc("POST /ui-login", publicLimit(srv.handleUILogin))
	mux.Handle("GET /", srv.uiHandler(ui))
	mux.HandleFunc("GET /api/peers", srv.requireAdmin(srv.handleListPeers))
	mux.HandleFunc("POST /api/mobile-peers", srv.requireAdmin(srv.handleCreateMobilePeer))
	mux.HandleFunc("GET /api/peers/{id}/config", srv.requireAdmin(srv.handleStaticPeerConfig))
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

	// Auth: session (who am I / change own password) and admin user
	// management. Account endpoints require a UI session, not the bearer
	// token, because they act as a specific user.
	mux.HandleFunc("POST /api/logout", srv.handleLogout)
	mux.HandleFunc("GET /api/account", srv.requireSession(srv.handleAccount))
	mux.HandleFunc("POST /api/account/password", srv.requireSession(srv.handleChangePassword))
	mux.HandleFunc("GET /api/users", srv.requireAdmin(srv.handleListUsers))
	mux.HandleFunc("POST /api/users", srv.requireAdmin(srv.handleCreateUser))
	mux.HandleFunc("POST /api/users/{id}/delete", srv.requireAdmin(srv.handleDeleteUser))

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
	hosts := strings.Split(*tlsHosts, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}
	if srv.quicHub != nil {
		hosts = append(hosts, relayEndpointHost(*relayHost))
	}
	if !*noTLS || srv.quicHub != nil {
		if err := tlsutil.LoadOrGenerateCert(*tlsCert, *tlsKey, hosts); err != nil {
			return err
		}
	}
	if srv.quicHub != nil {
		closeQUIC, err := srv.startQUICRelay(*relayQUICPort, *tlsCert, *tlsKey)
		if err != nil {
			return err
		}
		defer closeQUIC()
	}

	if *noTLS {
		if !isLoopback(*listen) && !*trustProxy {
			slog.Warn("serving plain HTTP with no TLS: setup keys, the admin token, and peer tokens cross the wire in cleartext; use only on a trusted network, or put TLS in front (Traefik) and set --trust-proxy", "listen", *listen)
		}

		slog.Info("control plane up (plain HTTP; terminate TLS upstream or use for dev only)",
			"url", "http://"+*listen, "network", srv.networkCIDR+srv.network6LogSuffix(), "db", *dbPath)
		slog.Info("web ui ready", "url", "http://"+*listen+"/", "token_file", *adminTokenFile)

		return runHTTPServer(httpSrv, false, "", "")
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

	// Persist the enrollee's self-gathered candidates outside the enroll
	// transaction: losing this write is harmless (every report re-sends
	// the list), and it keeps Enroll's idempotent-retry path untouched.
	if cands := encodeAgentCandidates(req.Candidates); cands != "" {
		if err := s.store.UpdatePeerCandidates(r.Context(), res.Peer.ID, cands); err != nil {
			slog.Warn("store enroll candidates failed", "peer_id", res.Peer.ID, "error", err)
		} else {
			res.Peer.CandidatesJSON = cands
		}
	}

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

// maxEndpointCandidates bounds how many candidates a peer entry carries.
// The agents' coordinated probe window (45s at 8s per candidate) can
// realistically try about this many before restoring relay, so anything
// past six would never be probed anyway.
const maxEndpointCandidates = 6

// maxAgentCandidates bounds how many self-reported candidates one peer
// may store; a hostile agent must not be able to grow every OTHER
// peer's sync payload without limit.
const maxAgentCandidates = 8

// encodeAgentCandidates canonicalizes an agent-supplied candidate list
// for storage: parseable udp host:port endpoints only (these get handed
// to every other agent's WireGuard config), known types only, capped.
// Returns "" when nothing valid remains.
func encodeAgentCandidates(cands []proto.AgentCandidate) string {
	kept := make([]proto.AgentCandidate, 0, len(cands))

	for _, c := range cands {
		if len(kept) == maxAgentCandidates {
			break
		}

		switch c.Type {
		case "host", "host6", "upnp":
		default:
			continue
		}

		if _, err := net.ResolveUDPAddr("udp", c.Endpoint); err != nil {
			continue
		}

		kept = append(kept, c)
	}

	if len(kept) == 0 {
		return ""
	}

	raw, err := json.Marshal(kept)
	if err != nil {
		return ""
	}

	return string(raw)
}

// agentCandidates decodes a peer's stored self-reported candidates;
// missing or malformed JSON is simply "no candidates".
func agentCandidates(p store.PeerRow) []proto.AgentCandidate {
	if p.CandidatesJSON == "" {
		return nil
	}

	var out []proto.AgentCandidate
	if err := json.Unmarshal([]byte(p.CandidatesJSON), &out); err != nil {
		return nil
	}

	if len(out) > maxAgentCandidates {
		out = out[:maxAgentCandidates]
	}

	return out
}

// endpointHint picks the best-known underlay endpoint for the peer p,
// as seen from the peer self requesting the list.
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

// endpointCandidates builds the ordered list of ways self might reach
// p, highest priority first. Sources: p's self-gathered candidates
// (interface addresses, router mappings), its STUN discovery, and the
// address the control plane observed it at.
//
// The big fork is whether the two sides discovered the same public IP.
// If they did, they sit behind the same NAT: p's own interface
// addresses are the path that routes (the server-observed address may
// itself be the shared WAN IP when the control plane is off-site), and
// anything via the public IP would have to hairpin through their
// router, which most consumer NATs refuse — so those sort last, kept
// only as a long shot. Across different NATs it inverts: a router
// mapping is a genuinely open port, STUN is the punchable mapping,
// global IPv6 needs no NAT at all, and private v4 addresses are
// unreachable (included only when a shared /24 with self suggests the
// sides are on the same wire despite different WAN IPs).
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

	reported := agentCandidates(p)
	lan := lanEndpoint(p)
	sameNAT := p.PublicEndpoint != "" && self.PublicEndpoint != "" && sameHost(self.PublicEndpoint, p.PublicEndpoint)

	if sameNAT {
		for _, c := range reported {
			switch c.Type {
			case "host":
				add(c.Endpoint, "host", 110)
			case "host6":
				add(c.Endpoint, "host6", 100)
			}
		}
		if lan != nil {
			add(*lan, "lan", 105)
		}
		add(p.PublicEndpoint, "stun", 85)
		for _, c := range reported {
			if c.Type == "upnp" {
				add(c.Endpoint, "upnp", 84)
			}
		}
	} else {
		selfReported := agentCandidates(self)

		for _, c := range reported {
			if c.Type == "upnp" {
				add(c.Endpoint, "upnp", 120)
			}
		}
		if p.PublicEndpoint != "" {
			add(p.PublicEndpoint, "stun", 90)
		}
		for _, c := range reported {
			switch c.Type {
			case "host6":
				add(c.Endpoint, "host6", 85)
			case "host":
				if sameV4Subnet(selfReported, c.Endpoint) {
					add(c.Endpoint, "host", 110)
				}
			}
		}
		if lan != nil {
			add(*lan, "lan", 80)
		}
	}

	return sortCandidates(out)
}

// sortCandidates orders by priority (stable, insertion order breaking
// ties) and caps the list at what a probe window can actually try.
func sortCandidates(out []proto.EndpointCandidate) []proto.EndpointCandidate {
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority > out[j].Priority })

	if len(out) > maxEndpointCandidates {
		out = out[:maxEndpointCandidates]
	}

	return out
}

// sameV4Subnet reports whether endpoint's host shares a /24 with any of
// self's reported v4 interface addresses. Agents do not report their
// interface masks, so /24 approximates typical home and lab subnetting;
// it is a cheap "possibly the same wire" test that keeps unreachable
// private addresses out of cross-NAT candidate lists.
func sameV4Subnet(selfCands []proto.AgentCandidate, endpoint string) bool {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return false
	}

	ip := net.ParseIP(host).To4()
	if ip == nil {
		return false
	}

	for _, c := range selfCands {
		if c.Type != "host" {
			continue
		}

		selfHost, _, err := net.SplitHostPort(c.Endpoint)
		if err != nil {
			continue
		}

		selfIP := net.ParseIP(selfHost).To4()
		if selfIP == nil {
			continue
		}

		if ip[0] == selfIP[0] && ip[1] == selfIP[1] && ip[2] == selfIP[2] {
			return true
		}
	}

	return false
}

// pairCandidates is endpointCandidates plus the live mapping the
// embedded UDP relay observed for p, when the pair is currently riding
// it. That mapping is p's real public WireGuard source, refreshed by
// every keepalive — fresher than any STUN discovery, and available for
// exactly the peers that need punching. Behind a shared NAT it is the
// hairpin WAN address, so it sorts with the other long shots there.
func (s *server) pairCandidates(self, p store.PeerRow) []proto.EndpointCandidate {
	out := endpointCandidates(self, p)

	if s == nil || s.relay == nil {
		return out
	}

	srcA, srcB, ok := s.relay.observed(relayPairID(self.PublicKey, p.PublicKey))
	if !ok {
		return out
	}

	// Port A serves the lexicographically smaller key (the allocate
	// convention), so packets arriving on leg A came from that peer.
	src := srcA
	if p.PublicKey > self.PublicKey {
		src = srcB
	}

	if !src.IsValid() || src.Addr().IsLoopback() {
		return out
	}

	for _, c := range out {
		if c.Endpoint == src.String() {
			return out
		}
	}

	priority := 95
	if p.PublicEndpoint != "" && self.PublicEndpoint != "" && sameHost(self.PublicEndpoint, p.PublicEndpoint) {
		priority = 83
	}

	out = append(out, proto.EndpointCandidate{Endpoint: src.String(), Type: "relay", Priority: priority})

	return sortCandidates(out)
}

// buildPeerEntries renders the WireGuard peer list for self out of the
// peers it may reach. Routed static/mobile peers (an iPhone importing a
// plain WireGuard config, pinned to a gateway agent) are handled by route,
// not NAT, so the mobile keeps its overlay source IP:
//
//   - To every OTHER agent, a routed mobile is invisible as its own peer;
//     instead its /32 (+/128) is folded into its gateway agent's
//     AllowedIPs, so mesh traffic to the mobile routes through the gateway.
//   - To its OWN gateway agent, the mobile IS a direct WireGuard peer
//     (PSK'd, no endpoint hint — it roams in — AllowedIPs = its /32,/128),
//     and the gateway is told (via GatewayRoutes) to forward without NAT.
func (s *server) buildPeerEntries(self store.PeerRow, others []store.PeerRow) ([]proto.PeerConfigResponse, error) {
	keepalive := keepaliveSeconds

	// Group routed mobiles by the gateway agent that carries their /32.
	mobilesByGateway := make(map[int64][]store.PeerRow)
	for _, o := range others {
		if o.PeerType == "static" && o.GatewayPeerID != 0 {
			mobilesByGateway[o.GatewayPeerID] = append(mobilesByGateway[o.GatewayPeerID], o)
		}
	}

	peers := make([]proto.PeerConfigResponse, 0, len(others))

	for _, o := range others {
		// A routed mobile is a real WireGuard peer only for its own
		// gateway; every other agent reaches it via the gateway's route.
		if o.PeerType == "static" && o.GatewayPeerID != 0 && o.GatewayPeerID != self.ID {
			continue
		}

		pairKey, err := psk.DerivePairKey(s.pskMaster, self.PublicKey, o.PublicKey)
		if err != nil {
			return nil, err
		}

		pairPSK := pairKey.String()

		allowed := allowedIPsForPeer(o)

		entry := proto.PeerConfigResponse{
			PublicKey:                   o.PublicKey,
			PresharedKey:                &pairPSK,
			PunchEpoch:                  s.punchEpoch(self.PublicKey, o.PublicKey),
			PersistentKeepaliveInterval: &keepalive,
		}

		if o.PeerType == "static" {
			// The mobile has no wgmesh signalling: it dials its gateway
			// and roams in. The gateway must not push an endpoint hint
			// (there is none) and lets WireGuard learn the source.
			entry.AllowedIPs = allowed
		} else {
			// A normal agent peer, plus the /32s of any routed mobiles
			// it is the gateway for — this is what teaches every other
			// agent to route mobile traffic through this gateway.
			for _, m := range mobilesByGateway[o.ID] {
				allowed = append(allowed, allowedIPsForPeer(m)...)
			}
			candidates := s.pairCandidates(self, o)
			if len(candidates) > 0 {
				entry.Endpoint = &candidates[0].Endpoint
			}
			entry.EndpointCandidates = candidates
			entry.AllowedIPs = allowed
		}

		peers = append(peers, entry)
	}

	return peers, nil
}

// gatewayRoutesFor returns the overlay CIDRs self is the routing gateway
// for — the /32 (+/128) of every routed mobile pinned to it. Drives the
// agent's forward-without-NAT setup.
func gatewayRoutesFor(self store.PeerRow, others []store.PeerRow) []string {
	var routes []string
	for _, o := range others {
		if o.PeerType == "static" && o.GatewayPeerID == self.ID {
			routes = append(routes, allowedIPsForPeer(o)...)
		}
	}
	return routes
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
		PeerID:        int(res.Peer.ID),
		AssignedIP:    res.Peer.AssignedIP,
		AssignedIP6:   res.Peer.AssignedIP6,
		NetworkCIDR:   cfg.NetworkCIDR,
		NetworkCIDR6:  cfg.NetworkCIDR6,
		DNS:           dnsConfigProto(dnsCfg),
		Peers:         peers,
		ACL:           acl,
		GatewayRoutes: gatewayRoutesFor(res.Peer, res.Others),
		AuthToken:     res.AuthToken,
		STUNServers:   s.stunServers,
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
