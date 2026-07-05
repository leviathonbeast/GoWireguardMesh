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
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	gowireguard "gowireguard"
	"gowireguard/internal/firewall"
	"gowireguard/internal/proto"
	"gowireguard/internal/psk"
	"gowireguard/internal/relay"
	"gowireguard/internal/store"
	"gowireguard/internal/tlsutil"
)

// keepaliveSeconds is handed to every peer. The control plane decides
// this, not the agent — resolves the old agent-side TODO.
const keepaliveSeconds = 25

type server struct {
	store       *store.Store
	networkCIDR string
	pskMaster   wgtypes.Key // never distributed; per-pair PSKs derive from it
	adminToken  string
	trustProxy  bool
	relay       relayAllocator // nil when no relay is configured
	relayHost   string         // public data-plane address agents dial
	wsHub       *relay.WSHub   // nil unless the embedded WS relay is enabled
}

// clientIP is the peer's underlay address as seen by the control
// plane. Behind a TLS-terminating proxy (Traefik) every request comes
// from the proxy, so --trust-proxy switches to X-Forwarded-For —
// trusting that header from direct clients would let them spoof it.
func (s *server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			return strings.TrimSpace(first)
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

func overlayAddress(addr string) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("parse overlay address %q", addr)
	}

	if ip.To4() != nil {
		return fmt.Sprintf("%s/32", ip.String()), nil
	}

	return fmt.Sprintf("%s/128", ip.String()), nil
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

	key, err := st.CreateSetupKey(context.Background(), *maxUses, *expiresIn)
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
	manageFirewall := fs.Bool("manage-firewall", true, "open the API port on the host firewall (removed again on shutdown)")

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

	switch *defaultPolicy {
	case "allow":
		st.DefaultAllow = true
	case "deny":
		st.DefaultAllow = false
	default:
		return fmt.Errorf("default-policy must be \"allow\" or \"deny\", got %q", *defaultPolicy)
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
				fw, ferr := firewall.Open("wgmesh-server")
				if ferr != nil {
					log.Printf("firewall: %v; open tcp %d yourself if needed", ferr, port)
				} else if err := fw.AllowTCP(port); err != nil {
					// Common when running unprivileged; the API port
					// then needs opening by hand.
					log.Printf("firewall (%s): %v", fw.Backend(), err)
				} else {
					log.Printf("firewall (%s): opened tcp %d", fw.Backend(), port)
					defer func() {
						if err := fw.Close(); err != nil {
							log.Printf("firewall cleanup: %v", err)
						}
					}()
				}
			}
		}
	}

	srv := &server{
		store:       st,
		networkCIDR: prefix.Masked().String(),
		pskMaster:   networkPSK,
		adminToken:  adminToken,
		trustProxy:  *trustProxy,
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
			fw, ferr := firewall.Open("wgmesh-server-relay")
			if ferr != nil {
				log.Printf("firewall: %v; open udp %d-%d yourself if needed", ferr, *relayPortMin, *relayPortMax)
			} else if err := fw.AllowUDPRange(*relayPortMin, *relayPortMax); err != nil {
				log.Printf("firewall (%s): %v", fw.Backend(), err)
			} else {
				log.Printf("firewall (%s): opened udp %d-%d", fw.Backend(), *relayPortMin, *relayPortMax)
				defer func() {
					if err := fw.Close(); err != nil {
						log.Printf("firewall cleanup: %v", err)
					}
				}()
			}
		}

		log.Printf("embedded relay on udp %d-%d, agents dial %s", *relayPortMin, *relayPortMax, *relayHost)

	case *relayHost != "":
		rc, err := newRelayClient(*relayControl, *relaySecretFile)
		if err != nil {
			return err
		}

		srv.relay = rc
		srv.relayHost = *relayHost

		log.Printf("standalone relay fallback via %s (control %s)", *relayHost, *relayControl)
	}

	ui, err := iofs.Sub(gowireguard.WebUI, "web/dist")
	if err != nil {
		return fmt.Errorf("locate embedded web ui: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll", srv.handleEnroll)
	mux.HandleFunc("POST /report", srv.handleReport)
	mux.HandleFunc("POST /relay-pair", srv.handleRelayPair)
	mux.HandleFunc("GET /relay-ws", srv.handleRelayWS)
	mux.Handle("GET /", http.FileServerFS(ui))
	mux.HandleFunc("GET /api/peers", srv.requireAdmin(srv.handleListPeers))
	mux.HandleFunc("POST /api/peers/{id}/revoke", srv.requireAdmin(srv.handleRevokePeer))
	mux.HandleFunc("GET /api/setup-keys", srv.requireAdmin(srv.handleListSetupKeys))
	mux.HandleFunc("POST /api/setup-keys", srv.requireAdmin(srv.handleCreateSetupKey))
	mux.HandleFunc("POST /api/setup-keys/{id}/revoke", srv.requireAdmin(srv.handleRevokeSetupKey))
	mux.HandleFunc("GET /api/link-stats", srv.requireAdmin(srv.handleListLinkStats))
	mux.HandleFunc("GET /api/flows", srv.requireAdmin(srv.handleListFlows))
	mux.HandleFunc("GET /api/acl", srv.requireAdmin(srv.handleListACL))
	mux.HandleFunc("POST /api/acl", srv.requireAdmin(srv.handleCreateACL))
	mux.HandleFunc("POST /api/acl/{id}/delete", srv.requireAdmin(srv.handleDeleteACL))

	pruneCtx, cancelPrune := context.WithCancel(context.Background())
	defer cancelPrune()

	go srv.pruneFlowsLoop(pruneCtx, *flowRetention)

	if *noTLS {
		log.Printf("control plane on http://%s (network %s, db %s) — plain HTTP; terminate TLS upstream (e.g. Traefik) or use for dev only", *listen, srv.networkCIDR, *dbPath)
		log.Printf("web UI at http://%s/ (token in %s)", *listen, *adminTokenFile)

		if err := http.ListenAndServe(*listen, mux); err != nil {
			return fmt.Errorf("http server: %w", err)
		}

		return nil
	}

	hosts := strings.Split(*tlsHosts, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}

	if err := tlsutil.LoadOrGenerateCert(*tlsCert, *tlsKey, hosts); err != nil {
		return err
	}

	log.Printf("[server] control plane on https://%s (network %s, db %s)", *listen, srv.networkCIDR, *dbPath)
	log.Printf("[server] web UI at https://%s/ (token in %s)", *listen, *adminTokenFile)
	log.Printf("[server] agents should pin the certificate: --server-ca %s", *tlsCert)
	if srv.relay == nil {
		log.Printf("[server] relay fallback disabled; direct UDP connectivity between peers is required")
	} else {
		log.Printf("[server] relay fallback enabled for NATed peers")
	}

	if err := http.ListenAndServeTLS(*listen, *tlsCert, *tlsKey, mux); err != nil {
		return fmt.Errorf("https server: %w", err)
	}

	return nil
}

func (s *server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req proto.EnrollRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
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
		// server log only.
		log.Printf("[server] enroll rejected for %s (listen_port=%d): %v", req.PublicKey, req.ListenPort, err)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	case err != nil:
		log.Printf("[server] enroll failed for %s (listen_port=%d): %v", req.PublicKey, req.ListenPort, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if res.Created {
		log.Printf("[server] enrolled peer %d (%s) at %s (listen_port=%d, endpoint=%s)", res.Peer.ID, req.PublicKey, res.Peer.AssignedIP, req.ListenPort, req.PublicEndpoint)
	} else {
		log.Printf("[server] idempotent re-enroll of peer %d (%s) (listen_port=%d, endpoint=%s)", res.Peer.ID, req.PublicKey, req.ListenPort, req.PublicEndpoint)
	}

	out, err := s.buildResponse(res)
	if err != nil {
		log.Printf("build enroll response for %s: %v", req.PublicKey, err)
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
	if p.PublicEndpoint == "" {
		return lanEndpoint(p)
	}

	if self.PublicEndpoint != "" && sameHost(self.PublicEndpoint, p.PublicEndpoint) {
		if lan := lanEndpoint(p); lan != nil {
			return lan
		}
	}

	return &p.PublicEndpoint
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
			PersistentKeepaliveInterval: &keepalive,
			AllowedIPs:                  []string{o.AssignedIP + "/32"},
		})
	}

	return peers, nil
}

func (s *server) buildResponse(res *store.EnrollResult) (proto.EnrollResponse, error) {
	peers, err := s.buildPeerEntries(res.Peer, res.Others)
	if err != nil {
		return proto.EnrollResponse{}, err
	}

	return proto.EnrollResponse{
		PeerID:      int(res.Peer.ID),
		AssignedIP:  res.Peer.AssignedIP,
		NetworkCIDR: s.networkCIDR,
		Peers:       peers,
		AuthToken:   res.AuthToken,
	}, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
