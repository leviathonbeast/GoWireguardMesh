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
	"gowireguard/internal/proto"
	"gowireguard/internal/psk"
	"gowireguard/internal/store"
	"gowireguard/internal/tlsutil"
)

// keepaliveSeconds is handed to every peer. The control plane decides
// this, not the agent — resolves the old agent-side TODO.
const keepaliveSeconds = 25

type server struct {
	store       *store.Store
	networkCIDR string
	psk         string
	adminToken  string
	trustProxy  bool
	relay       *relayClient // nil when no relay is configured
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
	relayHost := fs.String("relay-host", "", "public address of the relay's data plane (enables relay fallback)")
	relayControl := fs.String("relay-control", "http://127.0.0.1:8081", "relay control API URL")
	relaySecretFile := fs.String("relay-secret-file", "relay-secret", "path to the relay control shared secret")

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

	networkPSK, err := psk.LoadOrGenerate(*pskFile)
	if err != nil {
		return err
	}

	adminToken, err := loadOrGenerateAdminToken(*adminTokenFile)
	if err != nil {
		return err
	}

	srv := &server{
		store:       st,
		networkCIDR: prefix.Masked().String(),
		psk:         networkPSK.String(),
		adminToken:  adminToken,
		trustProxy:  *trustProxy,
	}

	if *relayHost != "" {
		srv.relay, err = newRelayClient(*relayHost, *relayControl, *relaySecretFile)
		if err != nil {
			return err
		}

		log.Printf("relay fallback enabled via %s (control %s)", *relayHost, *relayControl)
	}

	ui, err := iofs.Sub(gowireguard.WebUI, "web/dist")
	if err != nil {
		return fmt.Errorf("locate embedded web ui: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll", srv.handleEnroll)
	mux.HandleFunc("POST /report", srv.handleReport)
	mux.HandleFunc("POST /relay-pair", srv.handleRelayPair)
	mux.Handle("GET /", http.FileServerFS(ui))
	mux.HandleFunc("GET /api/peers", srv.requireAdmin(srv.handleListPeers))
	mux.HandleFunc("POST /api/peers/{id}/revoke", srv.requireAdmin(srv.handleRevokePeer))
	mux.HandleFunc("GET /api/setup-keys", srv.requireAdmin(srv.handleListSetupKeys))
	mux.HandleFunc("POST /api/setup-keys", srv.requireAdmin(srv.handleCreateSetupKey))
	mux.HandleFunc("POST /api/setup-keys/{id}/revoke", srv.requireAdmin(srv.handleRevokeSetupKey))
	mux.HandleFunc("GET /api/link-stats", srv.requireAdmin(srv.handleListLinkStats))
	mux.HandleFunc("GET /api/flows", srv.requireAdmin(srv.handleListFlows))

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

	log.Printf("control plane on https://%s (network %s, db %s)", *listen, srv.networkCIDR, *dbPath)
	log.Printf("web UI at https://%s/ (token in %s)", *listen, *adminTokenFile)
	log.Printf("agents should pin the certificate: --server-ca %s", *tlsCert)

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
		log.Printf("enroll rejected for %s: %v", req.PublicKey, err)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	case err != nil:
		log.Printf("enroll failed for %s: %v", req.PublicKey, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if res.Created {
		log.Printf("enrolled peer %d (%s) at %s", res.Peer.ID, req.PublicKey, res.Peer.AssignedIP)
	} else {
		log.Printf("idempotent re-enroll of peer %d (%s)", res.Peer.ID, req.PublicKey)
	}

	writeJSON(w, http.StatusOK, s.buildResponse(res))
}

// endpointHint picks the best-known underlay endpoint for a peer:
// its own STUN discovery wins, then the address the control plane
// observed it at combined with its listen port. Hints are exactly
// that — WireGuard roaming overrides them the moment real traffic
// arrives from somewhere else.
func endpointHint(p store.PeerRow) *string {
	if p.PublicEndpoint != "" {
		return &p.PublicEndpoint
	}

	if p.ObservedIP != "" && p.ListenPort > 0 {
		ep := net.JoinHostPort(p.ObservedIP, strconv.Itoa(p.ListenPort))
		return &ep
	}

	return nil
}

func (s *server) buildPeerEntries(others []store.PeerRow) []proto.PeerConfigResponse {
	keepalive := keepaliveSeconds

	peers := make([]proto.PeerConfigResponse, 0, len(others))

	for _, o := range others {
		peers = append(peers, proto.PeerConfigResponse{
			PublicKey:                   o.PublicKey,
			PresharedKey:                &s.psk,
			Endpoint:                    endpointHint(o),
			PersistentKeepaliveInterval: &keepalive,
			AllowedIPs:                  []string{o.AssignedIP + "/32"},
		})
	}

	return peers
}

func (s *server) buildResponse(res *store.EnrollResult) proto.EnrollResponse {
	return proto.EnrollResponse{
		PeerID:      int(res.Peer.ID),
		AssignedIP:  res.Peer.AssignedIP,
		NetworkCIDR: s.networkCIDR,
		Peers:       s.buildPeerEntries(res.Others),
		AuthToken:   res.AuthToken,
	}
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
