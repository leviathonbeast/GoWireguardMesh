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
	"log"
	"net/http"
	"net/netip"
	"os"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	gowireguard "gowireguard"
	"gowireguard/internal/proto"
	"gowireguard/internal/psk"
	"gowireguard/internal/store"
)

// keepaliveSeconds is handed to every peer. The control plane decides
// this, not the agent — resolves the old agent-side TODO.
const keepaliveSeconds = 25

type server struct {
	store       *store.Store
	networkCIDR string
	psk         string
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
	listen := fs.String("listen", "127.0.0.1:8080", "HTTP listen address")
	network := fs.String("network", "100.64.0.0/16", "overlay network (CIDR)")
	pskFile := fs.String("psk-file", "mesh-psk.key", "path to network preshared key file")

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

	srv := &server{
		store:       st,
		networkCIDR: prefix.Masked().String(),
		psk:         networkPSK.String(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll", srv.handleEnroll)

	log.Printf("control plane listening on %s (network %s, db %s)", *listen, srv.networkCIDR, *dbPath)

	// TODO: TLS. The control plane is the public-facing component;
	// plain HTTP is acceptable in dev only.
	if err := http.ListenAndServe(*listen, mux); err != nil {
		return fmt.Errorf("http server: %w", err)
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

	res, err := s.store.Enroll(r.Context(), req.SetupKey, req.PublicKey, req.Hostname, req.ListenPort)

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

func (s *server) buildResponse(res *store.EnrollResult) proto.EnrollResponse {
	keepalive := keepaliveSeconds

	peers := make([]proto.PeerConfigResponse, 0, len(res.Others))

	for _, o := range res.Others {
		peers = append(peers, proto.PeerConfigResponse{
			PublicKey:                   o.PublicKey,
			PresharedKey:                &s.psk,
			PersistentKeepaliveInterval: &keepalive,
			AllowedIPs:                  []string{o.AssignedIP + "/32"},
			// Endpoint stays null: the control plane does not yet
			// track peer underlay addresses. Config sync + STUN fill
			// this in later; until then roaming does the work once
			// any packet gets through.
		})
	}

	return proto.EnrollResponse{
		PeerID:      int(res.Peer.ID),
		AssignedIP:  res.Peer.AssignedIP,
		NetworkCIDR: s.networkCIDR,
		Peers:       peers,
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
