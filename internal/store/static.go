package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// StaticPeer describes a peer to register that will not run the wgmesh
// agent. PrivateKeyEnc and GatewayEndpoint are what let the admin UI show
// the peer's config again later; leave PrivateKeyEnc empty when the
// operator supplied their own key, since the control plane never saw it.
type StaticPeer struct {
	PublicKey     string
	Hostname      string
	GatewayPeerID int64
	// PrivateKeyEnc is sealed by internal/keyseal, never plaintext.
	PrivateKeyEnc   string
	GatewayEndpoint string
}

// CreateStaticPeer registers a peer that will not run the wgmesh agent.
// This is intended for official WireGuard clients such as iOS/Android:
// the control plane owns IP allocation and visibility, while the client
// imports a conventional WireGuard config.
//
// GatewayPeerID is the active agent peer that routes this peer's overlay
// /32 into the mesh (its WireGuard endpoint). It must reference an active
// agent peer; 0 is rejected. The gateway forwards — it does not NAT — so
// the mobile peer keeps its overlay source IP end-to-end, and every other
// agent learns the /32 via the gateway peer's AllowedIPs.
func (s *Store) CreateStaticPeer(ctx context.Context, spec StaticPeer) (PeerInfo, error) {
	publicKey := strings.TrimSpace(spec.PublicKey)
	hostname := strings.TrimSpace(spec.Hostname)
	gatewayPeerID := spec.GatewayPeerID
	if publicKey == "" {
		return PeerInfo{}, fmt.Errorf("public_key is required")
	}
	if gatewayPeerID <= 0 {
		return PeerInfo{}, fmt.Errorf("gateway_peer_id is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PeerInfo{}, fmt.Errorf("begin static peer create: %w", err)
	}
	defer tx.Rollback()

	var (
		gatewayType    string
		gatewayRevoked sql.NullString
	)
	err = tx.QueryRowContext(ctx,
		`SELECT COALESCE(peer_type, 'agent'), revoked_at FROM peers WHERE id = ?`, gatewayPeerID,
	).Scan(&gatewayType, &gatewayRevoked)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return PeerInfo{}, fmt.Errorf("gateway peer %d not found", gatewayPeerID)
	case err != nil:
		return PeerInfo{}, fmt.Errorf("check gateway peer: %w", err)
	case gatewayRevoked.Valid:
		return PeerInfo{}, fmt.Errorf("gateway peer %d is revoked", gatewayPeerID)
	case gatewayType != "agent":
		return PeerInfo{}, fmt.Errorf("gateway peer %d must be a wgmesh agent, not a %s peer", gatewayPeerID, gatewayType)
	}

	var existingID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM peers WHERE public_key = ?`, publicKey).Scan(&existingID)
	switch {
	case err == nil:
		return PeerInfo{}, fmt.Errorf("%w: public key belongs to peer %d", ErrPeerExists, existingID)
	case errors.Is(err, sql.ErrNoRows):
	default:
		return PeerInfo{}, fmt.Errorf("check peer public key: %w", err)
	}

	setupKey, err := randomStaticSetupKey()
	if err != nil {
		return PeerInfo{}, err
	}

	setupName := "static peer"
	if hostname != "" {
		setupName += ": " + hostname
	}

	insertKey, err := tx.ExecContext(ctx,
		`INSERT INTO setup_keys (key, name, max_uses, uses_consumed) VALUES (?, ?, 1, 1)`,
		setupKey, setupName,
	)
	if err != nil {
		return PeerInfo{}, fmt.Errorf("insert static setup key: %w", err)
	}
	setupKeyID, err := insertKey.LastInsertId()
	if err != nil {
		return PeerInfo{}, fmt.Errorf("insert static setup key: %w", err)
	}

	ip, err := s.allocateIP(ctx, tx)
	if err != nil {
		return PeerInfo{}, err
	}

	var ip6 string
	if s.v6Enabled() {
		ip6, err = s.allocateIP6(ctx, tx)
		if err != nil {
			return PeerInfo{}, err
		}
	}

	_, tokenHash, err := newAuthToken()
	if err != nil {
		return PeerInfo{}, err
	}
	now := time.Now().UTC().Format(timeFormat)

	insertPeer, err := tx.ExecContext(ctx,
		`INSERT INTO peers (public_key, assigned_ip, assigned_ip6, peer_type, gateway_peer_id, gateway_endpoint,
		                    private_key_enc, hostname, setup_key_id, auth_token_hash, auth_token_issued_at)
		 VALUES (?, ?, ?, 'static', ?, ?, ?, ?, ?, ?, ?)`,
		publicKey, ip, nullable(ip6), gatewayPeerID, nullable(spec.GatewayEndpoint),
		nullable(spec.PrivateKeyEnc), nullable(hostname), setupKeyID, tokenHash, now,
	)
	if err != nil {
		return PeerInfo{}, fmt.Errorf("insert static peer: %w", err)
	}
	peerID, err := insertPeer.LastInsertId()
	if err != nil {
		return PeerInfo{}, fmt.Errorf("insert static peer: %w", err)
	}

	peer, err := getPeerInfo(ctx, tx, peerID)
	if err != nil {
		return PeerInfo{}, err
	}

	if err := tx.Commit(); err != nil {
		return PeerInfo{}, fmt.Errorf("commit static peer create: %w", err)
	}

	return peer, nil
}

// ErrNoStoredConfig reports a static peer whose private key the control
// plane cannot produce: an agent, a pre-v15 peer, or one enrolled with an
// operator-supplied key. Its config can never be rebuilt.
var ErrNoStoredConfig = errors.New("peer has no stored configuration")

// SealedPrivateKey returns the static peer's sealed private key, for the
// caller to open with internal/keyseal. It is the only path out of the
// store for that column, deliberately narrow so that no listing or peer
// lookup can leak it by accident.
func (s *Store) SealedPrivateKey(ctx context.Context, peerID int64) (string, error) {
	var sealed sql.NullString

	err := s.db.QueryRowContext(ctx,
		`SELECT private_key_enc FROM peers WHERE id = ? AND COALESCE(peer_type, 'agent') = 'static'`,
		peerID,
	).Scan(&sealed)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("peer %d: %w", peerID, ErrNoStoredConfig)
	case err != nil:
		return "", fmt.Errorf("look up sealed key for peer %d: %w", peerID, err)
	case !sealed.Valid || sealed.String == "":
		return "", fmt.Errorf("peer %d: %w", peerID, ErrNoStoredConfig)
	}

	return sealed.String, nil
}

func randomStaticSetupKey() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate static setup key marker: %w", err)
	}

	return "static-" + base64.RawURLEncoding.EncodeToString(raw), nil
}
