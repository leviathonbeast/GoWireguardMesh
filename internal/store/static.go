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

// CreateStaticPeer registers a peer that will not run the wgmesh agent.
// This is intended for official WireGuard clients such as iOS/Android:
// the control plane owns IP allocation and visibility, while the client
// imports a conventional WireGuard config.
func (s *Store) CreateStaticPeer(ctx context.Context, publicKey, hostname string) (PeerInfo, error) {
	publicKey = strings.TrimSpace(publicKey)
	hostname = strings.TrimSpace(hostname)
	if publicKey == "" {
		return PeerInfo{}, fmt.Errorf("public_key is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PeerInfo{}, fmt.Errorf("begin static peer create: %w", err)
	}
	defer tx.Rollback()

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
		`INSERT INTO peers (public_key, assigned_ip, assigned_ip6, hostname, setup_key_id, auth_token_hash, auth_token_issued_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		publicKey, ip, nullable(ip6), nullable(hostname), setupKeyID, tokenHash, now,
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

func randomStaticSetupKey() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate static setup key marker: %w", err)
	}

	return "static-" + base64.RawURLEncoding.EncodeToString(raw), nil
}
