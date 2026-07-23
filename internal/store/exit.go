package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrInvalid marks a request the store understood and refused; handlers
// map it to 400 with the wrapped detail as the body.
var ErrInvalid = errors.New("invalid request")

// SetAdvertiseExitNode records whether peerID currently offers to be an
// exit node. Called on enrollment and on every telemetry report, so
// adding or removing --advertise-exit-node propagates without admin
// action. Withdrawing the offer does NOT clear existing assignments:
// silently breaking assigned clients' internet is worse than serving a
// little longer, and the admin UI shows the mismatch.
func (s *Store) SetAdvertiseExitNode(ctx context.Context, peerID int64, advertise bool) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE peers SET advertise_exit_node = ? WHERE id = ?`, advertise, peerID,
	); err != nil {
		return fmt.Errorf("set advertise_exit_node: %w", err)
	}

	return nil
}

// ExitAssignment names the two sides of an exit-node change so the
// caller can signal both agents for an immediate config sync.
type ExitAssignment struct {
	PeerPublicKey string // the client whose default route changes
	PeerHostname  string
	ExitPublicKey string // the assigned exit node; "" when clearing
	ExitHostname  string
}

// SetExitNode assigns (or, with exitPeerID = 0, clears) the exit node
// that peerID's internet traffic routes through. Both sides must be
// active agents — static/mobile peers neither sync nor forward — and
// the exit must currently advertise itself; assignment to self is
// rejected. Chains are rejected too: an exit node cannot itself be
// routed through another exit, and a peer serving as someone's exit
// cannot be pointed at one (its clients' traffic would cascade).
func (s *Store) SetExitNode(ctx context.Context, peerID, exitPeerID int64) (ExitAssignment, error) {
	var out ExitAssignment

	if peerID == exitPeerID && exitPeerID != 0 {
		return out, fmt.Errorf("%w: a peer cannot be its own exit node", ErrInvalid)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, fmt.Errorf("begin exit-node transaction: %w", err)
	}
	defer tx.Rollback()

	var (
		peerType string
		revoked  sql.NullString
		hostname sql.NullString
	)
	err = tx.QueryRowContext(ctx,
		`SELECT public_key, COALESCE(peer_type, 'agent'), revoked_at, hostname FROM peers WHERE id = ?`, peerID,
	).Scan(&out.PeerPublicKey, &peerType, &revoked, &hostname)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return out, fmt.Errorf("%w: peer %d not found", ErrInvalid, peerID)
	case err != nil:
		return out, fmt.Errorf("look up peer %d: %w", peerID, err)
	case revoked.Valid:
		return out, fmt.Errorf("%w: peer %d is revoked", ErrInvalid, peerID)
	case peerType != "agent":
		return out, fmt.Errorf("%w: only agent peers can use an exit node", ErrInvalid)
	}
	out.PeerHostname = hostname.String

	if exitPeerID != 0 {
		var (
			exitType  string
			exitRev   sql.NullString
			exitHost  sql.NullString
			advertise bool
			exitsVia  int64
		)
		err = tx.QueryRowContext(ctx,
			`SELECT public_key, COALESCE(peer_type, 'agent'), revoked_at, hostname,
			        COALESCE(advertise_exit_node, 0), COALESCE(exit_node_peer_id, 0)
			 FROM peers WHERE id = ?`, exitPeerID,
		).Scan(&out.ExitPublicKey, &exitType, &exitRev, &exitHost, &advertise, &exitsVia)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return out, fmt.Errorf("%w: exit node peer %d not found", ErrInvalid, exitPeerID)
		case err != nil:
			return out, fmt.Errorf("look up exit node %d: %w", exitPeerID, err)
		case exitRev.Valid:
			return out, fmt.Errorf("%w: exit node peer %d is revoked", ErrInvalid, exitPeerID)
		case exitType != "agent":
			return out, fmt.Errorf("%w: exit node must be an agent peer", ErrInvalid)
		case !advertise:
			return out, fmt.Errorf("%w: peer %d does not advertise itself as an exit node", ErrInvalid, exitPeerID)
		case exitsVia != 0:
			return out, fmt.Errorf("%w: peer %d routes through an exit node itself", ErrInvalid, exitPeerID)
		}
		out.ExitHostname = exitHost.String

		// The reverse chain: someone exits through peerID already.
		var clients int64
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM peers WHERE exit_node_peer_id = ? AND revoked_at IS NULL`, peerID,
		).Scan(&clients); err != nil {
			return out, fmt.Errorf("count exit clients: %w", err)
		}
		if clients > 0 {
			return out, fmt.Errorf("%w: peer %d is an exit node for %d peer(s) and cannot chain through another", ErrInvalid, peerID, clients)
		}
	}

	assign := sql.NullInt64{Int64: exitPeerID, Valid: exitPeerID != 0}
	if _, err := tx.ExecContext(ctx,
		`UPDATE peers SET exit_node_peer_id = ? WHERE id = ?`, assign, peerID,
	); err != nil {
		return out, fmt.Errorf("set exit_node_peer_id: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return out, fmt.Errorf("commit exit-node change: %w", err)
	}

	return out, nil
}
