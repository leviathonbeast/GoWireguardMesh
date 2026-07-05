package relay

import (
	"errors"
	"sync"
)

// FrameConn is one relayed connection carrying WireGuard datagrams as
// discrete messages. The websocket connection satisfies it; tests use
// an in-memory fake. Each ReadFrame/WriteFrame moves exactly one WG
// UDP packet.
type FrameConn interface {
	ReadFrame() ([]byte, error)
	WriteFrame([]byte) error
	Close() error
}

// WSHub cross-forwards frames between the two members of each pair.
// It is the WebSocket analogue of the UDP forwarder: instead of two
// UDP ports it holds two long-lived connections, and instead of
// learning addresses from packets it learns members as they join. No
// forwarding ports means nothing extra to open on a firewall — every
// agent reaches it outbound over the control plane's own port.
type WSHub struct {
	mu    sync.Mutex
	pairs map[string]*wsPair
}

type wsPair struct {
	// members is keyed by the joining peer's public key; a pair holds
	// at most two. Guarded by WSHub.mu.
	members map[string]FrameConn
}

func NewWSHub() *WSHub {
	return &WSHub{pairs: make(map[string]*wsPair)}
}

// errPairFull rejects a third member on a pair — only two peers ever
// share one relay path.
var errPairFull = errors.New("relay pair already has two members")

// join registers conn as memberID in pairID, evicting a stale
// connection the same member left behind (reconnect). It returns the
// other member if one is already present.
func (h *WSHub) join(pairID, memberID string, conn FrameConn) (other FrameConn, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	p := h.pairs[pairID]
	if p == nil {
		p = &wsPair{members: make(map[string]FrameConn)}
		h.pairs[pairID] = p
	}

	if _, isRejoin := p.members[memberID]; !isRejoin && len(p.members) >= 2 {
		return nil, errPairFull
	}

	if old := p.members[memberID]; old != nil {
		old.Close()
	}

	p.members[memberID] = conn

	for id, c := range p.members {
		if id != memberID {
			other = c
		}
	}

	return other, nil
}

func (h *WSHub) leave(pairID, memberID string, conn FrameConn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	p := h.pairs[pairID]
	if p == nil {
		return
	}

	// Only remove if it is still our connection: a reconnect may have
	// already replaced it.
	if p.members[memberID] == conn {
		delete(p.members, memberID)
	}

	if len(p.members) == 0 {
		delete(h.pairs, pairID)
	}
}

// peer returns the current other member of the pair, or nil.
func (h *WSHub) peer(pairID, memberID string) FrameConn {
	h.mu.Lock()
	defer h.mu.Unlock()

	p := h.pairs[pairID]
	if p == nil {
		return nil
	}

	for id, c := range p.members {
		if id != memberID {
			return c
		}
	}

	return nil
}

// Serve runs the read loop for one member until the connection ends,
// forwarding each frame to whoever the other member is at that
// moment. Blocks; the caller (an HTTP handler goroutine) owns conn's
// lifetime and should Close it after Serve returns.
func (h *WSHub) Serve(pairID, memberID string, conn FrameConn) error {
	if _, err := h.join(pairID, memberID, conn); err != nil {
		return err
	}
	defer h.leave(pairID, memberID, conn)

	for {
		frame, err := conn.ReadFrame()
		if err != nil {
			return err
		}

		// Re-resolve every frame: the other side may connect, drop,
		// or reconnect during this session. A frame with nobody on
		// the far end is dropped, exactly like the UDP path before
		// the second peer checks in.
		if other := h.peer(pairID, memberID); other != nil {
			if err := other.WriteFrame(frame); err != nil {
				// Writing failed: the far side is gone. Keep serving;
				// it may reconnect.
				continue
			}
		}
	}
}
