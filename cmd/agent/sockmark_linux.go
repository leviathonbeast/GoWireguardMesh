//go:build linux

package main

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// The agent's control-plane, relay, and STUN sockets carry the
// tunnel's own underlay traffic, so when exit-node routing is active
// they must bypass the tunnel default route — the same reason the
// WireGuard device gets a fwmark. SO_MARK needs CAP_NET_ADMIN, which
// the agent already requires; without the exit rules the mark is
// inert, so it is set unconditionally rather than toggled.

var sockMarkWarn sync.Once

func sockControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, exitFwmark)
	}); err != nil {
		return err
	}
	if serr != nil {
		// Never fail the dial over a missing mark: everything still
		// works until this node is assigned an exit node.
		sockMarkWarn.Do(func() {
			slog.Warn("SO_MARK failed; exit-node routing would loop agent traffic into the tunnel", "error", serr)
		})
	}
	return nil
}

// markedDialContext backs the agent's HTTP client and WebSocket dialer.
func markedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{Control: sockControl}
	return d.DialContext(ctx, network, address)
}

// listenUDPMarked replaces net.ListenUDP for sockets that talk to the
// underlay (STUN probes, the QUIC relay leg).
func listenUDPMarked(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: sockControl}

	addr := ""
	if laddr != nil {
		addr = laddr.String()
	}

	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}

	return pc.(*net.UDPConn), nil
}
