package relay

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/pion/stun/v3"
)

// STUNResponder is a minimal STUN binding server (RFC 5389 binding
// requests only). The mesh runs its own so agents need no third-party
// STUN dependency, and it deliberately answers on TWO ports on the same
// IP: an agent that sends binding requests to both ports from one
// socket and gets the same mapped address back has an
// endpoint-independent ("easy") NAT that hole punching works through;
// different mapped ports mean an endpoint-dependent ("hard"/symmetric)
// NAT. Classification with two ports on one IP cannot distinguish
// address-dependent from address-and-port-dependent mapping, but for
// punch/no-punch decisions that distinction does not matter.
//
// It lives on its own ports rather than the forwarding ports: those
// drop everything that is not WireGuard-shaped (see wgShaped), and a
// STUN answer from a forwarding port would fight the anti-hijack
// address latching.
type STUNResponder struct {
	conns []*net.UDPConn
}

// NewSTUNResponder binds and serves STUN binding requests on ip:port
// and ip:port+1. A zero ip binds the wildcard address.
func NewSTUNResponder(ip net.IP, port int) (*STUNResponder, error) {
	if port <= 0 || port+1 > 65535 {
		return nil, fmt.Errorf("stun port %d out of range (needs port and port+1)", port)
	}

	r := &STUNResponder{}

	for _, p := range []int{port, port + 1} {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: p})
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("bind stun port %d: %w", p, err)
		}

		r.conns = append(r.conns, conn)

		go serveSTUN(conn)
	}

	return r, nil
}

func (r *STUNResponder) Close() {
	for _, c := range r.conns {
		_ = c.Close()
	}
}

// serveSTUN answers binding requests on conn until it is closed.
// Everything that is not a well-formed binding request is dropped
// silently — these ports are internet-facing.
func serveSTUN(conn *net.UDPConn) {
	buf := make([]byte, 1500)

	for {
		n, src, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				slog.Debug("stun read failed", "error", err)
			}
			return
		}

		resp := stunBindingResponse(buf[:n], net.UDPAddrFromAddrPort(src))
		if resp == nil {
			continue
		}

		if _, err := conn.WriteToUDPAddrPort(resp, src); err != nil {
			slog.Debug("stun reply failed", "error", err)
		}
	}
}

// stunBindingResponse builds the binding success response for one
// datagram, or nil when the datagram is not a STUN binding request.
// Split from the read loop for testability.
func stunBindingResponse(pkt []byte, src *net.UDPAddr) []byte {
	if !stun.IsMessage(pkt) {
		return nil
	}

	req := &stun.Message{Raw: append([]byte(nil), pkt...)}
	if err := req.Decode(); err != nil {
		return nil
	}

	if req.Type != stun.BindingRequest {
		return nil
	}

	resp, err := stun.Build(
		stun.NewTransactionIDSetter(req.TransactionID),
		stun.BindingSuccess,
		&stun.XORMappedAddress{IP: src.IP, Port: src.Port},
		stun.Fingerprint,
	)
	if err != nil {
		return nil
	}

	return resp.Raw
}
