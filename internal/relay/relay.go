// Package relay implements the wgmesh NAT-traversal fallback: a dumb
// UDP pair forwarder.
//
// For each peer pair the control plane allocates two UDP ports. Peer
// A points its WireGuard endpoint for B at port A; peer B points its
// endpoint for A at port B. The relay learns each side's real address
// from the first packet it receives (WireGuard persistent keepalives
// guarantee those arrive) and then cross-forwards: traffic in on port
// A goes out port B to B's last known address, and vice versa.
//
// The relay never decrypts what it forwards — everything is WireGuard
// ciphertext, so a compromised relay can delay or drop traffic but
// not read or forge it. This design exists because kernel WireGuard
// owns its UDP socket and cannot speak TURN's allocation framing; a
// plain forwarder achieves the same fallback with zero cooperation
// from the kernel.
//
// The forwarding ports are necessarily open to the world (the peers'
// addresses are not known until they check in), so each leg's learned
// address is defended two ways: datagrams that are not shaped like
// WireGuard messages are dropped without forwarding, learning, or
// keeping the pair alive; and once a leg has an address, only a
// handshake-shaped message may move it. A roaming peer's WireGuard
// re-handshakes within seconds when replies stop arriving, so genuine
// address changes still converge, while a spoofed data packet cannot
// steal the return stream.
//
// It runs embedded inside the control plane (one binary, direct
// allocation calls) or standalone via cmd/relay (public-IP host,
// shared-secret HTTP control API).
package relay

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	idleTimeout   = 10 * time.Minute
	cleanupPeriod = time.Minute

	// socketBuffer sizes the relay's UDP send/receive buffers. The
	// default (~208KB) drops packets under the bursty, bidirectional
	// load a busy relayed pair generates; a few MB absorbs bursts
	// without adding latency. Best-effort: the kernel silently clamps
	// to net.core.{r,w}mem_max, so this never fails a bind.
	socketBuffer = 4 << 20
)

// tuneUDPBuffers enlarges a forwarding socket's kernel buffers. Errors
// are non-fatal — the socket still works at the default size.
func tuneUDPBuffers(conn *net.UDPConn) {
	_ = conn.SetReadBuffer(socketBuffer)
	_ = conn.SetWriteBuffer(socketBuffer)
}

// ErrPortsExhausted means the configured port range has no room for
// another pair. Callers should surface this distinctly (the control
// plane maps it to 503).
var ErrPortsExhausted = errors.New("relay port range exhausted")

type Config struct {
	// DataIP is the address forwarding sockets bind on.
	DataIP net.IP

	// PortMin/PortMax bound the forwarding ports so a firewall can
	// allow them. Both zero means ephemeral ports.
	PortMin, PortMax int
}

type Server struct {
	cfg  Config
	done chan struct{}

	mu    sync.Mutex
	pairs map[string]*pair
}

func New(cfg Config) (*Server, error) {
	if (cfg.PortMin == 0) != (cfg.PortMax == 0) {
		return nil, errors.New("set both PortMin and PortMax, or neither")
	}

	if cfg.PortMin > cfg.PortMax {
		return nil, fmt.Errorf("PortMin %d exceeds PortMax %d", cfg.PortMin, cfg.PortMax)
	}

	if cfg.DataIP == nil {
		cfg.DataIP = net.IPv4zero
	}

	s := &Server{
		cfg:   cfg,
		done:  make(chan struct{}),
		pairs: make(map[string]*pair),
	}

	go s.cleanupLoop()

	return s, nil
}

// Close stops the cleanup loop and tears down every forwarding pair.
func (s *Server) Close() {
	close(s.done)

	s.mu.Lock()
	defer s.mu.Unlock()

	for id, p := range s.pairs {
		p.connA.Close()
		p.connB.Close()
		delete(s.pairs, id)
	}
}

// listenUDP binds one forwarding socket, inside the configured port
// range when one is set. Ports held by live pairs simply fail the
// bind and are skipped; expired pairs release theirs on cleanup.
func (s *Server) listenUDP() (*net.UDPConn, error) {
	if s.cfg.PortMin == 0 {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: s.cfg.DataIP})
		if err == nil {
			tuneUDPBuffers(conn)
		}
		return conn, err
	}

	for p := s.cfg.PortMin; p <= s.cfg.PortMax; p++ {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: s.cfg.DataIP, Port: p})
		if err == nil {
			tuneUDPBuffers(conn)
			return conn, nil
		}
	}

	return nil, fmt.Errorf("%w: no free UDP port in %d-%d", ErrPortsExhausted, s.cfg.PortMin, s.cfg.PortMax)
}

// Allocate returns the port pair for id, creating the forwarding
// session on first use. Idempotent per id.
func (s *Server) Allocate(id string) (portA, portB int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p, ok := s.pairs[id]; ok {
		p.touch()
		return p.portA(), p.portB(), nil
	}

	connA, err := s.listenUDP()
	if err != nil {
		return 0, 0, fmt.Errorf("bind port A: %w", err)
	}

	connB, err := s.listenUDP()
	if err != nil {
		connA.Close()
		return 0, 0, fmt.Errorf("bind port B: %w", err)
	}

	p := &pair{id: id, connA: connA, connB: connB}
	p.touch()
	s.pairs[id] = p

	go p.forward(connA, connB, true)
	go p.forward(connB, connA, false)

	slog.Info("relay allocated pair", "pair", id, "port_a", p.portA(), "port_b", p.portB())

	return p.portA(), p.portB(), nil
}

func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(cleanupPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}

		s.mu.Lock()

		for id, p := range s.pairs {
			idle := time.Since(time.Unix(0, p.lastActive.Load()))

			if idle > idleTimeout {
				p.connA.Close()
				p.connB.Close()
				delete(s.pairs, id)

				slog.Debug("relay expired idle pair", "pair", id)
			}
		}

		s.mu.Unlock()
	}
}

// pair is one bidirectional forwarding session between two peers.
// The hot path is lock-free: each leg's learned address is an atomic
// pointer and liveness is an atomic timestamp, so the two forward
// goroutines never contend per packet.
type pair struct {
	id string

	connA, connB *net.UDPConn

	srcA, srcB atomic.Pointer[netip.AddrPort]
	lastActive atomic.Int64 // unix nanos
}

func (p *pair) portA() int { return p.connA.LocalAddr().(*net.UDPAddr).Port }
func (p *pair) portB() int { return p.connB.LocalAddr().(*net.UDPAddr).Port }

func (p *pair) touch() {
	p.lastActive.Store(time.Now().UnixNano())
}

// WireGuard wire-format message types with their datagram sizes. The
// relay checks shape only — type byte, zeroed reserved bytes, length —
// which costs nothing per packet and never touches the ciphertext.
const (
	msgInitiation = 1 // handshake initiation, exactly 148 bytes
	msgResponse   = 2 // handshake response, exactly 92 bytes
	msgCookie     = 3 // cookie reply, exactly 64 bytes
	msgTransport  = 4 // transport data, 32 bytes minimum (header + empty-payload tag)
)

// wgShaped reports whether b looks like a WireGuard datagram. Anything
// else — scanner probes, reflection junk, random UDP — is not learned
// from, not forwarded into a peer's WireGuard socket, and does not
// keep the pair alive.
func wgShaped(b []byte) bool {
	if len(b) < 4 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return false
	}

	switch b[0] {
	case msgInitiation:
		return len(b) == 148
	case msgResponse:
		return len(b) == 92
	case msgCookie:
		return len(b) == 64
	case msgTransport:
		return len(b) >= 32
	}

	return false
}

// forward reads packets arriving on in and cross-sends them out via
// out to the opposite side's last known address. fromA marks which
// leg this goroutine serves, so it knows which source to record and
// which destination to use.
//
// A leg adopts the first WireGuard-shaped sender outright, but once
// set, only a handshake-shaped message may move the address. A data
// packet from an unknown source is dropped: an off-path attacker who
// finds the port cannot redirect the ciphertext stream to themselves
// by spoofing, while a genuinely roaming peer re-handshakes from its
// new address within seconds (WireGuard initiates when replies stop)
// and converges.
func (p *pair) forward(in, out *net.UDPConn, fromA bool) {
	buf := make([]byte, 65535)

	self, other := &p.srcA, &p.srcB
	if !fromA {
		self, other = &p.srcB, &p.srcA
	}

	for {
		n, src, err := in.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // socket closed by cleanup or shutdown
		}

		pkt := buf[:n]
		if !wgShaped(pkt) {
			continue
		}

		if cur := self.Load(); cur == nil || *cur != src {
			if cur != nil && pkt[0] == msgTransport {
				continue
			}

			addr := src
			self.Store(&addr)
		}

		p.lastActive.Store(time.Now().UnixNano())

		dst := other.Load()
		if dst == nil {
			continue // other side hasn't checked in yet
		}

		if _, err := out.WriteToUDPAddrPort(pkt, *dst); err != nil {
			slog.Debug("relay forward error", "pair", p.id, "error", err)
		}
	}
}
