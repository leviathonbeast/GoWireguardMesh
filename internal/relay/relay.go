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
// The relay never parses what it forwards — everything is WireGuard
// ciphertext, so a compromised relay can delay or drop traffic but
// not read or forge it. This design exists because kernel WireGuard
// owns its UDP socket and cannot speak TURN's allocation framing; a
// plain forwarder achieves the same fallback with zero cooperation
// from the kernel.
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
	"sync"
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

	p := &pair{id: id, connA: connA, connB: connB, lastActive: time.Now()}
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
			p.mu.Lock()
			idle := time.Since(p.lastActive)
			p.mu.Unlock()

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
type pair struct {
	id string

	connA, connB *net.UDPConn

	mu         sync.Mutex
	srcA, srcB *net.UDPAddr
	lastActive time.Time
}

func (p *pair) portA() int { return p.connA.LocalAddr().(*net.UDPAddr).Port }
func (p *pair) portB() int { return p.connB.LocalAddr().(*net.UDPAddr).Port }

func (p *pair) touch() {
	p.mu.Lock()
	p.lastActive = time.Now()
	p.mu.Unlock()
}

// forward reads packets arriving on in and cross-sends them out via
// out to the opposite side's last known address. fromA marks which
// leg this goroutine serves, so it knows which source to record and
// which destination to use.
func (p *pair) forward(in, out *net.UDPConn, fromA bool) {
	buf := make([]byte, 65535)

	for {
		n, src, err := in.ReadFromUDP(buf)
		if err != nil {
			return // socket closed by cleanup or shutdown
		}

		p.mu.Lock()

		if fromA {
			p.srcA = src
		} else {
			p.srcB = src
		}

		dst := p.srcB
		if !fromA {
			dst = p.srcA
		}

		p.lastActive = time.Now()
		p.mu.Unlock()

		if dst == nil {
			continue // other side hasn't checked in yet
		}

		if _, err := out.WriteToUDP(buf[:n], dst); err != nil {
			slog.Debug("relay forward error", "pair", p.id, "error", err)
		}
	}
}
