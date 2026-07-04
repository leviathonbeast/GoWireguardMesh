// Command relay is the wgmesh NAT-traversal fallback: a dumb UDP
// pair forwarder.
//
// For each peer pair the control plane allocates two UDP ports over
// the control API. Peer A points its WireGuard endpoint for B at
// port A; peer B points its endpoint for A at port B. The relay
// learns each side's real address from the first packet it receives
// (WireGuard persistent keepalives guarantee those arrive) and then
// cross-forwards: traffic in on port A goes out port B to B's last
// known address, and vice versa.
//
// The relay never parses what it forwards — everything is WireGuard
// ciphertext, so a compromised relay can delay or drop traffic but
// not read or forge it. This design exists because kernel WireGuard
// owns its UDP socket and cannot speak TURN's allocation framing;
// a plain forwarder achieves the same fallback with zero cooperation
// from the kernel.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	idleTimeout   = 10 * time.Minute
	cleanupPeriod = time.Minute
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	control := flag.String("control", "127.0.0.1:8081", "control API listen address (server-to-relay; keep private)")
	dataIP := flag.String("data-ip", "0.0.0.0", "IP to bind forwarding ports on")
	secretFile := flag.String("secret-file", "relay-secret", "path to control API shared secret (generated if missing)")
	flag.Parse()

	secret, err := loadOrGenerateSecret(*secretFile)
	if err != nil {
		return err
	}

	r := &relay{
		dataIP: net.ParseIP(*dataIP),
		pairs:  make(map[string]*pair),
		secret: secret,
	}

	if r.dataIP == nil {
		return fmt.Errorf("parse data-ip %q: not an IP address", *dataIP)
	}

	go r.cleanupLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /allocate", r.handleAllocate)

	log.Printf("relay control on http://%s (secret in %s), forwarding on %s", *control, *secretFile, *dataIP)

	if err := http.ListenAndServe(*control, mux); err != nil {
		return fmt.Errorf("control server: %w", err)
	}

	return nil
}

func loadOrGenerateSecret(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				return "", fmt.Errorf("generate relay secret: %w", err)
			}

			secret := hex.EncodeToString(raw)

			if err := os.WriteFile(path, []byte(secret+"\n"), 0600); err != nil {
				return "", fmt.Errorf("write relay secret %q: %w", path, err)
			}

			return secret, nil
		}

		return "", fmt.Errorf("read relay secret %q: %w", path, err)
	}

	return strings.TrimSpace(string(data)), nil
}

type relay struct {
	dataIP net.IP
	secret string

	mu    sync.Mutex
	pairs map[string]*pair
}

// pair is one bidirectional forwarding session between two peers.
type pair struct {
	id string

	connA, connB *net.UDPConn

	mu         sync.Mutex
	srcA, srcB *net.UDPAddr
	lastActive time.Time
}

func (r *relay) handleAllocate(w http.ResponseWriter, req *http.Request) {
	presented, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(presented), []byte(r.secret)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var body struct {
		PairID string `json:"pair_id"`
	}

	if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.PairID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pair_id is required"})
		return
	}

	p, err := r.allocate(body.PairID)
	if err != nil {
		log.Printf("allocate %q: %v", body.PairID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})

		return
	}

	writeJSON(w, http.StatusOK, map[string]int{
		"port_a": p.connA.LocalAddr().(*net.UDPAddr).Port,
		"port_b": p.connB.LocalAddr().(*net.UDPAddr).Port,
	})
}

// allocate returns the existing pair for id or creates one on two
// fresh ephemeral UDP ports.
func (r *relay) allocate(id string) (*pair, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if p, ok := r.pairs[id]; ok {
		p.touch()
		return p, nil
	}

	connA, err := net.ListenUDP("udp", &net.UDPAddr{IP: r.dataIP})
	if err != nil {
		return nil, fmt.Errorf("bind port A: %w", err)
	}

	connB, err := net.ListenUDP("udp", &net.UDPAddr{IP: r.dataIP})
	if err != nil {
		connA.Close()
		return nil, fmt.Errorf("bind port B: %w", err)
	}

	p := &pair{id: id, connA: connA, connB: connB, lastActive: time.Now()}
	r.pairs[id] = p

	go p.forward(connA, connB, true)
	go p.forward(connB, connA, false)

	log.Printf("allocated pair %q: ports %d/%d",
		id,
		connA.LocalAddr().(*net.UDPAddr).Port,
		connB.LocalAddr().(*net.UDPAddr).Port,
	)

	return p, nil
}

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
			return // socket closed by cleanup
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
			log.Printf("pair %q: forward: %v", p.id, err)
		}
	}
}

func (r *relay) cleanupLoop() {
	ticker := time.NewTicker(cleanupPeriod)
	defer ticker.Stop()

	for range ticker.C {
		r.mu.Lock()

		for id, p := range r.pairs {
			p.mu.Lock()
			idle := time.Since(p.lastActive)
			p.mu.Unlock()

			if idle > idleTimeout {
				p.connA.Close()
				p.connB.Close()
				delete(r.pairs, id)

				log.Printf("expired idle pair %q", id)
			}
		}

		r.mu.Unlock()
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}
