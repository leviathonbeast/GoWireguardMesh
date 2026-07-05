// Command relay runs the wgmesh NAT-traversal relay standalone, for
// deployments where the relay lives on its own public-IP host. When
// the relay can run on the same host as the control plane, prefer
// the server's --relay-embedded mode instead: one binary, no shared
// secret, no control hop.
//
// The control API must be reachable by the control plane only —
// firewall it or bind it to a private address.
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

	"gowireguard/internal/firewall"
	"gowireguard/internal/relay"
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
	portMin := flag.Int("port-min", 0, "lowest forwarding UDP port (0 = ephemeral; set a range so the firewall can allow it)")
	portMax := flag.Int("port-max", 0, "highest forwarding UDP port")
	manageFirewall := flag.Bool("manage-firewall", true, "open the forwarding port range on the host firewall (requires --port-min/--port-max)")
	flag.Parse()

	ip := net.ParseIP(*dataIP)
	if ip == nil {
		return fmt.Errorf("parse data-ip %q: not an IP address", *dataIP)
	}

	secret, err := loadOrGenerateSecret(*secretFile)
	if err != nil {
		return err
	}

	rs, err := relay.New(relay.Config{DataIP: ip, PortMin: *portMin, PortMax: *portMax})
	if err != nil {
		return err
	}
	defer rs.Close()

	if *manageFirewall && *portMin > 0 {
		fw, ferr := firewall.OpenWithReconcile("wgmesh-relay", *secretFile+".fw")
		if ferr != nil {
			log.Printf("firewall: %v; open udp %d-%d yourself if needed", ferr, *portMin, *portMax)
		} else if err := fw.AllowUDPRange(*portMin, *portMax); err != nil {
			log.Printf("firewall (%s): %v", fw.Backend(), err)
		} else {
			log.Printf("firewall (%s): opened udp %d-%d", fw.Backend(), *portMin, *portMax)
			defer func() {
				if err := fw.Close(); err != nil {
					log.Printf("firewall cleanup: %v", err)
				}
			}()
		}
	} else if *manageFirewall {
		log.Printf("firewall: skipped — ephemeral ports cannot be pre-opened; set --port-min/--port-max")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /allocate", handleAllocate(rs, secret))

	log.Printf("relay control on http://%s (secret in %s), forwarding on %s", *control, *secretFile, *dataIP)

	if err := http.ListenAndServe(*control, mux); err != nil {
		return fmt.Errorf("control server: %w", err)
	}

	return nil
}

func handleAllocate(rs *relay.Server, secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		presented, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(presented), []byte(secret)) != 1 {
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

		portA, portB, err := rs.Allocate(body.PairID)
		if err != nil {
			log.Printf("allocate %q: %v", body.PairID, err)

			if errors.Is(err, relay.ErrPortsExhausted) {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "relay port range exhausted"})
				return
			}

			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})

			return
		}

		writeJSON(w, http.StatusOK, map[string]int{"port_a": portA, "port_b": portB})
	}
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}
