package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// relayFallbackAfter is how long a peer may sit without a handshake
// (from when we first saw it, or since its last one) before the agent
// gives up on the direct path and asks the control plane for a relay.
// Comfortably longer than a keepalive interval plus WireGuard's
// handshake retries, so working paths never get downgraded.
const relayFallbackAfter = 60 * time.Second

// checkHandshakes finds peers whose direct path never came up (or
// died) and moves them to a relayed endpoint. Runs on the telemetry
// tick. syncPeers never rewrites endpoints of existing peers, so a
// relayed endpoint sticks once set.
func (t *telemetryReporter) checkHandshakes() {
	device, err := t.wg.Device(t.iface)
	if err != nil {
		return
	}

	now := time.Now()

	for _, peer := range device.Peers {
		if _, ok := t.firstSeen[peer.PublicKey]; !ok {
			t.firstSeen[peer.PublicKey] = now
		}

		if t.relayed[peer.PublicKey] || t.relayBroken {
			continue
		}

		// No endpoint at all means we have no address to try; the
		// relay gives us one, so those peers qualify too.
		var silentFor time.Duration

		if peer.LastHandshakeTime.IsZero() {
			silentFor = now.Sub(t.firstSeen[peer.PublicKey])
		} else {
			silentFor = now.Sub(peer.LastHandshakeTime)
		}

		if silentFor < relayFallbackAfter {
			continue
		}

		endpoint, err := t.requestRelayEndpoint(peer.PublicKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "relay: %v\n", err)
			continue
		}

		if endpoint == "" {
			// Control plane has no relay configured; stop asking.
			t.relayBroken = true
			fmt.Fprintln(os.Stderr, "relay: control plane has no relay configured; direct connectivity only")

			continue
		}

		udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			fmt.Fprintf(os.Stderr, "relay: resolve %q: %v\n", endpoint, err)
			continue
		}

		err = t.wg.ConfigureDevice(t.iface, wgtypes.Config{
			Peers: []wgtypes.PeerConfig{{
				PublicKey:  peer.PublicKey,
				UpdateOnly: true,
				Endpoint:   udpAddr,
			}},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "relay: set endpoint for %s: %v\n", peer.PublicKey, err)
			continue
		}

		t.relayed[peer.PublicKey] = true

		fmt.Printf("relay: no handshake with %s for %s, switched to relay %s\n",
			peer.PublicKey, silentFor.Round(time.Second), endpoint)
	}
}

// requestRelayEndpoint asks the control plane for this side's relay
// port for the pair (us, peer). Returns "" when the control plane has
// no relay configured.
func (t *telemetryReporter) requestRelayEndpoint(peer wgtypes.Key) (string, error) {
	body, err := json.Marshal(map[string]string{"peer_public_key": peer.String()})
	if err != nil {
		return "", fmt.Errorf("encode relay request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, t.serverURL+"/relay-pair", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build relay request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+t.authToken)

	resp, err := t.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request relay pair: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", fmt.Errorf("read relay response: %w", err)
	}

	if resp.StatusCode == http.StatusServiceUnavailable {
		return "", nil
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("relay pair rejected: %s", resp.Status)
	}

	var out struct {
		Endpoint string `json:"endpoint"`
	}

	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("decode relay response: %w", err)
	}

	return out.Endpoint, nil
}
