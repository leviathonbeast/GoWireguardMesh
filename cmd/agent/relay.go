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

// directRetryAfter is how often a relayed peer gets a fresh chance to
// use the control plane's direct endpoint hint. If the probe does not
// handshake, relayFallbackAfter moves it back to the relay.
const directRetryAfter = 5 * time.Minute

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

	// Retire WebSocket proxies whose pumps have stopped (relay dropped
	// the connection); clearing relayed lets the peer fall back again.
	for key, p := range t.wsProxies {
		if !p.alive() {
			p.close()
			delete(t.wsProxies, key)
			delete(t.relayed, key)
			delete(t.relayedAt, key)
			delete(t.relayEndpoints, key)
			delete(t.directProbes, key)
		}
	}

	for _, peer := range device.Peers {
		t.checkDirectProbe(peer, now)

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

		if t.switchToRelay(peer.PublicKey, silentFor) {
			t.relayed[peer.PublicKey] = true
			t.relayedAt[peer.PublicKey] = now
		}
	}
}

func (t *telemetryReporter) maybeRetryDirect(peer wgtypes.Key, candidates []*net.UDPAddr) {
	if len(candidates) == 0 || !t.relayed[peer] {
		return
	}

	if _, probing := t.directProbes[peer]; probing {
		return
	}

	if time.Since(t.relayedAt[peer]) < directRetryAfter {
		return
	}

	relayEndpoint := t.relayEndpoints[peer]
	if relayEndpoint == nil {
		return
	}

	endpoint := candidates[0]
	if err := t.wg.ConfigureDevice(t.iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  peer,
			UpdateOnly: true,
			Endpoint:   endpoint,
		}},
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[agent] direct retry for %s: %v\n", peer, err)
		return
	}

	t.directProbes[peer] = directProbe{
		started:       time.Now(),
		candidates:    candidates,
		relayEndpoint: relayEndpoint,
	}

	fmt.Printf("[agent] relay: retrying direct endpoint for %s via %s\n", peer, endpoint)
}

func (t *telemetryReporter) checkDirectProbe(peer wgtypes.Peer, now time.Time) {
	probe, ok := t.directProbes[peer.PublicKey]
	if !ok {
		return
	}

	if !peer.LastHandshakeTime.IsZero() && peer.LastHandshakeTime.After(probe.started) &&
		peer.Endpoint != nil && peer.Endpoint.String() != probe.relayEndpoint.String() {
		if p := t.wsProxies[peer.PublicKey]; p != nil {
			p.close()
			delete(t.wsProxies, peer.PublicKey)
		}

		delete(t.directProbes, peer.PublicKey)
		delete(t.relayed, peer.PublicKey)
		delete(t.relayedAt, peer.PublicKey)
		delete(t.relayEndpoints, peer.PublicKey)
		t.firstSeen[peer.PublicKey] = now

		fmt.Printf("[agent] relay: direct endpoint for %s succeeded; leaving relay\n", peer.PublicKey)

		return
	}

	if now.Sub(probe.started) < relayFallbackAfter {
		return
	}

	if probe.index+1 < len(probe.candidates) {
		probe.index++
		probe.started = now
		next := probe.candidates[probe.index]

		if err := t.wg.ConfigureDevice(t.iface, wgtypes.Config{
			Peers: []wgtypes.PeerConfig{{
				PublicKey:  peer.PublicKey,
				UpdateOnly: true,
				Endpoint:   next,
			}},
		}); err != nil {
			fmt.Fprintf(os.Stderr, "[agent] relay: direct candidate %s for %s: %v\n", next, peer.PublicKey, err)
			return
		}

		t.directProbes[peer.PublicKey] = probe
		fmt.Printf("[agent] relay: trying next direct endpoint for %s via %s\n", peer.PublicKey, next)

		return
	}

	if err := t.wg.ConfigureDevice(t.iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  peer.PublicKey,
			UpdateOnly: true,
			Endpoint:   probe.relayEndpoint,
		}},
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[agent] relay: restore relay endpoint for %s: %v\n", peer.PublicKey, err)
		return
	}

	delete(t.directProbes, peer.PublicKey)
	t.relayedAt[peer.PublicKey] = now

	fmt.Printf("[agent] relay: direct probe for %s failed; staying on relay\n", peer.PublicKey)
}

// switchToRelay moves one peer onto the configured relay transport.
// Returns true when the peer is now relayed (so it is not retried).
func (t *telemetryReporter) switchToRelay(peer wgtypes.Key, silentFor time.Duration) bool {
	switch t.relayTransport {
	case relayWebSocket:
		proxy, err := t.startWSRelay(peer)
		if err != nil {
			if err == errNoWSRelay {
				t.relayBroken = true
				fmt.Fprintln(os.Stderr, "[agent] relay: control plane has no websocket relay; direct connectivity only")

				return false
			}

			fmt.Fprintf(os.Stderr, "[agent] relay ws for %s: %v\n", peer, err)

			return false
		}

		t.wsProxies[peer] = proxy
		t.relayEndpoints[peer] = proxy.endpoint()

		fmt.Printf("[agent] relay: no handshake with %s for %s, tunnelling over websocket\n",
			peer, silentFor.Round(time.Second))

		return true

	default: // relayUDP
		endpoint, err := t.requestRelayEndpoint(peer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[agent] relay request failed for %s: %v\n", peer, err)
			return false
		}

		if endpoint == "" {
			t.relayBroken = true
			fmt.Fprintln(os.Stderr, "[agent] relay: control plane has no relay configured; direct connectivity only")

			return false
		}

		udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[agent] relay: resolve %q: %v\n", endpoint, err)
			return false
		}

		if err := t.wg.ConfigureDevice(t.iface, wgtypes.Config{
			Peers: []wgtypes.PeerConfig{{
				PublicKey:  peer,
				UpdateOnly: true,
				Endpoint:   udpAddr,
			}},
		}); err != nil {
			fmt.Fprintf(os.Stderr, "[agent] relay: set endpoint for %s: %v\n", peer, err)
			return false
		}
		t.relayEndpoints[peer] = udpAddr

		fmt.Printf("[agent] relay: no handshake with %s for %s, switched to udp relay %s\n",
			peer, silentFor.Round(time.Second), endpoint)

		return true
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
