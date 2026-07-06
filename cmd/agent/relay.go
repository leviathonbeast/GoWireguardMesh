package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// directStaleAfter is how long a direct peer may be silent before the
// agent gives up and asks for a relay. It keys off inbound bytes too:
// WireGuard rekeys roughly every 120s, but persistent keepalives arrive
// every 25s and bump rx_bytes, so a healthy direct path stays sticky.
const directStaleAfter = 90 * time.Second

// directProbeInterval is the normal candidate dwell time during an
// uncoordinated relay->direct retry.
const directProbeInterval = 60 * time.Second

// coordinatedProbeInterval gives WireGuard's ~5s handshake retry a real
// chance on each candidate while still rotating fast enough for NAT
// hole-punch attempts to overlap between peers.
const coordinatedProbeInterval = 8 * time.Second

const coordinatedProbeWindow = 45 * time.Second

// directRetryAfter is the base cadence at which a relayed peer gets a
// fresh chance to use the control plane's direct endpoint hint. If the
// probe does not handshake, directProbeInterval moves it back to the
// relay. See directRetryInterval for the failure back-off.
const directRetryAfter = 5 * time.Minute

// directRetryInterval backs the uncoordinated relay->direct retry off as
// probes keep failing, so a pair that genuinely cannot hole-punch (e.g. a
// firewall-blocked inbound) settles on a stable relay instead of tearing it
// down every 5 min forever. maybeRetryDirect resets the failure count to 0
// when the peer's candidate set changes (a new path deserves a prompt try).
// Kept comfortably above the 25s keepalive / 120s rekey so it never fights
// the sticky-direct logic. 5m -> 10m -> 20m -> capped at 30m.
func directRetryInterval(failures int) time.Duration {
	if failures < 0 {
		failures = 0
	}
	if failures > 3 {
		failures = 3
	}

	d := directRetryAfter << failures
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}

	return d
}

// candidateDigest is a stable fingerprint of a peer's candidate set, used
// to detect when a new path appears (which re-arms a prompt direct retry).
func candidateDigest(candidates []*net.UDPAddr) string {
	if len(candidates) == 0 {
		return ""
	}

	addrs := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if c != nil {
			addrs = append(addrs, c.String())
		}
	}
	sort.Strings(addrs)

	return strings.Join(addrs, ",")
}

// checkHandshakes finds peers whose direct path never came up or has
// gone genuinely silent and moves them to a relayed endpoint. A direct
// peer that is still receiving keepalives stays direct even when its
// last handshake is older than the normal WireGuard rekey interval.
func (t *telemetryReporter) checkHandshakes() {
	device, err := t.wg.Device()
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

		silentFor := t.directSilentFor(peer, now)
		if silentFor < directStaleAfter {
			continue
		}

		if t.switchToRelay(peer.PublicKey, silentFor) {
			t.relayed[peer.PublicKey] = true
			t.relayedAt[peer.PublicKey] = now
		}
	}
}

func (t *telemetryReporter) directSilentFor(peer wgtypes.Peer, now time.Time) time.Duration {
	last := t.firstSeen[peer.PublicKey]

	if inbound := t.lastInbound[peer.PublicKey]; inbound.After(last) {
		last = inbound
	}

	if !peer.LastHandshakeTime.IsZero() && peer.LastHandshakeTime.After(last) {
		last = peer.LastHandshakeTime
	}

	if last.IsZero() {
		return 0
	}

	return now.Sub(last)
}

func (t *telemetryReporter) maybeRetryDirect(peer wgtypes.Key, candidates []*net.UDPAddr, punchEpoch int) {
	if len(candidates) == 0 || !t.relayed[peer] {
		return
	}

	// A changed candidate set means a new path may now work: forget past
	// failures so this peer gets a prompt (un-backed-off) retry.
	if digest := candidateDigest(candidates); digest != t.lastCandidates[peer] {
		if t.lastCandidates == nil {
			t.lastCandidates = make(map[wgtypes.Key]string)
		}
		t.lastCandidates[peer] = digest
		delete(t.directFailures, peer)
	}

	fast := false
	if punchEpoch > 0 && punchEpoch > t.lastPunchEpoch[peer] {
		if t.lastPunchEpoch == nil {
			t.lastPunchEpoch = make(map[wgtypes.Key]int)
		}
		t.lastPunchEpoch[peer] = punchEpoch
		fast = true
	}

	if _, probing := t.directProbes[peer]; probing && !fast {
		return
	}

	if !fast && time.Since(t.relayedAt[peer]) < directRetryInterval(t.directFailures[peer]) {
		return
	}

	interval := directProbeInterval
	window := time.Duration(0)
	if fast {
		interval = coordinatedProbeInterval
		window = coordinatedProbeWindow
	}

	t.startDirectProbe(peer, candidates, interval, window, punchEpoch)
}

func (t *telemetryReporter) startDirectProbe(peer wgtypes.Key, candidates []*net.UDPAddr, interval, window time.Duration, epoch int) {
	relayEndpoint := t.relayEndpoints[peer]
	if relayEndpoint == nil {
		return
	}

	now := time.Now()
	probe := directProbe{
		started:       now,
		candidates:    candidates,
		relayEndpoint: relayEndpoint,
		interval:      interval,
		epoch:         epoch,
	}
	if window > 0 {
		probe.deadline = now.Add(window)
	}

	if t.applyDirectProbeEndpoint(peer, candidates[0]) {
		if t.directProbes == nil {
			t.directProbes = make(map[wgtypes.Key]directProbe)
		}
		t.directProbes[peer] = probe
		fmt.Printf("[agent] relay: retrying direct endpoint for %s via %s\n", peer, candidates[0])
	}
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
		delete(t.directFailures, peer.PublicKey)
		delete(t.lastCandidates, peer.PublicKey)
		t.firstSeen[peer.PublicKey] = now

		fmt.Printf("[agent] relay: direct endpoint for %s succeeded; leaving relay\n", peer.PublicKey)

		return
	}

	if now.Sub(probe.started) < probe.interval {
		return
	}

	canRotate := false
	if probe.deadline.IsZero() {
		canRotate = probe.index+1 < len(probe.candidates)
	} else {
		canRotate = now.Before(probe.deadline)
	}

	if canRotate {
		probe.index++
		if probe.index >= len(probe.candidates) {
			probe.index = 0
		}
		probe.started = now
		next := probe.candidates[probe.index]

		if !t.applyDirectProbeEndpoint(peer.PublicKey, next) {
			return
		}

		t.directProbes[peer.PublicKey] = probe
		fmt.Printf("[agent] relay: trying next direct endpoint for %s via %s\n", peer.PublicKey, next)

		return
	}

	if err := t.wg.ConfigureDevice(wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  peer.PublicKey,
			UpdateOnly: true,
			Endpoint:   probe.relayEndpoint,
		}},
	}); err != nil {
		slog.Warn("restore relay endpoint failed", "peer", peer.PublicKey, "error", err)
		return
	}

	delete(t.directProbes, peer.PublicKey)
	t.relayedAt[peer.PublicKey] = now
	if t.directFailures == nil {
		t.directFailures = make(map[wgtypes.Key]int)
	}
	t.directFailures[peer.PublicKey]++

	fmt.Printf("[agent] relay: direct probe for %s failed; staying on relay (attempt %d)\n",
		peer.PublicKey, t.directFailures[peer.PublicKey])
}

func (t *telemetryReporter) applyDirectProbeEndpoint(peer wgtypes.Key, endpoint *net.UDPAddr) bool {
	if err := t.wg.ConfigureDevice(wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  peer,
			UpdateOnly: true,
			Endpoint:   endpoint,
		}},
	}); err != nil {
		slog.Debug("direct candidate failed", "candidate", endpoint, "peer", peer, "error", err)
		return false
	}

	return true
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

			slog.Warn("websocket relay failed", "peer", peer, "error", err)

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
			slog.Warn("relay request failed", "peer", peer, "error", err)
			return false
		}

		if endpoint == "" {
			t.relayBroken = true
			fmt.Fprintln(os.Stderr, "[agent] relay: control plane has no relay configured; direct connectivity only")

			return false
		}

		udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			slog.Warn("relay endpoint resolve failed", "endpoint", endpoint, "error", err)
			return false
		}

		if err := t.wg.ConfigureDevice(wgtypes.Config{
			Peers: []wgtypes.PeerConfig{{
				PublicKey:  peer,
				UpdateOnly: true,
				Endpoint:   udpAddr,
			}},
		}); err != nil {
			slog.Warn("relay set endpoint failed", "peer", peer, "error", err)
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
