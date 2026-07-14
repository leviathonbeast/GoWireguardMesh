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

// peerLabel renders a peer for logs: "hostname (ab12cd)" when the
// control plane has told us the name via sync, else the short key
// alone. Names are advisory only — routing stays keyed on the full
// public key.
func (t *telemetryReporter) peerLabel(key wgtypes.Key) string {
	short := key.String()[:6]
	if name := t.hostnames[key]; name != "" {
		return fmt.Sprintf("%s (%s)", name, short)
	}
	return short
}

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

// A single WireGuard handshake can be the last packet of an asymmetric
// probe: one peer may already have restored its relay endpoint. Keep the
// relay session available and require a later inbound keepalive/packet before
// committing to direct. Persistent keepalives are 25s, so 20s distinguishes
// a later observation while 60s gives it ample time to arrive.
const (
	directProbationMin     = 20 * time.Second
	directProbationTimeout = 60 * time.Second
)

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
			delete(t.pathKinds, key)
		}
	}
	for key, p := range t.quicProxies {
		if !p.alive() {
			p.close()
			delete(t.quicProxies, key)
			delete(t.relayed, key)
			delete(t.relayedAt, key)
			delete(t.relayEndpoints, key)
			delete(t.directProbes, key)
			delete(t.pathKinds, key)
			t.quicUnavailable[key] = true
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
	if t.directProbeOff {
		return
	}
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
		fmt.Printf("[agent] relay: retrying direct endpoint for %s via %s\n", t.peerLabel(peer), candidates[0])
	}
}

func (t *telemetryReporter) checkDirectProbe(peer wgtypes.Peer, now time.Time) {
	probe, ok := t.directProbes[peer.PublicKey]
	if !ok {
		return
	}

	directEndpoint := peer.Endpoint != nil && peer.Endpoint.String() != probe.relayEndpoint.String()
	if probe.confirmedAt.IsZero() && !peer.LastHandshakeTime.IsZero() &&
		peer.LastHandshakeTime.After(probe.started) && directEndpoint {
		probe.confirmedAt = now
		t.directProbes[peer.PublicKey] = probe
		fmt.Printf("[agent] relay: direct handshake with %s; verifying bidirectional stability\n", t.peerLabel(peer.PublicKey))
		return
	}

	if !probe.confirmedAt.IsZero() {
		// A later increase in received WireGuard bytes proves the remote still
		// targets this direct endpoint after the initial handshake exchange.
		if inbound := t.lastInbound[peer.PublicKey]; directEndpoint &&
			inbound.After(probe.confirmedAt.Add(directProbationMin)) {
			t.promoteDirect(peer.PublicKey, now)
			return
		}

		if now.Sub(probe.confirmedAt) < directProbationTimeout {
			return
		}

		t.restoreRelayAfterProbe(peer.PublicKey, probe, now, "direct path did not remain bidirectional")
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
		fmt.Printf("[agent] relay: trying next direct endpoint for %s via %s\n", t.peerLabel(peer.PublicKey), next)

		return
	}

	t.restoreRelayAfterProbe(peer.PublicKey, probe, now, "direct probe failed")
}

func (t *telemetryReporter) promoteDirect(key wgtypes.Key, now time.Time) {
	if p := t.wsProxies[key]; p != nil {
		p.close()
		delete(t.wsProxies, key)
	}
	if p := t.quicProxies[key]; p != nil {
		p.close()
		delete(t.quicProxies, key)
	}

	delete(t.directProbes, key)
	delete(t.relayed, key)
	delete(t.relayedAt, key)
	delete(t.relayEndpoints, key)
	delete(t.directFailures, key)
	delete(t.lastCandidates, key)
	delete(t.pathKinds, key)
	delete(t.quicUnavailable, key)
	t.firstSeen[key] = now

	fmt.Printf("[agent] relay: bidirectional direct path for %s stable; leaving relay\n", t.peerLabel(key))
}

func (t *telemetryReporter) restoreRelayAfterProbe(key wgtypes.Key, probe directProbe, now time.Time, reason string) {
	if err := t.wg.ConfigureDevice(wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  key,
			UpdateOnly: true,
			Endpoint:   probe.relayEndpoint,
		}},
	}); err != nil {
		slog.Warn("restore relay endpoint failed", "peer", key, "error", err)
		return
	}

	delete(t.directProbes, key)
	t.relayedAt[key] = now
	if t.directFailures == nil {
		t.directFailures = make(map[wgtypes.Key]int)
	}
	t.directFailures[key]++

	fmt.Printf("[agent] relay: %s for %s; staying on relay (attempt %d)\n",
		reason, t.peerLabel(key), t.directFailures[key])
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
	case relayAuto:
		if !t.quicUnavailable[peer] {
			proxy, err := t.startQUICRelay(peer)
			if err == nil {
				t.quicProxies[peer] = proxy
				t.relayEndpoints[peer] = proxy.endpoint()
				t.pathKinds[peer] = "quic-relay"
				fmt.Printf("[agent] relay: no handshake with %s for %s, tunnelling WireGuard ciphertext over QUIC\n",
					t.peerLabel(peer), silentFor.Round(time.Second))
				return true
			}
			t.quicUnavailable[peer] = true
			slog.Warn("QUIC relay unavailable; falling back to HTTPS WebSocket", "peer", peer, "error", err)
		}
		proxy, err := t.startWSRelay(peer)
		if err != nil {
			if err == errNoWSRelay {
				t.relayBroken = true
			}
			slog.Warn("websocket relay failed", "peer", peer, "error", err)
			return false
		}
		t.wsProxies[peer] = proxy
		t.relayEndpoints[peer] = proxy.endpoint()
		t.pathKinds[peer] = "ws-relay"
		fmt.Printf("[agent] relay: QUIC unavailable; tunnelling WireGuard ciphertext over HTTPS WebSocket for %s\n", t.peerLabel(peer))
		return true
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
		t.pathKinds[peer] = "ws-relay"

		fmt.Printf("[agent] relay: no handshake with %s for %s, tunnelling over websocket\n",
			t.peerLabel(peer), silentFor.Round(time.Second))

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
		t.pathKinds[peer] = "udp-relay"

		fmt.Printf("[agent] relay: no handshake with %s for %s, switched to udp relay %s\n",
			t.peerLabel(peer), silentFor.Round(time.Second), endpoint)

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
