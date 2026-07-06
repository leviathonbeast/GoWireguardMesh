package main

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// syncPeers reconciles the device's peer set with the control plane's
// desired list, applying an incremental diff:
//
//   - unknown peers are added (with the server's endpoint hint)
//   - vanished peers are removed
//   - changed peers (allowed IPs, PSK, keepalive) are updated in place
//
// Existing peers' endpoints are NEVER touched: WireGuard roaming owns
// them once traffic flows, and re-applying a stale server hint every
// interval would break a connection that roaming already fixed.
func syncPeers(backend wgBackend, desired []wgtypes.PeerConfig) error {
	device, err := backend.Device()
	if err != nil {
		return fmt.Errorf("read device: %w", err)
	}

	current := make(map[wgtypes.Key]wgtypes.Peer, len(device.Peers))
	for _, p := range device.Peers {
		current[p.PublicKey] = p
	}

	desiredByKey := make(map[wgtypes.Key]wgtypes.PeerConfig, len(desired))
	for _, p := range desired {
		desiredByKey[p.PublicKey] = p
	}

	var changes []wgtypes.PeerConfig

	for key := range current {
		if _, ok := desiredByKey[key]; !ok {
			changes = append(changes, wgtypes.PeerConfig{
				PublicKey: key,
				Remove:    true,
			})

			slog.Debug("sync remove peer", "peer", key)
		}
	}

	for key, want := range desiredByKey {
		cur, exists := current[key]

		if !exists {
			changes = append(changes, want)

			slog.Debug("sync add peer", "peer", key)

			continue
		}

		fieldsChanged := peerNeedsUpdate(cur, want)

		// A peer that has never completed a handshake may receive a
		// corrected endpoint hint — but only when the hint actually
		// differs from what the device already has. Without a
		// handshake, roaming cannot have moved the endpoint, so the
		// kernel's value IS the last applied hint; comparing against
		// it makes this a one-shot apply instead of a 30s flap. Once
		// a handshake exists, roaming owns the endpoint outright.
		endpointStale := cur.LastHandshakeTime.IsZero() &&
			want.Endpoint != nil &&
			(cur.Endpoint == nil || cur.Endpoint.String() != want.Endpoint.String())

		if !fieldsChanged && !endpointStale {
			continue
		}

		update := want
		update.UpdateOnly = true
		update.ReplaceAllowedIPs = true

		if !endpointStale {
			update.Endpoint = nil // roaming owns established endpoints
		}

		changes = append(changes, update)

		slog.Debug("sync update peer", "peer", key, "fields_changed", fieldsChanged, "endpoint_old", cur.Endpoint, "endpoint_new", update.Endpoint)
	}

	if len(changes) == 0 {
		return nil
	}

	if err := backend.ConfigureDevice(wgtypes.Config{Peers: changes}); err != nil {
		return fmt.Errorf("apply peer sync: %w", err)
	}

	return nil
}

// peerNeedsUpdate compares the fields the control plane owns —
// deliberately not the endpoint, and deliberately not handshake
// state: "no handshake yet" is not a config difference, and treating
// it as one made every sync tick rewrite the peer.
func peerNeedsUpdate(cur wgtypes.Peer, want wgtypes.PeerConfig) bool {
	if !sameAllowedIPs(cur.AllowedIPs, want.AllowedIPs) {
		return true
	}

	var wantPSK wgtypes.Key
	if want.PresharedKey != nil {
		wantPSK = *want.PresharedKey
	}

	if cur.PresharedKey != wantPSK {
		return true
	}

	if want.PersistentKeepaliveInterval != nil &&
		cur.PersistentKeepaliveInterval != *want.PersistentKeepaliveInterval {
		return true
	}

	return false
}

func sameAllowedIPs(a, b []net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}

	as := make([]string, 0, len(a))
	for _, n := range a {
		as = append(as, n.String())
	}

	bs := make([]string, 0, len(b))
	for _, n := range b {
		bs = append(bs, n.String())
	}

	sort.Strings(as)
	sort.Strings(bs)

	return strings.Join(as, ",") == strings.Join(bs, ",")
}
