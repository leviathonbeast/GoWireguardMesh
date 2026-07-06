package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgBackend is the subset of WireGuard device operations the agent's
// control loop needs. It lets the reporter, sync, and relay-fallback
// logic run identically on kernel WireGuard (Linux, via wgctrl) and on
// the embedded wireguard-go device (Windows, via its in-process UAPI).
// The backend knows its own device, so callers never pass an interface
// name.
type wgBackend interface {
	// Device returns the current peer set with counters, last-handshake
	// times, and endpoints — everything telemetry and relay fallback
	// read.
	Device() (*wgtypes.Device, error)

	// ConfigureDevice applies a full or incremental peer diff.
	ConfigureDevice(cfg wgtypes.Config) error

	// Close releases the backend's handle to the device.
	Close() error
}

// buildIPCSet renders a wgtypes.Config as wireguard-go UAPI "set" text
// for device.IpcSet. It is the Windows analogue of wgctrl's
// ConfigureDevice.
//
// Critical: never emit a blank line. IpcSetOperation treats the first
// blank line as end-of-input and stops — the reason the old
// buildIPCConfig (a blank line after every peer) silently configured
// only the first peer. Device-level directives must also precede the
// first public_key, which flips the parser out of its device section.
func buildIPCSet(cfg wgtypes.Config) string {
	var b strings.Builder

	if cfg.PrivateKey != nil {
		fmt.Fprintf(&b, "private_key=%s\n", hexKey(*cfg.PrivateKey))
	}

	if cfg.ListenPort != nil {
		fmt.Fprintf(&b, "listen_port=%d\n", *cfg.ListenPort)
	}

	if cfg.FirewallMark != nil {
		fmt.Fprintf(&b, "fwmark=%d\n", *cfg.FirewallMark)
	}

	if cfg.ReplacePeers {
		b.WriteString("replace_peers=true\n")
	}

	for _, p := range cfg.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", hexKey(p.PublicKey))

		if p.Remove {
			// A removed peer takes no other attributes.
			b.WriteString("remove=true\n")
			continue
		}

		if p.UpdateOnly {
			b.WriteString("update_only=true\n")
		}

		if p.PresharedKey != nil {
			fmt.Fprintf(&b, "preshared_key=%s\n", hexKey(*p.PresharedKey))
		}

		if p.Endpoint != nil {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint.String())
		}

		if p.PersistentKeepaliveInterval != nil {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(p.PersistentKeepaliveInterval.Seconds()))
		}

		if p.ReplaceAllowedIPs {
			b.WriteString("replace_allowed_ips=true\n")
		}

		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip.String())
		}
	}

	return b.String()
}

// parseUAPI parses wireguard-go UAPI "get" text (device.IpcGet) into a
// wgtypes.Device. Keys are lowercase hex, endpoints are numeric
// host:port, and byte/handshake counters are decimal — the format the
// embedded device emits.
func parseUAPI(conf string) (*wgtypes.Device, error) {
	dev := &wgtypes.Device{}

	// Handshake arrives as two lines (sec then nsec); combine them, and
	// keep the zero value as a zero time so LastHandshakeTime.IsZero()
	// stays true for peers that never handshook (relay fallback depends
	// on it — time.Unix(0,0) is NOT zero).
	var hsSec int64

	for _, line := range strings.Split(conf, "\n") {
		if line == "" {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			// Tolerate a trailing "errno=0" style terminator.
			continue
		}

		// Device-level fields (emitted before the first public_key).
		switch key {
		case "private_key":
			k, err := parseHexKey(value)
			if err != nil {
				return nil, fmt.Errorf("parse private_key: %w", err)
			}
			dev.PrivateKey = k
			dev.PublicKey = k.PublicKey()
			continue
		case "listen_port":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("parse listen_port %q: %w", value, err)
			}
			dev.ListenPort = n
			continue
		case "fwmark":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("parse fwmark %q: %w", value, err)
			}
			dev.FirewallMark = n
			continue
		case "errno", "protocol_version":
			continue
		}

		if key == "public_key" {
			k, err := parseHexKey(value)
			if err != nil {
				return nil, fmt.Errorf("parse public_key: %w", err)
			}
			dev.Peers = append(dev.Peers, wgtypes.Peer{PublicKey: k})
			hsSec = 0
			continue
		}

		// Remaining keys belong to the peer most recently opened.
		if len(dev.Peers) == 0 {
			continue
		}
		peer := &dev.Peers[len(dev.Peers)-1]

		if err := applyPeerField(peer, key, value, &hsSec); err != nil {
			return nil, err
		}
	}

	return dev, nil
}

// applyPeerField sets one UAPI get field on the current peer.
func applyPeerField(peer *wgtypes.Peer, key, value string, hsSec *int64) error {
	switch key {
	case "preshared_key":
		k, err := parseHexKey(value)
		if err != nil {
			return fmt.Errorf("parse preshared_key: %w", err)
		}
		peer.PresharedKey = k

	case "endpoint":
		ap, err := netip.ParseAddrPort(value)
		if err != nil {
			return fmt.Errorf("parse endpoint %q: %w", value, err)
		}
		peer.Endpoint = net.UDPAddrFromAddrPort(ap)

	case "last_handshake_time_sec":
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("parse last_handshake_time_sec %q: %w", value, err)
		}
		*hsSec = n
		if n != 0 {
			peer.LastHandshakeTime = time.Unix(n, 0)
		}

	case "last_handshake_time_nsec":
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("parse last_handshake_time_nsec %q: %w", value, err)
		}
		if *hsSec != 0 || n != 0 {
			peer.LastHandshakeTime = time.Unix(*hsSec, n)
		}

	case "tx_bytes":
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("parse tx_bytes %q: %w", value, err)
		}
		peer.TransmitBytes = n

	case "rx_bytes":
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("parse rx_bytes %q: %w", value, err)
		}
		peer.ReceiveBytes = n

	case "persistent_keepalive_interval":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parse persistent_keepalive_interval %q: %w", value, err)
		}
		peer.PersistentKeepaliveInterval = time.Duration(n) * time.Second

	case "allowed_ip":
		_, ipnet, err := net.ParseCIDR(value)
		if err != nil {
			return fmt.Errorf("parse allowed_ip %q: %w", value, err)
		}
		peer.AllowedIPs = append(peer.AllowedIPs, *ipnet)
	}

	// Unknown keys are ignored for forward-compatibility.
	return nil
}

// hexKey renders a WireGuard key as the lowercase hex the UAPI expects.
func hexKey(k wgtypes.Key) string {
	return hex.EncodeToString(k[:])
}

// parseHexKey decodes a 64-char hex UAPI key into a wgtypes.Key.
func parseHexKey(s string) (wgtypes.Key, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("decode hex key: %w", err)
	}

	return wgtypes.NewKey(raw)
}
