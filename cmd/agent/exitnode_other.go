//go:build !linux

package main

import (
	"log/slog"
	"net/netip"
)

// Exit-node routing needs Linux policy routing (fwmark + rule tables)
// and iptables; other platforms warn once and stay on their normal
// default route. The 0.0.0.0/0 AllowedIPs a client still receives are
// inert without the routes: nothing steers traffic into them.

var (
	exitRoutesWarned bool
	exitNATWarned    bool
)

func wgFirewallMark() *int { return nil }

func applyExitRoutes(iface string, active, v6 bool, enabled *bool) error {
	if active && !exitRoutesWarned {
		slog.Warn("exit-node routing is Linux-only; this platform keeps its normal default route")
		exitRoutesWarned = true
	}
	return nil
}

func applyExitNodeNAT(iface string, active bool, net4, net6 netip.Prefix, enabled *bool) error {
	if active && !exitNATWarned {
		slog.Warn("serving as an exit node is Linux-only; assigned peers get no internet through this node")
		exitNATWarned = true
	}
	return nil
}

func cleanupExitState() {}
