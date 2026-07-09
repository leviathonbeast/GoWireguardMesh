//go:build !linux

package main

import (
	"fmt"
	"log/slog"
	"strings"
)

func enableGatewayNAT(_ string, rawCIDRs string) (func(), error) {
	if strings.TrimSpace(rawCIDRs) == "" {
		return func() {}, nil
	}
	return nil, fmt.Errorf("--gateway-nat-cidrs is only supported on Linux agents")
}

func refreshGatewayNAT(_ string, rawCIDRs string) error {
	if strings.TrimSpace(rawCIDRs) == "" {
		return nil
	}
	return fmt.Errorf("--gateway-nat-cidrs is only supported on Linux agents")
}

var warnedGatewayRoutesUnsupported bool

// applyGatewayRoutes is a no-op on non-Linux agents: routed static/mobile
// peers still work as long as the underlying OS forwards between the wg
// interface and the mesh (WireGuard installs the AllowedIPs route), but we
// don't program firewall/forwarding rules here. Warn once if this agent is
// actually acting as a gateway so the operator can enable OS forwarding.
func applyGatewayRoutes(_ string, routes []string, enabled *bool) error {
	if len(routes) == 0 {
		*enabled = false
		return nil
	}
	if !warnedGatewayRoutesUnsupported {
		slog.Warn("this agent is a mobile-peer gateway but automatic IP forwarding is only programmed on Linux; enable OS-level forwarding for these routes", "routes", strings.Join(routes, ","))
		warnedGatewayRoutesUnsupported = true
	}
	*enabled = true
	return nil
}
