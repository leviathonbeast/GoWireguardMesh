//go:build windows

package main

import "net/netip"

// Windows has no kernel conntrack and no AF_PACKET; flow telemetry stays
// Linux-only for now. A nil dumper disables it. Link counters, config
// sync, STUN, and relay fallback all still work.
func newFlowDumper(_ string, _, _ netip.Addr) (flowDumper, error) {
	return nil, nil
}
