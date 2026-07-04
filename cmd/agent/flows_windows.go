//go:build windows

package main

import "errors"

// Windows has no conntrack; flow telemetry is Linux-only for now.
// Link counters, config sync, STUN, and relay fallback all still work.
func newFlowDumper() (flowDumper, error) {
	return nil, errors.New("flow telemetry is not supported on windows")
}
