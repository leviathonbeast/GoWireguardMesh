//go:build linux

package main

import (
	"encoding/hex"
	"net"
	"os"
	"strings"
)

// defaultGatewayIP reads the IPv4 default route's gateway from
// /proc/net/route. NAT-PMP only ever talks to this address — the
// protocol has no discovery step, and pointing it anywhere else would
// let configuration turn the agent into a port-probe.
func defaultGatewayIP() net.IP {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil
	}

	return parseProcRoute(string(data))
}

// parseProcRoute finds the gateway of the 0.0.0.0/0 route in
// /proc/net/route content (fields: Iface Destination Gateway ...,
// addresses as little-endian hex).
func parseProcRoute(content string) net.IP {
	lines := strings.Split(content, "\n")

	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "00000000" || fields[2] == "00000000" {
			continue
		}

		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			continue
		}

		// Little-endian: reverse into network order.
		return net.IPv4(raw[3], raw[2], raw[1], raw[0])
	}

	return nil
}
