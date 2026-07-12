//go:build !linux

package main

import "net"

// defaultGatewayIP has no portable implementation; without it NAT-PMP
// is skipped and port mapping relies on UPnP (which discovers the
// gateway itself via SSDP and works on every platform).
func defaultGatewayIP() net.IP {
	return nil
}
