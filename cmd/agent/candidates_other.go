//go:build !linux

package main

import "net/netip"

// temporaryV6Addrs is a no-op off Linux: the netlink flag read is
// Linux-specific. Non-Linux hosts advertise all global v6 addresses as
// before (Windows privacy addresses are a smaller concern there, and
// the agent is experimental on Windows regardless).
func temporaryV6Addrs() map[netip.Addr]bool { return nil }
