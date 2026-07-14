//go:build linux

package main

import (
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// temporaryV6Addrs returns the SLAAC privacy/temporary IPv6 addresses
// (RFC 4941) currently configured on this host. They rotate on a timer
// and are often deprecated by the time a peer dials them, so they make
// useless endpoint candidates — worse than useless once advertised,
// since a peer wastes probe attempts on an address that has moved.
//
// Go's net package strips the per-address flags, so this reads them
// over netlink directly. Best-effort: any failure returns an empty set,
// and the caller simply advertises what it has (the prior behavior).
func temporaryV6Addrs() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}

	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V6)
	if err != nil {
		return out
	}

	for _, a := range addrs {
		// IFA_F_TEMPORARY marks a privacy address; IFA_F_DEPRECATED
		// catches temporaries already aged out but not yet removed.
		if a.Flags&unix.IFA_F_TEMPORARY != 0 || a.Flags&unix.IFA_F_DEPRECATED != 0 {
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				out[ip.Unmap()] = true
			}
		}
	}

	return out
}
