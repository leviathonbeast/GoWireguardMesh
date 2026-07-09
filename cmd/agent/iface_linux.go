//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/vishvananda/netlink"
)

func ensurePrivileged() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}

	return nil
}

// wireGuardMTU is the overlay interface MTU. WireGuard adds a fixed
// header of 60 bytes over IPv4 and 80 over IPv6 to every encapsulated
// packet; 1420 = 1500 (typical Ethernet underlay) − 80 leaves headroom
// for the worse (IPv6) case, so a full-size overlay packet never needs
// underlay fragmentation. This is the same value wg-quick installs, and
// getting it wrong is the classic "handshakes work but bulk transfers
// stall" failure: without it the link inherits the 1500 default and
// every large packet fragments or is silently PMTU-blackholed.
const wireGuardMTU = 1420

func createInterface(name string) error {
	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
			MTU:  wireGuardMTU,
		},
		LinkType: "wireguard",
	}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("create interface %q: %w", name, err)
	}

	// Some kernels ignore MTU on LinkAdd for virtual links; set it
	// explicitly so the value is guaranteed regardless of kernel quirk.
	if created, err := netlink.LinkByName(name); err == nil {
		if err := netlink.LinkSetMTU(created, wireGuardMTU); err != nil {
			fmt.Printf("warning: could not set MTU %d on %s: %v\n", wireGuardMTU, name, err)
		}
	}

	fmt.Printf("Created interface %s (mtu %d)\n", name, wireGuardMTU)

	return nil
}

func assignIPAddress(ifaceName, cidr string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup interface %q: %w", ifaceName, err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("assign address %q: %w", cidr, err)
	}

	fmt.Printf("Assigned %s to %s\n", cidr, ifaceName)

	return nil
}

func replaceIPAddress(ifaceName, oldCIDR, newCIDR string) error {
	if oldCIDR == newCIDR {
		return nil
	}

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup interface %q: %w", ifaceName, err)
	}

	if newCIDR != "" {
		addr, err := netlink.ParseAddr(newCIDR)
		if err != nil {
			return fmt.Errorf("parse CIDR %q: %w", newCIDR, err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("assign address %q: %w", newCIDR, err)
		}
		fmt.Printf("Assigned %s to %s\n", newCIDR, ifaceName)
	}

	if oldCIDR != "" {
		addr, err := netlink.ParseAddr(oldCIDR)
		if err != nil {
			return fmt.Errorf("parse old CIDR %q: %w", oldCIDR, err)
		}
		if err := netlink.AddrDel(link, addr); err != nil {
			return fmt.Errorf("remove old address %q: %w", oldCIDR, err)
		}
		fmt.Printf("Removed %s from %s\n", oldCIDR, ifaceName)
	}

	return nil
}

func bringInterfaceUp(ifaceName string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup interface %q: %w", ifaceName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring interface up: %w", err)
	}

	fmt.Printf("Interface %s is UP\n", ifaceName)

	return nil
}

func deleteInterface(ifaceName string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}

		return fmt.Errorf("lookup interface %q: %w", ifaceName, err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete interface %q: %w", ifaceName, err)
	}

	fmt.Printf("Deleted interface %s\n", ifaceName)

	return nil
}
