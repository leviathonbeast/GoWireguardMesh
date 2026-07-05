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

func createInterface(name string) error {
	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		LinkType: "wireguard",
	}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("create interface %q: %w", name, err)
	}

	fmt.Printf("Created interface %s\n", name)

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
