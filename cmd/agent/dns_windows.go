//go:build windows

package main

import (
	"fmt"
	"net/netip"
	"os/exec"

	"gowireguard/internal/proto"
)

func applyDNSConfig(iface string, cfg proto.DNSConfig) error {
	if !cfg.Enabled {
		_ = runNetshDNS("interface", "ipv4", "set", "dnsservers", "name="+iface, "dhcp")
		_ = runNetshDNS("interface", "ipv6", "set", "dnsservers", "name="+iface, "dhcp")
		return setDNSSuffix(iface, "")
	}

	var v4, v6 []string
	for _, ns := range cfg.Nameservers {
		addr, err := netip.ParseAddr(ns)
		if err != nil {
			return fmt.Errorf("parse dns nameserver %q: %w", ns, err)
		}
		if addr.Is4() {
			v4 = append(v4, addr.String())
		} else {
			v6 = append(v6, addr.String())
		}
	}

	if err := applyWindowsFamilyDNS(iface, "ipv4", v4); err != nil {
		return err
	}
	if err := applyWindowsFamilyDNS(iface, "ipv6", v6); err != nil {
		return err
	}

	suffix := ""
	if cfg.MagicDNS && cfg.Domain != "" {
		suffix = cfg.Domain
	} else if len(cfg.SearchDomains) > 0 {
		suffix = cfg.SearchDomains[0]
	}
	return setDNSSuffix(iface, suffix)
}

func applyWindowsFamilyDNS(iface, family string, servers []string) error {
	if len(servers) == 0 {
		return runNetshDNS("interface", family, "set", "dnsservers", "name="+iface, "dhcp")
	}

	if err := runNetshDNS("interface", family, "set", "dnsservers", "name="+iface, "static", servers[0], "primary", "validate=no"); err != nil {
		return err
	}
	for i, server := range servers[1:] {
		if err := runNetshDNS("interface", family, "add", "dnsservers", "name="+iface, "address="+server, fmt.Sprintf("index=%d", i+2), "validate=no"); err != nil {
			return err
		}
	}
	return nil
}

func runNetshDNS(args ...string) error {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %v: %w: %s", args, err, out)
	}
	return nil
}

func setDNSSuffix(iface, suffix string) error {
	out, err := exec.Command(
		"powershell",
		"-NoProfile",
		"-Command",
		"Set-DnsClient -InterfaceAlias $args[0] -ConnectionSpecificSuffix $args[1]",
		iface,
		suffix,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("set dns suffix: %w: %s", err, out)
	}
	return nil
}
