//go:build windows

package main

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"gowireguard/internal/proto"
)

func applyDNSConfig(iface string, cfg proto.DNSConfig) error {
	if err := clearWindowsSplitDNS(iface); err != nil {
		return err
	}

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

	// Do not install the mesh resolver as this interface's general DNS
	// server. Keep the host's existing DNS priority for normal internet
	// names, and route only the configured mesh namespaces through NRPT.
	_ = runNetshDNS("interface", "ipv4", "set", "dnsservers", "name="+iface, "dhcp")
	_ = runNetshDNS("interface", "ipv6", "set", "dnsservers", "name="+iface, "dhcp")

	suffix := ""
	if cfg.MagicDNS && cfg.Domain != "" {
		suffix = cfg.Domain
	} else if len(cfg.SearchDomains) > 0 {
		suffix = cfg.SearchDomains[0]
	}
	if err := setDNSSuffix(iface, suffix); err != nil {
		return err
	}

	nameservers := append(v4, v6...)
	if len(nameservers) == 0 {
		return nil
	}
	for _, namespace := range windowsSplitDNSNamespaces(cfg) {
		if err := addWindowsSplitDNSRule(iface, namespace, nameservers); err != nil {
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

func windowsSplitDNSNamespaces(cfg proto.DNSConfig) []string {
	seen := map[string]bool{}
	var out []string
	add := func(domain string) {
		domain = strings.Trim(strings.TrimSpace(domain), ".")
		if domain == "" {
			return
		}
		namespace := "." + domain
		if seen[namespace] {
			return
		}
		seen[namespace] = true
		out = append(out, namespace)
	}

	for _, domain := range cfg.SearchDomains {
		add(domain)
	}
	if cfg.MagicDNS {
		add(cfg.Domain)
	}

	return out
}

func clearWindowsSplitDNS(iface string) error {
	comment := "wgmesh:" + iface
	out, err := exec.Command(
		"powershell",
		"-NoProfile",
		"-Command",
		"Get-DnsClientNrptRule | Where-Object { $_.Comment -eq $args[0] } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue",
		comment,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("clear split dns rules: %w: %s", err, out)
	}
	return nil
}

func addWindowsSplitDNSRule(iface, namespace string, nameservers []string) error {
	comment := "wgmesh:" + iface
	out, err := exec.Command(
		"powershell",
		"-NoProfile",
		"-Command",
		"Add-DnsClientNrptRule -Namespace $args[0] -NameServers ($args[1] -split ',') -Comment $args[2] | Out-Null",
		namespace,
		strings.Join(nameservers, ","),
		comment,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("add split dns rule %s: %w: %s", namespace, err, out)
	}
	return nil
}
