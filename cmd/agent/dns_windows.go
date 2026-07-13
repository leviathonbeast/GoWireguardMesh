//go:build windows

package main

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gowireguard/internal/hidecmd"
	"gowireguard/internal/proto"
)

func applyDNSConfig(iface string, cfg proto.DNSConfig) error {
	if dnsApplyMode == dnsModeOff {
		return fmt.Errorf("%w: dns push disabled (--dns-mode=off)", errDNSUnsupported)
	}

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
	out, err := hidecmd.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %v: %w: %s", args, err, compactOutput(out))
	}
	return nil
}

// compactOutput flattens a command's multi-line error dressing
// (PowerShell position art, CRLFs) into one line: these strings end up
// quoted inside a single slog attribute, where embedded newlines would
// render as literal \r\n escapes.
func compactOutput(out []byte) string {
	return strings.Join(strings.Fields(string(out)), " ")
}

// runPowerShell executes a script with its inputs passed as environment
// variables. powershell -Command does NOT populate $args from trailing
// argv (that only works with -File), and env vars sidestep quoting and
// injection for server-supplied values like search domains. Note an
// empty env value reads back as $null in PowerShell, so scripts that
// need "" must interpolate: "$env:NAME".
func runPowerShell(script string, env map[string]string) ([]byte, error) {
	cmd := hidecmd.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)

	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	return cmd.CombinedOutput()
}

func setDNSSuffix(iface, suffix string) error {
	// The quoted interpolation keeps an empty suffix an empty string
	// ($null fails ConnectionSpecificSuffix validation; "" clears it).
	out, err := runPowerShell(
		`Set-DnsClient -InterfaceAlias $env:WGMESH_IFACE -ConnectionSpecificSuffix "$env:WGMESH_SUFFIX"`,
		map[string]string{
			"WGMESH_IFACE":  iface,
			"WGMESH_SUFFIX": suffix,
		},
	)
	if err != nil {
		return fmt.Errorf("set dns suffix: %w: %s", err, compactOutput(out))
	}
	return nil
}

// restoreResolvConf is Linux-only cleanup; Windows DNS state is managed
// per-interface (NRPT rules keyed on our comment) and cleared on apply.
func restoreResolvConf() error {
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
	out, err := runPowerShell(
		"Get-DnsClientNrptRule | Where-Object { $_.Comment -eq $env:WGMESH_COMMENT } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue",
		map[string]string{"WGMESH_COMMENT": "wgmesh:" + iface},
	)
	if err != nil {
		return fmt.Errorf("clear split dns rules: %w: %s", err, compactOutput(out))
	}
	return nil
}

func addWindowsSplitDNSRule(iface, namespace string, nameservers []string) error {
	out, err := runPowerShell(
		"Add-DnsClientNrptRule -Namespace $env:WGMESH_NAMESPACE -NameServers ($env:WGMESH_NS -split ',') -Comment $env:WGMESH_COMMENT | Out-Null",
		map[string]string{
			"WGMESH_NAMESPACE": namespace,
			"WGMESH_NS":        strings.Join(nameservers, ","),
			"WGMESH_COMMENT":   "wgmesh:" + iface,
		},
	)
	if err != nil {
		return fmt.Errorf("add split dns rule %s: %w: %s", namespace, err, compactOutput(out))
	}
	return nil
}
