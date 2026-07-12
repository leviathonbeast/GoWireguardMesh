//go:build linux

package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

const gatewayRuleComment = "wgmesh-gateway"

var (
	gatewayRun = func(name string, args ...string) error {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	writeIPv4Forward = os.WriteFile
	readForwarding   = os.ReadFile
)

// ensureForwarding enables one forwarding sysctl, but avoids a redundant
// write when the namespace owner (for example Docker Compose) already set it.
// Container runtimes commonly expose /proc/sys read-only to sidecars even
// though the configured value is visible in their shared network namespace.
func ensureForwarding(path string) error {
	if current, err := readForwarding(path); err == nil && strings.TrimSpace(string(current)) == "1" {
		return nil
	}

	return writeIPv4Forward(path, []byte("1\n"), 0644)
}

func enableGatewayNAT(iface, rawCIDRs string) (func(), error) {
	cidrs, err := parseGatewayNATCIDRs(rawCIDRs)
	if err != nil {
		return nil, err
	}
	if len(cidrs) == 0 {
		return func() {}, nil
	}

	if err := ensureForwarding("/proc/sys/net/ipv4/ip_forward"); err != nil {
		slog.Warn("enable ipv4 forwarding failed; set net.ipv4.ip_forward=1 on the shared network namespace/container", "error", err)
	}

	if err := ensureGatewayNATRules(iface, cidrs); err != nil {
		return nil, err
	}

	fmt.Printf("[agent] gateway NAT enabled for %s\n", joinPrefixes(cidrs))

	return func() {
		for _, cidr := range cidrs {
			deleteIPTablesRule([]string{"-t", "nat", "POSTROUTING", "-s", cidr.String(), "-o", iface, "-m", "comment", "--comment", gatewayRuleComment, "-j", "MASQUERADE"})
		}
		for _, rule := range gatewayForwardRules(iface) {
			deleteIPTablesRule(rule)
		}
	}, nil
}

func refreshGatewayNAT(iface, rawCIDRs string) error {
	cidrs, err := parseGatewayNATCIDRs(rawCIDRs)
	if err != nil || len(cidrs) == 0 {
		return err
	}
	return ensureGatewayNATRules(iface, cidrs)
}

// applyGatewayRoutes enables plain routing (no NAT) for a routed
// static/mobile peer whose /32 the control plane pinned to this agent.
// WireGuard's cryptokey routing already installs the on-link route for
// the mobile's AllowedIPs; all this adds is IPv4/IPv6 forwarding plus a
// FORWARD accept for the overlay interface, so packets to/from the mobile
// traverse this node with their overlay source IP intact.
//
// *enabled tracks whether the forward accept is currently installed so the
// work runs once on transition, and the rules are removed when the last
// routed mobile detaches (routes goes empty).
func applyGatewayRoutes(iface string, routes []string, enabled *bool) error {
	if len(routes) == 0 {
		if *enabled {
			for _, rule := range gatewayForwardRules(iface) {
				deleteIPTablesRule(rule)
			}
			*enabled = false
		}
		return nil
	}

	if err := ensureForwarding("/proc/sys/net/ipv4/ip_forward"); err != nil {
		slog.Warn("enable ipv4 forwarding failed; set net.ipv4.ip_forward=1 on the shared network namespace/container", "error", err)
	}
	if gatewayNeedsIPv6(routes) {
		if err := ensureForwarding("/proc/sys/net/ipv6/conf/all/forwarding"); err != nil {
			slog.Warn("enable ipv6 forwarding failed; set net.ipv6.conf.all.forwarding=1 on the shared network namespace/container", "error", err)
		}
	}

	for _, rule := range gatewayForwardRules(iface) {
		if err := ensureIPTablesRule(rule); err != nil {
			return err
		}
	}
	if !*enabled {
		fmt.Printf("[agent] gateway routing (no NAT) enabled for %s\n", strings.Join(routes, ","))
	}
	*enabled = true

	return nil
}

func gatewayNeedsIPv6(routes []string) bool {
	for _, r := range routes {
		if strings.Contains(r, ":") {
			return true
		}
	}
	return false
}

func ensureGatewayNATRules(iface string, cidrs []netip.Prefix) error {
	for _, rule := range gatewayForwardRules(iface) {
		if err := ensureIPTablesRule(rule); err != nil {
			return err
		}
	}

	for _, cidr := range cidrs {
		rule := []string{"-t", "nat", "POSTROUTING", "-s", cidr.String(), "-o", iface, "-m", "comment", "--comment", gatewayRuleComment, "-j", "MASQUERADE"}
		if err := ensureIPTablesRule(rule); err != nil {
			return err
		}
	}

	return nil
}

func gatewayForwardRules(iface string) [][]string {
	return [][]string{
		{"FORWARD", "-i", iface, "-m", "comment", "--comment", gatewayRuleComment, "-j", "ACCEPT"},
		{"FORWARD", "-o", iface, "-m", "comment", "--comment", gatewayRuleComment, "-j", "ACCEPT"},
	}
}

func parseGatewayNATCIDRs(raw string) ([]netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var out []netip.Prefix
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			addr, addrErr := netip.ParseAddr(part)
			if addrErr != nil {
				return nil, fmt.Errorf("parse gateway NAT CIDR %q: %w", part, err)
			}
			if !addr.Is4() {
				return nil, fmt.Errorf("gateway NAT only supports IPv4, got %s", addr)
			}
			prefix = netip.PrefixFrom(addr, 32)
		}
		prefix = prefix.Masked()
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("gateway NAT only supports IPv4, got %s", prefix)
		}
		if seen[prefix.String()] {
			continue
		}
		seen[prefix.String()] = true
		out = append(out, prefix)
	}

	return out, nil
}

func ensureIPTablesRule(rule []string) error {
	if rule[0] == "-t" {
		check := append([]string{"-t", rule[1], "-C"}, rule[2:]...)
		if err := gatewayRun("iptables", check...); err == nil {
			return nil
		}

		insert := append([]string{"-t", rule[1], "-I"}, rule[2:]...)
		return gatewayRun("iptables", insert...)
	}

	check := append([]string{"-C"}, rule...)
	if err := gatewayRun("iptables", check...); err == nil {
		return nil
	}

	insert := append([]string{"-I"}, rule...)
	return gatewayRun("iptables", insert...)
}

func deleteIPTablesRule(rule []string) {
	for {
		remove := append([]string{"-D"}, rule...)
		if rule[0] == "-t" {
			remove = append([]string{"-t", rule[1], "-D"}, rule[2:]...)
		}
		if err := gatewayRun("iptables", remove...); err != nil {
			return
		}
	}
}

func joinPrefixes(prefixes []netip.Prefix) string {
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	return strings.Join(out, ",")
}
