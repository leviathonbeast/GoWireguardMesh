//go:build linux

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Exit-node data path, both roles.
//
// Client role (applyExitRoutes) uses wg-quick's fwmark scheme: the
// WireGuard device and the agent's own control/relay/STUN sockets are
// marked, a dedicated routing table holds only "default dev wg-int",
// and two policy rules send every UNMARKED default-route lookup there —
// so all internet traffic enters the tunnel while the tunnel's own
// underlay packets keep using the real default route. Main-table
// routes more specific than default (LAN, docker bridges, the overlay
// on-link route) stay effective via the suppress_prefixlength rule.
//
// Exit role (applyExitNodeNAT) enables forwarding and masquerades
// overlay-sourced traffic leaving through any non-overlay interface,
// with FORWARD accepts that stay ahead of the default-deny ACL chain.
const (
	// exitFwmark marks packets that must NOT loop into the exit-node
	// default route: kernel WireGuard's encrypted UDP (the device
	// fwmark) and the agent's control-plane/relay/STUN sockets
	// (SO_MARK, sockmark_linux.go). 51821 deliberately differs from
	// wg-quick's default 51820 so a host-mode agent can coexist with
	// an unrelated wg-quick tunnel.
	exitFwmark = 51821

	// exitRouteTable holds only the tunnel default route.
	exitRouteTable = 51821

	// The suppress rule must rank BEFORE the not-fwmark rule: it lets
	// any main-table route more specific than default win, so only
	// true default-route traffic falls through into the exit table.
	exitRulePrefSuppress = 32764
	exitRulePrefFwmark   = 32765

	exitChain       = "WGMESH-EXIT"
	exitRuleComment = "wgmesh-exit"
)

// exitTablesOut runs an iptables-family command and returns its output
// (gatewayRun folds output into the error, which listing needs intact).
// A var for tests.
var exitTablesOut = func(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// wgFirewallMark is the fwmark configured on the WireGuard device so
// its encrypted UDP bypasses exit-node policy routing. Always set on
// Linux: without the exit rules installed the mark changes nothing.
func wgFirewallMark() *int {
	m := exitFwmark
	return &m
}

func exitFamilies(v6 bool) []int {
	if v6 {
		return []int{netlink.FAMILY_V4, netlink.FAMILY_V6}
	}
	return []int{netlink.FAMILY_V4}
}

func exitSuppressRule(family int) *netlink.Rule {
	r := netlink.NewRule()
	r.Family = family
	r.Priority = exitRulePrefSuppress
	r.Table = unix.RT_TABLE_MAIN
	r.SuppressPrefixlen = 0
	return r
}

func exitFwmarkRule(family int) *netlink.Rule {
	r := netlink.NewRule()
	r.Family = family
	r.Priority = exitRulePrefFwmark
	r.Table = exitRouteTable
	r.Mark = exitFwmark
	r.Invert = true
	return r
}

func exitDefaultRoute(family, linkIndex int) *netlink.Route {
	route := &netlink.Route{
		LinkIndex: linkIndex,
		Table:     exitRouteTable,
		Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	}
	if family == netlink.FAMILY_V4 {
		route.Dst = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
		route.Scope = netlink.SCOPE_LINK
	}
	return route
}

// applyExitRoutes installs (active) or removes (!active) the
// client-side policy routing that sends this node's internet traffic
// to its assigned exit node. Idempotent; the reporter re-ensures it on
// every sync. *enabled tracks installation so teardown runs once and
// the transition is logged once.
func applyExitRoutes(iface string, active, v6 bool, enabled *bool) error {
	if !active {
		if *enabled {
			teardownExitRoutes()
			*enabled = false
			agentPrintf("[agent] exit-node routing disabled\n")
		}
		return nil
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("exit-node routing: find %s: %w", iface, err)
	}

	// Reverse-path filtering must validate marked flows against the
	// mark-aware route, or rp_filter=1 hosts drop the replies that
	// arrive over the tunnel.
	if err := ensureForwarding("/proc/sys/net/ipv4/conf/all/src_valid_mark"); err != nil {
		slog.Warn("set src_valid_mark failed; strict rp_filter may drop exit-node replies", "error", err)
	}

	for _, family := range exitFamilies(v6) {
		if err := netlink.RouteReplace(exitDefaultRoute(family, link.Attrs().Index)); err != nil {
			return fmt.Errorf("exit-node default route (family %d): %w", family, err)
		}
		for _, rule := range []*netlink.Rule{exitSuppressRule(family), exitFwmarkRule(family)} {
			if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("exit-node policy rule (family %d): %w", family, err)
			}
		}
	}

	if !*enabled {
		agentPrintf("[agent] exit-node routing enabled: internet traffic now leaves via the assigned exit node\n")
	}
	*enabled = true

	return nil
}

// teardownExitRoutes removes both families unconditionally — cheaper
// and safer than remembering whether v6 was installed, and rules
// survive interface deletion so cleanup cannot rely on the link.
func teardownExitRoutes() {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		for _, rule := range []*netlink.Rule{exitFwmarkRule(family), exitSuppressRule(family)} {
			if err := netlink.RuleDel(rule); err != nil && !errors.Is(err, os.ErrNotExist) {
				slog.Debug("exit-node rule removal failed", "family", family, "error", err)
			}
		}

		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: exitRouteTable}, netlink.RT_FILTER_TABLE)
		if err != nil {
			continue
		}
		for i := range routes {
			_ = netlink.RouteDel(&routes[i])
		}
	}
}

// applyExitNodeNAT installs (active) or removes (!active) the exit
// role's forwarding + masquerade. net4/net6 are the overlay networks
// whose sources get NAT'd; an invalid net6 skips the v6 family.
func applyExitNodeNAT(iface string, active bool, net4, net6 netip.Prefix, enabled *bool) error {
	if !active {
		if *enabled {
			teardownExitNAT()
			*enabled = false
			agentPrintf("[agent] exit-node forwarding disabled\n")
		}
		return nil
	}

	if err := ensureForwarding("/proc/sys/net/ipv4/ip_forward"); err != nil {
		slog.Warn("enable ipv4 forwarding failed; set net.ipv4.ip_forward=1 on the shared network namespace/container", "error", err)
	}
	if net6.IsValid() {
		if err := ensureForwarding("/proc/sys/net/ipv6/conf/all/forwarding"); err != nil {
			slog.Warn("enable ipv6 forwarding failed; set net.ipv6.conf.all.forwarding=1 on the shared network namespace/container", "error", err)
		}
	}

	if err := ensureExitNATFamily("iptables", iface, net4); err != nil {
		return err
	}
	if net6.IsValid() {
		if err := ensureExitNATFamily("ip6tables", iface, net6); err != nil {
			return err
		}
	}

	if !*enabled {
		agentPrintf("[agent] exit-node forwarding enabled: masquerading overlay traffic to the internet\n")
	}
	*enabled = true

	return nil
}

func ensureExitNATFamily(bin, iface string, overlay netip.Prefix) error {
	if !overlay.IsValid() {
		return nil
	}
	cidr := overlay.Masked().String()

	// Chain-exists errors are indistinguishable from real failures
	// here; the rule ensures below fail loudly if the chain is absent.
	_ = gatewayRun(bin, "-N", exitChain)

	for _, rule := range exitChainRules(iface, cidr) {
		if err := ensureTablesRule(bin, rule); err != nil {
			return err
		}
	}

	if err := ensureExitJumpFirst(bin); err != nil {
		return err
	}

	return ensureTablesRule(bin, exitNATRule(iface, cidr))
}

func exitChainRules(iface, cidr string) [][]string {
	return [][]string{
		// Overlay-sourced traffic heading out any non-overlay interface.
		{exitChain, "-i", iface, "!", "-o", iface, "-s", cidr, "-j", "ACCEPT"},
		// And the replies coming back toward the tunnel.
		{exitChain, "!", "-i", iface, "-o", iface, "-d", cidr, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
}

func exitNATRule(iface, cidr string) []string {
	return []string{"-t", "nat", "POSTROUTING", "-s", cidr, "!", "-o", iface, "-m", "comment", "--comment", exitRuleComment, "-j", "MASQUERADE"}
}

// ensureExitJumpFirst keeps FORWARD -> WGMESH-EXIT ahead of every
// other rule — in particular the default-deny overlay ACL chain, which
// ends in DROP and gets (re)inserted at the top whenever the admin
// toggles the policy. Checked cheaply on every sync; rewired only when
// out of position.
func ensureExitJumpFirst(bin string) error {
	out, err := exitTablesOut(bin, "-S", "FORWARD")
	if err != nil {
		return err
	}

	first := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "-A FORWARD") {
			first = line
			break
		}
	}
	if strings.Contains(first, exitChain) {
		return nil
	}

	deleteTablesRule(bin, []string{"FORWARD", "-j", exitChain})
	return gatewayRun(bin, "-I", "FORWARD", "1", "-j", exitChain)
}

// teardownExitNAT needs no parameters: the masquerade rule embeds the
// overlay CIDR of the moment it was installed, so it is found by its
// comment instead of being reconstructed (which would miss rules from
// before an overlay re-IP).
func teardownExitNAT() {
	for _, bin := range []string{"iptables", "ip6tables"} {
		deleteTablesRule(bin, []string{"FORWARD", "-j", exitChain})

		if out, err := exitTablesOut(bin, "-t", "nat", "-S", "POSTROUTING"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				if !strings.Contains(line, exitRuleComment) {
					continue
				}
				args := strings.Fields(line)
				if len(args) < 2 || args[0] != "-A" {
					continue
				}
				_ = gatewayRun(bin, append([]string{"-t", "nat", "-D"}, args[1:]...)...)
			}
		}

		_ = gatewayRun(bin, "-F", exitChain)
		_ = gatewayRun(bin, "-X", exitChain)
	}
}

// cleanupExitState removes exit-node routing rules and NAT chains a
// crashed previous run left behind. Best-effort, before setup.
func cleanupExitState() {
	teardownExitRoutes()
	teardownExitNAT()
}

// ensureTablesRule and deleteTablesRule are the iptables/ip6tables
// generalizations of ensureIPTablesRule/deleteIPTablesRule (which
// predate v6 rule management and keep their call sites).
func ensureTablesRule(bin string, rule []string) error {
	if rule[0] == "-t" {
		check := append([]string{"-t", rule[1], "-C"}, rule[2:]...)
		if err := gatewayRun(bin, check...); err == nil {
			return nil
		}

		insert := append([]string{"-t", rule[1], "-I"}, rule[2:]...)
		return gatewayRun(bin, insert...)
	}

	check := append([]string{"-C"}, rule...)
	if err := gatewayRun(bin, check...); err == nil {
		return nil
	}

	insert := append([]string{"-I"}, rule...)
	return gatewayRun(bin, insert...)
}

func deleteTablesRule(bin string, rule []string) {
	for {
		remove := append([]string{"-D"}, rule...)
		if rule[0] == "-t" {
			remove = append([]string{"-t", rule[1], "-D"}, rule[2:]...)
		}
		if err := gatewayRun(bin, remove...); err != nil {
			return
		}
	}
}
