//go:build linux

package main

import (
	"fmt"
	"log/slog"
	"strings"
)

// TCP MSS clamping for the overlay interface.
//
// MTU 1420 on wg-int sizes packets this host originates, but a peer at
// the far end may still advertise a 1460 MSS from its own 1500 NIC. If
// any hop on the encrypted underlay path silently drops the resulting
// oversized WireGuard packet — and PMTU discovery's ICMP is widely
// firewalled — the TCP connection establishes, small requests work,
// and the first large transfer hangs forever (the FLAC-stream
// black-hole). Rewriting the SYN's MSS down makes both ends agree to
// segments that always fit, independent of PMTUD.
//
// Clamped to PMTU rather than a fixed value: iptables derives the cap
// from the outgoing interface MTU (1420 → 1380 MSS), so it tracks any
// future MTU change automatically. Rules are tagged and reconciled
// like the gateway rules, and removed on interface teardown.

const mssRuleComment = "wgmesh-mss"

// mssClampRules returns the mangle-table rules that clamp TCP MSS on
// SYN packets crossing the overlay. FORWARD covers routed traffic (an
// agent front-ending apps, e.g. the Traefik sidecar); OUTPUT covers
// TCP this host originates onto the mesh itself. Matching only SYN (and
// SYN/RST-masked) segments keeps the rule off the per-packet fast path.
func mssClampRules(iface string) [][]string {
	base := func(chain string) []string {
		return []string{
			"-t", "mangle", chain,
			"-o", iface,
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-m", "comment", "--comment", mssRuleComment,
			"-j", "TCPMSS", "--clamp-mss-to-pmtu",
		}
	}

	return [][]string{base("FORWARD"), base("OUTPUT")}
}

// enableMSSClamp installs the clamp for the v4 overlay (and v6 when the
// interface carries an IPv6 overlay address). It is best-effort: a
// container without CAP_NET_ADMIN over the mangle table, or a kernel
// without xt_TCPMSS, must not block interface bring-up — large
// transfers may black-hole, but the mesh still comes up. Returns a
// teardown func that removes whatever was installed.
func enableMSSClamp(iface string, haveV6 bool) func() {
	installed := installMSSClamp("iptables", iface)

	installedV6 := false
	if haveV6 {
		installedV6 = installMSSClamp("ip6tables", iface)
	}

	if installed || installedV6 {
		fmt.Printf("[agent] TCP MSS clamping enabled on %s\n", iface)
	}

	return func() {
		if installed {
			removeMSSClamp("iptables", iface)
		}
		if installedV6 {
			removeMSSClamp("ip6tables", iface)
		}
	}
}

// installMSSClamp adds the clamp rules for one address family, checking
// for an existing rule first so re-runs are idempotent. Reports whether
// the family ended up with the rules present.
func installMSSClamp(tool, iface string) bool {
	for _, rule := range mssClampRules(iface) {
		check := append([]string{"-t", rule[1], "-C"}, rule[2:]...)
		if err := gatewayRun(tool, check...); err == nil {
			continue // already present
		}

		insert := append([]string{"-t", rule[1], "-I"}, rule[2:]...)
		if err := gatewayRun(tool, insert...); err != nil {
			slog.Warn("TCP MSS clamp unavailable; large transfers may black-hole on PMTU-blocked paths",
				"tool", tool, "iface", iface, "rule", strings.Join(rule, " "), "error", err)
			return false
		}
	}

	return true
}

func removeMSSClamp(tool, iface string) {
	for _, rule := range mssClampRules(iface) {
		for {
			remove := append([]string{"-t", rule[1], "-D"}, rule[2:]...)
			if err := gatewayRun(tool, remove...); err != nil {
				break
			}
		}
	}
}
