//go:build linux

package main

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// stubExitCommands captures every iptables-family invocation and serves
// canned outputs for the listing commands.
func stubExitCommands(t *testing.T, forwardDump, natDump string, failChecks bool) *[]string {
	t.Helper()

	var cmds []string

	oldRun := gatewayRun
	oldOut := exitTablesOut
	oldRead := readForwarding
	oldWrite := writeIPv4Forward
	t.Cleanup(func() {
		gatewayRun = oldRun
		exitTablesOut = oldOut
		readForwarding = oldRead
		writeIPv4Forward = oldWrite
	})

	readForwarding = func(string) ([]byte, error) { return []byte("1\n"), nil }
	writeIPv4Forward = func(string, []byte, os.FileMode) error { return nil }

	gatewayRun = func(name string, args ...string) error {
		cmd := name + " " + strings.Join(args, " ")
		cmds = append(cmds, cmd)
		// -C rule checks report "missing" so ensures insert; -D deletes
		// report "gone" so delete loops terminate.
		if failChecks && (strings.Contains(cmd, " -C ") || strings.Contains(cmd, " -D ")) {
			return errors.New("no match")
		}
		return nil
	}
	exitTablesOut = func(name string, args ...string) (string, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		if strings.Contains(strings.Join(args, " "), "POSTROUTING") {
			return natDump, nil
		}
		return forwardDump, nil
	}

	return &cmds
}

func TestApplyExitNodeNATInstallsRules(t *testing.T) {
	// FORWARD currently led by the ACL chain: the exit jump must be
	// (re)inserted at position 1, ahead of the default-deny DROP.
	cmds := stubExitCommands(t,
		"-P FORWARD ACCEPT\n-A FORWARD -i wg-int -j WGMESH-ACL-FWD\n",
		"-P POSTROUTING ACCEPT\n",
		true,
	)

	enabled := false
	err := applyExitNodeNAT("wg-int", true,
		netip.MustParsePrefix("100.64.0.0/16"), netip.Prefix{}, &enabled)
	if err != nil {
		t.Fatalf("applyExitNodeNAT() returned error: %v", err)
	}
	if !enabled {
		t.Fatal("enabled flag not set")
	}

	joined := strings.Join(*cmds, "\n")
	for _, want := range []string{
		"iptables -I WGMESH-EXIT -i wg-int ! -o wg-int -s 100.64.0.0/16 -j ACCEPT",
		"iptables -I WGMESH-EXIT ! -i wg-int -o wg-int -d 100.64.0.0/16 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"iptables -I FORWARD 1 -j WGMESH-EXIT",
		"iptables -t nat -I POSTROUTING -s 100.64.0.0/16 ! -o wg-int -m comment --comment wgmesh-exit -j MASQUERADE",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing command %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "ip6tables") {
		t.Fatalf("v6 rules installed without a v6 overlay:\n%s", joined)
	}
}

func TestApplyExitNodeNATIncludesV6(t *testing.T) {
	cmds := stubExitCommands(t, "", "", true)

	enabled := false
	err := applyExitNodeNAT("wg-int", true,
		netip.MustParsePrefix("100.64.0.0/16"),
		netip.MustParsePrefix("fd00:100:64::/64"), &enabled)
	if err != nil {
		t.Fatalf("applyExitNodeNAT() returned error: %v", err)
	}

	joined := strings.Join(*cmds, "\n")
	if !strings.Contains(joined, "ip6tables -t nat -I POSTROUTING -s fd00:100:64::/64 ! -o wg-int -m comment --comment wgmesh-exit -j MASQUERADE") {
		t.Fatalf("missing v6 masquerade in:\n%s", joined)
	}
}

func TestEnsureExitJumpFirstIsQuietWhenFirst(t *testing.T) {
	cmds := stubExitCommands(t,
		"-P FORWARD ACCEPT\n-A FORWARD -j WGMESH-EXIT\n-A FORWARD -i wg-int -j WGMESH-ACL-FWD\n",
		"", true,
	)

	if err := ensureExitJumpFirst("iptables"); err != nil {
		t.Fatalf("ensureExitJumpFirst() returned error: %v", err)
	}
	for _, cmd := range *cmds {
		if strings.Contains(cmd, "-I FORWARD") || strings.Contains(cmd, "-D FORWARD") {
			t.Fatalf("jump already first, but got %q", cmd)
		}
	}
}

func TestApplyExitNodeNATTeardownFindsRuleByComment(t *testing.T) {
	// The NAT dump carries a rule installed under an OLD overlay CIDR;
	// teardown must remove exactly what is there, not a reconstruction.
	cmds := stubExitCommands(t,
		"-P FORWARD ACCEPT\n",
		"-P POSTROUTING ACCEPT\n-A POSTROUTING -s 10.99.0.0/24 ! -o wg-int -m comment --comment wgmesh-exit -j MASQUERADE\n",
		true,
	)

	enabled := true
	err := applyExitNodeNAT("wg-int", false,
		netip.MustParsePrefix("100.64.0.0/16"), netip.Prefix{}, &enabled)
	if err != nil {
		t.Fatalf("applyExitNodeNAT() returned error: %v", err)
	}
	if enabled {
		t.Fatal("enabled flag not cleared")
	}

	joined := strings.Join(*cmds, "\n")
	for _, want := range []string{
		"iptables -t nat -D POSTROUTING -s 10.99.0.0/24 ! -o wg-int -m comment --comment wgmesh-exit -j MASQUERADE",
		"iptables -F WGMESH-EXIT",
		"iptables -X WGMESH-EXIT",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing teardown command %q in:\n%s", want, joined)
		}
	}
}

func TestApplyExitNodeNATInactiveIsNoop(t *testing.T) {
	cmds := stubExitCommands(t, "", "", true)

	enabled := false
	if err := applyExitNodeNAT("wg-int", false,
		netip.MustParsePrefix("100.64.0.0/16"), netip.Prefix{}, &enabled); err != nil {
		t.Fatalf("applyExitNodeNAT() returned error: %v", err)
	}
	if len(*cmds) != 0 {
		t.Fatalf("inactive+never-enabled ran commands: %v", *cmds)
	}
}

// The policy rules mirror wg-quick's scheme: suppress_prefixlength 0 on
// main first, then "not fwmark" into the exit table — and the fwmark
// value must match what the WireGuard device is configured with.
func TestExitPolicyRuleShape(t *testing.T) {
	sup := exitSuppressRule(netlink.FAMILY_V4)
	if sup.Priority != exitRulePrefSuppress || sup.SuppressPrefixlen != 0 {
		t.Fatalf("suppress rule = %+v", sup)
	}
	if sup.Priority >= exitFwmarkRule(netlink.FAMILY_V4).Priority {
		t.Fatal("suppress rule must be evaluated before the fwmark rule")
	}

	fw := exitFwmarkRule(netlink.FAMILY_V6)
	if !fw.Invert || fw.Mark != exitFwmark || fw.Table != exitRouteTable {
		t.Fatalf("fwmark rule = %+v", fw)
	}

	mark := wgFirewallMark()
	if mark == nil || *mark != exitFwmark {
		t.Fatalf("wgFirewallMark() = %v, want %d", mark, exitFwmark)
	}

	r4 := exitDefaultRoute(netlink.FAMILY_V4, 7)
	if ones, bits := r4.Dst.Mask.Size(); ones != 0 || bits != 32 {
		t.Fatalf("v4 route dst = %v, want 0.0.0.0/0", r4.Dst)
	}
	r6 := exitDefaultRoute(netlink.FAMILY_V6, 7)
	if ones, bits := r6.Dst.Mask.Size(); ones != 0 || bits != 128 {
		t.Fatalf("v6 route dst = %v, want ::/0", r6.Dst)
	}
	if r4.Table != exitRouteTable || r6.Table != exitRouteTable || r4.LinkIndex != 7 {
		t.Fatalf("route table/link = %+v / %+v", r4, r6)
	}
}
