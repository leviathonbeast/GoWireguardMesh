//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"strings"

	"gowireguard/internal/proto"
)

const (
	aclInChain  = "WGMESH-ACL-IN"
	aclOutChain = "WGMESH-ACL-OUT"
	aclFwdChain = "WGMESH-ACL-FWD"
)

var aclRun = func(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func applyOverlayACL(iface string, policy *proto.ACLPolicy) error {
	if policy == nil || policy.DefaultPolicy != "deny" {
		disableOverlayACL("iptables", iface)
		disableOverlayACL("ip6tables", iface)
		return nil
	}

	if err := applyOverlayACLFamily("iptables", iface, policy.Rules, false); err != nil {
		return err
	}
	if err := applyOverlayACLFamily("ip6tables", iface, policy.Rules, true); err != nil {
		return err
	}

	return nil
}

func disableOverlayACL(bin, iface string) {
	_ = aclRun(bin, "-D", "INPUT", "-i", iface, "-j", aclInChain)
	_ = aclRun(bin, "-D", "OUTPUT", "-o", iface, "-j", aclOutChain)
	_ = aclRun(bin, "-D", "FORWARD", "-i", iface, "-j", aclFwdChain)
	_ = aclRun(bin, "-D", "FORWARD", "-o", iface, "-j", aclFwdChain)
	_ = aclRun(bin, "-F", aclInChain)
	_ = aclRun(bin, "-F", aclOutChain)
	_ = aclRun(bin, "-F", aclFwdChain)
	_ = aclRun(bin, "-X", aclInChain)
	_ = aclRun(bin, "-X", aclOutChain)
	_ = aclRun(bin, "-X", aclFwdChain)
}

func applyOverlayACLFamily(bin, iface string, rules []proto.ACLRule, v6 bool) error {
	_ = aclRun(bin, "-N", aclInChain)
	_ = aclRun(bin, "-N", aclOutChain)
	_ = aclRun(bin, "-N", aclFwdChain)
	if err := aclRun(bin, "-F", aclInChain); err != nil {
		return err
	}
	if err := aclRun(bin, "-F", aclOutChain); err != nil {
		return err
	}
	if err := aclRun(bin, "-F", aclFwdChain); err != nil {
		return err
	}

	ensureJump(bin, "INPUT", "-i", iface, aclInChain)
	ensureJump(bin, "OUTPUT", "-o", iface, aclOutChain)
	ensureJump(bin, "FORWARD", "-i", iface, aclFwdChain)
	ensureJump(bin, "FORWARD", "-o", iface, aclFwdChain)

	for _, chain := range []string{aclInChain, aclOutChain, aclFwdChain} {
		if err := aclRun(bin, "-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
			return err
		}
	}

	for _, r := range rules {
		cmd := aclRuleArgs(r, v6)
		if cmd == nil {
			continue
		}
		if err := aclRun(bin, append([]string{"-A", aclInChain}, cmd...)...); err != nil {
			return err
		}
		if err := aclRun(bin, append([]string{"-A", aclOutChain}, cmd...)...); err != nil {
			return err
		}
		if err := aclRun(bin, append([]string{"-A", aclFwdChain}, cmd...)...); err != nil {
			return err
		}
	}

	if err := aclRun(bin, "-A", aclInChain, "-j", "DROP"); err != nil {
		return err
	}
	if err := aclRun(bin, "-A", aclOutChain, "-j", "DROP"); err != nil {
		return err
	}
	if err := aclRun(bin, "-A", aclFwdChain, "-j", "DROP"); err != nil {
		return err
	}

	return nil
}

func ensureJump(bin, baseChain, dirFlag, iface, aclChain string) {
	if aclRun(bin, "-C", baseChain, dirFlag, iface, "-j", aclChain) == nil {
		return
	}
	_ = aclRun(bin, "-I", baseChain, dirFlag, iface, "-j", aclChain)
}

func aclRuleArgs(r proto.ACLRule, v6 bool) []string {
	protoName := strings.ToLower(strings.TrimSpace(r.Protocol))
	if protoName == "" {
		protoName = "any"
	}

	switch protoName {
	case "icmp":
		if v6 {
			return nil
		}
		protoName = "icmp"
	case "icmpv6":
		if !v6 {
			return nil
		}
		protoName = "ipv6-icmp"
	case "tcp", "udp", "any":
	default:
		return nil
	}

	src, dst := r.SrcIP, r.DstIP
	if v6 {
		if (r.SrcIP != "" && r.SrcIP6 == "") || (r.DstIP != "" && r.DstIP6 == "") {
			return nil
		}
		src, dst = r.SrcIP6, r.DstIP6
	} else if (r.SrcIP6 != "" && r.SrcIP == "") || (r.DstIP6 != "" && r.DstIP == "") {
		return nil
	}

	args := []string{}
	if src != "" {
		args = append(args, "-s", src)
	}
	if dst != "" {
		args = append(args, "-d", dst)
	}
	if protoName != "any" {
		args = append(args, "-p", protoName)
	}
	if (protoName == "tcp" || protoName == "udp") && r.PortMin > 0 {
		port := fmt.Sprintf("%d", r.PortMin)
		if r.PortMax > 0 && r.PortMax != r.PortMin {
			port = fmt.Sprintf("%d:%d", r.PortMin, r.PortMax)
		}
		args = append(args, "--dport", port)
	}

	return append(args, "-j", "ACCEPT")
}
