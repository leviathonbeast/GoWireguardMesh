//go:build linux

package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseGatewayNATCIDRs(t *testing.T) {
	got, err := parseGatewayNATCIDRs("100.78.0.9, 100.78.0.10/32, 100.78.0.9/32")
	if err != nil {
		t.Fatalf("parseGatewayNATCIDRs() error = %v", err)
	}

	var strs []string
	for _, prefix := range got {
		strs = append(strs, prefix.String())
	}
	want := []string{"100.78.0.9/32", "100.78.0.10/32"}
	if !reflect.DeepEqual(strs, want) {
		t.Fatalf("parseGatewayNATCIDRs() = %#v, want %#v", strs, want)
	}
}

func TestParseGatewayNATCIDRsRejectsIPv6(t *testing.T) {
	if _, err := parseGatewayNATCIDRs("fd32:d2ad:be4f::9/128"); err == nil {
		t.Fatal("parseGatewayNATCIDRs accepted IPv6")
	}
}

func TestApplyGatewayRoutesForwardsWithoutNAT(t *testing.T) {
	var cmds []string
	oldRun := gatewayRun
	oldWrite := writeIPv4Forward
	t.Cleanup(func() {
		gatewayRun = oldRun
		writeIPv4Forward = oldWrite
	})

	writeIPv4Forward = func(name string, data []byte, perm os.FileMode) error {
		cmds = append(cmds, "write "+name+" "+strings.TrimSpace(string(data)))
		return nil
	}
	gatewayRun = func(name string, args ...string) error {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		if len(args) > 0 && (args[0] == "-C" || args[0] == "-D") {
			return os.ErrNotExist
		}
		return nil
	}

	enabled := false
	if err := applyGatewayRoutes("wg-int", []string{"100.64.0.2/32", "fd00:100:64::2/128"}, &enabled); err != nil {
		t.Fatalf("applyGatewayRoutes() error = %v", err)
	}
	if !enabled {
		t.Fatal("applyGatewayRoutes did not mark forwarding enabled")
	}

	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"write /proc/sys/net/ipv4/ip_forward 1",
		"write /proc/sys/net/ipv6/conf/all/forwarding 1",
		"iptables -I FORWARD -i wg-int -m comment --comment wgmesh-gateway -j ACCEPT",
		"iptables -I FORWARD -o wg-int -m comment --comment wgmesh-gateway -j ACCEPT",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commands missing %q:\n%s", want, joined)
		}
	}
	// Route mode must never masquerade — that is what preserves the
	// mobile's overlay source IP.
	if strings.Contains(joined, "MASQUERADE") {
		t.Fatalf("route-based gateway must not MASQUERADE:\n%s", joined)
	}

	// Empty routes tear the FORWARD accept back down.
	cmds = nil
	if err := applyGatewayRoutes("wg-int", nil, &enabled); err != nil {
		t.Fatalf("applyGatewayRoutes(teardown) error = %v", err)
	}
	if enabled {
		t.Fatal("applyGatewayRoutes(nil) should disable forwarding")
	}
	teardown := strings.Join(cmds, "\n")
	for _, want := range []string{
		"iptables -D FORWARD -i wg-int -m comment --comment wgmesh-gateway -j ACCEPT",
		"iptables -D FORWARD -o wg-int -m comment --comment wgmesh-gateway -j ACCEPT",
	} {
		if !strings.Contains(teardown, want) {
			t.Fatalf("teardown missing %q:\n%s", want, teardown)
		}
	}
}

func TestEnableGatewayNATInstallsAndCleansRules(t *testing.T) {
	var cmds []string
	oldRun := gatewayRun
	oldWrite := writeIPv4Forward
	t.Cleanup(func() {
		gatewayRun = oldRun
		writeIPv4Forward = oldWrite
	})

	writeIPv4Forward = func(name string, data []byte, perm os.FileMode) error {
		cmds = append(cmds, "write "+name+" "+strings.TrimSpace(string(data)))
		return nil
	}
	gatewayRun = func(name string, args ...string) error {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		if len(args) > 0 && args[0] == "-C" {
			return os.ErrNotExist
		}
		if len(args) > 2 && args[0] == "-t" && args[2] == "-C" {
			return os.ErrNotExist
		}
		if len(args) > 0 && args[0] == "-D" {
			return os.ErrNotExist
		}
		if len(args) > 2 && args[0] == "-t" && args[2] == "-D" {
			return os.ErrNotExist
		}
		return nil
	}

	cleanup, err := enableGatewayNAT("wg-int", "100.78.0.9/32")
	if err != nil {
		t.Fatalf("enableGatewayNAT() error = %v", err)
	}
	cleanup()

	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"write /proc/sys/net/ipv4/ip_forward 1",
		"iptables -I FORWARD -i wg-int -m comment --comment wgmesh-gateway -j ACCEPT",
		"iptables -I FORWARD -o wg-int -m comment --comment wgmesh-gateway -j ACCEPT",
		"iptables -t nat -I POSTROUTING -s 100.78.0.9/32 -o wg-int -m comment --comment wgmesh-gateway -j MASQUERADE",
		"iptables -t nat -D POSTROUTING -s 100.78.0.9/32 -o wg-int -m comment --comment wgmesh-gateway -j MASQUERADE",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commands missing %q:\n%s", want, joined)
		}
	}
}
