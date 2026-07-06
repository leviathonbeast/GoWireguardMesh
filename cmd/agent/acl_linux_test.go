//go:build linux

package main

import (
	"reflect"
	"testing"

	"gowireguard/internal/proto"
)

func TestACLRuleArgsTCPPort(t *testing.T) {
	got := aclRuleArgs(proto.ACLRule{
		SrcIP:    "100.64.0.2",
		DstIP:    "100.64.0.3",
		Protocol: "tcp",
		PortMin:  4040,
		PortMax:  4040,
	}, false)
	want := []string{"-s", "100.64.0.2", "-d", "100.64.0.3", "-p", "tcp", "--dport", "4040", "-j", "ACCEPT"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("aclRuleArgs() = %#v, want %#v", got, want)
	}
}

func TestACLRuleArgsICMPFamilies(t *testing.T) {
	rule := proto.ACLRule{Protocol: "icmp"}
	if got := aclRuleArgs(rule, false); !reflect.DeepEqual(got, []string{"-p", "icmp", "-j", "ACCEPT"}) {
		t.Fatalf("IPv4 ICMP args = %#v", got)
	}
	if got := aclRuleArgs(rule, true); got != nil {
		t.Fatalf("IPv6 args for ICMP rule = %#v, want nil", got)
	}
}

func TestACLRuleArgsSkipsMissingFamilySpecificAddress(t *testing.T) {
	got := aclRuleArgs(proto.ACLRule{
		SrcIP:    "100.64.0.2",
		DstIP:    "100.64.0.3",
		Protocol: "tcp",
		PortMin:  4040,
	}, true)
	if got != nil {
		t.Fatalf("IPv6 args with only specific IPv4 addresses = %#v, want nil", got)
	}
}
