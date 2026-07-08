//go:build linux

package main

import (
	"errors"
	"testing"

	"gowireguard/internal/proto"
)

func TestApplyDNSUnsupportedWhenResolvectlMissing(t *testing.T) {
	t.Setenv("PATH", "")

	err := applyDNSConfig("wg-test", proto.DNSConfig{
		Enabled:     true,
		Nameservers: []string{"100.78.0.7"},
		Domain:      "vpn",
	})
	if !errors.Is(err, errDNSUnsupported) {
		t.Fatalf("applyDNSConfig() error = %v, want errDNSUnsupported", err)
	}
}

func TestTelemetryDNSUnsupportedWarnsOnceAndDoesNotRetryUnchangedConfig(t *testing.T) {
	t.Setenv("PATH", "")

	tel := &telemetryReporter{iface: "wg-test"}
	cfg := proto.DNSConfig{
		Enabled:     true,
		Nameservers: []string{"100.78.0.7"},
		Domain:      "vpn",
	}

	if err := tel.applyDNS(cfg); err != nil {
		t.Fatalf("first applyDNS() returned error: %v", err)
	}
	if !tel.dnsWarned {
		t.Fatal("first applyDNS() did not mark dnsWarned")
	}
	if tel.lastDNS == "" {
		t.Fatal("first applyDNS() did not remember unsupported config digest")
	}

	if err := tel.applyDNS(cfg); err != nil {
		t.Fatalf("second applyDNS() returned error: %v", err)
	}
}
