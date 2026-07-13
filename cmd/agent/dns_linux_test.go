//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gowireguard/internal/proto"
)

func setDNSMode(t *testing.T, mode dnsMode) {
	t.Helper()
	prev := dnsApplyMode
	dnsApplyMode = mode
	t.Cleanup(func() { dnsApplyMode = prev })
}

// useTempResolvConf redirects the resolv.conf paths into a temp dir so
// tests exercise the takeover/restore lifecycle without touching the
// host's real /etc/resolv.conf.
func useTempResolvConf(t *testing.T, original string) {
	t.Helper()
	dir := t.TempDir()
	prevPath, prevBackup := resolvConfPath, resolvConfBackupPath
	resolvConfPath = filepath.Join(dir, "resolv.conf")
	resolvConfBackupPath = filepath.Join(dir, "resolv.conf.wgmesh-orig")
	t.Cleanup(func() { resolvConfPath, resolvConfBackupPath = prevPath, prevBackup })

	if err := os.WriteFile(resolvConfPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestApplyDNSUnsupportedWhenResolvedModeForcedWithoutResolvectl(t *testing.T) {
	t.Setenv("PATH", "")
	setDNSMode(t, dnsModeResolved)

	err := applyDNSConfig("wg-test", proto.DNSConfig{
		Enabled:     true,
		Nameservers: []string{"100.78.0.7"},
		Domain:      "vpn",
	})
	if !errors.Is(err, errDNSUnsupported) {
		t.Fatalf("applyDNSConfig() error = %v, want errDNSUnsupported", err)
	}
}

func TestApplyDNSUnsupportedWhenModeOff(t *testing.T) {
	setDNSMode(t, dnsModeOff)

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
	setDNSMode(t, dnsModeResolved)

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

func TestApplyDNSAutoFallsBackToResolvConfWithoutResolvectl(t *testing.T) {
	t.Setenv("PATH", "")
	setDNSMode(t, dnsModeAuto)
	useTempResolvConf(t, "nameserver 192.168.1.1\n")

	err := applyDNSConfig("wg-test", proto.DNSConfig{
		Enabled:       true,
		MagicDNS:      true,
		Nameservers:   []string{"100.78.0.7"},
		Domain:        "vpn",
		SearchDomains: []string{"vpn", "lab.internal"},
	})
	if err != nil {
		t.Fatalf("applyDNSConfig() returned error: %v", err)
	}

	got, err := os.ReadFile(resolvConfPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(got)
	if !strings.HasPrefix(content, resolvConfMarker) {
		t.Fatalf("resolv.conf missing marker header:\n%s", content)
	}
	if !strings.Contains(content, "nameserver 100.78.0.7\n") {
		t.Fatalf("resolv.conf missing mesh nameserver:\n%s", content)
	}
	if !strings.Contains(content, "search vpn lab.internal\n") {
		t.Fatalf("resolv.conf missing deduplicated search line:\n%s", content)
	}

	backup, err := os.ReadFile(resolvConfBackupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) != "nameserver 192.168.1.1\n" {
		t.Fatalf("backup does not hold original content: %q", backup)
	}
}

func TestApplyDNSResolvConfDisableRestoresOriginal(t *testing.T) {
	t.Setenv("PATH", "")
	setDNSMode(t, dnsModeResolvConf)
	useTempResolvConf(t, "nameserver 192.168.1.1\n")

	cfg := proto.DNSConfig{
		Enabled:     true,
		Nameservers: []string{"100.78.0.7"},
		Domain:      "vpn",
	}
	if err := applyDNSConfig("wg-test", cfg); err != nil {
		t.Fatalf("apply returned error: %v", err)
	}

	cfg.Enabled = false
	if err := applyDNSConfig("wg-test", cfg); err != nil {
		t.Fatalf("disable returned error: %v", err)
	}

	got, err := os.ReadFile(resolvConfPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "nameserver 192.168.1.1\n" {
		t.Fatalf("resolv.conf not restored: %q", got)
	}
	if _, err := os.Stat(resolvConfBackupPath); !os.IsNotExist(err) {
		t.Fatalf("backup not removed after restore: %v", err)
	}
}

func TestApplyDNSResolvConfReapplyKeepsOriginalBackup(t *testing.T) {
	t.Setenv("PATH", "")
	setDNSMode(t, dnsModeResolvConf)
	useTempResolvConf(t, "nameserver 192.168.1.1\n")

	cfg := proto.DNSConfig{
		Enabled:     true,
		Nameservers: []string{"100.78.0.7"},
		Domain:      "vpn",
	}
	if err := applyDNSConfig("wg-test", cfg); err != nil {
		t.Fatalf("first apply returned error: %v", err)
	}

	cfg.Nameservers = []string{"100.78.0.8"}
	if err := applyDNSConfig("wg-test", cfg); err != nil {
		t.Fatalf("second apply returned error: %v", err)
	}

	backup, err := os.ReadFile(resolvConfBackupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) != "nameserver 192.168.1.1\n" {
		t.Fatalf("reapply clobbered original backup: %q", backup)
	}

	got, err := os.ReadFile(resolvConfPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "nameserver 100.78.0.8\n") {
		t.Fatalf("resolv.conf not updated on reapply:\n%s", got)
	}
}

func TestRestoreResolvConfCleansStaleTakeover(t *testing.T) {
	setDNSMode(t, dnsModeAuto)
	useTempResolvConf(t, resolvConfMarker+" (dns push); do not edit.\nnameserver 100.78.0.7\n")
	if err := os.WriteFile(resolvConfBackupPath, []byte("nameserver 192.168.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := restoreResolvConf(); err != nil {
		t.Fatalf("restoreResolvConf() returned error: %v", err)
	}

	got, err := os.ReadFile(resolvConfPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "nameserver 192.168.1.1\n" {
		t.Fatalf("stale takeover not restored: %q", got)
	}
}

func TestRestoreResolvConfLeavesForeignFileAndDropsStaleBackup(t *testing.T) {
	setDNSMode(t, dnsModeAuto)
	useTempResolvConf(t, "nameserver 10.0.0.1\n")
	if err := os.WriteFile(resolvConfBackupPath, []byte("nameserver 192.168.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := restoreResolvConf(); err != nil {
		t.Fatalf("restoreResolvConf() returned error: %v", err)
	}

	got, err := os.ReadFile(resolvConfPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "nameserver 10.0.0.1\n" {
		t.Fatalf("foreign resolv.conf was modified: %q", got)
	}
	if _, err := os.Stat(resolvConfBackupPath); !os.IsNotExist(err) {
		t.Fatalf("stale backup not removed: %v", err)
	}
}

func TestParseDNSMode(t *testing.T) {
	cases := map[string]dnsMode{
		"":            dnsModeAuto,
		"auto":        dnsModeAuto,
		"resolved":    dnsModeResolved,
		"resolv-conf": dnsModeResolvConf,
		"resolvconf":  dnsModeResolvConf,
		"off":         dnsModeOff,
		"OFF":         dnsModeOff,
	}
	for in, want := range cases {
		got, err := parseDNSMode(in)
		if err != nil {
			t.Fatalf("parseDNSMode(%q) returned error: %v", in, err)
		}
		if got != want {
			t.Fatalf("parseDNSMode(%q) = %v, want %v", in, got, want)
		}
	}

	if _, err := parseDNSMode("bogus"); err == nil {
		t.Fatal("parseDNSMode(\"bogus\") did not return an error")
	}
}
