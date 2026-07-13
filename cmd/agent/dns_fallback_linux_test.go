//go:build linux

package main

import (
	"os"
	"strings"
	"testing"

	"gowireguard/internal/proto"
)

func setDNSFallback(t *testing.T, on bool) {
	t.Helper()
	prev := dnsKeepFallback
	dnsKeepFallback = on
	t.Cleanup(func() { dnsKeepFallback = prev })
}

func TestResolvConfTakeoverKeepsOriginalNameserversAsFallback(t *testing.T) {
	setDNSMode(t, dnsModeResolvConf)
	setDNSFallback(t, true)
	useTempResolvConf(t, "nameserver 127.0.0.11\nsearch lan\n")

	cfg := proto.DNSConfig{Enabled: true, Nameservers: []string{"100.78.0.7"}, Domain: "vpn", MagicDNS: true}
	if err := applyDNSConfig("wg-int", cfg); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(resolvConfPath)
	if err != nil {
		t.Fatal(err)
	}

	text := string(got)

	meshIdx := strings.Index(text, "nameserver 100.78.0.7")
	origIdx := strings.Index(text, "nameserver 127.0.0.11")

	if meshIdx < 0 || origIdx < 0 {
		t.Fatalf("takeover missing mesh or fallback nameserver:\n%s", text)
	}

	if origIdx < meshIdx {
		t.Fatalf("fallback must come after the mesh nameserver:\n%s", text)
	}

	if !strings.Contains(text, "options timeout:2") {
		t.Fatalf("expected tightened failover options:\n%s", text)
	}
}

func TestResolvConfTakeoverFallbackSurvivesReapply(t *testing.T) {
	setDNSMode(t, dnsModeResolvConf)
	setDNSFallback(t, true)
	useTempResolvConf(t, "nameserver 192.168.1.1\n")

	cfg := proto.DNSConfig{Enabled: true, Nameservers: []string{"100.78.0.7"}}

	// Apply twice: the second run sees our own file live and must pull
	// the fallback from the backup, not from our generated content.
	for range 2 {
		if err := applyDNSConfig("wg-int", cfg); err != nil {
			t.Fatal(err)
		}
	}

	got, err := os.ReadFile(resolvConfPath)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(got), "nameserver 192.168.1.1") {
		t.Fatalf("re-apply lost the original fallback nameserver:\n%s", got)
	}

	if n := strings.Count(string(got), "nameserver 192.168.1.1"); n != 1 {
		t.Fatalf("fallback duplicated %d times:\n%s", n, got)
	}
}

func TestResolvConfTakeoverFallbackDedupesAndCaps(t *testing.T) {
	setDNSMode(t, dnsModeResolvConf)
	setDNSFallback(t, true)
	useTempResolvConf(t, "nameserver 100.78.0.7\nnameserver 1.1.1.1\nnameserver 9.9.9.9\nnameserver 8.8.8.8\n")

	cfg := proto.DNSConfig{Enabled: true, Nameservers: []string{"100.78.0.7"}}
	if err := applyDNSConfig("wg-int", cfg); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(resolvConfPath)
	if err != nil {
		t.Fatal(err)
	}

	text := string(got)

	if n := strings.Count(text, "nameserver 100.78.0.7"); n != 1 {
		t.Fatalf("pushed nameserver appears %d times (dedup failed):\n%s", n, text)
	}

	if n := strings.Count(text, "nameserver "); n != resolvConfMaxNS {
		t.Fatalf("want %d nameservers total (MAXNS), got %d:\n%s", resolvConfMaxNS, n, text)
	}

	if strings.Contains(text, "8.8.8.8") {
		t.Fatalf("entries beyond MAXNS must be dropped:\n%s", text)
	}
}

func TestResolvConfTakeoverFallbackDisabled(t *testing.T) {
	setDNSMode(t, dnsModeResolvConf)
	setDNSFallback(t, false)
	useTempResolvConf(t, "nameserver 1.1.1.1\n")

	cfg := proto.DNSConfig{Enabled: true, Nameservers: []string{"100.78.0.7"}}
	if err := applyDNSConfig("wg-int", cfg); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(resolvConfPath)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(got), "1.1.1.1") {
		t.Fatalf("--dns-fallback=false must not keep original nameservers:\n%s", got)
	}
}
