package store

import (
	"context"
	"testing"
)

func TestDNSConfigPersistsAndNormalizes(t *testing.T) {
	st := openTestStore(t, "100.64.0.0/16")
	ctx := context.Background()

	cfg, err := st.LoadOrInitDNSConfig(ctx, DNSConfig{
		Enabled:       true,
		MagicDNS:      true,
		Domain:        "VPN.",
		Nameservers:   []string{"100.78.0.1", "100.78.0.1"},
		SearchDomains: []string{"VPN"},
	})
	if err != nil {
		t.Fatalf("LoadOrInitDNSConfig() error = %v", err)
	}
	if !cfg.Enabled || cfg.Domain != "vpn" {
		t.Fatalf("dns config = %#v, want enabled vpn domain", cfg)
	}
	if len(cfg.Nameservers) != 1 || cfg.Nameservers[0] != "100.78.0.1" {
		t.Fatalf("nameservers = %#v, want one normalized nameserver", cfg.Nameservers)
	}

	updated, err := st.UpdateDNSConfig(ctx, DNSConfig{
		Enabled:       true,
		MagicDNS:      true,
		Domain:        "corp.vpn",
		Nameservers:   []string{"fd32:d2ad:be4f::1"},
		SearchDomains: []string{"svc.vpn"},
	})
	if err != nil {
		t.Fatalf("UpdateDNSConfig() error = %v", err)
	}
	if updated.SearchDomains[0] != "corp.vpn" {
		t.Fatalf("search domains = %#v, want magic domain first", updated.SearchDomains)
	}

	got, err := st.CurrentDNSConfig(ctx)
	if err != nil {
		t.Fatalf("CurrentDNSConfig() error = %v", err)
	}
	if got.Domain != updated.Domain || got.Nameservers[0] != updated.Nameservers[0] {
		t.Fatalf("persisted config = %#v, want %#v", got, updated)
	}
}

func TestEnabledDNSRequiresNameserver(t *testing.T) {
	if _, err := NormalizeDNSConfig(DNSConfig{Enabled: true, Domain: "vpn"}); err == nil {
		t.Fatal("NormalizeDNSConfig accepted enabled DNS without a nameserver")
	}
}
