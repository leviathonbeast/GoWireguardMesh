package main

import (
	"net/http"
	"reflect"
	"testing"
)

func TestAcmeManagedDomainsDedupesAndAppendsRelayHost(t *testing.T) {
	got, err := acmeManagedDomains(" Mesh.Example.uk , mesh.example.uk,", true, "relay.example.uk:51820")
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"mesh.example.uk", "relay.example.uk"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("domains = %v, want %v", got, want)
	}
}

func TestAcmeManagedDomainsRelayHostAlreadyCovered(t *testing.T) {
	got, err := acmeManagedDomains("mesh.example.uk", true, "mesh.example.uk")
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 {
		t.Fatalf("domains = %v, want just mesh.example.uk", got)
	}
}

func TestAcmeManagedDomainsRejectsIPRelayHost(t *testing.T) {
	if _, err := acmeManagedDomains("mesh.example.uk", true, "203.0.113.7:51820"); err == nil {
		t.Fatal("want error for IP relay host with ACME")
	}
}

func TestAcmeManagedDomainsIgnoresRelayHostWithoutQUIC(t *testing.T) {
	got, err := acmeManagedDomains("mesh.example.uk", false, "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"mesh.example.uk"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("domains = %v, want %v", got, want)
	}
}

func TestAcmeManagedDomainsEmpty(t *testing.T) {
	if _, err := acmeManagedDomains(" , ", false, ""); err == nil {
		t.Fatal("want error for empty domain list")
	}
}

func TestParseTrustedProxiesAcceptsCIDRsAndBareIPs(t *testing.T) {
	prefixes, err := parseTrustedProxies("172.18.0.0/16, 10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	if len(prefixes) != 2 {
		t.Fatalf("got %d prefixes, want 2", len(prefixes))
	}

	if prefixes[1].Bits() != 32 {
		t.Fatalf("bare IP should become /32, got /%d", prefixes[1].Bits())
	}
}

func TestParseTrustedProxiesRejectsGarbage(t *testing.T) {
	if _, err := parseTrustedProxies("not-a-cidr"); err == nil {
		t.Fatal("want error for invalid entry")
	}
}

func TestClientIPTrustedProxies(t *testing.T) {
	prefixes, err := parseTrustedProxies("172.18.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	s := &server{trustedProxies: prefixes}

	mkReq := func(remote, xff string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	// From the proxy: the RIGHTMOST XFF entry is the vouched-for one.
	if ip := s.clientIP(mkReq("172.18.0.3:41000", "6.6.6.6, 92.40.214.58")); ip != "92.40.214.58" {
		t.Fatalf("proxied request: got %q, want 92.40.214.58", ip)
	}

	// Direct client sending a forged XFF: header must be ignored.
	if ip := s.clientIP(mkReq("203.0.113.9:55555", "10.0.0.1")); ip != "203.0.113.9" {
		t.Fatalf("direct request: got %q, want 203.0.113.9", ip)
	}

	// Legacy --trust-proxy still trusts anyone.
	legacy := &server{trustProxy: true}
	if ip := legacy.clientIP(mkReq("203.0.113.9:55555", "10.0.0.1")); ip != "10.0.0.1" {
		t.Fatalf("legacy trust-proxy: got %q, want 10.0.0.1", ip)
	}
}
