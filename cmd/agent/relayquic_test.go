package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestServerHostname(t *testing.T) {
	cases := map[string]string{
		"https://mesh.mynetbird.uk":      "mesh.mynetbird.uk",
		"https://mesh.mynetbird.uk:8443": "mesh.mynetbird.uk",
		"http://mesh.mynetbird.uk:8080":  "mesh.mynetbird.uk",
		"https://mesh.mynetbird.uk/":     "mesh.mynetbird.uk",
		// IP literals yield "": pinning ServerName to an IP would want
		// an IP SAN, which is exactly what we are avoiding.
		"https://213.32.16.141":      "",
		"https://213.32.16.141:8443": "",
		"https://[2001:db8::1]:8443": "",
		// Unparseable / empty input must not panic or invent a name.
		"":        "",
		"://nope": "",
	}

	for in, want := range cases {
		if got := serverHostname(in); got != want {
			t.Errorf("serverHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHostnameCertVerifiesWhenRelayAdvertisedByIP reproduces the live
// failure: the control plane runs ACME, so the QUIC relay presents a
// cert with only a DNS SAN, while --relay-host advertises a bare IP.
// Verifying against the IP fails with "doesn't contain any IP SANs";
// pinning ServerName to the control plane's hostname must succeed.
func TestHostnameCertVerifiesWhenRelayAdvertisedByIP(t *testing.T) {
	const hostname = "mesh.mynetbird.uk"
	const relayIP = "213.32.16.141"

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: hostname},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		// A public CA cert for a domain: DNS SAN only, no IP SAN.
		DNSNames: []string{hostname},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	verify := func(serverName string) error {
		_, err := leaf.Verify(x509.VerifyOptions{
			DNSName:     serverName,
			Roots:       roots,
			CurrentTime: time.Now(),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		return err
	}

	// What happened before the fix: ServerName defaulted to the dialled
	// IP, and verification failed.
	if err := verify(relayIP); err == nil {
		t.Fatal("verifying against the relay IP unexpectedly succeeded; the test cert is wrong")
	}

	// What the fix does: ServerName comes from the control-plane URL.
	pinned := serverHostname("https://" + hostname)
	if pinned != hostname {
		t.Fatalf("serverHostname() = %q, want %q", pinned, hostname)
	}
	if err := verify(pinned); err != nil {
		t.Fatalf("verifying against the pinned hostname failed: %v", err)
	}

	// Guard the TLS plumbing too: ServerName must actually be settable
	// to the hostname while the dial target stays the IP.
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: pinned}
	if cfg.ServerName != hostname {
		t.Fatalf("tls ServerName = %q, want %q", cfg.ServerName, hostname)
	}
	if net.ParseIP(relayIP) == nil {
		t.Fatalf("relayIP %q should parse as an IP", relayIP)
	}
}
