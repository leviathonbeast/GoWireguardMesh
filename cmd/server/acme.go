package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"go.uber.org/zap"
)

// ACME (Let's Encrypt) over DNS-01 gives the control plane a publicly
// trusted certificate without a reverse proxy in front and without
// serving challenges on 80/443: the proof of control is a DNS TXT
// record, so issuance works on any listen port. Agents then verify the
// server like any HTTPS client — no --server-ca file to distribute.
//
// DNS-01 requires API access to the zone. Cloudflare is the supported
// provider; the token needs exactly one permission: Zone → DNS → Edit
// on the zone containing --acme-domain.

// acmeManagedDomains is the SAN set to obtain: the configured names
// plus the QUIC relay host, which agents verify against this same
// certificate when they dial the relay. An IP relay host can never
// appear in a publicly trusted certificate, so it is rejected here at
// startup rather than failing at the first relayed connection.
func acmeManagedDomains(domainFlag string, quicRelay bool, relayHost string) ([]string, error) {
	var domains []string

	seen := map[string]bool{}

	for _, d := range strings.Split(domainFlag, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}

		seen[d] = true
		domains = append(domains, d)
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("--acme-domain %q contains no domain names", domainFlag)
	}

	if quicRelay {
		host := strings.ToLower(relayEndpointHost(relayHost))
		if _, err := netip.ParseAddr(host); err == nil {
			return nil, fmt.Errorf("--relay-host %q is an IP address, which a publicly trusted certificate cannot cover; use a DNS name with --acme-domain", relayHost)
		}

		if !seen[host] {
			domains = append(domains, host)
		}
	}

	return domains, nil
}

// acmeTLSConfig obtains (or loads from storageDir) certificates for
// domains and returns a tls.Config that serves and auto-renews them.
// It blocks until every certificate is available: on first boot that
// is a live ACME issuance, afterwards a disk load.
func acmeTLSConfig(ctx context.Context, domains []string, email, tokenFile, storageDir string, staging bool) (*tls.Config, error) {
	token := os.Getenv("CLOUDFLARE_API_TOKEN")

	if tokenFile != "" {
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, fmt.Errorf("read ACME DNS token file: %w", err)
		}

		token = strings.TrimSpace(string(data))
	}

	if token == "" {
		return nil, fmt.Errorf("ACME needs a Cloudflare API token: set CLOUDFLARE_API_TOKEN or --acme-dns-token-file")
	}

	// certmagic logs through zap; warn-and-up keeps renewal failures
	// visible in our stderr stream without narrating every check.
	zapCfg := zap.NewProductionConfig()
	zapCfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)

	logger, err := zapCfg.Build()
	if err != nil {
		return nil, fmt.Errorf("build acme logger: %w", err)
	}

	var cfg *certmagic.Config

	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return cfg, nil
		},
		Logger: logger,
	})

	cfg = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: storageDir},
		Logger:  logger,
		// SNI-less handshakes (health checks and probes dialing the
		// listener by IP) get the primary certificate instead of a
		// handshake failure.
		DefaultServerName: domains[0],
	})

	ca := certmagic.LetsEncryptProductionCA
	if staging {
		ca = certmagic.LetsEncryptStagingCA
	}

	cfg.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA:     ca,
		Email:  email,
		Agreed: true,
		Logger: logger,
		DNS01Solver: &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &cloudflare.Provider{APIToken: token},
				Logger:      logger,
			},
		},
	})}

	if err := cfg.ManageSync(ctx, domains); err != nil {
		return nil, fmt.Errorf("obtain certificate for %s: %w", strings.Join(domains, ", "), err)
	}

	tlsCfg := cfg.TLSConfig()
	tlsCfg.MinVersion = tls.VersionTLS13
	tlsCfg.NextProtos = []string{"h2", "http/1.1"}

	return tlsCfg, nil
}
