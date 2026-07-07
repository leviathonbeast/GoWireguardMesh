package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

const (
	settingDNSEnabled       = "dns_enabled"
	settingDNSMagic         = "dns_magic"
	settingDNSDomain        = "dns_domain"
	settingDNSNameservers   = "dns_nameservers"
	settingDNSSearchDomains = "dns_search_domains"
)

type DNSConfig struct {
	Enabled       bool     `json:"enabled"`
	MagicDNS      bool     `json:"magic_dns"`
	Domain        string   `json:"domain,omitempty"`
	Nameservers   []string `json:"nameservers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
}

func (s *Store) LoadOrInitDNSConfig(ctx context.Context, defaults DNSConfig) (DNSConfig, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DNSConfig{}, fmt.Errorf("begin dns config: %w", err)
	}
	defer tx.Rollback()

	cfg, err := loadDNSConfig(ctx, tx)
	if err != nil {
		return DNSConfig{}, err
	}

	if cfg.Domain == "" {
		cfg.Domain = defaults.Domain
	}
	if len(cfg.Nameservers) == 0 {
		cfg.Nameservers = defaults.Nameservers
	}
	if len(cfg.SearchDomains) == 0 {
		cfg.SearchDomains = defaults.SearchDomains
	}
	if !settingExists(ctx, tx, settingDNSEnabled) {
		cfg.Enabled = defaults.Enabled
	}
	if !settingExists(ctx, tx, settingDNSMagic) {
		cfg.MagicDNS = defaults.MagicDNS
	}

	cfg, err = NormalizeDNSConfig(cfg)
	if err != nil {
		return DNSConfig{}, err
	}

	if err := saveDNSConfig(ctx, tx, cfg); err != nil {
		return DNSConfig{}, err
	}

	if err := tx.Commit(); err != nil {
		return DNSConfig{}, fmt.Errorf("commit dns config: %w", err)
	}

	return cfg, nil
}

func (s *Store) CurrentDNSConfig(ctx context.Context) (DNSConfig, error) {
	return loadDNSConfig(ctx, s.db)
}

func (s *Store) UpdateDNSConfig(ctx context.Context, cfg DNSConfig) (DNSConfig, error) {
	cfg, err := NormalizeDNSConfig(cfg)
	if err != nil {
		return DNSConfig{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DNSConfig{}, fmt.Errorf("begin dns config update: %w", err)
	}
	defer tx.Rollback()

	if err := saveDNSConfig(ctx, tx, cfg); err != nil {
		return DNSConfig{}, err
	}

	if err := tx.Commit(); err != nil {
		return DNSConfig{}, fmt.Errorf("commit dns config update: %w", err)
	}

	return cfg, nil
}

func NormalizeDNSConfig(cfg DNSConfig) (DNSConfig, error) {
	cfg.Domain = normalizeDomain(cfg.Domain)
	if cfg.Domain == "" {
		cfg.Domain = "vpn"
	}
	if err := validateDomain("domain", cfg.Domain); err != nil {
		return DNSConfig{}, err
	}

	var nameservers []string
	seenNS := map[string]bool{}
	for _, raw := range cfg.Nameservers {
		ns := strings.TrimSpace(raw)
		if ns == "" {
			continue
		}
		addr, err := netip.ParseAddr(ns)
		if err != nil {
			return DNSConfig{}, fmt.Errorf("nameserver %q must be an IP address: %w", ns, err)
		}
		ns = addr.String()
		if !seenNS[ns] {
			seenNS[ns] = true
			nameservers = append(nameservers, ns)
		}
	}

	var search []string
	seenSearch := map[string]bool{}
	for _, raw := range cfg.SearchDomains {
		domain := normalizeDomain(raw)
		if domain == "" {
			continue
		}
		if err := validateDomain("search domain", domain); err != nil {
			return DNSConfig{}, err
		}
		if !seenSearch[domain] {
			seenSearch[domain] = true
			search = append(search, domain)
		}
	}
	if cfg.Enabled && cfg.MagicDNS && cfg.Domain != "" && !seenSearch[cfg.Domain] {
		search = append([]string{cfg.Domain}, search...)
	}

	cfg.Nameservers = nameservers
	cfg.SearchDomains = search

	if cfg.Enabled && len(cfg.Nameservers) == 0 {
		return DNSConfig{}, fmt.Errorf("at least one nameserver is required when DNS is enabled")
	}

	return cfg, nil
}

func loadDNSConfig(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (DNSConfig, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT key, value FROM settings WHERE key IN (?, ?, ?, ?, ?)`,
		settingDNSEnabled, settingDNSMagic, settingDNSDomain, settingDNSNameservers, settingDNSSearchDomains,
	)
	if err != nil {
		return DNSConfig{}, fmt.Errorf("load dns config: %w", err)
	}
	defer rows.Close()

	cfg := DNSConfig{Domain: "vpn", MagicDNS: true}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return DNSConfig{}, fmt.Errorf("scan dns config: %w", err)
		}
		switch key {
		case settingDNSEnabled:
			cfg.Enabled = value == "true"
		case settingDNSMagic:
			cfg.MagicDNS = value != "false"
		case settingDNSDomain:
			cfg.Domain = value
		case settingDNSNameservers:
			if err := json.Unmarshal([]byte(value), &cfg.Nameservers); err != nil {
				return DNSConfig{}, fmt.Errorf("parse dns nameservers: %w", err)
			}
		case settingDNSSearchDomains:
			if err := json.Unmarshal([]byte(value), &cfg.SearchDomains); err != nil {
				return DNSConfig{}, fmt.Errorf("parse dns search domains: %w", err)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return DNSConfig{}, fmt.Errorf("load dns config: %w", err)
	}

	return NormalizeDNSConfig(cfg)
}

func saveDNSConfig(ctx context.Context, tx *sql.Tx, cfg DNSConfig) error {
	nameservers, err := json.Marshal(cfg.Nameservers)
	if err != nil {
		return fmt.Errorf("encode dns nameservers: %w", err)
	}
	searchDomains, err := json.Marshal(cfg.SearchDomains)
	if err != nil {
		return fmt.Errorf("encode dns search domains: %w", err)
	}

	values := map[string]string{
		settingDNSEnabled:       fmt.Sprintf("%t", cfg.Enabled),
		settingDNSMagic:         fmt.Sprintf("%t", cfg.MagicDNS),
		settingDNSDomain:        cfg.Domain,
		settingDNSNameservers:   string(nameservers),
		settingDNSSearchDomains: string(searchDomains),
	}
	for key, value := range values {
		if err := upsertSetting(ctx, tx, key, value); err != nil {
			return err
		}
	}

	return nil
}

func settingExists(ctx context.Context, tx *sql.Tx, key string) bool {
	var n int
	return tx.QueryRowContext(ctx, `SELECT count(*) FROM settings WHERE key = ?`, key).Scan(&n) == nil && n > 0
}

func normalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, ".")
	return s
}

func validateDomain(field, domain string) error {
	if len(domain) > 253 {
		return fmt.Errorf("%s %q is too long", field, domain)
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("%s %q is not a valid DNS name", field, domain)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%s %q labels cannot start or end with '-'", field, domain)
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Errorf("%s %q contains invalid character %q", field, domain, r)
		}
	}
	return nil
}
