package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
)

const (
	settingNetworkCIDR  = "network_cidr"
	settingNetworkCIDR6 = "network_cidr6"
)

type NetworkConfig struct {
	NetworkCIDR  string `json:"network_cidr"`
	NetworkCIDR6 string `json:"network_cidr6"`
}

type NetworkPeerChange struct {
	ID        int64  `json:"id"`
	Hostname  string `json:"hostname,omitempty"`
	RevokedAt string `json:"revoked_at,omitempty"`
	OldIP     string `json:"old_ip"`
	NewIP     string `json:"new_ip"`
	OldIP6    string `json:"old_ip6,omitempty"`
	NewIP6    string `json:"new_ip6"`
}

type NetworkMigrationPlan struct {
	Current NetworkConfig       `json:"current"`
	Target  NetworkConfig       `json:"target"`
	Changes []NetworkPeerChange `json:"changes"`
	Message string              `json:"message,omitempty"`
}

func (s *Store) LoadOrInitNetworkConfig(ctx context.Context, default4, default6 netip.Prefix) (NetworkConfig, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return NetworkConfig{}, fmt.Errorf("begin network config: %w", err)
	}
	defer tx.Rollback()

	cfg, err := loadNetworkConfig(ctx, tx)
	if err != nil {
		return NetworkConfig{}, err
	}

	if cfg.NetworkCIDR == "" {
		cfg.NetworkCIDR = default4.Masked().String()
		if err := upsertSetting(ctx, tx, settingNetworkCIDR, cfg.NetworkCIDR); err != nil {
			return NetworkConfig{}, err
		}
	}

	if cfg.NetworkCIDR6 == "" {
		cfg.NetworkCIDR6 = default6.Masked().String()
		if err := upsertSetting(ctx, tx, settingNetworkCIDR6, cfg.NetworkCIDR6); err != nil {
			return NetworkConfig{}, err
		}
	}

	network4, network6, err := parseNetworkConfig(cfg.NetworkCIDR, cfg.NetworkCIDR6)
	if err != nil {
		return NetworkConfig{}, err
	}

	if err := tx.Commit(); err != nil {
		return NetworkConfig{}, fmt.Errorf("commit network config: %w", err)
	}

	s.setNetworks(network4, network6)

	return NetworkConfig{NetworkCIDR: network4.String(), NetworkCIDR6: network6.String()}, nil
}

func (s *Store) CurrentNetworkConfig() NetworkConfig {
	return NetworkConfig{
		NetworkCIDR:  s.network4().String(),
		NetworkCIDR6: s.network6().String(),
	}
}

func (s *Store) PreviewNetworkMigration(ctx context.Context, target4, target6 netip.Prefix) (NetworkMigrationPlan, error) {
	return s.previewNetworkMigration(ctx, s.network4(), s.network6(), target4.Masked(), target6.Masked())
}

func (s *Store) ApplyNetworkMigration(ctx context.Context, target4, target6 netip.Prefix) (NetworkMigrationPlan, error) {
	target4 = target4.Masked()
	target6 = target6.Masked()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return NetworkMigrationPlan{}, fmt.Errorf("begin network migration: %w", err)
	}
	defer tx.Rollback()

	current4, current6 := s.network4(), s.network6()
	plan, err := buildNetworkMigrationPlan(ctx, tx, current4, current6, target4, target6)
	if err != nil {
		return NetworkMigrationPlan{}, err
	}

	for _, c := range plan.Changes {
		if _, err := tx.ExecContext(ctx,
			`UPDATE peers SET assigned_ip = ?, assigned_ip6 = ? WHERE id = ?`,
			fmt.Sprintf("__migrating4_%d", c.ID),
			fmt.Sprintf("__migrating6_%d", c.ID),
			c.ID,
		); err != nil {
			return NetworkMigrationPlan{}, fmt.Errorf("stage peer %d network migration: %w", c.ID, err)
		}
	}

	for _, c := range plan.Changes {
		if _, err := tx.ExecContext(ctx,
			`UPDATE peers SET assigned_ip = ?, assigned_ip6 = ? WHERE id = ?`,
			c.NewIP, c.NewIP6, c.ID,
		); err != nil {
			return NetworkMigrationPlan{}, fmt.Errorf("apply peer %d network migration: %w", c.ID, err)
		}
	}

	if err := upsertSetting(ctx, tx, settingNetworkCIDR, target4.String()); err != nil {
		return NetworkMigrationPlan{}, err
	}
	if err := upsertSetting(ctx, tx, settingNetworkCIDR6, target6.String()); err != nil {
		return NetworkMigrationPlan{}, err
	}

	if err := tx.Commit(); err != nil {
		return NetworkMigrationPlan{}, fmt.Errorf("commit network migration: %w", err)
	}

	s.setNetworks(target4, target6)

	return plan, nil
}

func (s *Store) previewNetworkMigration(ctx context.Context, current4, current6, target4, target6 netip.Prefix) (NetworkMigrationPlan, error) {
	return buildNetworkMigrationPlan(ctx, s.db, current4, current6, target4, target6)
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func buildNetworkMigrationPlan(ctx context.Context, q queryer, current4, current6, target4, target6 netip.Prefix) (NetworkMigrationPlan, error) {
	peers, err := listNetworkPeers(ctx, q)
	if err != nil {
		return NetworkMigrationPlan{}, err
	}

	v4, err := firstOverlayHosts(target4, len(peers))
	if err != nil {
		return NetworkMigrationPlan{}, err
	}
	v6, err := firstOverlayHosts(target6, len(peers))
	if err != nil {
		return NetworkMigrationPlan{}, err
	}

	changes := make([]NetworkPeerChange, 0, len(peers))
	for i, p := range peers {
		p.NewIP = v4[i]
		p.NewIP6 = v6[i]
		changes = append(changes, p)
	}

	return NetworkMigrationPlan{
		Current: NetworkConfig{NetworkCIDR: current4.String(), NetworkCIDR6: current6.String()},
		Target:  NetworkConfig{NetworkCIDR: target4.String(), NetworkCIDR6: target6.String()},
		Changes: changes,
	}, nil
}

func firstOverlayHosts(prefix netip.Prefix, n int) ([]string, error) {
	if n == 0 {
		return nil, nil
	}

	out := make([]string, 0, n)
	for ip := prefix.Addr().Next(); prefix.Contains(ip); ip = ip.Next() {
		out = append(out, ip.String())
		if len(out) == n {
			return out, nil
		}
	}

	return nil, fmt.Errorf("overlay network %s has room for %d peer(s), need %d", prefix, len(out), n)
}

func listNetworkPeers(ctx context.Context, q queryer) ([]NetworkPeerChange, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT id, COALESCE(hostname, ''), assigned_ip, COALESCE(assigned_ip6, ''), COALESCE(revoked_at, '')
		 FROM peers ORDER BY id`,
	)
	if err != nil {
		return nil, fmt.Errorf("list peers for network migration: %w", err)
	}
	defer rows.Close()

	var peers []NetworkPeerChange
	for rows.Next() {
		var p NetworkPeerChange
		if err := rows.Scan(&p.ID, &p.Hostname, &p.OldIP, &p.OldIP6, &p.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan network migration peer: %w", err)
		}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list peers for network migration: %w", err)
	}

	return peers, nil
}

func loadNetworkConfig(ctx context.Context, tx *sql.Tx) (NetworkConfig, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT key, value FROM settings WHERE key IN (?, ?)`,
		settingNetworkCIDR, settingNetworkCIDR6,
	)
	if err != nil {
		return NetworkConfig{}, fmt.Errorf("load network config: %w", err)
	}
	defer rows.Close()

	var cfg NetworkConfig
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return NetworkConfig{}, fmt.Errorf("scan network config: %w", err)
		}
		switch key {
		case settingNetworkCIDR:
			cfg.NetworkCIDR = value
		case settingNetworkCIDR6:
			cfg.NetworkCIDR6 = value
		}
	}
	if err := rows.Err(); err != nil {
		return NetworkConfig{}, fmt.Errorf("load network config: %w", err)
	}

	return cfg, nil
}

func upsertSetting(ctx context.Context, tx *sql.Tx, key, value string) error {
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	); err != nil {
		return fmt.Errorf("save setting %s: %w", key, err)
	}

	return nil
}

func parseNetworkConfig(raw4, raw6 string) (netip.Prefix, netip.Prefix, error) {
	network4, err := netip.ParsePrefix(raw4)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("parse network_cidr %q: %w", raw4, err)
	}
	if !network4.Addr().Is4() {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("network_cidr must be IPv4, got %q", raw4)
	}

	network6, err := netip.ParsePrefix(raw6)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("parse network_cidr6 %q: %w", raw6, err)
	}
	if !network6.Addr().Is6() {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("network_cidr6 must be IPv6, got %q", raw6)
	}

	return network4.Masked(), network6.Masked(), nil
}
