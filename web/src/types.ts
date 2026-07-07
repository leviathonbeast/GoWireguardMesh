// Mirrors the JSON emitted by cmd/server/admin.go.

export interface Peer {
  id: number;
  public_key: string;
  assigned_ip: string;
  assigned_ip6?: string;
  health_status: "online" | "stale" | "offline" | "revoked" | "unknown";
  last_seen_age_seconds?: number;
  hostname?: string;
  listen_port?: number;
  observed_ip?: string;
  public_endpoint?: string;
  created_at: string;
  last_seen_at?: string;
  revoked_at?: string;
}

export interface SetupKey {
  id: number;
  key: string;
  name?: string;
  created_at: string;
  expires_at?: string;
  revoked_at?: string;
  max_uses: number; // 0 = unlimited
  uses_consumed: number;
}

export interface LinkStat {
  peer_id: number;
  peer_hostname?: string;
  peer_ip: string;
  remote_peer_id: number;
  remote_hostname?: string;
  remote_ip: string;
  rx_bytes: number;
  tx_bytes: number;
  last_handshake_at?: string;
  updated_at: string;
  path_state?: "direct" | "ws-relay" | "udp-relay" | "probing-direct";
  path_endpoint?: string;
  path_updated_at?: string;
}

export interface AclRule {
  id: number;
  src_peer_id: number | null;
  src_label: string;
  dst_peer_id: number | null;
  dst_label: string;
  name?: string;
  protocol: "any" | "tcp" | "udp" | "icmp" | "icmpv6";
  port_min?: number;
  port_max?: number;
  created_at: string;
}

export interface AclResponse {
  default_policy: "allow" | "deny";
  rules: AclRule[];
}

export interface AclExport {
  version: number;
  exported_at: string;
  default_policy: "allow" | "deny";
  rules: AclRule[];
  rule_count: number;
}

export interface Flow {
  id: number;
  peer_id: number;
  peer_hostname?: string;
  protocol: number;
  protocol_name: string;
  direction: string; // egress | ingress | transit
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  ingress_port: number;
  egress_port: number;
  tx_bytes: number;
  rx_bytes: number;
  tx_packets: number;
  rx_packets: number;
  reported_at: string;
}

export interface AuditRow {
  id: number;
  at: string;
  event: string;
  peer_id?: number;
  peer_hostname?: string;
  overlay_ip?: string;
  remote_ip?: string;
  forwarded_for?: string;
  user_agent?: string;
  method?: string;
  path?: string;
  status?: number;
  detail?: string;
}

export interface AccessLogRow {
  time: string;
  event: string;
  method: string;
  path: string;
  status: number;
  duration_ms: number;
  remote_ip: string;
  forwarded_for?: string;
  overlay_ip?: string;
  peer_id?: number;
  user_agent?: string;
  headers?: Record<string, string>;
}

export interface NetworkConfig {
  network_cidr: string;
  network_cidr6: string;
}

export interface DNSConfig {
  enabled: boolean;
  magic_dns: boolean;
  domain?: string;
  nameservers?: string[];
  search_domains?: string[];
}

export interface NetworkPeerChange {
  id: number;
  hostname?: string;
  revoked_at?: string;
  old_ip: string;
  new_ip: string;
  old_ip6?: string;
  new_ip6: string;
}

export interface NetworkMigrationPlan {
  current: NetworkConfig;
  target: NetworkConfig;
  changes: NetworkPeerChange[];
  message?: string;
}
