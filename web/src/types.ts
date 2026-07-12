// Mirrors the JSON emitted by cmd/server/admin.go.

export interface Peer {
  id: number;
  public_key: string;
  assigned_ip: string;
  assigned_ip6?: string;
  peer_type: "agent" | "static";
  gateway_peer_id?: number; // for a routed mobile peer, the agent that carries its /32
  gateway_endpoint?: string; // the address a static peer dials
  has_stored_config?: boolean; // GET /api/peers/{id}/config can rebuild its WireGuard config
  health_status: "online" | "stale" | "offline" | "revoked" | "static" | "unknown";
  last_seen_age_seconds?: number;
  hostname?: string;
  listen_port?: number;
  observed_ip?: string;
  public_endpoint?: string;
  nat_type?: "easy" | "hard"; // agent's NAT classification; absent when unknown
  created_at: string;
  last_seen_at?: string;
  revoked_at?: string;
}

export interface Account {
  id: number;
  username: string;
  auth_source: "local" | "oidc";
  created_at: string;
  updated_at: string;
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

// MobilePeerResponse carries a static peer's complete WireGuard config,
// private key included. Returned when the peer is created and again from
// GET /api/peers/{id}/config, which rebuilds it from the sealed key.
// Mirrors mobilePeerResponse in mobile.go.
export interface MobilePeerResponse {
  peer: Peer;
  config: string;
  private_key?: string; // only on create; on re-show the key rides inside config
  preshared_key: string;
  warnings?: string[];
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
  path_state?: "direct" | "quic-relay" | "ws-relay" | "udp-relay" | "probing-direct";
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

export interface ProxyEvent {
  id: number;
  at: string;
  peer_id?: number;
  peer_hostname?: string;
  method?: string;
  host?: string;
  path?: string;
  status?: number;
  duration_ms?: number;
  req_bytes?: number;
  resp_bytes?: number;
  client_ip?: string;
  service?: string;
}

export interface ConnectionEvent {
  id: number;
  at: string;
  kind: string; // "direct" | "relay"
  from_state?: string;
  to_state: string;
  reporter_peer_id: number;
  reporter_hostname?: string;
  remote_peer_id: number;
  remote_hostname?: string;
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
