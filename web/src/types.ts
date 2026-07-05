// Mirrors the JSON emitted by cmd/server/admin.go.

export interface Peer {
  id: number;
  public_key: string;
  assigned_ip: string;
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
}

export interface AclRule {
  id: number;
  src_peer_id: number | null;
  src_label: string;
  dst_peer_id: number | null;
  dst_label: string;
  created_at: string;
}

export interface AclResponse {
  default_policy: "allow" | "deny";
  rules: AclRule[];
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
