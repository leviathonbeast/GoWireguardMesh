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

export interface Flow {
  id: number;
  peer_id: number;
  peer_hostname?: string;
  protocol: number;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  tx_bytes: number;
  rx_bytes: number;
  tx_packets: number;
  rx_packets: number;
  reported_at: string;
}
