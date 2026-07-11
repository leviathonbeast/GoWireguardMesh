import type {
  AccessLogRow,
  AclRule,
  AuditRow,
  Flow,
  LinkStat,
  NetworkPeerChange,
  Peer,
  ProxyEvent,
  SetupKey,
} from "../types";
import { lastSeenLabel, serviceLabel, setupKeyStatus } from "./format";

export function textMatches(q: string, ...parts: unknown[]): boolean {
  const terms = q.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const hay = parts
    .flatMap((part) => (Array.isArray(part) ? part : [part]))
    .filter((part) => part != null)
    .join(" ")
    .toLowerCase();
  return terms.every((term) => hay.includes(term));
}

// The *Matches helpers do free-text search across the fields an operator
// would filter on: ip, port, hostname, protocol, direction, event,
// detail. Multiple terms are ANDed together.
export function flowMatches(f: Flow, q: string, srcName: string, dstName: string): boolean {
  return textMatches(
    q,
    f.src_ip, f.src_port, f.dst_ip, f.dst_port,
    f.protocol_name, f.direction, f.peer_hostname, srcName, dstName,
  );
}

export function auditMatches(a: AuditRow, q: string): boolean {
  return textMatches(
    q,
    a.event, a.detail, a.remote_ip, a.overlay_ip, a.peer_hostname,
    a.forwarded_for, a.method, a.path, a.status,
  );
}

export function accessMatches(a: AccessLogRow, q: string): boolean {
  return textMatches(
    q,
    a.method, a.path, a.status, a.remote_ip, a.forwarded_for, a.overlay_ip,
    a.peer_id, a.user_agent, Object.entries(a.headers ?? {}).flat().join(" "),
  );
}

export function peerMatches(p: Peer, q: string): boolean {
  return textMatches(
    q,
    p.id, p.hostname, p.assigned_ip, p.assigned_ip6, p.peer_type, p.health_status,
    p.public_key, p.public_endpoint, p.observed_ip, p.listen_port,
    lastSeenLabel(p), p.created_at, p.revoked_at,
  );
}

export function linkMatches(l: LinkStat, q: string): boolean {
  return textMatches(
    q,
    l.peer_hostname, l.peer_ip, l.remote_hostname, l.remote_ip,
    l.path_state, l.path_endpoint, l.rx_bytes, l.tx_bytes,
    l.last_handshake_at, l.updated_at,
  );
}

export function aclMatches(rule: AclRule, q: string): boolean {
  return textMatches(
    q,
    rule.id, rule.name, rule.src_label, rule.dst_label,
    rule.protocol, rule.port_min, rule.port_max, serviceLabel(rule), rule.created_at,
  );
}

export function setupKeyMatches(key: SetupKey, q: string): boolean {
  return textMatches(
    q,
    key.id, key.name, key.key, key.max_uses, key.uses_consumed,
    setupKeyStatus(key), key.created_at, key.expires_at, key.revoked_at,
  );
}

export function migrationChangeMatches(change: NetworkPeerChange, q: string): boolean {
  return textMatches(
    q,
    change.id, change.hostname, change.old_ip, change.new_ip,
    change.old_ip6, change.new_ip6, change.revoked_at,
  );
}

export function proxyMatches(e: ProxyEvent, q: string): boolean {
  return textMatches(q, e.method, e.host, e.path, e.status, e.client_ip, e.peer_hostname, e.service);
}
