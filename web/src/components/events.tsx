import type { AccessLogRow, AuditRow, ConnectionEvent, Flow } from "../types";
import { formatTime, humanBytes } from "../lib/format";
import { Endpoint } from "./ui";

// ConnectionEventRow renders one peer-to-peer connection lifecycle event
// (a direct/P2P connection established, or a relay fallback), NetBird-style.
export function ConnectionEventRow({ e }: { e: ConnectionEvent }) {
  const reporter = e.reporter_hostname || `peer ${e.reporter_peer_id}`;
  const remote = e.remote_hostname || `peer ${e.remote_peer_id}`;
  const direct = e.kind === "direct";

  return (
    <div className="flex items-start justify-between gap-3 border-b border-line/60 py-2.5 last:border-b-0">
      <div className="flex min-w-0 gap-2.5">
        <span className={`dot ${direct ? "dot-ok" : "dot-warn"}`} />
        <div className="min-w-0">
          <div className="event-time">{formatTime(e.at)}</div>
          <div>
            Peer <strong>{reporter}</strong>{" "}
            {direct ? "established a direct (P2P) connection to" : "connected over relay to"}{" "}
            Peer <strong>{remote}</strong>
          </div>
        </div>
      </div>
      <div className="flex shrink-0 gap-1.5">
        <span className={`pill ${direct ? "pill-p2p" : "pill-relay"}`}>{direct ? "P2P" : "RELAY"}</span>
        <span className="pill">{e.to_state}</span>
      </div>
    </div>
  );
}

// FlowEvent renders one observed flow as a NetBird-style traffic
// event: a sentence, both peer endpoints, protocol/port, and
// directional byte counts from the reporting peer's vantage.
export function FlowEvent({ f, ipName }: { f: Flow; ipName: (ip: string) => string }) {
  const srcName = ipName(f.src_ip);
  const dstName = ipName(f.dst_ip);

  const subject = f.direction === "ingress" ? dstName : srcName;
  const other = f.direction === "ingress" ? srcName : dstName;
  const verb = f.direction === "ingress" ? "received a" : "opened a";
  const prep = f.direction === "ingress" ? "from" : "to";

  return (
    <div className="activity-row">
      <div className="flex min-w-0 gap-2.5">
        <span className="dot dot-ok" />
        <div className="min-w-0">
          <div className="event-time">{formatTime(f.reported_at)}</div>
          <div>
            Peer <strong>{subject}</strong> {verb} {f.protocol_name.toUpperCase()} connection{" "}
            {prep} Peer <strong>{other}</strong>
          </div>
        </div>
      </div>
      <Endpoint name={srcName} ip={f.src_port ? `${f.src_ip}:${f.src_port}` : f.src_ip} />
      <div className="flex flex-wrap gap-1.5">
        <span className="pill">{f.protocol_name.toUpperCase()}</span>
        {f.dst_port ? <span className="pill">{f.dst_port}</span> : null}
      </div>
      <Endpoint name={dstName} ip={f.dst_port ? `${f.dst_ip}:${f.dst_port}` : f.dst_ip} />
      <div className="text-xs whitespace-nowrap">
        <div>
          <span className="text-ok">↓</span> {humanBytes(f.rx_bytes)}
        </div>
        <div>
          <span className="text-accent">↑</span> {humanBytes(f.tx_bytes)}
        </div>
      </div>
    </div>
  );
}

const ADMIN_EVENTS = new Set([
  "setup_key_create",
  "acl_create",
  "acl_delete",
  "acl_import",
  "dns_update",
  "peer_address_update",
  "peer_remove",
  "revoke",
]);

const EVENT_PHRASE: Record<string, string> = {
  enroll: "enrolled",
  re_enroll: "re-enrolled",
  enroll_rejected: "was rejected at enrollment",
  report_rejected: "had a telemetry report rejected",
  relay_pair: "requested a UDP relay path",
  relay_pair_rejected: "was rejected requesting a relay",
  relay_ws_open: "opened a WebSocket relay",
  relay_ws_close: "closed a WebSocket relay",
  relay_ws_rejected: "was rejected opening a relay",
  setup_key_create: "created a setup key",
  acl_create: "added an ACL rule",
  acl_delete: "deleted an ACL rule",
  acl_import: "imported ACL rules",
  dns_update: "changed DNS settings",
  network_migrate: "changed the overlay network",
  peer_address_update: "changed a peer address",
  peer_remove: "removed a peer",
  revoke: "revoked",
  ui_login: "signed in to the web UI",
  ui_login_failed: "failed a web UI sign-in",
};

function auditDot(a: AuditRow): string {
  if (a.event.endsWith("rejected") || a.event.endsWith("failed") || (a.status ?? 0) >= 400) return "dot-bad";
  if (ADMIN_EVENTS.has(a.event)) return "dot-warn";
  if (a.event.includes("relay")) return "dot-info";
  return "dot-ok";
}

export function AuditEvent({ a }: { a: AuditRow }) {
  const phrase = EVENT_PHRASE[a.event] ?? a.event;
  const who = a.peer_hostname || a.overlay_ip || "";

  let subject;
  if (ADMIN_EVENTS.has(a.event)) subject = <>Admin </>;
  else if (who)
    subject = (
      <>
        Peer <strong>{who}</strong>{" "}
      </>
    );
  else if (a.remote_ip)
    subject = (
      <>
        <strong>{a.remote_ip}</strong>{" "}
      </>
    );
  else subject = null;

  return (
    <div className="activity-row">
      <div className="flex min-w-0 gap-2.5">
        <span className={`dot ${auditDot(a)}`} />
        <div className="min-w-0">
          <div className="event-time">{formatTime(a.at)}</div>
          <div>
            {subject}
            {phrase}
            {a.detail ? <span className="text-muted"> — {a.detail}</span> : null}
          </div>
        </div>
      </div>
      <Endpoint name={a.remote_ip || "—"} ip={a.forwarded_for || undefined} />
      <div className="flex flex-wrap gap-1.5">
        {a.method ? <span className="pill">{a.method}</span> : null}
        {a.path ? <span className="pill">{a.path}</span> : null}
      </div>
      <Endpoint name={a.peer_hostname || "—"} ip={a.overlay_ip || undefined} />
      <div className="whitespace-nowrap">
        {a.status ? (
          <span className={(a.status ?? 0) >= 400 ? "text-bad" : "text-ok"}>{a.status}</span>
        ) : (
          ""
        )}
      </div>
    </div>
  );
}

export function AccessEvent({ a }: { a: AccessLogRow }) {
  return (
    <div className="activity-row">
      <div className="flex min-w-0 gap-2.5">
        <span className={`dot ${a.status >= 400 ? "dot-bad" : "dot-info"}`} />
        <div className="min-w-0">
          <div className="event-time">{formatTime(a.time)}</div>
          <div className="truncate">
            <strong>{a.method}</strong> {a.path}
            {a.user_agent ? <span className="text-muted"> — {a.user_agent}</span> : null}
          </div>
        </div>
      </div>
      <Endpoint name={a.remote_ip || "—"} ip={a.forwarded_for || undefined} />
      <div className="flex flex-wrap gap-1.5">
        <span className="pill">{a.duration_ms}ms</span>
        {a.peer_id ? <span className="pill">peer {a.peer_id}</span> : null}
      </div>
      <Endpoint name={a.overlay_ip || "—"} />
      <div className="whitespace-nowrap">
        <span className={a.status >= 400 ? "text-bad" : "text-ok"}>{a.status}</span>
      </div>
    </div>
  );
}
