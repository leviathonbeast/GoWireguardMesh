import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import type {
  AccessLogRow,
  AclResponse,
  AuditRow,
  Flow,
  LinkStat,
  NetworkConfig,
  NetworkMigrationPlan,
  Peer,
  SetupKey,
} from "./types";

function formatTime(iso?: string): string {
  return iso ? iso.replace("T", " ").replace(/\.\d+Z$/, "Z") : "";
}

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let u = -1;
  do {
    v /= 1024;
    u++;
  } while (v >= 1024 && u < units.length - 1);
  return `${v.toFixed(1)} ${units[u]}`;
}

function peerLabel(hostname: string | undefined, ip: string): string {
  return hostname ? `${hostname} (${ip})` : ip;
}

// copyToClipboard works in secure contexts via the Clipboard API and
// falls back to the legacy execCommand path on plain-HTTP origins,
// where navigator.clipboard does not exist at all.
async function copyToClipboard(text: string): Promise<boolean> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // fall through to the legacy path
    }
  }

  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();

  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }

  ta.remove();
  return ok;
}

function CopyButton({ text }: { text: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");

  const copy = async () => {
    const ok = await copyToClipboard(text);
    setState(ok ? "copied" : "failed");
    setTimeout(() => setState("idle"), 1500);
  };

  return (
    <button className="copy" onClick={() => void copy()}>
      {state === "idle" ? "copy" : state}
    </button>
  );
}

function PeerBadge({ peer }: { peer: Peer }) {
  switch (peer.health_status) {
    case "online":
      return <span className="badge ok">online</span>;
    case "stale":
      return <span className="badge warn">stale</span>;
    case "revoked":
      return <span className="badge bad">revoked</span>;
    case "offline":
      return <span className="badge bad">offline</span>;
    default:
      return <span className="badge warn">unknown</span>;
  }
}

function KeyBadge({ k }: { k: SetupKey }) {
  if (k.revoked_at) return <span className="badge bad">revoked</span>;
  if (k.expires_at && k.expires_at <= new Date().toISOString())
    return <span className="badge warn">expired</span>;
  if (k.max_uses > 0 && k.uses_consumed >= k.max_uses)
    return <span className="badge warn">exhausted</span>;
  return <span className="badge ok">active</span>;
}

function endpointOf(p: Peer): string {
  if (p.public_endpoint) return p.public_endpoint;
  if (p.observed_ip && p.listen_port) return `${p.observed_ip}:${p.listen_port}`;
  return "";
}

function lastSeenLabel(p: Peer): string {
  if (p.revoked_at) return "revoked";
  if (!p.last_seen_at) return "never seen";
  if (p.last_seen_age_seconds == null) return formatTime(p.last_seen_at);
  if (p.last_seen_age_seconds < 60) return `${p.last_seen_age_seconds}s ago`;
  const minutes = Math.floor(p.last_seen_age_seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  return `${Math.floor(minutes / 60)}h ago`;
}

const TABS = ["peers", "traffic", "access", "audit", "admin"] as const;
type Tab = (typeof TABS)[number];

// flowMatches / auditMatches do free-text search across the fields an
// operator would filter on: ip, port, hostname, protocol, direction,
// event, detail. Case-insensitive substring.
function flowMatches(f: Flow, q: string, srcName: string, dstName: string): boolean {
  if (!q) return true;
  const hay = [
    f.src_ip, f.src_port, f.dst_ip, f.dst_port,
    f.protocol_name, f.direction, f.peer_hostname, srcName, dstName,
  ]
    .join(" ")
    .toLowerCase();
  return hay.includes(q.toLowerCase());
}

function auditMatches(a: AuditRow, q: string): boolean {
  if (!q) return true;
  const hay = [
    a.event, a.detail, a.remote_ip, a.overlay_ip, a.peer_hostname,
    a.forwarded_for, a.method, a.path, a.status,
  ]
    .join(" ")
    .toLowerCase();
  return hay.includes(q.toLowerCase());
}

function accessMatches(a: AccessLogRow, q: string): boolean {
  if (!q) return true;
  const hay = [
    a.method, a.path, a.status, a.remote_ip, a.forwarded_for, a.overlay_ip,
    a.peer_id, a.user_agent, Object.entries(a.headers ?? {}).flat().join(" "),
  ]
    .join(" ")
    .toLowerCase();
  return hay.includes(q.toLowerCase());
}

function Endpoint({ name, ip }: { name: string; ip?: string }) {
  return (
    <div>
      <div className="endpoint-name">{name}</div>
      {ip ? <div className="endpoint-ip">{ip}</div> : null}
    </div>
  );
}

// FlowEvent renders one observed flow as a NetBird-style traffic
// event: a sentence, both peer endpoints, protocol/port, and
// directional byte counts from the reporting peer's vantage.
function FlowEvent({ f, ipName }: { f: Flow; ipName: (ip: string) => string }) {
  const srcName = ipName(f.src_ip);
  const dstName = ipName(f.dst_ip);

  const subject = f.direction === "ingress" ? dstName : srcName;
  const other = f.direction === "ingress" ? srcName : dstName;
  const verb = f.direction === "ingress" ? "received a" : "opened a";
  const prep = f.direction === "ingress" ? "from" : "to";

  return (
    <div className="activity-row">
      <div className="event-cell">
        <span className="dot ok" />
        <div>
          <div className="event-time">{formatTime(f.reported_at)}</div>
          <div className="event-text">
            Peer <strong>{subject}</strong> {verb}{" "}
            {f.protocol_name.toUpperCase()} connection {prep} Peer{" "}
            <strong>{other}</strong>
          </div>
        </div>
      </div>
      <Endpoint name={srcName} ip={`${f.src_ip}:${f.src_port}`} />
      <div className="pills">
        <span className="pill">{f.protocol_name.toUpperCase()}</span>
        <span className="pill">{f.dst_port}</span>
      </div>
      <Endpoint name={dstName} ip={`${f.dst_ip}:${f.dst_port}`} />
      <div className="traffic">
        <div>
          <span className="down">↓</span> {humanBytes(f.rx_bytes)}
        </div>
        <div>
          <span className="up">↑</span> {humanBytes(f.tx_bytes)}
        </div>
      </div>
    </div>
  );
}

const ADMIN_EVENTS = new Set([
  "setup_key_create",
  "acl_create",
  "acl_delete",
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
  network_migrate: "changed the overlay network",
  revoke: "revoked",
};

function auditDot(a: AuditRow): string {
  if (a.event.endsWith("rejected") || (a.status ?? 0) >= 400) return "bad";
  if (ADMIN_EVENTS.has(a.event)) return "warn";
  if (a.event.includes("relay")) return "info";
  return "ok";
}

function AuditEvent({ a }: { a: AuditRow }) {
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
      <div className="event-cell">
        <span className={`dot ${auditDot(a)}`} />
        <div>
          <div className="event-time">{formatTime(a.at)}</div>
          <div className="event-text">
            {subject}
            {phrase}
            {a.detail ? <span className="muted"> — {a.detail}</span> : null}
          </div>
        </div>
      </div>
      <Endpoint name={a.remote_ip || "—"} ip={a.forwarded_for || undefined} />
      <div className="pills">
        {a.method ? <span className="pill">{a.method}</span> : null}
        {a.path ? <span className="pill">{a.path}</span> : null}
      </div>
      <Endpoint name={a.peer_hostname || "—"} ip={a.overlay_ip || undefined} />
      <div className="traffic">
        {a.status ? (
          <span className={(a.status ?? 0) >= 400 ? "up" : "down"}>
            {a.status}
          </span>
        ) : (
          ""
        )}
      </div>
    </div>
  );
}

function AccessEvent({ a }: { a: AccessLogRow }) {
  return (
    <div className="activity-row">
      <div className="event-cell">
        <span className={`dot ${a.status >= 400 ? "bad" : "info"}`} />
        <div>
          <div className="event-time">{formatTime(a.time)}</div>
          <div className="event-text">
            <strong>{a.method}</strong> {a.path}
            {a.user_agent ? <span className="muted"> — {a.user_agent}</span> : null}
          </div>
        </div>
      </div>
      <Endpoint name={a.remote_ip || "—"} ip={a.forwarded_for || undefined} />
      <div className="pills">
        <span className="pill">{a.duration_ms}ms</span>
        {a.peer_id ? <span className="pill">peer {a.peer_id}</span> : null}
      </div>
      <Endpoint name={a.overlay_ip || "—"} />
      <div className="traffic">
        <span className={a.status >= 400 ? "up" : "down"}>{a.status}</span>
      </div>
    </div>
  );
}

export default function App() {
  const [token, setToken] = useState(
    () => sessionStorage.getItem("wgmesh-token") ?? "",
  );
  const [tokenInput, setTokenInput] = useState(token);
  const [tab, setTab] = useState<Tab>("peers");
  const [peers, setPeers] = useState<Peer[]>([]);
  const [keys, setKeys] = useState<SetupKey[]>([]);
  const [links, setLinks] = useState<LinkStat[]>([]);
  const [flows, setFlows] = useState<Flow[]>([]);
  const [acl, setAcl] = useState<AclResponse>({ default_policy: "allow", rules: [] });
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [access, setAccess] = useState<AccessLogRow[]>([]);
  const [network, setNetwork] = useState<NetworkConfig>({
    network_cidr: "",
    network_cidr6: "",
  });
  const [networkCIDR, setNetworkCIDR] = useState("");
  const [networkCIDR6, setNetworkCIDR6] = useState("");
  const [networkPlan, setNetworkPlan] = useState<NetworkMigrationPlan | null>(null);
  const [networkConfirm, setNetworkConfirm] = useState("");
  const [filter, setFilter] = useState("");
  const [error, setError] = useState("");

  // ipName resolves an overlay IP to a peer hostname (both sides of a
  // flow get named, like NetBird), falling back to the raw IP.
  const ipName = useCallback(
    (ip: string) =>
      peers.find((p) => p.assigned_ip === ip || p.assigned_ip6 === ip)
        ?.hostname || ip,
    [peers],
  );
  const [maxUses, setMaxUses] = useState(0);
  const [expiresIn, setExpiresIn] = useState("");
  const [aclSrc, setAclSrc] = useState("any");
  const [aclDst, setAclDst] = useState("any");

  const refresh = useCallback(async () => {
    if (!token) return;
    setError("");
    try {
      const [p, k, l, f, a, au, al, n] = await Promise.all([
        api<Peer[]>("/api/peers", token),
        api<SetupKey[]>("/api/setup-keys", token),
        api<LinkStat[]>("/api/link-stats", token),
        api<Flow[]>("/api/flows?limit=100", token),
        api<AclResponse>("/api/acl", token),
        api<AuditRow[]>("/api/audit?limit=200", token),
        api<AccessLogRow[]>("/api/access-log?limit=200", token),
        api<NetworkConfig>("/api/network", token),
      ]);
      setPeers(p);
      setKeys(k);
      setLinks(l);
      setFlows(f);
      setAcl(a);
      setAudit(au);
      setAccess(al);
      setNetwork(n);
      setNetworkCIDR((cur) => cur || n.network_cidr);
      setNetworkCIDR6((cur) => cur || n.network_cidr6);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [token]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const connect = () => {
    const t = tokenInput.trim();
    sessionStorage.setItem("wgmesh-token", t);
    setToken(t);
  };

  const createKey = async () => {
    setError("");
    try {
      await api("/api/setup-keys", token, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ max_uses: maxUses, expires_in: expiresIn.trim() }),
      });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const revoke = async (path: string, prompt: string) => {
    if (!confirm(prompt)) return;
    setError("");
    try {
      await api(path, token, { method: "POST" });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const createAclRule = async () => {
    setError("");
    try {
      await api("/api/acl", token, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          src_peer_id: aclSrc === "any" ? null : parseInt(aclSrc, 10),
          dst_peer_id: aclDst === "any" ? null : parseInt(aclDst, 10),
        }),
      });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const previewNetworkMigration = async () => {
    setError("");
    try {
      const plan = await api<NetworkMigrationPlan>("/api/network/preview", token, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          network_cidr: networkCIDR.trim(),
          network_cidr6: networkCIDR6.trim(),
        }),
      });
      setNetworkPlan(plan);
      setNetworkConfirm("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setNetworkPlan(null);
    }
  };

  const applyNetworkMigration = async () => {
    setError("");
    try {
      const plan = await api<NetworkMigrationPlan>("/api/network/apply", token, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          network_cidr: networkCIDR.trim(),
          network_cidr6: networkCIDR6.trim(),
          confirm: networkConfirm,
        }),
      });
      setNetworkPlan(plan);
      setNetwork(plan.target);
      setNetworkCIDR(plan.target.network_cidr);
      setNetworkCIDR6(plan.target.network_cidr6);
      setNetworkConfirm("");
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="wrap">
      <header className="topbar">
        <h1>
          wgmesh <span>control plane</span>
        </h1>
        <div className="auth row">
          <input
            id="token"
            type="password"
            placeholder="admin token"
            value={tokenInput}
            onChange={(e) => setTokenInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && connect()}
          />
          <button className="primary" onClick={connect}>
            connect
          </button>
          <button onClick={() => void refresh()}>refresh</button>
        </div>
      </header>

      <nav className="tabs">
        {TABS.map((t) => (
          <button
            key={t}
            className={tab === t ? "tab active" : "tab"}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </nav>

      <div className="error">{error}</div>

      {tab === "peers" && (
        <>
          <h2>Registered peers</h2>
          <div className="panel tablewrap">
            <table>
              <thead>
                <tr>
                  <th>id</th>
                  <th>status</th>
                  <th>hostname</th>
                  <th>overlay ip</th>
                  <th>last seen</th>
                  <th>public key</th>
                  <th>endpoint</th>
                  <th>created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {peers.length === 0 && (
                  <tr>
                    <td colSpan={9} className="muted">
                      no peers enrolled
                    </td>
                  </tr>
                )}
                {peers.map((p) => (
                  <tr key={p.id}>
                    <td>{p.id}</td>
                    <td>
                      <PeerBadge peer={p} />
                    </td>
                    <td>{p.hostname ?? ""}</td>
                    <td>
                      {p.assigned_ip}
                      {p.assigned_ip6 && (
                        <div className="muted">{p.assigned_ip6}</div>
                      )}
                    </td>
                    <td className="muted">{lastSeenLabel(p)}</td>
                    <td className="mono">
                      {p.public_key} <CopyButton text={p.public_key} />
                    </td>
                    <td>
                      {endpointOf(p) || <span className="muted">unknown</span>}
                    </td>
                    <td className="muted">{formatTime(p.created_at)}</td>
                    <td>
                      {!p.revoked_at && (
                        <button
                          className="danger"
                          onClick={() =>
                            void revoke(
                              `/api/peers/${p.id}/revoke`,
                              `revoke peer ${p.id} (${p.hostname || p.assigned_ip})?`,
                            )
                          }
                        >
                          revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {tab === "traffic" && (
        <>
          <h2>Liveness</h2>
          <div className="panel tablewrap">
            <table>
              <thead>
                <tr>
                  <th>peer</th>
                  <th>last seen</th>
                </tr>
              </thead>
              <tbody>
                {peers.filter((p) => !p.revoked_at).length === 0 && (
                  <tr>
                    <td colSpan={2} className="muted">
                      no active peers
                    </td>
                  </tr>
                )}
                {peers
                  .filter((p) => !p.revoked_at)
                  .map((p) => (
                    <tr key={p.id}>
                      <td>{peerLabel(p.hostname, p.assigned_ip)}</td>
                      <td className="muted">
                        {formatTime(p.last_seen_at) || "never"}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>

          <h2>Links</h2>
          <div className="panel tablewrap">
            <table>
              <thead>
                <tr>
                  <th>reporter</th>
                  <th>remote</th>
                  <th>rx</th>
                  <th>tx</th>
                  <th>last handshake</th>
                  <th>updated</th>
                </tr>
              </thead>
              <tbody>
                {links.length === 0 && (
                  <tr>
                    <td colSpan={6} className="muted">
                      no reports yet
                    </td>
                  </tr>
                )}
                {links.map((l) => (
                  <tr key={`${l.peer_id}-${l.remote_peer_id}`}>
                    <td>{peerLabel(l.peer_hostname, l.peer_ip)}</td>
                    <td>{peerLabel(l.remote_hostname, l.remote_ip)}</td>
                    <td>{humanBytes(l.rx_bytes)}</td>
                    <td>{humanBytes(l.tx_bytes)}</td>
                    <td className="muted">
                      {formatTime(l.last_handshake_at) || "never"}
                    </td>
                    <td className="muted">{formatTime(l.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="row" style={{ justifyContent: "space-between" }}>
            <h2 style={{ margin: 0 }}>Traffic events</h2>
            <input
              type="search"
              placeholder="filter by ip, port, hostname, protocol…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              style={{ width: 320 }}
            />
          </div>
          <div className="panel tablewrap" style={{ marginTop: 12 }}>
            <div className="activity">
              <div className="activity-head">
                <span>event</span>
                <span>source</span>
                <span>protocol &amp; port</span>
                <span>destination</span>
                <span className="right">traffic</span>
              </div>
              {(() => {
                const shown = flows.filter((f) =>
                  flowMatches(f, filter, ipName(f.src_ip), ipName(f.dst_ip)),
                );
                if (shown.length === 0)
                  return (
                    <div className="activity-row muted">
                      {flows.length ? "no matching flows" : "no flows recorded"}
                    </div>
                  );
                return shown.map((f) => (
                  <FlowEvent key={f.id} f={f} ipName={ipName} />
                ));
              })()}
            </div>
          </div>
        </>
      )}

      {tab === "audit" && (
        <>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <h2 style={{ margin: 0 }}>Activity log</h2>
            <input
              type="search"
              placeholder="filter by event, ip, hostname, path…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              style={{ width: 320 }}
            />
          </div>
          <p className="sub">
            security events — enrollment, revocation, ACL and key changes, relay
            sessions, and auth failures. Full request tracing is available in the
            Access tab when the server runs with the default in-memory access log.
          </p>
          <div className="panel tablewrap">
            <div className="activity">
              <div className="activity-head">
                <span>event</span>
                <span>source</span>
                <span>request</span>
                <span>peer</span>
                <span className="right">status</span>
              </div>
              {(() => {
                const shown = audit.filter((a) => auditMatches(a, filter));
                if (shown.length === 0)
                  return (
                    <div className="activity-row muted">
                      {audit.length ? "no matching events" : "no activity yet"}
                    </div>
                  );
                return shown.map((a) => <AuditEvent key={a.id} a={a} />);
              })()}
            </div>
          </div>
        </>
      )}

      {tab === "access" && (
        <>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <h2 style={{ margin: 0 }}>Request log</h2>
            <input
              type="search"
              placeholder="filter by method, path, ip, status…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              style={{ width: 320 }}
            />
          </div>
          <div className="panel tablewrap">
            <div className="activity">
              <div className="activity-head">
                <span>request</span>
                <span>source</span>
                <span>trace</span>
                <span>peer</span>
                <span className="right">status</span>
              </div>
              {(() => {
                const shown = access.filter((a) => accessMatches(a, filter));
                if (shown.length === 0)
                  return (
                    <div className="activity-row muted">
                      {access.length ? "no matching requests" : "no request log entries"}
                    </div>
                  );
                return shown.map((a, i) => <AccessEvent key={`${a.time}-${i}`} a={a} />);
              })()}
            </div>
          </div>
        </>
      )}

      {tab === "admin" && (
        <>
          <h2>Overlay network</h2>
          <div className="panel stack">
            <div className="metric-grid">
              <div className="metric">
                <div className="metric-label">current IPv4</div>
                <div className="metric-value">{network.network_cidr || "unknown"}</div>
              </div>
              <div className="metric">
                <div className="metric-label">current IPv6</div>
                <div className="metric-value">{network.network_cidr6 || "unknown"}</div>
              </div>
              <div className="metric">
                <div className="metric-label">active peers</div>
                <div className="metric-value">
                  {peers.filter((p) => !p.revoked_at).length}
                </div>
              </div>
              <div className="metric">
                <div className="metric-label">total assignments</div>
                <div className="metric-value">{peers.length}</div>
              </div>
            </div>

            <div className="notice warn">
              Changing the overlay network reassigns every peer. Running agents
              adopt the new interface address from their next report response;
              restarting an agent also re-enrolls it onto the new assignment.
            </div>

            <div className="form-grid">
              <label>
                <span>IPv4 CIDR</span>
                <input
                  value={networkCIDR}
                  placeholder="100.64.0.0/16"
                  onChange={(e) => {
                    setNetworkCIDR(e.target.value);
                    setNetworkPlan(null);
                  }}
                />
              </label>
              <label>
                <span>IPv6 CIDR</span>
                <input
                  value={networkCIDR6}
                  placeholder="fd00:100:64::/64"
                  onChange={(e) => {
                    setNetworkCIDR6(e.target.value);
                    setNetworkPlan(null);
                  }}
                />
              </label>
              <div className="form-actions">
                <button className="primary" onClick={() => void previewNetworkMigration()}>
                  preview changes
                </button>
              </div>
            </div>

            {networkPlan && (
              <div className="stack">
                <div className="notice">
                  {networkPlan.message ||
                    "Preview ready. Review the reassignment plan before applying."}
                </div>
                <div className="tablewrap">
                  <table>
                    <thead>
                      <tr>
                        <th>peer</th>
                        <th>IPv4</th>
                        <th>IPv6</th>
                        <th>status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {networkPlan.changes.length === 0 && (
                        <tr>
                          <td colSpan={4} className="muted">
                            no peers to reassign
                          </td>
                        </tr>
                      )}
                      {networkPlan.changes.map((c) => (
                        <tr key={c.id}>
                          <td>{c.hostname || `peer ${c.id}`}</td>
                          <td>
                            <span className="muted">{c.old_ip}</span>
                            <div>{c.new_ip}</div>
                          </td>
                          <td>
                            <span className="muted">{c.old_ip6 || "none"}</span>
                            <div>{c.new_ip6}</div>
                          </td>
                          <td>
                            {c.revoked_at ? (
                              <span className="badge bad">revoked</span>
                            ) : (
                              <span className="badge warn">will move</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="confirm-box">
                  <label>
                    <span>type REASSIGN OVERLAY NETWORK to apply</span>
                    <input
                      value={networkConfirm}
                      onChange={(e) => setNetworkConfirm(e.target.value)}
                    />
                  </label>
                  <button
                    className="danger"
                    disabled={networkConfirm !== "REASSIGN OVERLAY NETWORK"}
                    onClick={() => void applyNetworkMigration()}
                  >
                    apply network migration
                  </button>
                </div>
              </div>
            )}
          </div>

          <h2>ACL rules</h2>
          <div className="panel">
            <p className="muted" style={{ marginTop: 0 }}>
              default policy: <strong>{acl.default_policy}</strong>
              {acl.default_policy === "allow"
                ? " — every peer sees every peer; rules below have no effect until the server runs with --default-policy deny"
                : " — peers only see each other when a rule below connects them (bidirectional; \"any\" is a wildcard)"}
            </p>
            <div className="row">
              <select value={aclSrc} onChange={(e) => setAclSrc(e.target.value)}>
                <option value="any">any</option>
                {peers
                  .filter((p) => !p.revoked_at)
                  .map((p) => (
                    <option key={p.id} value={p.id}>
                      {peerLabel(p.hostname, p.assigned_ip)}
                    </option>
                  ))}
              </select>
              <span className="muted">↔</span>
              <select value={aclDst} onChange={(e) => setAclDst(e.target.value)}>
                <option value="any">any</option>
                {peers
                  .filter((p) => !p.revoked_at)
                  .map((p) => (
                    <option key={p.id} value={p.id}>
                      {peerLabel(p.hostname, p.assigned_ip)}
                    </option>
                  ))}
              </select>
              <button className="primary" onClick={() => void createAclRule()}>
                add rule
              </button>
            </div>
            <div className="tablewrap">
              <table>
                <thead>
                  <tr>
                    <th>id</th>
                    <th>src</th>
                    <th>dst</th>
                    <th>created</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {acl.rules.length === 0 && (
                    <tr>
                      <td colSpan={5} className="muted">
                        no rules
                      </td>
                    </tr>
                  )}
                  {acl.rules.map((r) => (
                    <tr key={r.id}>
                      <td>{r.id}</td>
                      <td>{r.src_label}</td>
                      <td>{r.dst_label}</td>
                      <td className="muted">{formatTime(r.created_at)}</td>
                      <td>
                        <button
                          className="danger"
                          onClick={() =>
                            void revoke(
                              `/api/acl/${r.id}/delete`,
                              `delete ACL rule ${r.id} (${r.src_label} ↔ ${r.dst_label})?`,
                            )
                          }
                        >
                          delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <h2>Setup keys</h2>
          <div className="panel">
            <div className="row">
              <label htmlFor="maxUses">max uses (0 = unlimited)</label>
              <input
                id="maxUses"
                type="number"
                min={0}
                style={{ width: 70 }}
                value={maxUses}
                onChange={(e) => setMaxUses(parseInt(e.target.value, 10) || 0)}
              />
              <label htmlFor="expiresIn">expires in (e.g. 24h, blank = never)</label>
              <input
                id="expiresIn"
                type="text"
                size={8}
                placeholder="never"
                value={expiresIn}
                onChange={(e) => setExpiresIn(e.target.value)}
              />
              <button className="primary" onClick={() => void createKey()}>
                new setup key
              </button>
            </div>
            <div className="tablewrap">
              <table>
                <thead>
                  <tr>
                    <th>id</th>
                    <th>status</th>
                    <th>key</th>
                    <th>uses</th>
                    <th>expires</th>
                    <th>created</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {keys.length === 0 && (
                    <tr>
                      <td colSpan={7} className="muted">
                        no setup keys
                      </td>
                    </tr>
                  )}
                  {keys.map((k) => (
                    <tr key={k.id}>
                      <td>{k.id}</td>
                      <td>
                        <KeyBadge k={k} />
                      </td>
                      <td className="mono">
                        {k.key} <CopyButton text={k.key} />
                      </td>
                      <td>
                        {k.uses_consumed}/{k.max_uses > 0 ? k.max_uses : "∞"}
                      </td>
                      <td className="muted">
                        {formatTime(k.expires_at) || "never"}
                      </td>
                      <td className="muted">{formatTime(k.created_at)}</td>
                      <td>
                        {!k.revoked_at && (
                          <button
                            className="danger"
                            onClick={() =>
                              void revoke(
                                `/api/setup-keys/${k.id}/revoke`,
                                `revoke setup key ${k.id}?`,
                              )
                            }
                          >
                            revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
