import { Fragment, useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { ApiError, api } from "./api";
import type {
  AccessLogRow,
  AclExport,
  AclRule,
  AclResponse,
  AuditRow,
  DNSConfig,
  Flow,
  LinkStat,
  NetworkConfig,
  NetworkPeerChange,
  NetworkMigrationPlan,
  Peer,
  SetupKey,
} from "./types";

const LONDON_TIME_FORMAT = new Intl.DateTimeFormat("en-GB", {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
  timeZone: "Europe/London",
  timeZoneName: "short",
});

function formatTime(iso?: string): string {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;

  const parts = LONDON_TIME_FORMAT.formatToParts(date).reduce<Record<string, string>>((acc, part) => {
    if (part.type !== "literal") acc[part.type] = part.value;
    return acc;
  }, {});
  const tz = parts.timeZoneName ? ` ${parts.timeZoneName}` : "";
  return `${parts.day}/${parts.month}/${parts.year} ${parts.hour}:${parts.minute}:${parts.second}${tz}`;
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

function parseListInput(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((v) => v.trim())
    .filter(Boolean);
}

function splitNameservers(nameservers: string[] = []): { v4: string[]; v6: string[] } {
  return nameservers.reduce(
    (acc, ns) => {
      if (ns.includes(":")) acc.v6.push(ns);
      else acc.v4.push(ns);
      return acc;
    },
    { v4: [] as string[], v6: [] as string[] },
  );
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
  const status = setupKeyStatus(k);
  if (status === "revoked") return <span className="badge bad">revoked</span>;
  if (status === "expired") return <span className="badge warn">expired</span>;
  if (status === "exhausted") return <span className="badge warn">exhausted</span>;
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

function PathBadge({ state }: { state?: LinkStat["path_state"] }) {
  switch (state) {
    case "direct":
      return <span className="badge ok">direct</span>;
    case "probing-direct":
      return <span className="badge warn">probing-direct</span>;
    case "ws-relay":
      return <span className="badge warn">ws-relay</span>;
    case "udp-relay":
      return <span className="badge warn">udp-relay</span>;
    default:
      return <span className="badge bad">unknown</span>;
  }
}


const TABS = ["overview", "machines", "traffic", "policies", "setup", "logs", "proxy", "settings"] as const;
type Tab = (typeof TABS)[number];
const DEFAULT_PAGE_SIZE = 10;
const PAGE_SIZE_OPTIONS = [10, 25, 50, 100] as const;

const TAB_LABEL: Record<Tab, string> = {
  overview: "Overview",
  machines: "Peers",
  traffic: "Traffic Events",
  policies: "Policies",
  setup: "Setup keys",
  logs: "Audit Events",
  proxy: "Proxy Events",
  settings: "Settings",
};

// Sidebar layout: most tabs are top-level; the activity views (audit,
// traffic, proxy) are grouped under a collapsible "Activity" section.
const TOP_TABS: Tab[] = ["overview", "machines", "policies", "setup"];
const ACTIVITY_TABS: Tab[] = ["logs", "traffic", "proxy"];

function textMatches(q: string, ...parts: unknown[]): boolean {
  const terms = q.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const hay = parts
    .flatMap((part) => Array.isArray(part) ? part : [part])
    .filter((part) => part != null)
    .join(" ")
    .toLowerCase();
  return terms.every((term) => hay.includes(term));
}

// flowMatches / auditMatches do free-text search across the fields an
// operator would filter on: ip, port, hostname, protocol, direction,
// event, detail. Multiple terms are ANDed together.
function flowMatches(f: Flow, q: string, srcName: string, dstName: string): boolean {
  return textMatches(
    q,
    f.src_ip, f.src_port, f.dst_ip, f.dst_port,
    f.protocol_name, f.direction, f.peer_hostname, srcName, dstName,
  );
}

function auditMatches(a: AuditRow, q: string): boolean {
  return textMatches(
    q,
    a.event, a.detail, a.remote_ip, a.overlay_ip, a.peer_hostname,
    a.forwarded_for, a.method, a.path, a.status,
  );
}

function accessMatches(a: AccessLogRow, q: string): boolean {
  return textMatches(
    q,
    a.method, a.path, a.status, a.remote_ip, a.forwarded_for, a.overlay_ip,
    a.peer_id, a.user_agent, Object.entries(a.headers ?? {}).flat().join(" "),
  );
}

function peerMatches(p: Peer, q: string): boolean {
  return textMatches(
    q,
    p.id, p.hostname, p.assigned_ip, p.assigned_ip6, p.health_status,
    p.public_key, p.public_endpoint, p.observed_ip, p.listen_port,
    lastSeenLabel(p), p.created_at, p.revoked_at,
  );
}

function linkMatches(l: LinkStat, q: string): boolean {
  return textMatches(
    q,
    l.peer_hostname, l.peer_ip, l.remote_hostname, l.remote_ip,
    l.path_state, l.path_endpoint, l.rx_bytes, l.tx_bytes,
    l.last_handshake_at, l.updated_at,
  );
}

function aclMatches(rule: AclRule, q: string): boolean {
  return textMatches(
    q,
    rule.id, rule.name, rule.src_label, rule.dst_label,
    rule.protocol, rule.port_min, rule.port_max, serviceLabel(rule), rule.created_at,
  );
}

function setupKeyMatches(key: SetupKey, q: string): boolean {
  return textMatches(
    q,
    key.id, key.name, key.key, key.max_uses, key.uses_consumed,
    setupKeyStatus(key), key.created_at, key.expires_at, key.revoked_at,
  );
}

function setupKeyStatus(k: SetupKey): "active" | "revoked" | "expired" | "exhausted" {
  if (k.revoked_at) return "revoked";
  if (k.expires_at && k.expires_at <= new Date().toISOString()) return "expired";
  if (k.max_uses > 0 && k.uses_consumed >= k.max_uses) return "exhausted";
  return "active";
}

function migrationChangeMatches(change: NetworkPeerChange, q: string): boolean {
  return textMatches(
    q,
    change.id, change.hostname, change.old_ip, change.new_ip,
    change.old_ip6, change.new_ip6, change.revoked_at,
  );
}

function Endpoint({ name, ip }: { name: string; ip?: string }) {
  return (
    <div>
      <div className="endpoint-name">{name}</div>
      {ip ? <div className="endpoint-ip">{ip}</div> : null}
    </div>
  );
}

function serviceLabel(rule: { protocol: string; port_min?: number; port_max?: number }): string {
  const proto = (rule.protocol || "any").toUpperCase();
  if (!rule.port_min) return proto;
  if (rule.port_max && rule.port_max !== rule.port_min) {
    return `${proto} ${rule.port_min}-${rule.port_max}`;
  }
  return `${proto} ${rule.port_min}`;
}

function PaginationControls({
  page,
  pageSize,
  setPageSize,
  setPage,
  total,
}: {
  page: number;
  pageSize: number;
  setPageSize: (pageSize: number) => void;
  setPage: (fn: (page: number) => number) => void;
  total: number;
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.min(page, totalPages);
  const start = (currentPage - 1) * pageSize;

  return (
    <div className="pagination">
      <div className="muted">
        {start + 1}-{Math.min(start + pageSize, total)} of {total}
      </div>
      <label className="page-size">
        <span>Rows</span>
        <select
          value={pageSize}
          onChange={(e) => setPageSize(parseInt(e.target.value, 10))}
        >
          {PAGE_SIZE_OPTIONS.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </label>
      <button
        disabled={currentPage <= 1}
        onClick={() => setPage((p) => Math.max(1, p - 1))}
      >
        previous
      </button>
      <span className="muted">page {currentPage} of {totalPages}</span>
      <button
        disabled={currentPage >= totalPages}
        onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
      >
        next
      </button>
    </div>
  );
}

function Paginated<T>({
  items,
  resetKey,
  children,
}: {
  items: T[];
  resetKey?: unknown;
  children: (pageItems: T[], pager: ReactNode) => ReactNode;
}) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);

  useEffect(() => {
    setPage(1);
  }, [items.length, pageSize, resetKey]);

  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const start = (currentPage - 1) * pageSize;
  const pageItems = items.slice(start, start + pageSize);
  const pager =
    items.length > DEFAULT_PAGE_SIZE ? (
      <PaginationControls
        page={currentPage}
        pageSize={pageSize}
        setPage={setPage}
        setPageSize={setPageSize}
        total={items.length}
      />
    ) : null;

  return <>{children(pageItems, pager)}</>;
}

function SearchBox({
  value,
  onChange,
  placeholder,
  total,
  shown,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  total: number;
  shown: number;
}) {
  const active = value.trim() !== "";

  return (
    <div className="searchbox">
      <input
        type="search"
        placeholder={placeholder}
        value={value}
        aria-label={placeholder}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Escape") onChange("");
        }}
      />
      {active && (
        <button className="ghost" onClick={() => onChange("")}>
          clear
        </button>
      )}
      <span className="muted">
        {active ? `${shown} of ${total}` : `${total} total`}
      </span>
    </div>
  );
}

type ConfirmAction = {
  title: string;
  message: string;
  confirmLabel?: string;
  danger?: boolean;
  onConfirm: () => Promise<void> | void;
};

function ConfirmModal({
  action,
  busy,
  onCancel,
  onConfirm,
}: {
  action: ConfirmAction;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="modal-backdrop" role="presentation">
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
        <h2 id="confirm-title">{action.title}</h2>
        <p>{action.message}</p>
        <div className="modal-actions">
          <button disabled={busy} onClick={onCancel}>
            no
          </button>
          <button
            className={action.danger ? "danger" : "primary"}
            disabled={busy}
            onClick={onConfirm}
          >
            {busy ? "working" : action.confirmLabel || "yes"}
          </button>
        </div>
      </div>
    </div>
  );
}

type ProxyEvent = {
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
};

type ConnectionEvent = {
  id: number;
  at: string;
  kind: string; // "direct" | "relay"
  from_state?: string;
  to_state: string;
  reporter_peer_id: number;
  reporter_hostname?: string;
  remote_peer_id: number;
  remote_hostname?: string;
};

// ConnectionEventRow renders one peer-to-peer connection lifecycle event
// (a direct/P2P connection established, or a relay fallback), NetBird-style.
function ConnectionEventRow({ e }: { e: ConnectionEvent }) {
  const reporter = e.reporter_hostname || `peer ${e.reporter_peer_id}`;
  const remote = e.remote_hostname || `peer ${e.remote_peer_id}`;
  const direct = e.kind === "direct";

  return (
    <div className="activity-row">
      <div className="event-cell">
        <span className={`dot ${direct ? "ok" : "warn"}`} />
        <div>
          <div className="event-time">{formatTime(e.at)}</div>
          <div className="event-text">
            Peer <strong>{reporter}</strong>{" "}
            {direct ? "established a direct (P2P) connection to" : "connected over relay to"}{" "}
            Peer <strong>{remote}</strong>
          </div>
        </div>
      </div>
      <div className="pills">
        <span className={`pill ${direct ? "pill-p2p" : "pill-relay"}`}>{direct ? "P2P" : "RELAY"}</span>
        <span className="pill">{e.to_state}</span>
      </div>
    </div>
  );
}

// StatusPill colors an HTTP status code green/neutral/amber/red.
function StatusPill({ status }: { status?: number }) {
  if (!status) return <span className="pill">-</span>;
  const cls = status >= 500 ? "pill-bad" : status >= 400 ? "pill-warn" : status >= 300 ? "" : "pill-ok";
  return <span className={`pill ${cls}`}>{status}</span>;
}

function formatDuration(ms?: number): string {
  if (!ms) return "-";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function proxyRequest(e: ProxyEvent): string {
  return `${e.host || ""}${e.path || ""}` || "-";
}

function proxyMatches(e: ProxyEvent, q: string): boolean {
  return textMatches(q, e.method, e.host, e.path, e.status, e.client_ip, e.peer_hostname, e.service);
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
      <Endpoint name={srcName} ip={f.src_port ? `${f.src_ip}:${f.src_port}` : f.src_ip} />
      <div className="pills">
        <span className="pill">{f.protocol_name.toUpperCase()}</span>
        {f.dst_port ? <span className="pill">{f.dst_port}</span> : null}
      </div>
      <Endpoint name={dstName} ip={f.dst_port ? `${f.dst_ip}:${f.dst_port}` : f.dst_ip} />
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
  const [authenticated, setAuthenticated] = useState(false);
  const [authChecking, setAuthChecking] = useState(false);
  const [sessionChecked, setSessionChecked] = useState(false);
  const [tab, setTab] = useState<Tab>("overview");
  const [peers, setPeers] = useState<Peer[]>([]);
  const [keys, setKeys] = useState<SetupKey[]>([]);
  const [links, setLinks] = useState<LinkStat[]>([]);
  const [flows, setFlows] = useState<Flow[]>([]);
  const [connEvents, setConnEvents] = useState<ConnectionEvent[]>([]);
  const [proxyEvents, setProxyEvents] = useState<ProxyEvent[]>([]);
  const [proxyFilter, setProxyFilter] = useState("");
  const [activityOpen, setActivityOpen] = useState(true);
  const [acl, setAcl] = useState<AclResponse>({ default_policy: "allow", rules: [] });
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [access, setAccess] = useState<AccessLogRow[]>([]);
  const [network, setNetwork] = useState<NetworkConfig>({
    network_cidr: "",
    network_cidr6: "",
  });
  const [dns, setDNS] = useState<DNSConfig>({
    enabled: false,
    magic_dns: true,
    domain: "vpn",
    nameservers: [],
    search_domains: ["vpn"],
  });
  const [networkCIDR, setNetworkCIDR] = useState("");
  const [networkCIDR6, setNetworkCIDR6] = useState("");
  const [networkPlan, setNetworkPlan] = useState<NetworkMigrationPlan | null>(null);
  const [networkConfirm, setNetworkConfirm] = useState("");
  const [dnsEnabled, setDNSEnabled] = useState(false);
  const [dnsMagic, setDNSMagic] = useState(true);
  const [dnsDomain, setDNSDomain] = useState("vpn");
  const [dnsNameservers4, setDNSNameservers4] = useState("");
  const [dnsNameservers6, setDNSNameservers6] = useState("");
  const [dnsSearchDomains, setDNSSearchDomains] = useState("vpn");
  const [dnsDirty, setDNSDirty] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [machineFilter, setMachineFilter] = useState("");
  const [selectedPeerID, setSelectedPeerID] = useState<number | null>(null);
  const [trafficFilter, setTrafficFilter] = useState("");
  const [auditFilter, setAuditFilter] = useState("");
  const [accessFilter, setAccessFilter] = useState("");
  const [aclFilter, setAclFilter] = useState("");
  const [aclImportReplace, setAclImportReplace] = useState(true);
  const [aclImporting, setAclImporting] = useState(false);
  const [setupFilter, setSetupFilter] = useState("");
  const [migrationFilter, setMigrationFilter] = useState("");
  const [editingPeerID, setEditingPeerID] = useState<number | null>(null);
  const [peerIP, setPeerIP] = useState("");
  const [peerIP6, setPeerIP6] = useState("");
  const [savingPeerID, setSavingPeerID] = useState<number | null>(null);
  const [confirmAction, setConfirmAction] = useState<ConfirmAction | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const [toast, setToast] = useState("");
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
  const [setupName, setSetupName] = useState("");
  const [aclSrc, setAclSrc] = useState("any");
  const [aclDst, setAclDst] = useState("any");
  const [aclName, setAclName] = useState("");
  const [aclProtocol, setAclProtocol] = useState("any");
  const [aclPortMin, setAclPortMin] = useState("");
  const [aclPortMax, setAclPortMax] = useState("");

  const loadDashboard = useCallback(async (authToken: string) => {
    const [p, k, l, f, a, au, al, n, d, ce, pe] = await Promise.all([
      api<Peer[]>("/api/peers", authToken),
      api<SetupKey[]>("/api/setup-keys", authToken),
      api<LinkStat[]>("/api/link-stats", authToken),
      api<Flow[]>("/api/flows?limit=1000", authToken),
      api<AclResponse>("/api/acl", authToken),
      api<AuditRow[]>("/api/audit?limit=1000", authToken),
      api<AccessLogRow[]>("/api/access-log?limit=1000", authToken),
      api<NetworkConfig>("/api/network", authToken),
      api<DNSConfig>("/api/dns", authToken),
      api<ConnectionEvent[]>("/api/connection-events?limit=1000", authToken),
      api<ProxyEvent[]>("/api/proxy-events?limit=1000", authToken),
    ]);
    setPeers(p);
    setKeys(k);
    setLinks(l);
    setFlows(f);
    setAcl(a);
    setAudit(au);
    setAccess(al);
    setNetwork(n);
    setDNS(d);
    setConnEvents(ce);
    setProxyEvents(pe);
    setNetworkCIDR((cur) => cur || n.network_cidr);
    setNetworkCIDR6((cur) => cur || n.network_cidr6);
    if (!dnsDirty) {
      setDNSEnabled(d.enabled);
      setDNSMagic(d.magic_dns);
      setDNSDomain(d.domain || "vpn");
      const nameservers = splitNameservers(d.nameservers);
      setDNSNameservers4(nameservers.v4.join("\n"));
      setDNSNameservers6(nameservers.v6.join("\n"));
      setDNSSearchDomains((d.search_domains || []).join("\n"));
    }
  }, [dnsDirty]);

  const lockAdminUI = useCallback((message?: string) => {
    sessionStorage.removeItem("wgmesh-token");
    setToken("");
    setAuthenticated(false);
    setSessionChecked(true);
    setPeers([]);
    setKeys([]);
    setLinks([]);
    setFlows([]);
    setConnEvents([]);
    setProxyEvents([]);
    setAudit([]);
    setAccess([]);
    setDNS({ enabled: false, magic_dns: true, domain: "vpn", nameservers: [], search_domains: ["vpn"] });
    setDNSDirty(false);
    setError(message ?? "");
  }, []);

  const refresh = useCallback(async () => {
    if (!authenticated) return;
    setError("");
    try {
      await loadDashboard(token);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        lockAdminUI("admin token rejected");
        return;
      }
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [authenticated, loadDashboard, lockAdminUI, token]);

  useEffect(() => {
    if (authenticated || sessionChecked) return;

    let cancelled = false;
    setAuthChecking(true);
    setError("");
    void loadDashboard(token)
      .then(() => {
        if (cancelled) return;
        setAuthenticated(true);
      })
      .catch(() => {
        if (cancelled) return;
        lockAdminUI(token ? "admin token rejected" : "");
      })
      .finally(() => {
        if (!cancelled) {
          setSessionChecked(true);
          setAuthChecking(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [authenticated, loadDashboard, lockAdminUI, sessionChecked, token]);

  useEffect(() => {
    if (!authenticated || !autoRefresh) return;

    const id = window.setInterval(() => {
      void refresh();
    }, 5000);

    return () => window.clearInterval(id);
  }, [authenticated, autoRefresh, refresh]);

  useEffect(() => {
    if (!toast) return;

    const id = window.setTimeout(() => setToast(""), 3200);
    return () => window.clearTimeout(id);
  }, [toast]);

  useEffect(() => {
    if (selectedPeerID == null) return;
    if (!peers.some((p) => p.id === selectedPeerID)) setSelectedPeerID(null);
  }, [peers, selectedPeerID]);

  const refreshUISession = async (adminToken: string) => {
    const body = new URLSearchParams();
    body.set("token", adminToken);
    await fetch("/ui-login", {
      method: "POST",
      body,
      credentials: "same-origin",
    });
  };

  const connect = async () => {
    const t = tokenInput.trim();
    if (!t) {
      lockAdminUI("admin token required");
      return;
    }

    setAuthChecking(true);
    setError("");
    try {
      await loadDashboard(t);
      await refreshUISession(t);
      sessionStorage.setItem("wgmesh-token", t);
      setToken(t);
      setAuthenticated(true);
      setSessionChecked(true);
    } catch (e) {
      sessionStorage.removeItem("wgmesh-token");
      setToken("");
      setAuthenticated(false);
      if (e instanceof ApiError && e.status === 401) {
        setError("admin token rejected");
      } else {
        setError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      setAuthChecking(false);
    }
  };

  const signIn = (
    <div className="login-shell">
      <div className="login-panel">
        <div className="brand login-brand">
          <div className="brand-mark">wg</div>
          <div>
            <div className="brand-name">wgmesh</div>
            <div className="brand-sub">control plane</div>
          </div>
        </div>
        <div className="login-form">
          <label htmlFor="token">
            <span>Admin token</span>
            <input
              id="token"
              type="password"
              autoFocus
              placeholder="paste admin token"
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void connect()}
            />
          </label>
          <button className="primary" disabled={authChecking} onClick={() => void connect()}>
            {authChecking ? "checking" : "connect"}
          </button>
        </div>
        <div className="error">{error}</div>
      </div>
    </div>
  );

  if (!authenticated) {
    return signIn;
  }

  const createKey = async () => {
    setError("");
    try {
      await api("/api/setup-keys", token, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: setupName.trim(),
          max_uses: maxUses,
          expires_in: expiresIn.trim(),
        }),
      });
      setSetupName("");
      await refresh();
      showToast("Setup key created");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const showToast = (message: string) => {
    setToast(message);
  };

  const runConfirmAction = async () => {
    if (!confirmAction) return;

    setConfirmBusy(true);
    setError("");
    try {
      await confirmAction.onConfirm();
      setConfirmAction(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setConfirmBusy(false);
    }
  };

  const postAdminAction = async (path: string, success: string) => {
    setError("");
    await api(path, token, { method: "POST" });
    await refresh();
    showToast(success);
  };

  const confirmPost = (action: ConfirmAction) => {
    setConfirmAction(action);
  };

  const startPeerAddressEdit = (p: Peer) => {
    setEditingPeerID(p.id);
    setPeerIP(p.assigned_ip);
    setPeerIP6(p.assigned_ip6 || "");
    setError("");
  };

  const cancelPeerAddressEdit = () => {
    setEditingPeerID(null);
    setPeerIP("");
    setPeerIP6("");
  };

  const savePeerAddress = async (p: Peer) => {
    setError("");
    setSavingPeerID(p.id);
    try {
      const updated = await api<Peer>(`/api/peers/${p.id}/address`, token, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          assigned_ip: peerIP.trim(),
          assigned_ip6: peerIP6.trim(),
        }),
      });
      setPeers((current) =>
        current.map((peer) => (peer.id === updated.id ? updated : peer)),
      );
      cancelPeerAddressEdit();
      showToast("Peer address updated");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSavingPeerID(null);
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
          name: aclName.trim(),
          protocol: aclProtocol,
          port_min: aclPortMin.trim() ? parseInt(aclPortMin, 10) : null,
          port_max: aclPortMax.trim() ? parseInt(aclPortMax, 10) : null,
        }),
      });
      setAclName("");
      setAclPortMin("");
      setAclPortMax("");
      await refresh();
      showToast("ACL rule added");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const exportAcl = async () => {
    setError("");
    try {
      const payload = await api<AclExport>("/api/acl/export", token);
      const blob = new Blob([JSON.stringify(payload, null, 2) + "\n"], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `wgmesh-acl-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      showToast("ACL export downloaded");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const importAcl = async (file: File | null) => {
    if (!file) return;

    if (aclImportReplace) {
      setConfirmAction({
        title: "Import ACL rules?",
        message: "This will replace all existing ACL rules with the selected file.",
        confirmLabel: "import",
        danger: true,
        onConfirm: () => importAclFile(file),
      });
      return;
    }

    await importAclFile(file);
  };

  const importAclFile = async (file: File) => {
    setError("");
    setAclImporting(true);
    try {
      const parsed = JSON.parse(await file.text()) as unknown;
      const rules = Array.isArray(parsed)
        ? parsed
        : typeof parsed === "object" && parsed !== null && "rules" in parsed
          ? (parsed as { rules?: unknown }).rules
          : null;
      if (!Array.isArray(rules)) {
        throw new Error("ACL import file must contain a rules array");
      }

      const next = await api<AclResponse>("/api/acl/import", token, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          replace: aclImportReplace,
          rules,
        }),
      });
      setAcl(next);
      setAclFilter("");
      showToast(aclImportReplace ? "ACL rules replaced" : "ACL rules imported");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setAclImporting(false);
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
      showToast("Migration preview ready");
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
      showToast("Overlay network updated");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const saveDNSSettings = async () => {
    setError("");
    try {
      const next = await api<DNSConfig>("/api/dns", token, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled: dnsEnabled,
          magic_dns: dnsMagic,
          domain: dnsDomain.trim(),
          nameservers: [
            ...parseListInput(dnsNameservers4),
            ...parseListInput(dnsNameservers6),
          ],
          search_domains: parseListInput(dnsSearchDomains),
        }),
      });
      setDNS(next);
      setDNSEnabled(next.enabled);
      setDNSMagic(next.magic_dns);
      setDNSDomain(next.domain || "vpn");
      const nameservers = splitNameservers(next.nameservers);
      setDNSNameservers4(nameservers.v4.join("\n"));
      setDNSNameservers6(nameservers.v6.join("\n"));
      setDNSSearchDomains((next.search_domains || []).join("\n"));
      setDNSDirty(false);
      showToast("DNS settings updated");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const activePeers = peers.filter((p) => !p.revoked_at);
  const onlinePeers = activePeers.filter((p) => p.health_status === "online");
  const relayedLinks = links.filter((l) => l.path_state === "ws-relay" || l.path_state === "udp-relay");
  const directLinks = links.filter((l) => l.path_state === "direct");
  const activeKeys = keys.filter((k) => !k.revoked_at && !(k.max_uses > 0 && k.uses_consumed >= k.max_uses));
  const shownPeers = peers.filter((p) => peerMatches(p, machineFilter));
  const shownActivePeers = activePeers.filter((p) => peerMatches(p, trafficFilter));
  const shownLinks = links.filter((l) => linkMatches(l, trafficFilter));
  const shownFlows = flows.filter((f) =>
    flowMatches(f, trafficFilter, ipName(f.src_ip), ipName(f.dst_ip)),
  );
  const shownAudit = audit.filter((a) => auditMatches(a, auditFilter));
  const shownProxy = proxyEvents.filter((e) => proxyMatches(e, proxyFilter));
  const shownAccess = access.filter((a) => accessMatches(a, accessFilter));
  const shownRules = acl.rules.filter((r) => aclMatches(r, aclFilter));
  const shownKeys = keys.filter((k) => setupKeyMatches(k, setupFilter));
  const shownMigrationChanges =
    networkPlan?.changes.filter((c) => migrationChangeMatches(c, migrationFilter)) ?? [];
  const selectedPeer = selectedPeerID == null ? null : peers.find((p) => p.id === selectedPeerID) ?? null;
  const selectedPeerLinks = selectedPeer
    ? links.filter((l) => l.peer_id === selectedPeer.id || l.remote_peer_id === selectedPeer.id)
    : [];
  const selectedPeerFlows = selectedPeer
    ? flows.filter(
        (f) =>
          f.src_ip === selectedPeer.assigned_ip ||
          f.dst_ip === selectedPeer.assigned_ip ||
          (selectedPeer.assigned_ip6 &&
            (f.src_ip === selectedPeer.assigned_ip6 || f.dst_ip === selectedPeer.assigned_ip6)),
      )
    : [];
  const selectedPeerPathState = selectedPeerLinks.find((l) => l.path_state)?.path_state;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">wg</div>
          <div>
            <div className="brand-name">wgmesh</div>
            <div className="brand-sub">control plane</div>
          </div>
        </div>
        <nav className="side-nav">
          {TOP_TABS.map((t) => (
            <button
              key={t}
              className={tab === t ? "side-link active" : "side-link"}
              onClick={() => setTab(t)}
            >
              {TAB_LABEL[t]}
            </button>
          ))}
          <div className="side-group">
            <button
              className="side-link group-head"
              onClick={() => setActivityOpen((o) => !o)}
              aria-expanded={activityOpen}
            >
              <span>Activity</span>
              <span className="chev">{activityOpen ? "▾" : "▸"}</span>
            </button>
            {activityOpen &&
              ACTIVITY_TABS.map((t) => (
                <button
                  key={t}
                  className={tab === t ? "side-link side-sub active" : "side-link side-sub"}
                  onClick={() => setTab(t)}
                >
                  {TAB_LABEL[t]}
                </button>
              ))}
          </div>
          <button
            className={tab === "settings" ? "side-link active" : "side-link"}
            onClick={() => setTab("settings")}
          >
            {TAB_LABEL.settings}
          </button>
        </nav>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <h1>{TAB_LABEL[tab]}</h1>
            <p className="page-sub">
              {network.network_cidr || "overlay"} {network.network_cidr6 ? `· ${network.network_cidr6}` : ""}
            </p>
          </div>
          <div className="auth row">
            <input
              id="token"
              type="password"
              placeholder="admin token"
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void connect()}
            />
            <button className="primary" disabled={authChecking} onClick={() => void connect()}>
              {authChecking ? "checking" : "connect"}
            </button>
            <button onClick={() => void refresh()}>refresh</button>
            <label className="toggle">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
              />
              5s auto
            </label>
          </div>
        </header>

        <div className="error">{error}</div>

        {tab === "overview" && (
          <>
            <section className="metric-grid">
              <div className="metric">
                <div className="metric-label">peers</div>
                <div className="metric-value">{activePeers.length}</div>
                <div className="muted">{onlinePeers.length} online</div>
              </div>
              <div className="metric">
                <div className="metric-label">direct links</div>
                <div className="metric-value">{directLinks.length}</div>
                <div className="muted">{relayedLinks.length} relayed</div>
              </div>
              <div className="metric">
                <div className="metric-label">setup keys</div>
                <div className="metric-value">{activeKeys.length}</div>
                <div className="muted">{keys.length} total</div>
              </div>
              <div className="metric">
                <div className="metric-label">ACL policy</div>
                <div className="metric-value">{acl.default_policy}</div>
                <div className="muted">{acl.rules.length} rules</div>
              </div>
            </section>

            <section className="split">
              <div className="panel">
                <div className="section-head">
                  <h2>Recent peers</h2>
                  <button onClick={() => setTab("machines")}>view all</button>
                </div>
                <div className="compact-list">
                  {activePeers.slice(0, 6).map((p) => (
                    <div className="compact-row" key={p.id}>
                      <Endpoint name={p.hostname || p.assigned_ip} ip={p.assigned_ip6 || p.assigned_ip} />
                      <PeerBadge peer={p} />
                    </div>
                  ))}
                  {activePeers.length === 0 && <div className="muted">no peers enrolled</div>}
                </div>
              </div>
              <div className="panel">
                <div className="section-head">
                  <h2>Path state</h2>
                  <button onClick={() => setTab("traffic")}>inspect</button>
                </div>
                <div className="compact-list">
                  {links.slice(0, 6).map((l) => (
                    <div className="compact-row" key={`${l.peer_id}-${l.remote_peer_id}`}>
                      <Endpoint name={`${l.peer_hostname || l.peer_ip} → ${l.remote_hostname || l.remote_ip}`} />
                      <PathBadge state={l.path_state} />
                    </div>
                  ))}
                  {links.length === 0 && <div className="muted">no link reports yet</div>}
                </div>
              </div>
            </section>
          </>
        )}

        {tab === "machines" && (
          <>
          {selectedPeer ? (
            <>
              <div className="peer-detail-head">
                <button
                  onClick={() => {
                    cancelPeerAddressEdit();
                    setSelectedPeerID(null);
                  }}
                >
                  back to peers
                </button>
                <div>
                  <h2>{selectedPeer.hostname || `peer ${selectedPeer.id}`}</h2>
                  <p className="page-sub">
                    peer {selectedPeer.id} · {selectedPeer.assigned_ip}
                    {selectedPeer.assigned_ip6 ? ` · ${selectedPeer.assigned_ip6}` : ""}
                  </p>
                </div>
                <PeerBadge peer={selectedPeer} />
              </div>

              <section className="metric-grid peer-metrics">
                <div className="metric">
                  <div className="metric-label">last seen</div>
                  <div className="metric-value small">{lastSeenLabel(selectedPeer)}</div>
                </div>
                <div className="metric">
                  <div className="metric-label">path state</div>
                  <div className="metric-value small">
                    <PathBadge state={selectedPeerPathState} />
                  </div>
                </div>
                <div className="metric">
                  <div className="metric-label">links</div>
                  <div className="metric-value">{selectedPeerLinks.length}</div>
                </div>
                <div className="metric">
                  <div className="metric-label">recent flows</div>
                  <div className="metric-value">{selectedPeerFlows.length}</div>
                </div>
              </section>

              <section className="split peer-detail-grid">
                <div className="panel stack">
                  <div className="section-head">
                    <h2>Identity</h2>
                    <PeerBadge peer={selectedPeer} />
                  </div>
                  <div className="detail-list">
                    <div>
                      <span>Hostname</span>
                      <strong>{selectedPeer.hostname || "unknown"}</strong>
                    </div>
                    <div>
                      <span>Public key</span>
                      <strong className="breakable">
                        {selectedPeer.public_key} <CopyButton text={selectedPeer.public_key} />
                      </strong>
                    </div>
                    <div>
                      <span>Created</span>
                      <strong>{formatTime(selectedPeer.created_at)}</strong>
                    </div>
                    {selectedPeer.revoked_at && (
                      <div>
                        <span>Revoked</span>
                        <strong>{formatTime(selectedPeer.revoked_at)}</strong>
                      </div>
                    )}
                  </div>
                </div>

                <div className="panel stack">
                  <div className="section-head">
                    <h2>Network</h2>
                    {!selectedPeer.revoked_at && (
                      <button onClick={() => startPeerAddressEdit(selectedPeer)}>
                        edit IP
                      </button>
                    )}
                  </div>
                  <div className="detail-list">
                    <div>
                      <span>IPv4 overlay</span>
                      <strong>{selectedPeer.assigned_ip}</strong>
                    </div>
                    <div>
                      <span>IPv6 overlay</span>
                      <strong>{selectedPeer.assigned_ip6 || "not assigned"}</strong>
                    </div>
                    <div>
                      <span>Endpoint</span>
                      <strong>{endpointOf(selectedPeer) || "unknown"}</strong>
                    </div>
                    <div>
                      <span>Observed address</span>
                      <strong>{selectedPeer.observed_ip || "unknown"}</strong>
                    </div>
                  </div>
                  {editingPeerID === selectedPeer.id && (
                    <div className="inline-editor boxed-editor">
                      <label>
                        <span>IPv4</span>
                        <input
                          value={peerIP}
                          placeholder={network.network_cidr}
                          onChange={(e) => setPeerIP(e.target.value)}
                        />
                      </label>
                      <label>
                        <span>IPv6</span>
                        <input
                          value={peerIP6}
                          placeholder={network.network_cidr6}
                          onChange={(e) => setPeerIP6(e.target.value)}
                        />
                      </label>
                      <button
                        className="primary"
                        disabled={savingPeerID === selectedPeer.id}
                        onClick={() => void savePeerAddress(selectedPeer)}
                      >
                        {savingPeerID === selectedPeer.id ? "saving" : "save"}
                      </button>
                      <button onClick={cancelPeerAddressEdit}>cancel</button>
                    </div>
                  )}
                </div>
              </section>

              <section className="panel stack">
                <div className="section-head">
                  <h2>Lifecycle</h2>
                  {!selectedPeer.revoked_at ? (
                    <button
                      className="danger"
                      onClick={() =>
                        confirmPost({
                          title: "Revoke peer?",
                          message: `Revoke peer ${selectedPeer.id} (${selectedPeer.hostname || selectedPeer.assigned_ip})? It will stop receiving mesh config but remain in history.`,
                          confirmLabel: "revoke",
                          danger: true,
                          onConfirm: () =>
                            postAdminAction(`/api/peers/${selectedPeer.id}/revoke`, "Peer revoked"),
                        })
                      }
                    >
                      revoke peer
                    </button>
                  ) : (
                    <button
                      className="danger"
                      onClick={() =>
                        confirmPost({
                          title: "Remove peer?",
                          message: `Permanently remove peer ${selectedPeer.id} (${selectedPeer.hostname || selectedPeer.assigned_ip})? This releases its overlay address and removes live ACL/topology references.`,
                          confirmLabel: "remove",
                          danger: true,
                          onConfirm: () =>
                            postAdminAction(`/api/peers/${selectedPeer.id}/remove`, "Peer removed"),
                        })
                      }
                    >
                      remove peer
                    </button>
                  )}
                </div>
                <div className="notice">
                  Revoked peers stop receiving mesh configuration but remain visible for history.
                  Removed peers are deleted from the control plane and release their overlay address.
                </div>
              </section>

              <section className="panel tablewrap">
                <div className="section-head">
                  <h2>Connections</h2>
                  <button onClick={() => setTab("traffic")}>open traffic</button>
                </div>
                <table>
                  <thead>
                    <tr>
                      <th>remote peer</th>
                      <th>path</th>
                      <th>rx</th>
                      <th>tx</th>
                      <th>last handshake</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedPeerLinks.length === 0 && (
                      <tr>
                        <td colSpan={5} className="muted">no link reports for this peer yet</td>
                      </tr>
                    )}
                    {selectedPeerLinks.slice(0, 8).map((l) => {
                      const isReporter = l.peer_id === selectedPeer.id;
                      return (
                        <tr key={`${l.peer_id}-${l.remote_peer_id}`}>
                          <td>
                            {isReporter
                              ? peerLabel(l.remote_hostname, l.remote_ip)
                              : peerLabel(l.peer_hostname, l.peer_ip)}
                          </td>
                          <td>
                            <PathBadge state={l.path_state} />
                            {l.path_endpoint && <div className="muted">{l.path_endpoint}</div>}
                          </td>
                          <td>{humanBytes(l.rx_bytes)}</td>
                          <td>{humanBytes(l.tx_bytes)}</td>
                          <td className="muted">{formatTime(l.last_handshake_at) || "never"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </section>
            </>
          ) : (
            <>
          <div className="row page-tools">
            <h2 style={{ margin: 0 }}>Peers</h2>
            <SearchBox
              value={machineFilter}
              onChange={setMachineFilter}
              placeholder="Search peers by name, IP, status, endpoint, key…"
              total={peers.length}
              shown={shownPeers.length}
            />
          </div>
          <div className="panel tablewrap">
            <Paginated items={shownPeers} resetKey={machineFilter}>
              {(pagePeers, pager) => (
                <>
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
                      {shownPeers.length === 0 && (
                        <tr>
                          <td colSpan={9} className="muted">
                            {peers.length ? "no matching peers" : "no peers enrolled"}
                          </td>
                        </tr>
                      )}
                      {pagePeers.map((p) => (
                        <Fragment key={p.id}>
                          <tr>
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
		                                <div className="row table-actions">
		                                  <button onClick={() => setSelectedPeerID(p.id)}>
		                                    details
		                                  </button>
		                                  <button onClick={() => startPeerAddressEdit(p)}>
		                                    edit IP
		                                  </button>
	                                  <button
	                                    className="danger"
	                                    onClick={() =>
	                                      confirmPost({
	                                        title: "Revoke peer?",
	                                        message: `Revoke peer ${p.id} (${p.hostname || p.assigned_ip})? It will stop receiving mesh config but remain in history.`,
	                                        confirmLabel: "revoke",
	                                        danger: true,
	                                        onConfirm: () =>
	                                          postAdminAction(`/api/peers/${p.id}/revoke`, "Peer revoked"),
	                                      })
	                                    }
	                                  >
	                                    revoke
	                                  </button>
	                                </div>
	                              )}
		                              {p.revoked_at && (
		                                <div className="row table-actions">
		                                  <button onClick={() => setSelectedPeerID(p.id)}>
		                                    details
		                                  </button>
		                                  <button
		                                    className="danger"
		                                    onClick={() =>
		                                      confirmPost({
		                                        title: "Remove peer?",
		                                        message: `Permanently remove peer ${p.id} (${p.hostname || p.assigned_ip})? This releases its overlay address and removes live ACL/topology references.`,
		                                        confirmLabel: "remove",
		                                        danger: true,
		                                        onConfirm: () =>
		                                          postAdminAction(`/api/peers/${p.id}/remove`, "Peer removed"),
		                                      })
		                                    }
		                                  >
		                                    remove
		                                  </button>
		                                </div>
		                              )}
		                            </td>
                          </tr>
                          {editingPeerID === p.id && (
                            <tr className="edit-row">
                              <td colSpan={9}>
                                <div className="inline-editor">
                                  <label>
                                    <span>IPv4</span>
                                    <input
                                      value={peerIP}
                                      placeholder={network.network_cidr}
                                      onChange={(e) => setPeerIP(e.target.value)}
                                    />
                                  </label>
                                  <label>
                                    <span>IPv6</span>
                                    <input
                                      value={peerIP6}
                                      placeholder={network.network_cidr6}
                                      onChange={(e) => setPeerIP6(e.target.value)}
                                    />
                                  </label>
                                  <button
                                    className="primary"
                                    disabled={savingPeerID === p.id}
                                    onClick={() => void savePeerAddress(p)}
                                  >
                                    {savingPeerID === p.id ? "saving" : "save"}
                                  </button>
                                  <button onClick={cancelPeerAddressEdit}>cancel</button>
                                  <span className="muted">
                                    {network.network_cidr}
                                    {network.network_cidr6 ? ` · ${network.network_cidr6}` : ""}
                                  </span>
                                </div>
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      ))}
                    </tbody>
                  </table>
                  {pager}
                </>
              )}
            </Paginated>
          </div>
            </>
          )}
          </>
        )}
        {tab === "traffic" && (
          <>
          <div className="row page-tools">
            <SearchBox
              value={trafficFilter}
              onChange={setTrafficFilter}
              placeholder="Search traffic by peer, IP, path, protocol, port…"
              total={flows.length + links.length + activePeers.length}
              shown={shownFlows.length + shownLinks.length + shownActivePeers.length}
            />
          </div>

          <h2>Connection events</h2>
          <div className="panel">
            {connEvents.length === 0 ? (
              <div className="muted">no connection events yet</div>
            ) : (
              <Paginated items={connEvents} resetKey={trafficFilter}>
                {(page, pager) => (
                  <>
                    {page.map((e) => (
                      <ConnectionEventRow key={e.id} e={e} />
                    ))}
                    {pager}
                  </>
                )}
              </Paginated>
            )}
          </div>
		          <h2>Links</h2>
		          <div className="panel tablewrap">
		            <Paginated items={shownLinks} resetKey={trafficFilter}>
	              {(pageLinks, pager) => (
	                <>
	                  <table>
	                    <thead>
	                      <tr>
	                        <th>reporter</th>
	                        <th>remote</th>
	                        <th>path</th>
	                        <th>rx</th>
	                        <th>tx</th>
	                        <th>last handshake</th>
	                        <th>updated</th>
	                      </tr>
	                    </thead>
	                    <tbody>
		                      {shownLinks.length === 0 && (
		                        <tr>
		                          <td colSpan={7} className="muted">
		                            {links.length ? "no matching links" : "no reports yet"}
		                          </td>
	                        </tr>
	                      )}
	                      {pageLinks.map((l) => (
	                        <tr key={`${l.peer_id}-${l.remote_peer_id}`}>
	                          <td>{peerLabel(l.peer_hostname, l.peer_ip)}</td>
	                          <td>{peerLabel(l.remote_hostname, l.remote_ip)}</td>
	                          <td>
	                            <PathBadge state={l.path_state} />
	                            {l.path_endpoint && (
	                              <div className="muted">{l.path_endpoint}</div>
	                            )}
	                          </td>
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
	                  {pager}
	                </>
	              )}
	            </Paginated>
	          </div>

          <h2>Traffic events</h2>
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
	                if (shownFlows.length === 0)
	                  return (
	                    <div className="activity-row muted">
	                      {flows.length ? "no matching flows" : "no flows recorded"}
	                    </div>
	                  );
		                return (
		                  <Paginated items={shownFlows} resetKey={trafficFilter}>
	                    {(pageRows, pager) => (
	                      <>
	                        {pageRows.map((f) => (
	                          <FlowEvent key={f.id} f={f} ipName={ipName} />
	                        ))}
	                        {pager}
	                      </>
	                    )}
	                  </Paginated>
	                );
	              })()}
            </div>
          </div>
          </>
        )}

        {tab === "proxy" && (
          <>
            <div className="row page-tools">
              <SearchBox
                value={proxyFilter}
                onChange={setProxyFilter}
                placeholder="Search proxy events by host, path, method, status, client…"
                total={proxyEvents.length}
                shown={shownProxy.length}
              />
            </div>
            <div className="panel tablewrap tablewrap-fit">
              <Paginated items={shownProxy} resetKey={proxyFilter}>
                {(page, pager) => (
                  <>
                    <table className="proxy-table">
                      <colgroup>
                        <col className="col-time" />
                        <col className="col-method" />
                        <col className="col-request" />
                        <col className="col-status" />
                        <col className="col-duration" />
                        <col className="col-size" />
                        <col className="col-client" />
                        <col className="col-service" />
                      </colgroup>
                      <thead>
                        <tr>
                          <th>time</th>
                          <th>method</th>
                          <th>request</th>
                          <th>status</th>
                          <th>duration</th>
                          <th>size</th>
                          <th>client</th>
                          <th>service</th>
                        </tr>
                      </thead>
                      <tbody>
                        {shownProxy.length === 0 && (
                          <tr>
                            <td colSpan={8} className="muted">
                              {proxyEvents.length
                                ? "no matching proxy events"
                                : "no proxy events — enable Traefik access-log ingestion on an agent (--traefik-access-log)"}
                            </td>
                          </tr>
                        )}
                        {page.map((e) => (
                          <tr key={e.id}>
                            <td className="muted">{formatTime(e.at)}</td>
                            <td>
                              <span className="pill">{e.method || "-"}</span>
                            </td>
                            <td className="request-cell" title={proxyRequest(e)}>
                              <span className="request-url">
                                {e.host}
                                <span className="muted">{e.path}</span>
                              </span>
                            </td>
                            <td>
                              <StatusPill status={e.status} />
                            </td>
                            <td className="muted">{formatDuration(e.duration_ms)}</td>
                            <td className="muted">{humanBytes((e.req_bytes || 0) + (e.resp_bytes || 0))}</td>
                            <td className="muted">{e.client_ip}</td>
                            <td className="muted">{e.service}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {pager}
                  </>
                )}
              </Paginated>
            </div>
          </>
        )}

        {tab === "logs" && (
          <>
          <div className="row page-tools">
            <h2 style={{ margin: 0 }}>Activity log</h2>
            <SearchBox
              value={auditFilter}
              onChange={setAuditFilter}
              placeholder="Search activity by event, peer, IP, path, status…"
              total={audit.length}
              shown={shownAudit.length}
            />
          </div>
            <p className="sub">
              security events — enrollment, revocation, ACL and key changes, relay
              sessions, auth failures, and request tracing when the server runs with
              the default in-memory access log.
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
		                if (shownAudit.length === 0)
		                  return (
		                    <div className="activity-row muted">
		                      {audit.length ? "no matching events" : "no activity yet"}
		                    </div>
		                  );
		                return (
		                  <Paginated items={shownAudit} resetKey={auditFilter}>
	                    {(pageRows, pager) => (
	                      <>
	                        {pageRows.map((a) => <AuditEvent key={a.id} a={a} />)}
	                        {pager}
	                      </>
	                    )}
	                  </Paginated>
	                );
	              })()}
            </div>
	          </div>
	          <div className="row page-tools">
	            <h2 style={{ margin: 0 }}>Request log</h2>
	            <SearchBox
	              value={accessFilter}
	              onChange={setAccessFilter}
	              placeholder="Search requests by method, path, IP, peer, status…"
	              total={access.length}
	              shown={shownAccess.length}
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
		                if (shownAccess.length === 0)
		                  return (
		                    <div className="activity-row muted">
		                      {access.length ? "no matching requests" : "no request log entries"}
		                    </div>
		                  );
		                return (
		                  <Paginated items={shownAccess} resetKey={accessFilter}>
	                    {(pageRows, pager) => (
	                      <>
	                        {pageRows.map((a, i) => <AccessEvent key={`${a.time}-${i}`} a={a} />)}
	                        {pager}
	                      </>
	                    )}
	                  </Paginated>
	                );
	              })()}
            </div>
          </div>
          </>
        )}

        {tab === "settings" && (
          <>
          <div className="section-title">
            <h2>Overlay network</h2>
            <p className="page-sub">
              Manage the IPv4 and IPv6 address ranges assigned to enrolled peers.
            </p>
          </div>

          <section className="settings-layout">
            <div className="panel stack settings-card">
              <div className="section-head">
                <h2>Current network</h2>
                <span className="badge ok">active</span>
              </div>
              <div className="detail-list">
                <div>
                  <span>IPv4 range</span>
                  <strong>{network.network_cidr || "unknown"}</strong>
                </div>
                <div>
                  <span>IPv6 range</span>
                  <strong>{network.network_cidr6 || "unknown"}</strong>
                </div>
                <div>
                  <span>Active peers</span>
                  <strong>{peers.filter((p) => !p.revoked_at).length}</strong>
                </div>
                <div>
                  <span>Total assignments</span>
                  <strong>{peers.length}</strong>
                </div>
              </div>
            </div>

            <div className="panel stack settings-card">
              <div className="section-head">
                <h2>Network settings</h2>
              </div>
              <div className="notice warn">
                Changing the overlay network reassigns every peer. Running agents
                adopt the new interface address from their next report response;
                restarting an agent also re-enrolls it onto the new assignment.
              </div>
              <div className="form-grid network-form">
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
            </div>
          </section>

          <div className="section-title">
            <h2>DNS</h2>
            <p className="page-sub">
              Push CoreDNS resolver settings to peers for names such as jellyfin.vpn.
            </p>
          </div>

          <section className="settings-layout">
            <div className="panel stack settings-card">
              <div className="section-head">
                <h2>Current DNS</h2>
                <span className={dns.enabled ? "badge ok" : "badge warn"}>
                  {dns.enabled ? "enabled" : "disabled"}
                </span>
              </div>
              <div className="detail-list">
                <div>
                  <span>Domain</span>
                  <strong>{dns.domain || "vpn"}</strong>
                </div>
                <div>
                  <span>IPv4 nameservers</span>
                  <strong className="breakable">
                    {splitNameservers(dns.nameservers).v4.join(", ") || "not configured"}
                  </strong>
                </div>
                <div>
                  <span>IPv6 nameservers</span>
                  <strong className="breakable">
                    {splitNameservers(dns.nameservers).v6.join(", ") || "not configured"}
                  </strong>
                </div>
                <div>
                  <span>Search domains</span>
                  <strong>{(dns.search_domains || []).join(", ") || "none"}</strong>
                </div>
                <div>
                  <span>Peer-name DNS</span>
                  <strong>{dns.magic_dns ? "on" : "off"}</strong>
                </div>
              </div>
            </div>

            <div className="panel stack settings-card">
              <div className="section-head">
                <h2>DNS settings</h2>
              </div>
              <div className="notice">
                Point nameservers at your CoreDNS container or its overlay IP.
                Agents apply these settings on enroll and on their next report sync.
              </div>
              <div className="form-grid dns-form">
                <label className="toggle setting-toggle">
                  <input
                    type="checkbox"
                    checked={dnsEnabled}
                    onChange={(e) => {
                      setDNSEnabled(e.target.checked);
                      setDNSDirty(true);
                    }}
                  />
                  enable DNS push
                </label>
                <label className="toggle setting-toggle">
                  <input
                    type="checkbox"
                    checked={dnsMagic}
                    onChange={(e) => {
                      setDNSMagic(e.target.checked);
                      setDNSDirty(true);
                    }}
                  />
                  peer-name DNS
                </label>
                <label>
                  <span>Domain</span>
                  <input
                    value={dnsDomain}
                    placeholder="vpn"
                    onChange={(e) => {
                      setDNSDomain(e.target.value);
                      setDNSDirty(true);
                    }}
                  />
                </label>
                <label>
                  <span>IPv4 nameservers</span>
                  <textarea
                    value={dnsNameservers4}
                    placeholder="100.78.0.7"
                    onChange={(e) => {
                      setDNSNameservers4(e.target.value);
                      setDNSDirty(true);
                    }}
                  />
                </label>
                <label>
                  <span>IPv6 nameservers</span>
                  <textarea
                    value={dnsNameservers6}
                    placeholder="fd32:d2ad:be4f::7"
                    onChange={(e) => {
                      setDNSNameservers6(e.target.value);
                      setDNSDirty(true);
                    }}
                  />
                </label>
                <label>
                  <span>Search domains</span>
                  <textarea
                    value={dnsSearchDomains}
                    placeholder="vpn"
                    onChange={(e) => {
                      setDNSSearchDomains(e.target.value);
                      setDNSDirty(true);
                    }}
                  />
                </label>
                <div className="form-actions">
                  <button className="primary" onClick={() => void saveDNSSettings()}>
                    save DNS settings
                  </button>
                </div>
              </div>
            </div>
          </section>

            {networkPlan && (
              <div className="panel stack">
                <div className="section-head">
                  <h2>Migration preview</h2>
                  <span className="badge warn">{networkPlan.changes.length} peers</span>
                </div>
	                <div className="notice">
	                  {networkPlan.message ||
	                    "Preview ready. Review the reassignment plan before applying."}
	                </div>
	                <SearchBox
	                  value={migrationFilter}
	                  onChange={setMigrationFilter}
                  placeholder="Search migration by peer, old IP, new IP…"
                  total={networkPlan.changes.length}
                  shown={shownMigrationChanges.length}
                />
                <div className="tablewrap">
                  <Paginated
                    items={shownMigrationChanges}
                    resetKey={migrationFilter}
                  >
	                    {(pageChanges, pager) => (
	                      <>
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
                            {shownMigrationChanges.length === 0 && (
	                              <tr>
	                                <td colSpan={4} className="muted">
	                                  {networkPlan.changes.length ? "no matching peers" : "no peers to reassign"}
	                                </td>
	                              </tr>
	                            )}
	                            {pageChanges.map((c) => (
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
	                        {pager}
	                      </>
	                    )}
	                  </Paginated>
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
          </>
        )}

        {tab === "policies" && (
          <>
          <h2>ACL rules</h2>
          <div className="panel">
            <p className="muted" style={{ marginTop: 0 }}>
              default policy: <strong>{acl.default_policy}</strong>
              {acl.default_policy === "allow"
                ? " — every peer sees every peer; rules below become active when the server runs with --default-policy deny"
                : " — peers only see each other when a rule below connects them"}
            </p>
            <div className="form-grid acl-form">
              <label>
                <span>Name</span>
                <input
                  placeholder="Jellyfin access"
                  value={aclName}
                  onChange={(e) => setAclName(e.target.value)}
                />
              </label>
              <label>
                <span>Source</span>
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
              </label>
              <label>
                <span>Destination</span>
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
              </label>
              <label>
                <span>Protocol</span>
                <select value={aclProtocol} onChange={(e) => setAclProtocol(e.target.value)}>
                  <option value="any">any</option>
                  <option value="tcp">tcp</option>
                  <option value="udp">udp</option>
                  <option value="icmp">icmp</option>
                  <option value="icmpv6">icmpv6</option>
                </select>
              </label>
              <label>
                <span>Port from</span>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  placeholder="any"
                  value={aclPortMin}
                  disabled={aclProtocol === "icmp" || aclProtocol === "icmpv6"}
                  onChange={(e) => setAclPortMin(e.target.value)}
                />
              </label>
              <label>
                <span>Port to</span>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  placeholder="same"
                  value={aclPortMax}
                  disabled={aclProtocol === "icmp" || aclProtocol === "icmpv6"}
                  onChange={(e) => setAclPortMax(e.target.value)}
                />
              </label>
              <div className="form-actions">
                <button className="primary" onClick={() => void createAclRule()}>
                  add rule
                </button>
	              </div>
	            </div>
		            <div className="row policy-tools">
		              <SearchBox
		                value={aclFilter}
		                onChange={setAclFilter}
		                placeholder="Search ACLs by name, source, destination, protocol, port…"
		                total={acl.rules.length}
		                shown={shownRules.length}
		              />
		              <div className="row import-export">
		                <button onClick={() => void exportAcl()}>export</button>
		                <label className="toggle">
		                  <input
		                    type="checkbox"
		                    checked={aclImportReplace}
		                    onChange={(e) => setAclImportReplace(e.target.checked)}
		                  />
		                  replace existing
		                </label>
		                <label className="file-button">
		                  {aclImporting ? "importing" : "import"}
		                  <input
		                    type="file"
		                    accept="application/json,.json"
		                    disabled={aclImporting}
		                    onChange={(e) => {
		                      const file = e.currentTarget.files?.[0] ?? null;
		                      e.currentTarget.value = "";
		                      void importAcl(file);
		                    }}
		                  />
		                </label>
		              </div>
		            </div>
		            <div className="tablewrap">
	              <Paginated items={shownRules} resetKey={aclFilter}>
	                {(pageRules, pager) => (
	                  <>
	                    <table>
	                      <thead>
	                        <tr>
	                          <th>id</th>
	                          <th>name</th>
	                          <th>src</th>
	                          <th>dst</th>
	                          <th>service</th>
	                          <th>created</th>
	                          <th></th>
	                        </tr>
	                      </thead>
	                      <tbody>
	                        {shownRules.length === 0 && (
	                          <tr>
	                            <td colSpan={7} className="muted">
	                              {acl.rules.length ? "no matching rules" : "no rules"}
	                            </td>
	                          </tr>
	                        )}
	                        {pageRules.map((r) => (
	                          <tr key={r.id}>
	                            <td>{r.id}</td>
	                            <td>{r.name || <span className="muted">unnamed</span>}</td>
	                            <td>{r.src_label}</td>
	                            <td>{r.dst_label}</td>
	                            <td>{serviceLabel(r)}</td>
	                            <td className="muted">{formatTime(r.created_at)}</td>
	                            <td>
		                              <button
		                                className="danger"
		                                onClick={() =>
		                                  confirmPost({
		                                    title: "Delete ACL rule?",
		                                    message: `Delete ACL rule ${r.id} (${r.src_label} to ${r.dst_label})?`,
		                                    confirmLabel: "delete",
		                                    danger: true,
		                                    onConfirm: () =>
		                                      postAdminAction(`/api/acl/${r.id}/delete`, "ACL rule deleted"),
		                                  })
		                                }
		                              >
		                                delete
	                              </button>
	                            </td>
	                          </tr>
	                        ))}
	                      </tbody>
	                    </table>
	                    {pager}
	                  </>
	                )}
	              </Paginated>
	            </div>
          </div>
          </>
        )}

        {tab === "setup" && (
          <>
          <h2>Setup keys</h2>
          <div className="panel">
            <div className="form-grid key-form">
              <label>
                <span>Name</span>
                <input
                  placeholder="Jellyfin sidecar"
                  value={setupName}
                  onChange={(e) => setSetupName(e.target.value)}
                />
              </label>
              <label htmlFor="maxUses">
                <span>Max uses</span>
                <input
                  id="maxUses"
                  type="number"
                  min={0}
                  value={maxUses}
                  onChange={(e) => setMaxUses(parseInt(e.target.value, 10) || 0)}
                />
              </label>
              <label htmlFor="expiresIn">
                <span>Expires in</span>
                <input
                  id="expiresIn"
                  type="text"
                  placeholder="never"
                  value={expiresIn}
                  onChange={(e) => setExpiresIn(e.target.value)}
                />
              </label>
              <div className="form-actions">
                <button className="primary" onClick={() => void createKey()}>
                  new setup key
                </button>
	              </div>
	            </div>
	            <SearchBox
	              value={setupFilter}
	              onChange={setSetupFilter}
	              placeholder="Search setup keys by name, key, status, expiry…"
	              total={keys.length}
	              shown={shownKeys.length}
	            />
	            <div className="tablewrap">
	              <Paginated items={shownKeys} resetKey={setupFilter}>
	                {(pageKeys, pager) => (
	                  <>
	                    <table>
	                      <thead>
	                        <tr>
	                          <th>id</th>
	                          <th>status</th>
	                          <th>name</th>
	                          <th>key</th>
	                          <th>uses</th>
	                          <th>expires</th>
	                          <th>created</th>
	                          <th></th>
	                        </tr>
	                      </thead>
	                      <tbody>
	                        {shownKeys.length === 0 && (
	                          <tr>
	                            <td colSpan={8} className="muted">
	                              {keys.length ? "no matching setup keys" : "no setup keys"}
	                            </td>
	                          </tr>
	                        )}
	                        {pageKeys.map((k) => (
	                          <tr key={k.id}>
	                            <td>{k.id}</td>
	                            <td>
	                              <KeyBadge k={k} />
	                            </td>
	                            <td>{k.name || <span className="muted">unnamed</span>}</td>
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
	                                    confirmPost({
	                                      title: "Revoke setup key?",
	                                      message: `Revoke setup key ${k.id}? Agents already enrolled keep working, but this key can no longer enroll or re-enroll peers.`,
	                                      confirmLabel: "revoke",
	                                      danger: true,
	                                      onConfirm: () =>
	                                        postAdminAction(`/api/setup-keys/${k.id}/revoke`, "Setup key revoked"),
	                                    })
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
	                    {pager}
	                  </>
	                )}
	              </Paginated>
	            </div>
          </div>
          </>
        )}
      </main>
      {confirmAction && (
        <ConfirmModal
          action={confirmAction}
          busy={confirmBusy}
          onCancel={() => !confirmBusy && setConfirmAction(null)}
          onConfirm={() => void runConfirmAction()}
        />
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
