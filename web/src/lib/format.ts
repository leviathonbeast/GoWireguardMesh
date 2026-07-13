import type { Peer, SetupKey } from "../types";

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

export function formatTime(iso?: string): string {
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

export function humanBytes(n: number): string {
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

export function formatDuration(ms?: number): string {
  if (!ms) return "-";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function parseListInput(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((v) => v.trim())
    .filter(Boolean);
}

export function splitNameservers(nameservers: string[] = []): { v4: string[]; v6: string[] } {
  return nameservers.reduce(
    (acc, ns) => {
      if (ns.includes(":")) acc.v6.push(ns);
      else acc.v4.push(ns);
      return acc;
    },
    { v4: [] as string[], v6: [] as string[] },
  );
}

export function peerLabel(hostname: string | undefined, ip: string): string {
  return hostname ? `${hostname} (${ip})` : ip;
}

// gatewayName resolves a routed mobile peer's gateway_peer_id to a label.
export function gatewayName(peers: Peer[], gatewayID: number): string {
  const g = peers.find((p) => p.id === gatewayID);
  if (!g) return `peer ${gatewayID}`;
  return g.hostname || g.assigned_ip || `peer ${gatewayID}`;
}

export function endpointOf(p: Peer): string {
  if (p.public_endpoint) return p.public_endpoint;
  if (p.observed_ip && p.listen_port) return `${p.observed_ip}:${p.listen_port}`;
  return "";
}

// natLabel renders the agent's NAT classification: "easy" NATs keep the
// same public mapping toward every destination (hole-punchable), "hard"
// (symmetric) NATs mint one per destination and generally need the relay.
export function natLabel(t: "easy" | "hard" | "static"): string {
  if (t === "static") return "static (pinned endpoint)";
  return t === "easy" ? "easy NAT" : "hard NAT (symmetric)";
}

export function lastSeenLabel(p: Peer): string {
  if (p.revoked_at) return "revoked";
  if (p.peer_type === "static" || p.health_status === "static") return "WireGuard-only";
  if (!p.last_seen_at) return "never seen";
  if (p.last_seen_age_seconds == null) return formatTime(p.last_seen_at);
  if (p.last_seen_age_seconds < 60) return `${p.last_seen_age_seconds}s ago`;
  const minutes = Math.floor(p.last_seen_age_seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  return `${Math.floor(minutes / 60)}h ago`;
}

export function setupKeyStatus(k: SetupKey): "active" | "revoked" | "expired" | "exhausted" {
  if (k.revoked_at) return "revoked";
  if (k.expires_at && k.expires_at <= new Date().toISOString()) return "expired";
  if (k.max_uses > 0 && k.uses_consumed >= k.max_uses) return "exhausted";
  return "active";
}

export function serviceLabel(rule: { protocol: string; port_min?: number; port_max?: number }): string {
  const proto = (rule.protocol || "any").toUpperCase();
  if (!rule.port_min) return proto;
  if (rule.port_max && rule.port_max !== rule.port_min) {
    return `${proto} ${rule.port_min}-${rule.port_max}`;
  }
  return `${proto} ${rule.port_min}`;
}

export function hostPort(host: string, port: number): string {
  return host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;
}

// Only an active agent can act as a static peer's gateway: it is the peer
// that routes the device's overlay /32 into the mesh. Static peers run
// stock WireGuard, so they cannot route for each other.
export function gatewayCandidates(peers: Peer[]): Peer[] {
  return peers.filter((p) => p.peer_type === "agent" && !p.revoked_at);
}

// suggestEndpoint prefills the address the device will dial. A gateway's
// observed_ip is the source of its last report, so its listen port — not
// that report's ephemeral source port — is what accepts WireGuard.
export function suggestEndpoint(gateway?: Peer): string {
  if (!gateway) return "";
  if (gateway.public_endpoint) return gateway.public_endpoint;
  if (!gateway.observed_ip) return "";

  return hostPort(gateway.observed_ip, gateway.listen_port || 51820);
}

// configFileName is also the tunnel name the WireGuard apps display, and
// they only accept [a-zA-Z0-9_=+.-] up to 15 characters.
export function configFileName(peer: Peer): string {
  const cleaned = (peer.hostname || "").replace(/[^a-zA-Z0-9_=+.-]/g, "-").slice(0, 15);

  return `${cleaned || `wgmesh-${peer.id}`}.conf`;
}

// shortKey renders a WireGuard public key compactly for tables; the full
// key stays available via tooltip and the copy button.
export function shortKey(key: string): string {
  if (key.length <= 12) return key;
  return `${key.slice(0, 8)}…${key.slice(-4)}`;
}

// copyToClipboard works in secure contexts via the Clipboard API and
// falls back to the legacy execCommand path on plain-HTTP origins,
// where navigator.clipboard does not exist at all.
export async function copyToClipboard(text: string): Promise<boolean> {
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

// downloadText saves a string the browser already holds, without a second
// trip to the server. A static peer's config carries its private key and
// exists only in the create response, so re-fetching it is not an option.
export function downloadText(filename: string, contents: string, type: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
