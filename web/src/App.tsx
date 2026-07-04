import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import type { AclResponse, Flow, LinkStat, Peer, SetupKey } from "./types";

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

const PROTOCOLS: Record<number, string> = { 1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6" };

function protocolName(p: number): string {
  return PROTOCOLS[p] ?? String(p);
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
  return peer.revoked_at ? (
    <span className="badge bad">revoked</span>
  ) : (
    <span className="badge ok">active</span>
  );
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

const TABS = ["peers", "traffic", "access"] as const;
type Tab = (typeof TABS)[number];

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
  const [error, setError] = useState("");
  const [maxUses, setMaxUses] = useState(0);
  const [expiresIn, setExpiresIn] = useState("");
  const [aclSrc, setAclSrc] = useState("any");
  const [aclDst, setAclDst] = useState("any");

  const refresh = useCallback(async () => {
    if (!token) return;
    setError("");
    try {
      const [p, k, l, f, a] = await Promise.all([
        api<Peer[]>("/api/peers", token),
        api<SetupKey[]>("/api/setup-keys", token),
        api<LinkStat[]>("/api/link-stats", token),
        api<Flow[]>("/api/flows?limit=100", token),
        api<AclResponse>("/api/acl", token),
      ]);
      setPeers(p);
      setKeys(k);
      setLinks(l);
      setFlows(f);
      setAcl(a);
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
                  <th>public key</th>
                  <th>endpoint</th>
                  <th>created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {peers.length === 0 && (
                  <tr>
                    <td colSpan={8} className="muted">
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
                    <td>{p.assigned_ip}</td>
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

          <h2>Recent flows</h2>
          <div className="panel tablewrap">
            <table>
              <thead>
                <tr>
                  <th>reported</th>
                  <th>reporter</th>
                  <th>proto</th>
                  <th>flow</th>
                  <th>tx</th>
                  <th>rx</th>
                  <th>pkts</th>
                </tr>
              </thead>
              <tbody>
                {flows.length === 0 && (
                  <tr>
                    <td colSpan={7} className="muted">
                      no flows recorded
                    </td>
                  </tr>
                )}
                {flows.map((f) => (
                  <tr key={f.id}>
                    <td className="muted">{formatTime(f.reported_at)}</td>
                    <td>{f.peer_hostname || f.peer_id}</td>
                    <td>{protocolName(f.protocol)}</td>
                    <td className="mono">
                      {f.src_ip}:{f.src_port} → {f.dst_ip}:{f.dst_port}
                    </td>
                    <td>{humanBytes(f.tx_bytes)}</td>
                    <td>{humanBytes(f.rx_bytes)}</td>
                    <td className="muted">
                      {f.tx_packets}/{f.rx_packets}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {tab === "access" && (
        <>
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
