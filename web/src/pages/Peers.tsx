import { Fragment, useEffect, useState } from "react";
import { api } from "../api";
import type { AppCtx } from "../appctx";
import type { MobilePeerResponse, Peer } from "../types";
import {
  endpointOf,
  formatTime,
  gatewayCandidates,
  gatewayName,
  humanBytes,
  lastSeenLabel,
  natLabel,
  peerLabel,
  shortKey,
} from "../lib/format";
import { peerMatches } from "../lib/match";
import { CopyButton, PageHead, Paginated, PathBadge, PeerBadge, SearchBox, Section } from "../components/ui";
import { DeviceConfig, StaticPeerDialog } from "../components/DeviceConfig";

export default function Peers({ ctx }: { ctx: AppCtx }) {
  const { peers, network } = ctx.data;

  const [filter, setFilter] = useState("");
  const [staticPeerOpen, setStaticPeerOpen] = useState(false);
  const [selectedPeerID, setSelectedPeerID] = useState<number | null>(null);
  const [editingPeerID, setEditingPeerID] = useState<number | null>(null);
  const [peerIP, setPeerIP] = useState("");
  const [peerIP6, setPeerIP6] = useState("");
  const [savingPeerID, setSavingPeerID] = useState<number | null>(null);

  // Deselect a peer that disappears from the snapshot (e.g. removed).
  useEffect(() => {
    if (selectedPeerID == null) return;
    if (!peers.some((p) => p.id === selectedPeerID)) setSelectedPeerID(null);
  }, [peers, selectedPeerID]);

  const startAddressEdit = (p: Peer) => {
    setEditingPeerID(p.id);
    setPeerIP(p.assigned_ip);
    setPeerIP6(p.assigned_ip6 || "");
    ctx.setError("");
  };

  const cancelAddressEdit = () => {
    setEditingPeerID(null);
    setPeerIP("");
    setPeerIP6("");
  };

  const saveAddress = async (p: Peer) => {
    ctx.setError("");
    setSavingPeerID(p.id);
    try {
      await api<Peer>(`/api/peers/${p.id}/address`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          assigned_ip: peerIP.trim(),
          assigned_ip6: peerIP6.trim(),
        }),
      });
      await ctx.refresh();
      cancelAddressEdit();
      ctx.toast("Peer address updated");
    } catch (e) {
      ctx.setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSavingPeerID(null);
    }
  };

  const confirmRevoke = (p: Peer) =>
    ctx.confirm({
      title: "Revoke peer?",
      message: `Revoke peer ${p.id} (${p.hostname || p.assigned_ip})? It will stop receiving mesh config but remain in history.`,
      confirmLabel: "revoke",
      danger: true,
      onConfirm: () => ctx.postAction(`/api/peers/${p.id}/revoke`, "Peer revoked"),
    });

  const confirmRemove = (p: Peer) =>
    ctx.confirm({
      title: "Remove peer?",
      message: `Permanently remove peer ${p.id} (${p.hostname || p.assigned_ip})? This releases its overlay address and removes live ACL/topology references.`,
      confirmLabel: "remove",
      danger: true,
      onConfirm: () => ctx.postAction(`/api/peers/${p.id}/remove`, "Peer removed"),
    });

  const selected = selectedPeerID == null ? null : (peers.find((p) => p.id === selectedPeerID) ?? null);

  if (selected) {
    return (
      <PeerDetail
        ctx={ctx}
        peer={selected}
        onBack={() => {
          cancelAddressEdit();
          setSelectedPeerID(null);
        }}
        editing={editingPeerID === selected.id}
        peerIP={peerIP}
        peerIP6={peerIP6}
        setPeerIP={setPeerIP}
        setPeerIP6={setPeerIP6}
        saving={savingPeerID === selected.id}
        onEdit={() => startAddressEdit(selected)}
        onSave={() => void saveAddress(selected)}
        onCancelEdit={cancelAddressEdit}
        onRevoke={() => confirmRevoke(selected)}
        onRemove={() => confirmRemove(selected)}
      />
    );
  }

  const shown = peers.filter((p) => peerMatches(p, filter));

  const addressEditor = (p: Peer) => (
    <div className="flex flex-wrap items-end gap-2 rounded-md border border-line bg-panel-soft p-3">
      <label className="grid gap-1">
        <span className="text-xs text-muted">IPv4</span>
        <input
          className="w-44"
          value={peerIP}
          placeholder={network.network_cidr}
          onChange={(e) => setPeerIP(e.target.value)}
        />
      </label>
      <label className="grid gap-1">
        <span className="text-xs text-muted">IPv6</span>
        <input
          className="w-56"
          value={peerIP6}
          placeholder={network.network_cidr6}
          onChange={(e) => setPeerIP6(e.target.value)}
        />
      </label>
      <button className="btn-primary" disabled={savingPeerID === p.id} onClick={() => void saveAddress(p)}>
        {savingPeerID === p.id ? "saving" : "save"}
      </button>
      <button onClick={cancelAddressEdit}>cancel</button>
      <span className="text-xs text-muted">
        {network.network_cidr}
        {network.network_cidr6 ? ` · ${network.network_cidr6}` : ""}
      </span>
    </div>
  );

  return (
    <>
      <PageHead title="Peers" sub="Every machine and device enrolled in the mesh.">
        <button
          className="btn-primary"
          disabled={gatewayCandidates(peers).length === 0}
          title={
            gatewayCandidates(peers).length === 0
              ? "Enroll an agent first: a static peer is routed through one"
              : "Generate a WireGuard config and QR code for a phone or appliance"
          }
          onClick={() => setStaticPeerOpen(true)}
        >
          add device
        </button>
      </PageHead>

      <div className="mb-3">
        <SearchBox
          value={filter}
          onChange={setFilter}
          placeholder="Search peers by name, IP, status, endpoint, key…"
          total={peers.length}
          shown={shown.length}
        />
      </div>

      <div className="panel tablewrap">
        <Paginated items={shown} resetKey={filter}>
          {(pagePeers, pager) => (
            <>
              <table>
                <thead>
                  <tr>
                    <th>status</th>
                    <th>hostname</th>
                    <th>overlay ip</th>
                    <th>last seen</th>
                    <th className="hidden md:table-cell">public key</th>
                    <th className="hidden lg:table-cell">endpoint</th>
                    <th className="hidden xl:table-cell">created</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {shown.length === 0 && (
                    <tr>
                      <td colSpan={8} className="text-muted">
                        {peers.length ? "no matching peers" : "no peers enrolled"}
                      </td>
                    </tr>
                  )}
                  {pagePeers.map((p) => (
                    <Fragment key={p.id}>
                      <tr>
                        <td>
                          <PeerBadge peer={p} />
                        </td>
                        <td>
                          <button className="btn-ghost p-0 font-medium" onClick={() => setSelectedPeerID(p.id)}>
                            {p.hostname || `peer ${p.id}`}
                          </button>
                        </td>
                        <td>
                          {p.assigned_ip}
                          {p.assigned_ip6 && <div className="text-xs text-muted">{p.assigned_ip6}</div>}
                        </td>
                        <td className="text-muted">{lastSeenLabel(p)}</td>
                        <td className="hidden font-mono text-xs md:table-cell">
                          <span title={p.public_key}>{shortKey(p.public_key)}</span>{" "}
                          <CopyButton text={p.public_key} />
                        </td>
                        <td className="hidden lg:table-cell">
                          {p.gateway_peer_id ? (
                            <span
                              className="text-muted"
                              title="routed (no NAT) through this gateway; keeps its overlay source IP"
                            >
                              via {gatewayName(peers, p.gateway_peer_id)}
                            </span>
                          ) : (
                            endpointOf(p) || <span className="text-muted">unknown</span>
                          )}
                          {p.nat_type && <div className="text-xs text-muted">{natLabel(p.nat_type)}</div>}
                        </td>
                        <td className="hidden text-muted xl:table-cell">{formatTime(p.created_at)}</td>
                        <td>
                          <div className="flex justify-end gap-1.5 whitespace-nowrap">
                            <button onClick={() => setSelectedPeerID(p.id)}>details</button>
                            {!p.revoked_at ? (
                              <button className="btn-danger" onClick={() => confirmRevoke(p)}>
                                revoke
                              </button>
                            ) : (
                              <button className="btn-danger" onClick={() => confirmRemove(p)}>
                                remove
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                      {editingPeerID === p.id && (
                        <tr>
                          <td colSpan={8}>{addressEditor(p)}</td>
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

      {staticPeerOpen && (
        <StaticPeerDialog
          peers={peers}
          onCreated={ctx.refresh}
          onClose={() => setStaticPeerOpen(false)}
        />
      )}
    </>
  );
}

function PeerDetail({
  ctx,
  peer,
  onBack,
  editing,
  peerIP,
  peerIP6,
  setPeerIP,
  setPeerIP6,
  saving,
  onEdit,
  onSave,
  onCancelEdit,
  onRevoke,
  onRemove,
}: {
  ctx: AppCtx;
  peer: Peer;
  onBack: () => void;
  editing: boolean;
  peerIP: string;
  peerIP6: string;
  setPeerIP: (v: string) => void;
  setPeerIP6: (v: string) => void;
  saving: boolean;
  onEdit: () => void;
  onSave: () => void;
  onCancelEdit: () => void;
  onRevoke: () => void;
  onRemove: () => void;
}) {
  const { peers, links, flows, network } = ctx.data;

  const [config, setConfig] = useState<MobilePeerResponse | null>(null);
  const [configLoading, setConfigLoading] = useState(false);

  // A fetched config holds a private key. Drop it the moment the operator
  // leaves the peer, so it neither lingers nor renders under another peer.
  useEffect(() => {
    setConfig(null);
  }, [peer.id]);

  const peerLinks = links.filter((l) => l.peer_id === peer.id || l.remote_peer_id === peer.id);
  const peerFlows = flows.filter(
    (f) =>
      f.src_ip === peer.assigned_ip ||
      f.dst_ip === peer.assigned_ip ||
      (peer.assigned_ip6 && (f.src_ip === peer.assigned_ip6 || f.dst_ip === peer.assigned_ip6)),
  );
  const pathState = peerLinks.find((l) => l.path_state)?.path_state;

  // loadConfig fetches a static peer's config on demand rather than with
  // the dashboard: it embeds a private key, so it is only pulled when an
  // admin explicitly asks, and the read is audited server-side.
  const loadConfig = async () => {
    ctx.setError("");
    setConfigLoading(true);
    try {
      setConfig(await api<MobilePeerResponse>(`/api/peers/${peer.id}/config`));
    } catch (e) {
      ctx.setError(e instanceof Error ? e.message : String(e));
    } finally {
      setConfigLoading(false);
    }
  };

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <button onClick={onBack}>← back to peers</button>
        <div>
          <h1>{peer.hostname || `peer ${peer.id}`}</h1>
          <p className="mt-0.5 text-[13px] text-muted">
            peer {peer.id} · {peer.assigned_ip}
            {peer.assigned_ip6 ? ` · ${peer.assigned_ip6}` : ""}
          </p>
        </div>
        <PeerBadge peer={peer} />
      </div>

      <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div className="metric">
          <div className="metric-label">last seen</div>
          <div className="text-base font-semibold">{lastSeenLabel(peer)}</div>
        </div>
        <div className="metric">
          <div className="metric-label">path state</div>
          <div>
            <PathBadge state={pathState} />
          </div>
        </div>
        <div className="metric">
          <div className="metric-label">links</div>
          <div className="metric-value">{peerLinks.length}</div>
        </div>
        <div className="metric">
          <div className="metric-label">recent flows</div>
          <div className="metric-value">{peerFlows.length}</div>
        </div>
      </section>

      <section className="mt-4 grid gap-3 lg:grid-cols-2">
        <div className="panel">
          <h2 className="mb-2">Identity</h2>
          <div className="detail-list">
            <div>
              <span>Hostname</span>
              <strong>{peer.hostname || "unknown"}</strong>
            </div>
            <div>
              <span>Public key</span>
              <strong className="font-mono text-xs">
                {peer.public_key} <CopyButton text={peer.public_key} />
              </strong>
            </div>
            <div>
              <span>Created</span>
              <strong>{formatTime(peer.created_at)}</strong>
            </div>
            {peer.revoked_at && (
              <div>
                <span>Revoked</span>
                <strong>{formatTime(peer.revoked_at)}</strong>
              </div>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="mb-2 flex items-center justify-between">
            <h2>Network</h2>
            {!peer.revoked_at && <button onClick={onEdit}>edit IP</button>}
          </div>
          <div className="detail-list">
            <div>
              <span>IPv4 overlay</span>
              <strong>{peer.assigned_ip}</strong>
            </div>
            <div>
              <span>IPv6 overlay</span>
              <strong>{peer.assigned_ip6 || "not assigned"}</strong>
            </div>
            <div>
              <span>Endpoint</span>
              <strong>
                {peer.peer_type === "static"
                  ? peer.gateway_endpoint || "unknown"
                  : endpointOf(peer) || "unknown"}
              </strong>
            </div>
            <div>
              <span>Observed address</span>
              <strong>{peer.observed_ip || "unknown"}</strong>
            </div>
            {peer.peer_type !== "static" && (
              <div>
                <span>NAT</span>
                <strong>{peer.nat_type ? natLabel(peer.nat_type) : "unknown"}</strong>
              </div>
            )}
          </div>
          {editing && (
            <div className="mt-3 flex flex-wrap items-end gap-2 rounded-md border border-line bg-panel-soft p-3">
              <label className="grid gap-1">
                <span className="text-xs text-muted">IPv4</span>
                <input
                  className="w-40"
                  value={peerIP}
                  placeholder={network.network_cidr}
                  onChange={(e) => setPeerIP(e.target.value)}
                />
              </label>
              <label className="grid gap-1">
                <span className="text-xs text-muted">IPv6</span>
                <input
                  className="w-52"
                  value={peerIP6}
                  placeholder={network.network_cidr6}
                  onChange={(e) => setPeerIP6(e.target.value)}
                />
              </label>
              <button className="btn-primary" disabled={saving} onClick={onSave}>
                {saving ? "saving" : "save"}
              </button>
              <button onClick={onCancelEdit}>cancel</button>
            </div>
          )}
        </div>
      </section>

      {peer.peer_type === "static" && !peer.revoked_at && (
        <Section
          title="WireGuard configuration"
          actions={
            <>
              {peer.has_stored_config && !config && (
                <button className="btn-primary" disabled={configLoading} onClick={() => void loadConfig()}>
                  {configLoading ? "loading" : "show config & QR"}
                </button>
              )}
              {config && <button onClick={() => setConfig(null)}>hide</button>}
            </>
          }
        >
          <div className="panel">
            {!peer.has_stored_config && (
              <p className="text-muted">
                This device's private key is not stored, so its config cannot be shown again.
                That happens when the key was supplied by an operator rather than generated
                here, or when the device predates config storage. Create a new device to issue
                a fresh config.
              </p>
            )}

            {peer.has_stored_config && !config && (
              <p className="text-muted">
                Rebuilds this device's config from its stored key, using the current overlay
                network and DNS settings. Reading it is recorded in the audit log.
              </p>
            )}

            {config && <DeviceConfig result={config} peers={peers} />}
          </div>
        </Section>
      )}

      <Section
        title="Lifecycle"
        actions={
          !peer.revoked_at ? (
            <button className="btn-danger" onClick={onRevoke}>
              revoke peer
            </button>
          ) : (
            <button className="btn-danger" onClick={onRemove}>
              remove peer
            </button>
          )
        }
      >
        <div className="notice">
          Revoked peers stop receiving mesh configuration but remain visible for history.
          Removed peers are deleted from the control plane and release their overlay address.
        </div>
      </Section>

      <Section
        title="Connections"
        actions={
          <button className="btn-ghost" onClick={() => ctx.setTab("traffic")}>
            open traffic →
          </button>
        }
      >
        <div className="panel tablewrap">
          <table>
            <thead>
              <tr>
                <th>remote peer</th>
                <th>path</th>
                <th>rx</th>
                <th>tx</th>
                <th className="hidden md:table-cell">last handshake</th>
              </tr>
            </thead>
            <tbody>
              {peerLinks.length === 0 && (
                <tr>
                  <td colSpan={5} className="text-muted">
                    no link reports for this peer yet
                  </td>
                </tr>
              )}
              {peerLinks.slice(0, 8).map((l) => {
                const isReporter = l.peer_id === peer.id;
                return (
                  <tr key={`${l.peer_id}-${l.remote_peer_id}`}>
                    <td>
                      {isReporter
                        ? peerLabel(l.remote_hostname, l.remote_ip)
                        : peerLabel(l.peer_hostname, l.peer_ip)}
                    </td>
                    <td>
                      <PathBadge state={l.path_state} />
                      {l.path_endpoint && <div className="text-xs text-muted">{l.path_endpoint}</div>}
                    </td>
                    <td>{humanBytes(l.rx_bytes)}</td>
                    <td>{humanBytes(l.tx_bytes)}</td>
                    <td className="hidden text-muted md:table-cell">
                      {formatTime(l.last_handshake_at) || "never"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Section>
    </>
  );
}
