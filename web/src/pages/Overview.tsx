import type { AppCtx } from "../appctx";
import { Endpoint, PageHead, PathBadge, PeerBadge } from "../components/ui";

export default function Overview({ ctx }: { ctx: AppCtx }) {
  const { peers, links, keys, acl, network } = ctx.data;

  const activePeers = peers.filter((p) => !p.revoked_at);
  const onlinePeers = activePeers.filter((p) => p.health_status === "online");
  const directLinks = links.filter((l) => l.path_state === "direct");
  const relayedLinks = links.filter((l) =>
    l.path_state === "quic-relay" || l.path_state === "ws-relay" || l.path_state === "udp-relay"
  );
  const activeKeys = keys.filter((k) => !k.revoked_at && !(k.max_uses > 0 && k.uses_consumed >= k.max_uses));

  return (
    <>
      <PageHead
        title="Overview"
        sub={`${network.network_cidr || "overlay"}${network.network_cidr6 ? ` · ${network.network_cidr6}` : ""}`}
      />

      <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div className="metric">
          <div className="metric-label">peers</div>
          <div className="metric-value">{activePeers.length}</div>
          <div className="text-xs text-muted">{onlinePeers.length} online</div>
        </div>
        <div className="metric">
          <div className="metric-label">direct links</div>
          <div className="metric-value">{directLinks.length}</div>
          <div className="text-xs text-muted">{relayedLinks.length} relayed</div>
        </div>
        <div className="metric">
          <div className="metric-label">setup keys</div>
          <div className="metric-value">{activeKeys.length}</div>
          <div className="text-xs text-muted">{keys.length} total</div>
        </div>
        <div className="metric">
          <div className="metric-label">ACL policy</div>
          <div className="metric-value">{acl.default_policy}</div>
          <div className="text-xs text-muted">{acl.rules.length} rules</div>
        </div>
      </section>

      <section className="mt-4 grid gap-3 lg:grid-cols-2">
        <div className="panel">
          <div className="mb-2 flex items-center justify-between">
            <h2>Recent peers</h2>
            <button className="btn-ghost" onClick={() => ctx.setTab("machines")}>
              view all →
            </button>
          </div>
          <div className="grid gap-1">
            {activePeers.slice(0, 6).map((p) => (
              <div
                className="flex items-center justify-between gap-3 border-b border-line/60 py-1.5 last:border-b-0"
                key={p.id}
              >
                <Endpoint name={p.hostname || p.assigned_ip} ip={p.assigned_ip6 || p.assigned_ip} />
                <PeerBadge peer={p} />
              </div>
            ))}
            {activePeers.length === 0 && <div className="text-muted">no peers enrolled</div>}
          </div>
        </div>
        <div className="panel">
          <div className="mb-2 flex items-center justify-between">
            <h2>Path state</h2>
            <button className="btn-ghost" onClick={() => ctx.setTab("traffic")}>
              inspect →
            </button>
          </div>
          <div className="grid gap-1">
            {links.slice(0, 6).map((l) => (
              <div
                className="flex items-center justify-between gap-3 border-b border-line/60 py-1.5 last:border-b-0"
                key={`${l.peer_id}-${l.remote_peer_id}`}
              >
                <Endpoint name={`${l.peer_hostname || l.peer_ip} → ${l.remote_hostname || l.remote_ip}`} />
                <PathBadge state={l.path_state} />
              </div>
            ))}
            {links.length === 0 && <div className="text-muted">no link reports yet</div>}
          </div>
        </div>
      </section>
    </>
  );
}
