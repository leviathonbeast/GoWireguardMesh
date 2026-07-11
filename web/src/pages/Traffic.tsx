import { useCallback, useState } from "react";
import type { AppCtx } from "../appctx";
import { formatTime, humanBytes, peerLabel } from "../lib/format";
import { flowMatches, linkMatches } from "../lib/match";
import { PageHead, Paginated, PathBadge, SearchBox, Section } from "../components/ui";
import { ConnectionEventRow, FlowEvent } from "../components/events";

export default function Traffic({ ctx }: { ctx: AppCtx }) {
  const { peers, links, flows, connEvents } = ctx.data;
  const [filter, setFilter] = useState("");

  // ipName resolves an overlay IP to a peer hostname (both sides of a
  // flow get named, like NetBird), falling back to the raw IP.
  const ipName = useCallback(
    (ip: string) => peers.find((p) => p.assigned_ip === ip || p.assigned_ip6 === ip)?.hostname || ip,
    [peers],
  );

  const shownLinks = links.filter((l) => linkMatches(l, filter));
  const shownFlows = flows.filter((f) => flowMatches(f, filter, ipName(f.src_ip), ipName(f.dst_ip)));

  return (
    <>
      <PageHead title="Traffic" sub="Connection events, live links, and per-flow telemetry.">
        <SearchBox
          value={filter}
          onChange={setFilter}
          placeholder="Search traffic by peer, IP, path, protocol, port…"
          total={flows.length + links.length}
          shown={shownFlows.length + shownLinks.length}
        />
      </PageHead>

      <Section title="Connection events">
        <div className="panel">
          {connEvents.length === 0 ? (
            <div className="text-muted">no connection events yet</div>
          ) : (
            <Paginated items={connEvents} resetKey={filter}>
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
      </Section>

      <Section title="Links">
        <div className="panel tablewrap">
          <Paginated items={shownLinks} resetKey={filter}>
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
                      <th className="hidden md:table-cell">last handshake</th>
                      <th className="hidden lg:table-cell">updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {shownLinks.length === 0 && (
                      <tr>
                        <td colSpan={7} className="text-muted">
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
                          {l.path_endpoint && <div className="text-xs text-muted">{l.path_endpoint}</div>}
                        </td>
                        <td>{humanBytes(l.rx_bytes)}</td>
                        <td>{humanBytes(l.tx_bytes)}</td>
                        <td className="hidden text-muted md:table-cell">
                          {formatTime(l.last_handshake_at) || "never"}
                        </td>
                        <td className="hidden text-muted lg:table-cell">{formatTime(l.updated_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {pager}
              </>
            )}
          </Paginated>
        </div>
      </Section>

      <Section title="Traffic events">
        <div className="panel">
          <div className="activity-head">
            <span>event</span>
            <span>source</span>
            <span>protocol &amp; port</span>
            <span>destination</span>
            <span>traffic</span>
          </div>
          {shownFlows.length === 0 ? (
            <div className="py-2 text-muted">{flows.length ? "no matching flows" : "no flows recorded"}</div>
          ) : (
            <Paginated items={shownFlows} resetKey={filter}>
              {(pageRows, pager) => (
                <>
                  {pageRows.map((f) => (
                    <FlowEvent key={f.id} f={f} ipName={ipName} />
                  ))}
                  {pager}
                </>
              )}
            </Paginated>
          )}
        </div>
      </Section>
    </>
  );
}
