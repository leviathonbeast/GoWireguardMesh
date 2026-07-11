import { useState } from "react";
import type { AppCtx } from "../appctx";
import type { ProxyEvent } from "../types";
import { formatDuration, formatTime, humanBytes } from "../lib/format";
import { proxyMatches } from "../lib/match";
import { PageHead, Paginated, SearchBox, StatusPill } from "../components/ui";

function proxyRequest(e: ProxyEvent): string {
  return `${e.host || ""}${e.path || ""}` || "-";
}

export default function Proxy({ ctx }: { ctx: AppCtx }) {
  const { proxyEvents } = ctx.data;
  const [filter, setFilter] = useState("");

  const shown = proxyEvents.filter((e) => proxyMatches(e, filter));

  return (
    <>
      <PageHead title="Proxy Events" sub="HTTP requests seen by Traefik, ingested from its access log.">
        <SearchBox
          value={filter}
          onChange={setFilter}
          placeholder="Search proxy events by host, path, method, status, client…"
          total={proxyEvents.length}
          shown={shown.length}
        />
      </PageHead>

      <div className="panel tablewrap">
        <Paginated items={shown} resetKey={filter}>
          {(page, pager) => (
            <>
              <table>
                <thead>
                  <tr>
                    <th>time</th>
                    <th>method</th>
                    <th>request</th>
                    <th>status</th>
                    <th className="hidden md:table-cell">duration</th>
                    <th className="hidden md:table-cell">size</th>
                    <th className="hidden lg:table-cell">client</th>
                    <th className="hidden lg:table-cell">service</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.length === 0 && (
                    <tr>
                      <td colSpan={8} className="text-muted">
                        {proxyEvents.length
                          ? "no matching proxy events"
                          : "no proxy events — enable Traefik access-log ingestion on an agent (--traefik-access-log)"}
                      </td>
                    </tr>
                  )}
                  {page.map((e) => (
                    <tr key={e.id}>
                      <td className="whitespace-nowrap text-muted">{formatTime(e.at)}</td>
                      <td>
                        <span className="pill">{e.method || "-"}</span>
                      </td>
                      <td className="max-w-64 lg:max-w-96" title={proxyRequest(e)}>
                        <div className="truncate">
                          {e.host}
                          <span className="text-muted">{e.path}</span>
                        </div>
                      </td>
                      <td>
                        <StatusPill status={e.status} />
                      </td>
                      <td className="hidden text-muted md:table-cell">{formatDuration(e.duration_ms)}</td>
                      <td className="hidden text-muted md:table-cell">
                        {humanBytes((e.req_bytes || 0) + (e.resp_bytes || 0))}
                      </td>
                      <td className="hidden text-muted lg:table-cell">{e.client_ip}</td>
                      <td className="hidden text-muted lg:table-cell">{e.service}</td>
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
  );
}
