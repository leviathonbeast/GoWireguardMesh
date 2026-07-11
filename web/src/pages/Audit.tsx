import { useState } from "react";
import type { AppCtx } from "../appctx";
import { accessMatches, auditMatches } from "../lib/match";
import { PageHead, Paginated, SearchBox, Section } from "../components/ui";
import { AccessEvent, AuditEvent } from "../components/events";

export default function Audit({ ctx }: { ctx: AppCtx }) {
  const { audit, access } = ctx.data;
  const [auditFilter, setAuditFilter] = useState("");
  const [accessFilter, setAccessFilter] = useState("");

  const shownAudit = audit.filter((a) => auditMatches(a, auditFilter));
  const shownAccess = access.filter((a) => accessMatches(a, accessFilter));

  return (
    <>
      <PageHead
        title="Audit Events"
        sub="Security events — enrollment, revocation, ACL and key changes, relay sessions, auth failures — plus request tracing when the access log is enabled."
      />

      <Section
        title="Activity log"
        actions={
          <SearchBox
            value={auditFilter}
            onChange={setAuditFilter}
            placeholder="Search activity by event, peer, IP, path, status…"
            total={audit.length}
            shown={shownAudit.length}
          />
        }
      >
        <div className="panel">
          <div className="activity-head">
            <span>event</span>
            <span>source</span>
            <span>request</span>
            <span>peer</span>
            <span>status</span>
          </div>
          {shownAudit.length === 0 ? (
            <div className="py-2 text-muted">{audit.length ? "no matching events" : "no activity yet"}</div>
          ) : (
            <Paginated items={shownAudit} resetKey={auditFilter}>
              {(pageRows, pager) => (
                <>
                  {pageRows.map((a) => (
                    <AuditEvent key={a.id} a={a} />
                  ))}
                  {pager}
                </>
              )}
            </Paginated>
          )}
        </div>
      </Section>

      <Section
        title="Request log"
        actions={
          <SearchBox
            value={accessFilter}
            onChange={setAccessFilter}
            placeholder="Search requests by method, path, IP, peer, status…"
            total={access.length}
            shown={shownAccess.length}
          />
        }
      >
        <div className="panel">
          <div className="activity-head">
            <span>request</span>
            <span>source</span>
            <span>trace</span>
            <span>peer</span>
            <span>status</span>
          </div>
          {shownAccess.length === 0 ? (
            <div className="py-2 text-muted">
              {access.length ? "no matching requests" : "no request log entries"}
            </div>
          ) : (
            <Paginated items={shownAccess} resetKey={accessFilter}>
              {(pageRows, pager) => (
                <>
                  {pageRows.map((a, i) => (
                    <AccessEvent key={`${a.time}-${i}`} a={a} />
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
