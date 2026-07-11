import { useState } from "react";
import { api } from "../api";
import type { AppCtx } from "../appctx";
import { formatTime } from "../lib/format";
import { setupKeyMatches } from "../lib/match";
import { CopyButton, KeyBadge, PageHead, Paginated, SearchBox, Section } from "../components/ui";

export default function SetupKeys({ ctx }: { ctx: AppCtx }) {
  const { keys } = ctx.data;

  const [filter, setFilter] = useState("");
  const [name, setName] = useState("");
  const [maxUses, setMaxUses] = useState(0);
  const [expiresIn, setExpiresIn] = useState("");

  const shownKeys = keys.filter((k) => setupKeyMatches(k, filter));

  const createKey = async () => {
    ctx.setError("");
    try {
      await api("/api/setup-keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          max_uses: maxUses,
          expires_in: expiresIn.trim(),
        }),
      });
      setName("");
      await ctx.refresh();
      ctx.toast("Setup key created");
    } catch (e) {
      ctx.setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <>
      <PageHead title="Setup Keys" sub="Enrollment credentials for new agents. Revoking a key never affects already-enrolled peers." />

      <Section title="New key">
        <div className="panel">
          <div className="form-grid">
            <label>
              <span>Name</span>
              <input placeholder="Jellyfin sidecar" value={name} onChange={(e) => setName(e.target.value)} />
            </label>
            <label>
              <span>Max uses (0 = unlimited)</span>
              <input
                type="number"
                min={0}
                value={maxUses}
                onChange={(e) => setMaxUses(parseInt(e.target.value, 10) || 0)}
              />
            </label>
            <label>
              <span>Expires in</span>
              <input
                type="text"
                placeholder="never (e.g. 24h)"
                value={expiresIn}
                onChange={(e) => setExpiresIn(e.target.value)}
              />
            </label>
            <div>
              <button className="btn-primary" onClick={() => void createKey()}>
                new setup key
              </button>
            </div>
          </div>
        </div>
      </Section>

      <Section title="Keys">
        <div className="mb-3">
          <SearchBox
            value={filter}
            onChange={setFilter}
            placeholder="Search setup keys by name, key, status, expiry…"
            total={keys.length}
            shown={shownKeys.length}
          />
        </div>
        <div className="panel tablewrap">
          <Paginated items={shownKeys} resetKey={filter}>
            {(pageKeys, pager) => (
              <>
                <table>
                  <thead>
                    <tr>
                      <th>status</th>
                      <th>name</th>
                      <th>key</th>
                      <th>uses</th>
                      <th className="hidden md:table-cell">expires</th>
                      <th className="hidden lg:table-cell">created</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {shownKeys.length === 0 && (
                      <tr>
                        <td colSpan={7} className="text-muted">
                          {keys.length ? "no matching setup keys" : "no setup keys"}
                        </td>
                      </tr>
                    )}
                    {pageKeys.map((k) => (
                      <tr key={k.id}>
                        <td>
                          <KeyBadge k={k} />
                        </td>
                        <td>{k.name || <span className="text-muted">unnamed</span>}</td>
                        <td className="font-mono text-xs">
                          <span className="break-all">{k.key}</span> <CopyButton text={k.key} />
                        </td>
                        <td>
                          {k.uses_consumed}/{k.max_uses > 0 ? k.max_uses : "∞"}
                        </td>
                        <td className="hidden text-muted md:table-cell">{formatTime(k.expires_at) || "never"}</td>
                        <td className="hidden text-muted lg:table-cell">{formatTime(k.created_at)}</td>
                        <td className="text-right">
                          {!k.revoked_at && (
                            <button
                              className="btn-danger"
                              onClick={() =>
                                ctx.confirm({
                                  title: "Revoke setup key?",
                                  message: `Revoke setup key ${k.id}? Agents already enrolled keep working, but this key can no longer enroll or re-enroll peers.`,
                                  confirmLabel: "revoke",
                                  danger: true,
                                  onConfirm: () =>
                                    ctx.postAction(`/api/setup-keys/${k.id}/revoke`, "Setup key revoked"),
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
      </Section>
    </>
  );
}
