import { useState } from "react";
import { api } from "../api";
import type { AppCtx } from "../appctx";
import type { AclExport, AclResponse } from "../types";
import { downloadText, formatTime, peerLabel, serviceLabel } from "../lib/format";
import { aclMatches } from "../lib/match";
import { PageHead, Paginated, SearchBox, Section } from "../components/ui";

export default function Policies({ ctx }: { ctx: AppCtx }) {
  const { peers, acl } = ctx.data;

  const [filter, setFilter] = useState("");
  const [name, setName] = useState("");
  const [src, setSrc] = useState("any");
  const [dst, setDst] = useState("any");
  const [protocol, setProtocol] = useState("any");
  const [portMin, setPortMin] = useState("");
  const [portMax, setPortMax] = useState("");
  const [importReplace, setImportReplace] = useState(true);
  const [importing, setImporting] = useState(false);

  const shownRules = acl.rules.filter((r) => aclMatches(r, filter));
  const activePeers = peers.filter((p) => !p.revoked_at);

  const createRule = async () => {
    ctx.setError("");
    try {
      await api("/api/acl", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          src_peer_id: src === "any" ? null : parseInt(src, 10),
          dst_peer_id: dst === "any" ? null : parseInt(dst, 10),
          name: name.trim(),
          protocol,
          port_min: portMin.trim() ? parseInt(portMin, 10) : null,
          port_max: portMax.trim() ? parseInt(portMax, 10) : null,
        }),
      });
      setName("");
      setPortMin("");
      setPortMax("");
      await ctx.refresh();
      ctx.toast("ACL rule added");
    } catch (e) {
      ctx.setError(e instanceof Error ? e.message : String(e));
    }
  };

  const exportAcl = async () => {
    ctx.setError("");
    try {
      const payload = await api<AclExport>("/api/acl/export");
      downloadText(
        `wgmesh-acl-${new Date().toISOString().replace(/[:.]/g, "-")}.json`,
        JSON.stringify(payload, null, 2) + "\n",
        "application/json",
      );
      ctx.toast("ACL export downloaded");
    } catch (e) {
      ctx.setError(e instanceof Error ? e.message : String(e));
    }
  };

  const importAclFile = async (file: File) => {
    ctx.setError("");
    setImporting(true);
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

      await api<AclResponse>("/api/acl/import", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          replace: importReplace,
          rules,
        }),
      });
      await ctx.refresh();
      setFilter("");
      ctx.toast(importReplace ? "ACL rules replaced" : "ACL rules imported");
    } catch (e) {
      ctx.setError(e instanceof Error ? e.message : String(e));
    } finally {
      setImporting(false);
    }
  };

  const importAcl = (file: File | null) => {
    if (!file) return;

    if (importReplace) {
      ctx.confirm({
        title: "Import ACL rules?",
        message: "This will replace all existing ACL rules with the selected file.",
        confirmLabel: "import",
        danger: true,
        onConfirm: () => importAclFile(file),
      });
      return;
    }

    void importAclFile(file);
  };

  const peerOptions = activePeers.map((p) => (
    <option key={p.id} value={p.id}>
      {peerLabel(p.hostname, p.assigned_ip)}
    </option>
  ));

  return (
    <>
      <PageHead
        title="Policies"
        sub={
          acl.default_policy === "allow"
            ? "Default policy: allow — every peer sees every peer; rules apply when the server runs with --default-policy deny."
            : "Default policy: deny — peers only see each other when a rule connects them."
        }
      />

      <Section title="Add rule">
        <div className="panel">
          <div className="form-grid">
            <label>
              <span>Name</span>
              <input placeholder="Jellyfin access" value={name} onChange={(e) => setName(e.target.value)} />
            </label>
            <label>
              <span>Source</span>
              <select value={src} onChange={(e) => setSrc(e.target.value)}>
                <option value="any">any</option>
                {peerOptions}
              </select>
            </label>
            <label>
              <span>Destination</span>
              <select value={dst} onChange={(e) => setDst(e.target.value)}>
                <option value="any">any</option>
                {peerOptions}
              </select>
            </label>
            <label>
              <span>Protocol</span>
              <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
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
                value={portMin}
                disabled={protocol === "icmp" || protocol === "icmpv6"}
                onChange={(e) => setPortMin(e.target.value)}
              />
            </label>
            <label>
              <span>Port to</span>
              <input
                type="number"
                min={1}
                max={65535}
                placeholder="same"
                value={portMax}
                disabled={protocol === "icmp" || protocol === "icmpv6"}
                onChange={(e) => setPortMax(e.target.value)}
              />
            </label>
            <div>
              <button className="btn-primary" onClick={() => void createRule()}>
                add rule
              </button>
            </div>
          </div>
        </div>
      </Section>

      <Section
        title="Rules"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <button onClick={() => void exportAcl()}>export</button>
            <label className="toggle">
              <input
                type="checkbox"
                checked={importReplace}
                onChange={(e) => setImportReplace(e.target.checked)}
              />
              replace existing
            </label>
            <label className="cursor-pointer rounded-md border border-line bg-panel-soft px-3 py-1.5">
              {importing ? "importing" : "import"}
              <input
                type="file"
                className="hidden"
                accept="application/json,.json"
                disabled={importing}
                onChange={(e) => {
                  const file = e.currentTarget.files?.[0] ?? null;
                  e.currentTarget.value = "";
                  importAcl(file);
                }}
              />
            </label>
          </div>
        }
      >
        <div className="mb-3">
          <SearchBox
            value={filter}
            onChange={setFilter}
            placeholder="Search ACLs by name, source, destination, protocol, port…"
            total={acl.rules.length}
            shown={shownRules.length}
          />
        </div>
        <div className="panel tablewrap">
          <Paginated items={shownRules} resetKey={filter}>
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
                      <th className="hidden md:table-cell">created</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {shownRules.length === 0 && (
                      <tr>
                        <td colSpan={7} className="text-muted">
                          {acl.rules.length ? "no matching rules" : "no rules"}
                        </td>
                      </tr>
                    )}
                    {pageRules.map((r) => (
                      <tr key={r.id}>
                        <td>{r.id}</td>
                        <td>{r.name || <span className="text-muted">unnamed</span>}</td>
                        <td>{r.src_label}</td>
                        <td>{r.dst_label}</td>
                        <td>{serviceLabel(r)}</td>
                        <td className="hidden text-muted md:table-cell">{formatTime(r.created_at)}</td>
                        <td className="text-right">
                          <button
                            className="btn-danger"
                            onClick={() =>
                              ctx.confirm({
                                title: "Delete ACL rule?",
                                message: `Delete ACL rule ${r.id} (${r.src_label} to ${r.dst_label})?`,
                                confirmLabel: "delete",
                                danger: true,
                                onConfirm: () => ctx.postAction(`/api/acl/${r.id}/delete`, "ACL rule deleted"),
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
      </Section>
    </>
  );
}
