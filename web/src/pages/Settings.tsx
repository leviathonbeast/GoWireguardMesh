import { useEffect, useState } from "react";
import { api } from "../api";
import type { AppCtx } from "../appctx";
import type { DNSConfig, NetworkMigrationPlan } from "../types";
import { parseListInput, splitNameservers } from "../lib/format";
import { migrationChangeMatches } from "../lib/match";
import { Badge, PageHead, Paginated, SearchBox, Section } from "../components/ui";

export default function Settings({ ctx }: { ctx: AppCtx }) {
  const { peers, network, dns } = ctx.data;

  const [networkCIDR, setNetworkCIDR] = useState(network.network_cidr);
  const [networkCIDR6, setNetworkCIDR6] = useState(network.network_cidr6);
  const [plan, setPlan] = useState<NetworkMigrationPlan | null>(null);
  const [confirmText, setConfirmText] = useState("");
  const [migrationFilter, setMigrationFilter] = useState("");

  const [dnsEnabled, setDNSEnabled] = useState(dns.enabled);
  const [dnsMagic, setDNSMagic] = useState(dns.magic_dns);
  const [dnsDomain, setDNSDomain] = useState(dns.domain || "vpn");
  const [dnsNameservers4, setDNSNameservers4] = useState("");
  const [dnsNameservers6, setDNSNameservers6] = useState("");
  const [dnsSearchDomains, setDNSSearchDomains] = useState("vpn");
  const [dnsDirty, setDNSDirty] = useState(false);

  // Reseed the DNS form from each data snapshot until the operator
  // starts editing; their in-progress edits are never clobbered by the
  // 5-second refresh.
  useEffect(() => {
    if (dnsDirty) return;
    seedDNSForm(dns);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dns, dnsDirty]);

  function seedDNSForm(d: DNSConfig) {
    setDNSEnabled(d.enabled);
    setDNSMagic(d.magic_dns);
    setDNSDomain(d.domain || "vpn");
    const nameservers = splitNameservers(d.nameservers);
    setDNSNameservers4(nameservers.v4.join("\n"));
    setDNSNameservers6(nameservers.v6.join("\n"));
    setDNSSearchDomains((d.search_domains || []).join("\n"));
  }

  const previewMigration = async () => {
    ctx.setError("");
    try {
      const p = await api<NetworkMigrationPlan>("/api/network/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          network_cidr: networkCIDR.trim(),
          network_cidr6: networkCIDR6.trim(),
        }),
      });
      setPlan(p);
      setConfirmText("");
      ctx.toast("Migration preview ready");
    } catch (e) {
      ctx.setError(e instanceof Error ? e.message : String(e));
      setPlan(null);
    }
  };

  const applyMigration = async () => {
    ctx.setError("");
    try {
      const p = await api<NetworkMigrationPlan>("/api/network/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          network_cidr: networkCIDR.trim(),
          network_cidr6: networkCIDR6.trim(),
          confirm: confirmText,
        }),
      });
      setPlan(p);
      setNetworkCIDR(p.target.network_cidr);
      setNetworkCIDR6(p.target.network_cidr6);
      setConfirmText("");
      await ctx.refresh();
      ctx.toast("Overlay network updated");
    } catch (e) {
      ctx.setError(e instanceof Error ? e.message : String(e));
    }
  };

  const saveDNS = async () => {
    ctx.setError("");
    try {
      const next = await api<DNSConfig>("/api/dns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled: dnsEnabled,
          magic_dns: dnsMagic,
          domain: dnsDomain.trim(),
          nameservers: [...parseListInput(dnsNameservers4), ...parseListInput(dnsNameservers6)],
          search_domains: parseListInput(dnsSearchDomains),
        }),
      });
      seedDNSForm(next);
      setDNSDirty(false);
      await ctx.refresh();
      ctx.toast("DNS settings updated");
    } catch (e) {
      ctx.setError(e instanceof Error ? e.message : String(e));
    }
  };

  const shownChanges = plan?.changes.filter((c) => migrationChangeMatches(c, migrationFilter)) ?? [];

  const dirty = () => setDNSDirty(true);

  return (
    <>
      <PageHead title="Settings" sub="Overlay network ranges and DNS pushed to peers." />

      <Section title="Overlay network">
        <div className="grid gap-3 lg:grid-cols-2">
          <div className="panel">
            <div className="mb-2 flex items-center justify-between">
              <h2>Current network</h2>
              <Badge tone="ok">active</Badge>
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

          <div className="panel">
            <h2 className="mb-2">Change network</h2>
            <div className="notice-warn notice mb-3">
              Changing the overlay network reassigns every peer. Running agents adopt the new
              interface address from their next report response; restarting an agent also
              re-enrolls it onto the new assignment.
            </div>
            <div className="form-grid">
              <label>
                <span>IPv4 CIDR</span>
                <input
                  value={networkCIDR}
                  placeholder="100.64.0.0/16"
                  onChange={(e) => {
                    setNetworkCIDR(e.target.value);
                    setPlan(null);
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
                    setPlan(null);
                  }}
                />
              </label>
              <div>
                <button className="btn-primary" onClick={() => void previewMigration()}>
                  preview changes
                </button>
              </div>
            </div>
          </div>
        </div>

        {plan && (
          <div className="panel mt-3">
            <div className="mb-2 flex items-center justify-between">
              <h2>Migration preview</h2>
              <Badge tone="warn">{plan.changes.length} peers</Badge>
            </div>
            <div className="notice mb-3">
              {plan.message || "Preview ready. Review the reassignment plan before applying."}
            </div>
            <SearchBox
              value={migrationFilter}
              onChange={setMigrationFilter}
              placeholder="Search migration by peer, old IP, new IP…"
              total={plan.changes.length}
              shown={shownChanges.length}
            />
            <div className="tablewrap mt-2">
              <Paginated items={shownChanges} resetKey={migrationFilter}>
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
                        {shownChanges.length === 0 && (
                          <tr>
                            <td colSpan={4} className="text-muted">
                              {plan.changes.length ? "no matching peers" : "no peers to reassign"}
                            </td>
                          </tr>
                        )}
                        {pageChanges.map((c) => (
                          <tr key={c.id}>
                            <td>{c.hostname || `peer ${c.id}`}</td>
                            <td>
                              <span className="text-muted line-through">{c.old_ip}</span>
                              <div>{c.new_ip}</div>
                            </td>
                            <td>
                              <span className="text-muted line-through">{c.old_ip6 || "none"}</span>
                              <div>{c.new_ip6}</div>
                            </td>
                            <td>
                              {c.revoked_at ? <Badge tone="bad">revoked</Badge> : <Badge tone="warn">will move</Badge>}
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
            <div className="mt-4 flex flex-wrap items-end gap-2 rounded-md border border-bad/40 bg-bad/5 p-3">
              <label className="grid grow gap-1">
                <span className="text-xs text-muted">type REASSIGN OVERLAY NETWORK to apply</span>
                <input value={confirmText} onChange={(e) => setConfirmText(e.target.value)} />
              </label>
              <button
                className="btn-danger"
                disabled={confirmText !== "REASSIGN OVERLAY NETWORK"}
                onClick={() => void applyMigration()}
              >
                apply network migration
              </button>
            </div>
          </div>
        )}
      </Section>

      <Section title="DNS">
        <div className="grid gap-3 lg:grid-cols-2">
          <div className="panel">
            <div className="mb-2 flex items-center justify-between">
              <h2>Current DNS</h2>
              <Badge tone={dns.enabled ? "ok" : "warn"}>{dns.enabled ? "enabled" : "disabled"}</Badge>
            </div>
            <div className="detail-list">
              <div>
                <span>Domain</span>
                <strong>{dns.domain || "vpn"}</strong>
              </div>
              <div>
                <span>IPv4 nameservers</span>
                <strong>{splitNameservers(dns.nameservers).v4.join(", ") || "not configured"}</strong>
              </div>
              <div>
                <span>IPv6 nameservers</span>
                <strong>{splitNameservers(dns.nameservers).v6.join(", ") || "not configured"}</strong>
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

          <div className="panel">
            <h2 className="mb-2">DNS settings</h2>
            <div className="notice mb-3">
              Point nameservers at your CoreDNS container or its overlay IP. Agents apply these
              settings on enroll and on their next report sync.
            </div>
            <div className="form-grid">
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={dnsEnabled}
                  onChange={(e) => {
                    setDNSEnabled(e.target.checked);
                    dirty();
                  }}
                />
                enable DNS push
              </label>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={dnsMagic}
                  onChange={(e) => {
                    setDNSMagic(e.target.checked);
                    dirty();
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
                    dirty();
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
                    dirty();
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
                    dirty();
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
                    dirty();
                  }}
                />
              </label>
              <div>
                <button className="btn-primary" onClick={() => void saveDNS()}>
                  save DNS settings
                </button>
              </div>
            </div>
          </div>
        </div>
      </Section>
    </>
  );
}
