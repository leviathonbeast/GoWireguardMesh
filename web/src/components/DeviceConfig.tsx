import { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { api } from "../api";
import type { MobilePeerResponse, Peer } from "../types";
import { configFileName, downloadText, gatewayCandidates, gatewayName, suggestEndpoint } from "../lib/format";
import { CopyButton } from "./ui";

/**
 * DeviceConfig renders a static peer's WireGuard config as a QR code to
 * scan, a listing to copy, and a .conf to download. It is shown when the
 * device is created and again from the peer's details page, which rebuilds
 * the same config from the sealed private key.
 */
export function DeviceConfig({ result, peers }: { result: MobilePeerResponse; peers: Peer[] }) {
  const label = result.peer.hostname || `peer ${result.peer.id}`;

  return (
    <>
      <div className="mt-3 grid gap-4 sm:grid-cols-[auto_minmax(0,1fr)]">
        <div className="w-fit rounded-lg bg-white p-2">
          <QRCodeSVG
            className="block h-auto w-56 max-w-full"
            value={result.config}
            size={256}
            level="L"
            marginSize={4}
            title={`WireGuard configuration for ${label}`}
          />
        </div>
        <div className="grid content-start gap-3">
          <p>
            In the WireGuard app, add a tunnel by <strong>scanning from a QR code</strong>. Or
            download the config and import it.
          </p>
          <div className="detail-list">
            <div>
              <span>Overlay IPv4</span>
              <strong>{result.peer.assigned_ip}</strong>
            </div>
            {result.peer.assigned_ip6 && (
              <div>
                <span>Overlay IPv6</span>
                <strong>{result.peer.assigned_ip6}</strong>
              </div>
            )}
            <div>
              <span>Gateway</span>
              <strong>
                {result.peer.gateway_peer_id
                  ? gatewayName(peers, result.peer.gateway_peer_id)
                  : "none"}
              </strong>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <CopyButton text={result.config} />
            <button
              onClick={() => downloadText(configFileName(result.peer), result.config, "text/plain")}
            >
              download .conf
            </button>
          </div>
        </div>
      </div>

      <p className="mt-3 text-sm text-warn">
        This config contains the device's private key. Anyone who scans this code can join the mesh
        as {label}.
      </p>

      <pre className="config-block mt-2">{result.config}</pre>

      {result.warnings?.map((warning) => (
        <p className="mt-2 text-muted" key={warning}>
          {warning}
        </p>
      ))}
    </>
  );
}

/**
 * StaticPeerDialog enrolls a device that runs stock WireGuard rather than
 * the wgmesh agent — a phone, a router, an appliance — and hands back its
 * config as a QR code to scan and a .conf to download.
 *
 * When the control plane generates the key it also stores it sealed, so
 * the config can be shown again later from the peer's details page. A
 * key supplied by the operator is never stored, and that config is shown
 * exactly once.
 */
export function StaticPeerDialog({
  peers,
  onCreated,
  onClose,
}: {
  peers: Peer[];
  onCreated: () => Promise<void>;
  onClose: () => void;
}) {
  const gateways = gatewayCandidates(peers);
  const [name, setName] = useState("");
  const [gatewayKey, setGatewayKey] = useState(gateways[0]?.public_key ?? "");
  const [endpoint, setEndpoint] = useState(() => suggestEndpoint(gateways[0]));
  const [endpointEdited, setEndpointEdited] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<MobilePeerResponse | null>(null);

  const selectGateway = (key: string) => {
    setGatewayKey(key);
    if (!endpointEdited) setEndpoint(suggestEndpoint(gateways.find((p) => p.public_key === key)));
  };

  const create = async () => {
    setBusy(true);
    setError("");
    try {
      const created = await api<MobilePeerResponse>("/api/mobile-peers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          gateway_public_key: gatewayKey,
          gateway_endpoint: endpoint.trim(),
        }),
      });
      setResult(created);
      await onCreated();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation">
      <div className="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby="static-title">
        <h2 id="static-title">
          {result
            ? `Scan to configure ${result.peer.hostname || `peer ${result.peer.id}`}`
            : "Add a WireGuard device"}
        </h2>

        {!result && (
          <>
            <p className="mt-2 text-muted">
              For devices that run the official WireGuard client instead of the wgmesh agent.
              The device joins as a static peer routed through a gateway agent, keeping its own
              overlay address end to end.
            </p>

            <div className="form-grid mt-3">
              <label>
                <span>Name</span>
                <input
                  placeholder="pixel-8"
                  value={name}
                  autoFocus
                  onChange={(e) => setName(e.target.value)}
                />
              </label>
              <label>
                <span>Gateway</span>
                <select value={gatewayKey} onChange={(e) => selectGateway(e.target.value)}>
                  {gateways.map((p) => (
                    <option key={p.id} value={p.public_key}>
                      {p.hostname || `peer ${p.id}`} ({p.assigned_ip})
                    </option>
                  ))}
                </select>
              </label>
              <label>
                <span>Gateway endpoint</span>
                <input
                  placeholder="vpn.example.com:51820"
                  value={endpoint}
                  onChange={(e) => {
                    setEndpointEdited(true);
                    setEndpoint(e.target.value);
                  }}
                />
              </label>
            </div>
            <p className="mt-3 text-muted">
              The device dials this address over UDP, so it must be reachable from wherever the
              device roams. Static peers cannot use the wgmesh relay.
            </p>
          </>
        )}

        {result && <DeviceConfig result={result} peers={peers} />}

        {error && <div className="mt-3 text-bad">{error}</div>}

        <div className="mt-4 flex justify-end gap-2">
          <button disabled={busy} onClick={onClose}>
            {result ? "done" : "cancel"}
          </button>
          {!result && (
            <button
              className="btn-primary"
              disabled={busy || !gatewayKey || !endpoint.trim()}
              onClick={() => void create()}
            >
              {busy ? "creating" : "create device"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
