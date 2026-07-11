import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import type { LinkStat, Peer, SetupKey } from "../types";
import type { ConfirmAction } from "../appctx";
import { copyToClipboard, setupKeyStatus } from "../lib/format";

export function CopyButton({ text }: { text: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");

  const copy = async () => {
    const ok = await copyToClipboard(text);
    setState(ok ? "copied" : "failed");
    setTimeout(() => setState("idle"), 1500);
  };

  return (
    <button className="btn-ghost px-1.5 py-0.5 text-xs" onClick={() => void copy()}>
      {state === "idle" ? "copy" : state}
    </button>
  );
}

export function Badge({ tone, children }: { tone: "ok" | "warn" | "bad"; children: ReactNode }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function PeerBadge({ peer }: { peer: Peer }) {
  switch (peer.health_status) {
    case "online":
      return <Badge tone="ok">online</Badge>;
    case "stale":
      return <Badge tone="warn">stale</Badge>;
    case "revoked":
      return <Badge tone="bad">revoked</Badge>;
    case "static":
      return <Badge tone="warn">static</Badge>;
    case "offline":
      return <Badge tone="bad">offline</Badge>;
    default:
      return <Badge tone="warn">unknown</Badge>;
  }
}

export function KeyBadge({ k }: { k: SetupKey }) {
  const status = setupKeyStatus(k);
  if (status === "revoked") return <Badge tone="bad">revoked</Badge>;
  if (status === "expired") return <Badge tone="warn">expired</Badge>;
  if (status === "exhausted") return <Badge tone="warn">exhausted</Badge>;
  return <Badge tone="ok">active</Badge>;
}

export function PathBadge({ state }: { state?: LinkStat["path_state"] }) {
  switch (state) {
    case "direct":
      return <Badge tone="ok">direct</Badge>;
    case "probing-direct":
      return <Badge tone="warn">probing-direct</Badge>;
    case "ws-relay":
      return <Badge tone="warn">ws-relay</Badge>;
    case "udp-relay":
      return <Badge tone="warn">udp-relay</Badge>;
    default:
      return <Badge tone="bad">unknown</Badge>;
  }
}

// StatusPill colors an HTTP status code green/neutral/amber/red.
export function StatusPill({ status }: { status?: number }) {
  if (!status) return <span className="pill">-</span>;
  const cls = status >= 500 ? "pill-bad" : status >= 400 ? "pill-warn" : status >= 300 ? "" : "pill-ok";
  return <span className={`pill ${cls}`}>{status}</span>;
}

export function Endpoint({ name, ip }: { name: string; ip?: string }) {
  return (
    <div className="min-w-0">
      <div className="truncate font-medium">{name}</div>
      {ip ? <div className="truncate text-xs text-muted">{ip}</div> : null}
    </div>
  );
}

export function SearchBox({
  value,
  onChange,
  placeholder,
  total,
  shown,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  total: number;
  shown: number;
}) {
  const active = value.trim() !== "";

  return (
    <div className="flex min-w-0 grow items-center gap-2">
      <input
        type="search"
        className="max-w-sm"
        placeholder={placeholder}
        value={value}
        aria-label={placeholder}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Escape") onChange("");
        }}
      />
      {active && (
        <button className="btn-ghost" onClick={() => onChange("")}>
          clear
        </button>
      )}
      <span className="text-xs whitespace-nowrap text-muted">
        {active ? `${shown} of ${total}` : `${total} total`}
      </span>
    </div>
  );
}

const DEFAULT_PAGE_SIZE = 10;
const PAGE_SIZE_OPTIONS = [10, 25, 50, 100] as const;

function PaginationControls({
  page,
  pageSize,
  setPageSize,
  setPage,
  total,
}: {
  page: number;
  pageSize: number;
  setPageSize: (pageSize: number) => void;
  setPage: (fn: (page: number) => number) => void;
  total: number;
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.min(page, totalPages);
  const start = (currentPage - 1) * pageSize;

  return (
    <div className="mt-3 flex flex-wrap items-center gap-3 text-sm">
      <div className="text-muted">
        {start + 1}-{Math.min(start + pageSize, total)} of {total}
      </div>
      <label className="flex items-center gap-1.5">
        <span className="text-xs text-muted">Rows</span>
        <select
          className="w-auto"
          value={pageSize}
          onChange={(e) => setPageSize(parseInt(e.target.value, 10))}
        >
          {PAGE_SIZE_OPTIONS.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </label>
      <div className="ml-auto flex items-center gap-2">
        <button disabled={currentPage <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
          previous
        </button>
        <span className="whitespace-nowrap text-muted">
          page {currentPage} of {totalPages}
        </span>
        <button
          disabled={currentPage >= totalPages}
          onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
        >
          next
        </button>
      </div>
    </div>
  );
}

export function Paginated<T>({
  items,
  resetKey,
  children,
}: {
  items: T[];
  resetKey?: unknown;
  children: (pageItems: T[], pager: ReactNode) => ReactNode;
}) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);

  useEffect(() => {
    setPage(1);
  }, [items.length, pageSize, resetKey]);

  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const start = (currentPage - 1) * pageSize;
  const pageItems = items.slice(start, start + pageSize);
  const pager =
    items.length > DEFAULT_PAGE_SIZE ? (
      <PaginationControls
        page={currentPage}
        pageSize={pageSize}
        setPage={setPage}
        setPageSize={setPageSize}
        total={items.length}
      />
    ) : null;

  return <>{children(pageItems, pager)}</>;
}

export function ConfirmModal({
  action,
  busy,
  onCancel,
  onConfirm,
}: {
  action: ConfirmAction;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="modal-backdrop" role="presentation">
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
        <h2 id="confirm-title">{action.title}</h2>
        <p className="mt-2 text-muted">{action.message}</p>
        <div className="mt-4 flex justify-end gap-2">
          <button disabled={busy} onClick={onCancel}>
            no
          </button>
          <button
            className={action.danger ? "btn-danger" : "btn-primary"}
            disabled={busy}
            onClick={onConfirm}
          >
            {busy ? "working" : action.confirmLabel || "yes"}
          </button>
        </div>
      </div>
    </div>
  );
}

// PageHead gives every page the same linear opening: title, one-line
// description, then the page's primary tools on the right.
export function PageHead({
  title,
  sub,
  children,
}: {
  title: string;
  sub?: string;
  children?: ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1>{title}</h1>
        {sub ? <p className="mt-1 text-[13px] text-muted">{sub}</p> : null}
      </div>
      {children ? <div className="flex flex-wrap items-center gap-2">{children}</div> : null}
    </div>
  );
}

// Section labels a block within a page and optionally carries actions.
export function Section({
  title,
  actions,
  children,
}: {
  title: string;
  actions?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <section className="mt-5">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h2>{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  );
}
