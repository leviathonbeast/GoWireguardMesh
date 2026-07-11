import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api, login, logout } from "./api";
import type {
  AccessLogRow,
  Account,
  AclResponse,
  AuditRow,
  ConnectionEvent,
  DNSConfig,
  Flow,
  LinkStat,
  NetworkConfig,
  Peer,
  ProxyEvent,
  SetupKey,
} from "./types";
import type { AppCtx, AppData, ConfirmAction, Tab } from "./appctx";
import { ConfirmModal } from "./components/ui";
import Overview from "./pages/Overview";
import Peers from "./pages/Peers";
import Traffic from "./pages/Traffic";
import Proxy from "./pages/Proxy";
import Audit from "./pages/Audit";
import Policies from "./pages/Policies";
import SetupKeys from "./pages/SetupKeys";
import Settings from "./pages/Settings";
import AccountPage from "./pages/Account";

const TAB_LABEL: Record<Tab, string> = {
  overview: "Overview",
  machines: "Peers",
  policies: "Policies",
  setup: "Setup Keys",
  traffic: "Traffic Events",
  proxy: "Proxy Events",
  logs: "Audit Events",
  settings: "Settings",
  account: "Account",
};

// The sidebar is three flat, always-visible groups — network objects,
// then monitoring, then administration — so every destination is one
// click away and reads top-to-bottom.
const NAV_GROUPS: { label: string; tabs: Tab[] }[] = [
  { label: "Network", tabs: ["overview", "machines", "policies", "setup"] },
  { label: "Monitor", tabs: ["traffic", "proxy", "logs"] },
  { label: "Admin", tabs: ["settings", "account"] },
];

const EMPTY_DATA: AppData = {
  peers: [],
  keys: [],
  links: [],
  flows: [],
  connEvents: [],
  proxyEvents: [],
  acl: { default_policy: "allow", rules: [] },
  audit: [],
  access: [],
  network: { network_cidr: "", network_cidr6: "" },
  dns: { enabled: false, magic_dns: true, domain: "vpn", nameservers: [], search_domains: ["vpn"] },
  account: null,
  users: [],
};

async function loadDashboard(): Promise<AppData> {
  const [peers, keys, links, flows, acl, audit, access, network, dns, connEvents, proxyEvents] =
    await Promise.all([
      api<Peer[]>("/api/peers"),
      api<SetupKey[]>("/api/setup-keys"),
      api<LinkStat[]>("/api/link-stats"),
      api<Flow[]>("/api/flows?limit=1000"),
      api<AclResponse>("/api/acl"),
      api<AuditRow[]>("/api/audit?limit=1000"),
      api<AccessLogRow[]>("/api/access-log?limit=1000"),
      api<NetworkConfig>("/api/network"),
      api<DNSConfig>("/api/dns"),
      api<ConnectionEvent[]>("/api/connection-events?limit=1000"),
      api<ProxyEvent[]>("/api/proxy-events?limit=1000"),
    ]);

  // Account endpoints are session-scoped; a transient failure there
  // must not take down the whole dashboard refresh.
  const account = await api<Account>("/api/account").catch(() => null);
  const users = await api<Account[]>("/api/users").catch(() => [] as Account[]);

  return { peers, keys, links, flows, connEvents, proxyEvents, acl, audit, access, network, dns, account, users };
}

function Brand() {
  return (
    <div className="flex items-center gap-2.5">
      <div className="grid size-9 place-items-center rounded-lg border border-accent/55 font-bold text-accent">
        wg
      </div>
      <div>
        <div className="leading-tight font-bold">wgmesh</div>
        <div className="text-xs text-muted">control plane</div>
      </div>
    </div>
  );
}

// SessionGate renders when there is no valid session cookie: on a
// mid-session expiry, or under `npm run dev` where the SPA is served by
// Vite instead of the (session-gated) control plane. It posts to the
// same /ui-login the server-rendered login form uses.
function SessionGate({ message, onSignedIn }: { message: string; onSignedIn: () => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const signIn = async () => {
    setBusy(true);
    setError("");
    try {
      await login(username.trim(), password);
      onSignedIn();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-dvh place-items-center p-4">
      <div className="panel w-full max-w-sm">
        <div className="border-b border-line pb-4">
          <Brand />
        </div>
        {message && <p className="mt-3 text-sm text-warn">{message}</p>}
        <div className="mt-4 grid gap-3">
          <label className="grid gap-1.5">
            <span className="text-xs text-muted">Username</span>
            <input
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </label>
          <label className="grid gap-1.5">
            <span className="text-xs text-muted">Password</span>
            <input
              type="password"
              autoComplete="current-password"
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void signIn()}
            />
          </label>
          <button className="btn-primary" disabled={busy || !password} onClick={() => void signIn()}>
            {busy ? "signing in" : "sign in"}
          </button>
          {error && <div className="text-sm text-bad">{error}</div>}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [phase, setPhase] = useState<"checking" | "signedOut" | "ready">("checking");
  const [gateMessage, setGateMessage] = useState("");
  const [data, setData] = useState<AppData>(EMPTY_DATA);
  const [tab, setTab] = useState<Tab>("overview");
  const [navOpen, setNavOpen] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [confirmAction, setConfirmAction] = useState<ConfirmAction | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);

  // wasReady distinguishes a mid-session expiry (worth a message) from
  // the initial cookie check simply finding no session.
  const wasReady = useRef(false);

  const refresh = useCallback(async () => {
    try {
      setData(await loadDashboard());
      wasReady.current = true;
      setPhase("ready");
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setGateMessage(wasReady.current ? "session expired — sign in again" : "");
        wasReady.current = false;
        setPhase("signedOut");
        setData(EMPTY_DATA);
        return;
      }
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  // ctxRefresh is the page-facing refresh: it also clears the sticky
  // error banner, so a successful action wipes stale failures.
  const ctxRefresh = useCallback(async () => {
    setError("");
    await refresh();
  }, [refresh]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (phase !== "ready" || !autoRefresh) return;

    const id = window.setInterval(() => {
      void refresh();
    }, 5000);

    return () => window.clearInterval(id);
  }, [phase, autoRefresh, refresh]);

  useEffect(() => {
    if (!toast) return;

    const id = window.setTimeout(() => setToast(""), 3200);
    return () => window.clearTimeout(id);
  }, [toast]);

  const postAction = useCallback(
    async (path: string, success: string) => {
      setError("");
      await api(path, { method: "POST" });
      await refresh();
      setToast(success);
    },
    [refresh],
  );

  const runConfirmAction = async () => {
    if (!confirmAction) return;

    setConfirmBusy(true);
    setError("");
    try {
      await confirmAction.onConfirm();
      setConfirmAction(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setConfirmBusy(false);
    }
  };

  if (phase === "checking") {
    return <div className="grid min-h-dvh place-items-center text-muted">loading…</div>;
  }

  if (phase === "signedOut") {
    return (
      <SessionGate
        message={gateMessage}
        onSignedIn={() => {
          setGateMessage("");
          void refresh();
        }}
      />
    );
  }

  const ctx: AppCtx = {
    data,
    refresh: ctxRefresh,
    toast: setToast,
    confirm: setConfirmAction,
    postAction,
    setError,
    setTab: (t) => {
      setTab(t);
      setNavOpen(false);
    },
  };

  const nav = (
    <nav className="flex grow flex-col gap-4 overflow-y-auto pt-4">
      {NAV_GROUPS.map((group) => (
        <div key={group.label}>
          <div className="px-2.5 pb-1.5 text-[11px] font-semibold tracking-widest text-muted/70 uppercase">
            {group.label}
          </div>
          <div className="flex flex-col gap-0.5">
            {group.tabs.map((t) => (
              <button
                key={t}
                className={`side-link ${tab === t ? "side-link-active" : ""}`}
                onClick={() => ctx.setTab(t)}
              >
                {TAB_LABEL[t]}
              </button>
            ))}
          </div>
        </div>
      ))}
      <div className="mt-auto border-t border-line pt-3">
        <div className="flex items-center justify-between gap-2 px-2.5">
          <span className="truncate text-xs text-muted">{data.account?.username ?? "signed in"}</span>
          <button className="btn-ghost text-xs" onClick={() => void logout()}>
            sign out
          </button>
        </div>
      </div>
    </nav>
  );

  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[232px_minmax(0,1fr)]">
      {/* Desktop sidebar */}
      <aside className="sticky top-0 hidden h-dvh flex-col border-r border-line bg-sidebar p-3.5 lg:flex">
        <div className="border-b border-line pb-4">
          <Brand />
        </div>
        {nav}
      </aside>

      {/* Mobile drawer */}
      {navOpen && (
        <div className="fixed inset-0 z-40 lg:hidden" role="presentation">
          <div className="absolute inset-0 bg-black/60" onClick={() => setNavOpen(false)} />
          <aside className="absolute inset-y-0 left-0 flex w-64 flex-col border-r border-line bg-sidebar p-3.5">
            <div className="flex items-center justify-between border-b border-line pb-4">
              <Brand />
              <button className="btn-ghost" aria-label="close menu" onClick={() => setNavOpen(false)}>
                ✕
              </button>
            </div>
            {nav}
          </aside>
        </div>
      )}

      <div className="min-w-0">
        {/* Top bar */}
        <header className="sticky top-0 z-30 flex items-center justify-between gap-3 border-b border-line bg-bg/95 px-4 py-2.5 backdrop-blur">
          <div className="flex items-center gap-3">
            <button
              className="lg:hidden"
              aria-label="open menu"
              aria-expanded={navOpen}
              onClick={() => setNavOpen(true)}
            >
              ☰
            </button>
            <span className="font-semibold lg:hidden">wgmesh</span>
            <span className="hidden text-sm text-muted lg:inline">{TAB_LABEL[tab]}</span>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={() => void ctxRefresh()}>refresh</button>
            <label className="toggle text-muted">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
              />
              5s auto
            </label>
          </div>
        </header>

        <main className="px-4 py-5 pb-16 lg:px-6">
          {error && (
            <div className="mb-4 rounded-md border border-bad/40 bg-bad/10 px-3 py-2 text-sm text-bad">
              {error}
            </div>
          )}

          {tab === "overview" && <Overview ctx={ctx} />}
          {tab === "machines" && <Peers ctx={ctx} />}
          {tab === "policies" && <Policies ctx={ctx} />}
          {tab === "setup" && <SetupKeys ctx={ctx} />}
          {tab === "traffic" && <Traffic ctx={ctx} />}
          {tab === "proxy" && <Proxy ctx={ctx} />}
          {tab === "logs" && <Audit ctx={ctx} />}
          {tab === "settings" && <Settings ctx={ctx} />}
          {tab === "account" && <AccountPage ctx={ctx} />}
        </main>
      </div>

      {confirmAction && (
        <ConfirmModal
          action={confirmAction}
          busy={confirmBusy}
          onCancel={() => !confirmBusy && setConfirmAction(null)}
          onConfirm={() => void runConfirmAction()}
        />
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
