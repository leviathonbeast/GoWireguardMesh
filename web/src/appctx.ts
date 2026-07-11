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

export const TABS = [
  "overview",
  "machines",
  "policies",
  "setup",
  "traffic",
  "logs",
  "proxy",
  "settings",
  "account",
] as const;

export type Tab = (typeof TABS)[number];

export type ConfirmAction = {
  title: string;
  message: string;
  confirmLabel?: string;
  danger?: boolean;
  onConfirm: () => Promise<void> | void;
};

// AppData is one consistent snapshot of everything the dashboard shows,
// refreshed as a unit every 5 seconds.
export type AppData = {
  peers: Peer[];
  keys: SetupKey[];
  links: LinkStat[];
  flows: Flow[];
  connEvents: ConnectionEvent[];
  proxyEvents: ProxyEvent[];
  acl: AclResponse;
  audit: AuditRow[];
  access: AccessLogRow[];
  network: NetworkConfig;
  dns: DNSConfig;
  account: Account | null;
  users: Account[];
};

// AppCtx is what every page receives from the shell: the data snapshot
// plus the shared imperative surface (refresh, toasts, confirm dialogs,
// error reporting, navigation).
export type AppCtx = {
  data: AppData;
  refresh: () => Promise<void>;
  toast: (message: string) => void;
  confirm: (action: ConfirmAction) => void;
  // postAction fires an admin POST, refreshes the snapshot, and toasts.
  postAction: (path: string, success: string) => Promise<void>;
  setError: (message: string) => void;
  setTab: (tab: Tab) => void;
};
