import { CircleAlert, CircleCheck, CircleX, LoaderCircle, type LucideIcon } from "lucide-react";

export const fields = [
  "Artifacts complete",
  "Repository integrity checked",
  "Decryption tested",
  "Application consistency assessed",
  "Restored in isolation",
  "Health checks passed",
  "Independent copy confirmed",
] as const;

export type Mark = "pass" | "fail" | "unknown" | "not_run";

const all = (mark: Mark): Mark[] => fields.map(() => mark);

export type Site = {
  id: string;
  domain: string;
  serving: string;
  servingKind: "ok" | "err" | "muted" | "unknown";
  runtime: string;
  ownership: string;
  operation: string;
  operationDetail: string;
  operationHref: string | null;
  marks: Mark[];
  http: string;
  httpKind: "ok" | "warn" | "stale" | "muted";
  /** W379: journal settings for a live site; absent on fixture rows. */
  journal?: SiteJournal;
};

export type SiteJournal = {
  pageCache: string;
  quotaLimit: string;
  quotaUsage: string;
  adoption: { operationId: string; previousEpoch: string; evidence: string } | null;
};

export const sites: Site[] = [
  {
    id: "site_8KD2QW",
    domain: "shop.lab.test",
    serving: "Blocked",
    servingKind: "err",
    runtime: "WordPress · LSPHP 8.4",
    ownership: "Created",
    operation: "Config activation",
    operationDetail: "Needs attention · 35m",
    operationHref: "/operations/op_7Q2KX9",
    marks: ["pass", "pass", "pass", "not_run", "not_run", "not_run", "unknown"],
    http: "200 · 1.9 s",
    httpKind: "warn",
  },
  {
    id: "site_2PL7VB",
    domain: "portfolio.lab.test",
    serving: "Serving",
    servingKind: "ok",
    runtime: "WordPress · LSPHP 8.4",
    ownership: "Created",
    operation: "Backup capture",
    operationDetail: "Succeeded · 6h",
    operationHref: null,
    marks: ["pass", "pass", "fail", "not_run", "not_run", "not_run", "pass"],
    http: "200 · 180 ms",
    httpKind: "ok",
  },
  {
    id: "site_6RT1ZM",
    domain: "news.lab.test",
    serving: "Not serving",
    servingKind: "muted",
    runtime: "WordPress · LSPHP 8.4",
    ownership: "Created · partial",
    operation: "Site provision",
    operationDetail: "Failed, partial · 1d",
    operationHref: null,
    marks: all("not_run"),
    http: "—",
    httpKind: "muted",
  },
  {
    id: "site_4HX9KC",
    domain: "blog.lab.test",
    serving: "Serving",
    servingKind: "ok",
    runtime: "WordPress · LSPHP 8.4",
    ownership: "Created",
    operation: "Backup capture",
    operationDetail: "Succeeded · 2h",
    operationHref: null,
    marks: all("pass"),
    http: "200 · 142 ms",
    httpKind: "ok",
  },
  {
    id: "site_9BN3TF",
    domain: "docs.lab.test",
    serving: "Serving",
    servingKind: "ok",
    runtime: "WordPress · LSPHP 8.4",
    ownership: "Created",
    operation: "Restore probe",
    operationDetail: "Succeeded · 5h",
    operationHref: null,
    marks: ["pass", "pass", "pass", "pass", "pass", "pass", "unknown"],
    http: "200 · 121 ms",
    httpKind: "ok",
  },
  {
    id: "site_1QS8JD",
    domain: "wiki.lab.test",
    serving: "Serving",
    servingKind: "ok",
    runtime: "WordPress · LSPHP 8.4",
    ownership: "Explicitly adopted",
    operation: "Config activation",
    operationDetail: "Succeeded · 3d",
    operationHref: null,
    marks: ["pass", "pass", "pass", "pass", "pass", "not_run", "not_run"],
    http: "200 · 230 ms",
    httpKind: "ok",
  },
  {
    id: "site_7CW5GA",
    domain: "status.lab.test",
    serving: "Serving",
    servingKind: "ok",
    runtime: "WordPress · LSPHP 8.4",
    ownership: "Created",
    operation: "Site provision",
    operationDetail: "Succeeded · 9d",
    operationHref: null,
    marks: ["pass", "pass", "pass", "not_run", "not_run", "not_run", "not_run"],
    http: "Stale · 2h",
    httpKind: "stale",
  },
  {
    id: "site_3VU0EY",
    domain: "legacy.lab.test",
    serving: "Unknown",
    servingKind: "unknown",
    runtime: "Not identified",
    ownership: "Observed only",
    operation: "None · read-only",
    operationDetail: "",
    operationHref: null,
    marks: all("not_run"),
    http: "200 · 410 ms",
    httpKind: "ok",
  },
];

const markWord: Record<Mark, string> = {
  pass: "pass",
  fail: "fail",
  unknown: "unknown",
  not_run: "not run",
};

export function evidenceLabel(marks: Mark[]): string {
  return `Recovery evidence. ${fields.map((name, index) => `${name}: ${markWord[marks[index] ?? "not_run"]}`).join("; ")}`;
}

export const searchTargets = [
  { href: "/", label: "Host overview" },
  { href: "/host/metrics", label: "Host metrics" },
  { href: "/host/services", label: "Services" },
  { href: "/host/diagnoses", label: "Host diagnoses" },
  { href: "/host/updates", label: "Host updates" },
  { href: "/host/alerts", label: "Alerts · Uptime Kuma" },
  { href: "/host/firewall", label: "Firewall · rustiron zone" },
  { href: "/host/cron", label: "Cron jobs & timers" },
  { href: "/host/logs", label: "Server logs" },
  { href: "/sites", label: "Sites" },
  { href: "/sites/new", label: "Add website" },
  { href: "/sites/site_8KD2QW", label: "shop.lab.test" },
  { href: "/sites/site_8KD2QW/maintenance", label: "shop.lab.test · Maintenance" },
  { href: "/apps", label: "Apps · Node.js, Bun & EmDash" },
  { href: "/databases", label: "Databases · MariaDB & SQLite" },
  { href: "/apps/app_emdash", label: "emdash.lab.test (EmDash 1.6.1)" },
  { href: "/apps/app_api", label: "api.lab.test (Bun 1.4.2)" },
  { href: "/domains", label: "Domains & SSL certificates" },
  { href: "/domains/new", label: "Add domain & DNS zone" },
  { href: "/mail", label: "Email · Outbound mail relay" },
  { href: "/domains/blog.lab.test", label: "blog.lab.test · SSL certificate" },
  { href: "/domains/blog.lab.test/dns", label: "blog.lab.test · DNS records" },
  { href: "/migration", label: "Migration · CyberPanel & EmDash" },
  {
    href: "/migration/emdash/wxr_emdash_01",
    label: "WordPress → EmDash migration (wxr_emdash_01)",
  },
  { href: "/operations", label: "Operations" },
  { href: "/operations/op_7Q2KX9", label: "Operation op_7Q2KX9" },
  { href: "/plans/plan_3HV8RA", label: "Plan plan_3HV8RA" },
  { href: "/recovery", label: "Recovery" },
  { href: "/recovery/schedules", label: "Scheduled backups" },
  { href: "/recovery/store", label: "Backup store" },
  { href: "/recovery/artifacts/snap_P8Q1", label: "Snapshot snap_P8Q1" },
  { href: "/recovery/evidence/rcpt_2YB7", label: "Receipt rcpt_2YB7" },
  { href: "/users", label: "Users & access" },
  { href: "/settings", label: "Settings" },
  { href: "/help", label: "Docs & Knowledge Base" },
  { href: "/states", label: "Shared states" },
];

export type RecoveryState = { label: string; kind: "ok" | "err" | "notrun" | "unknown" };

export type RecoveryRow = {
  siteId: string;
  snapshot: string | null;
  snapshotNote?: string;
  /** Local gap from the newest succeeded capture to the journal's last time. */
  exposure?: string;
  restore: RecoveryState | null;
  copy: RecoveryState | string | null;
  receipt: string | null;
};

export type SiteSnapshot = {
  id: string;
  /** Full id for the snapshot page. Absent when this row has no detail view. */
  artifactId?: string;
  note: string;
  captured: string;
  repository: string;
  size: string;
  marks: Mark[];
  restore: RecoveryState;
};

/** Recovery overview rows, sorted by weakest evidence. */
export const recoveryRows: RecoveryRow[] = [
  {
    siteId: "site_2PL7VB",
    snapshot: "snap_R3T6 · 24 Oct, 02:00",
    restore: { label: "Failed today", kind: "err" },
    copy: "offsite-b2",
    receipt: "rcpt_2YB7",
  },
  {
    siteId: "site_8KD2QW",
    snapshot: "snap_P8Q1 · 23 Oct, 02:00",
    restore: { label: "Not run · last pass 9 d ago", kind: "notrun" },
    copy: { label: "Unknown", kind: "unknown" },
    receipt: "rcpt_9PL1",
  },
  {
    siteId: "site_9BN3TF",
    snapshot: "snap_D1F5 · 24 Oct, 02:00",
    restore: { label: "Passed today", kind: "ok" },
    copy: { label: "Same provider as host", kind: "unknown" },
    receipt: "rcpt_7KD3",
  },
  {
    siteId: "site_1QS8JD",
    snapshot: "snap_W6E2 · 23 Oct, 02:00",
    restore: { label: "Restored, probes not run", kind: "ok" },
    copy: { label: "Not run", kind: "notrun" },
    receipt: "rcpt_4QW8",
  },
  {
    siteId: "site_4HX9KC",
    snapshot: "snap_B9C4 · 22 Oct, 02:00",
    restore: { label: "Passed 2 d ago", kind: "ok" },
    copy: "offsite-b2",
    receipt: "rcpt_8HN2",
  },
  {
    siteId: "site_7CW5GA",
    snapshot: "snap_S2K8 · 24 Oct, 02:00",
    restore: { label: "Never", kind: "notrun" },
    copy: { label: "Not run", kind: "notrun" },
    receipt: "rcpt_1ZX5",
  },
  {
    siteId: "site_6RT1ZM",
    snapshot: null,
    snapshotNote: "No snapshot",
    restore: null,
    copy: null,
    receipt: null,
  },
  {
    siteId: "site_3VU0EY",
    snapshot: null,
    snapshotNote: "Observed only · not backed up by Rustiron",
    restore: null,
    copy: null,
    receipt: null,
  },
];

/** Fixture operations from the operations mockup. */
export type OperationRow = {
  id: string;
  action: string;
  outcome: string;
  kind: "err" | "info" | "ok" | "warn" | "muted";
  icon: LucideIcon;
  resources: string;
  requester: string;
  started: string;
  duration: string;
  linked: boolean;
};

export const operationRows: OperationRow[] = [
  {
    id: "op_7Q2KX9",
    action: "Config activation",
    outcome: "Needs attention",
    kind: "err",
    icon: CircleAlert,
    resources: "shop.lab.test · global OLS",
    requester: "operator (CLI)",
    started: "24 Oct, 16:06",
    duration: "1 m 12 s",
    linked: true,
  },
  {
    id: "op_5ZC1YH",
    action: "Backup capture",
    outcome: "Running · step 3 of 6",
    kind: "info",
    icon: LoaderCircle,
    resources: "wiki.lab.test",
    requester: "schedule",
    started: "24 Oct, 16:40",
    duration: "2 m so far",
    linked: false,
  },
  {
    id: "—",
    action: "Config activation",
    outcome: "Rejected",
    kind: "muted",
    icon: CircleX,
    resources: "shop.lab.test",
    requester: "agent: maint-bot",
    started: "24 Oct, 15:58",
    duration: "—",
    linked: false,
  },
  {
    id: "op_3XR8DD",
    action: "Backup capture",
    outcome: "Succeeded",
    kind: "ok",
    icon: CircleCheck,
    resources: "blog.lab.test",
    requester: "schedule",
    started: "24 Oct, 14:00",
    duration: "5 m 02 s",
    linked: false,
  },
  {
    id: "op_6LB4UW",
    action: "Restore probe",
    outcome: "Succeeded",
    kind: "ok",
    icon: CircleCheck,
    resources: "docs.lab.test · sandbox",
    requester: "operator (CLI)",
    started: "24 Oct, 11:20",
    duration: "12 m 48 s",
    linked: false,
  },
  {
    id: "op_8GH2TT",
    action: "Site provision",
    outcome: "Failed · partial effects",
    kind: "err",
    icon: CircleX,
    resources: "news.lab.test",
    requester: "operator (CLI)",
    started: "23 Oct, 10:02",
    duration: "2 m 37 s",
    linked: false,
  },
  {
    id: "op_9JW3LE",
    action: "Backup capture",
    outcome: "Succeeded",
    kind: "ok",
    icon: CircleCheck,
    resources: "shop.lab.test",
    requester: "schedule",
    started: "23 Oct, 02:00",
    duration: "6 m 41 s",
    linked: false,
  },
  {
    id: "op_2KK9QP",
    action: "Config activation",
    outcome: "Failed, compensated",
    kind: "warn",
    icon: CircleCheck,
    resources: "shop.lab.test · global OLS",
    requester: "operator (CLI)",
    started: "22 Oct, 13:40",
    duration: "1 m 30 s",
    linked: false,
  },
];

/** Fixture services from the services mockup. */
export type ServiceState =
  | "Running"
  | "Synced"
  | "Not checked"
  | "Stale"
  | "Starting"
  | "Stopped"
  | "Failed";

export type HostService = {
  name: string;
  unit: string;
  role: string;
  state: ServiceState;
  since: string;
  management: string;
  /** Present when host status read the unit MainPID label. */
  selinux?: string | null;
};

export const hostServices: HostService[] = [
  {
    name: "OpenLiteSpeed 1.9.3",
    unit: "lshttpd.service",
    role: "Web server",
    state: "Running",
    since: "16:07 UTC (graceful restart)",
    management: "Owned includes",
  },
  {
    name: "LSPHP 8.4",
    unit: "lsphp84 · per-site processes",
    role: "PHP runtime",
    state: "Running",
    since: "16:07 UTC",
    management: "Rustiron-managed",
  },
  {
    name: "MariaDB 11.4",
    unit: "mariadb.service",
    role: "Database",
    state: "Running",
    since: "1 Oct, 09:13",
    management: "Rustiron-managed",
  },
  {
    name: "Executor",
    unit: "rustiron-executor.service",
    role: "Privileged executor",
    state: "Running",
    since: "1 Oct, 09:13",
    management: "Rustiron",
  },
  {
    name: "Observer",
    unit: "rustiron-observer.service",
    role: "Metrics collection",
    state: "Running",
    since: "08:20 UTC",
    management: "Rustiron",
  },
  {
    name: "Coordinator",
    unit: "rustiron-coordinator.service",
    role: "Planning, API",
    state: "Running",
    since: "1 Oct, 09:13",
    management: "Rustiron",
  },
  {
    name: "chronyd",
    unit: "chronyd.service",
    role: "Time sync",
    state: "Synced",
    since: "1 Oct, 09:12",
    management: "Observed only",
  },
  {
    name: "firewalld",
    unit: "firewalld.service",
    role: "Firewall",
    state: "Not checked",
    since: "—",
    management: "Observed only",
  },
  {
    name: "crond",
    unit: "crond.service",
    role: "Scheduled jobs",
    state: "Stale",
    since: "Last seen 3 h ago",
    management: "Observed only",
  },
];
