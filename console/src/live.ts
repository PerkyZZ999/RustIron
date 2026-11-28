// Maps the executor's read-only observation (rustiron-lab-observation/1) onto
// the console's view rows. Only what the journal records is shown: serving and
// HTTP are not observed by it, so they stay "Not observed", never a guess.
import {
  CircleAlert,
  CircleCheck,
  CircleMinus,
  CircleX,
  LoaderCircle,
  RotateCcw,
  type LucideIcon,
} from "lucide-react";

import type {
  HostService,
  Mark,
  OperationRow,
  RecoveryRow,
  RecoveryState,
  ServiceState,
  Site,
  SiteJournal,
  SiteSnapshot,
} from "./fixture";
import { signedRequester } from "./signed";

type Field = {
  status?: string;
  scope?: string;
  observed_at?: number | null;
  evidence_refs?: string[];
  limitations?: string[];
};

/** Unprivileged host status (`rustiron-control --host-status`). */
export type Machine = {
  schema: "rustiron-host-status/1";
  observed_at: number | null;
  os: { name: string | null; version: string | null; kernel: string | null };
  uptime_seconds: number | null;
  cpu: { count: number | null; load: [number, number, number] | null };
  memory: { total_bytes: number | null; available_bytes: number | null };
  disk: {
    path: string;
    total_bytes: number | null;
    available_bytes: number | null;
    inode_total?: number | null;
    inode_available?: number | null;
  };
  selinux: string | null;
  /** Absent on observations taken before the executor context was read. */
  executor_selinux?: { unit: string; readable: boolean; context: string | null };
  /** Absent on observations taken before NTP sync was read. */
  clock?: { synchronized: boolean | null; offset_us?: number | null };
  /** Absent on observations taken before the SSH read was attempted. */
  ssh?: {
    readable: boolean;
    permit_root_login: string | null;
    password_authentication: string | null;
    pubkey_authentication: string | null;
    kbd_interactive_authentication: string | null;
  };
  /** Absent on observations taken before the port 443 count. */
  tls?: { listeners_443: number | null };
  /** Absent on observations taken before the firewall read was attempted. */
  firewall?: {
    readable: boolean;
    state: string | null;
    default_zone: string | null;
    services: string[] | null;
  };
  /** Absent on observations taken before the MariaDB ping. */
  database?: {
    socket: string;
    ping: "responding" | "not_responding" | "unknown";
    listeners_beyond_loopback?: number | null;
  };
  /** W656 (D-102): optional PostgreSQL 18 probe. */
  postgresql?: {
    installed: boolean;
    ping: "responding" | "not_responding" | "not_installed" | "unknown";
    listeners_beyond_loopback?: number | null;
  };
  /** W656 (D-102): optional confined Caddy edge ingress probe. */
  caddy?: {
    installed: boolean;
    admin_port_listeners?: number | null;
  };
  /** Absent on observations taken before the version read. */
  stack?: {
    openlitespeed: string | null;
    mariadb: string | null;
    php: string[];
    powerdns?: string | null;
    nodejs?: string | null;
    bun?: string | null;
    caddy?: string | null;
    postgresql?: string | null;
  };
  /** Absent on observations taken before failed units were listed. */
  failed_units?: { readable: boolean; units: string[] | null; truncated?: boolean };
  /** Absent on observations taken before the active OLS map was read. */
  ols_map?: { readable: boolean; hosts: string[] | null };
  services: {
    unit: string | null;
    label: string | null;
    active: string | null;
    sub: string | null;
    since: number | null;
    /** Unix seconds. Absent on observations taken before timer triggers were read. */
    last_trigger?: number | null;
    /** MainPID label. Absent on observations taken before unit contexts were read. */
    selinux_context?: string | null;
  }[];
  /** Optional capped samples from rustiron-control --record-samples. */
  samples?: HostSample[];
};

export type HostSample = {
  t: number | null;
  cpu: number | null;
  mem: number | null;
  disk: number | null;
};

export type Observation = {
  schema: "rustiron-lab-observation/1";
  /** Added by the lab bridge when the host status read succeeded. */
  machine?: Machine;
  host: {
    host_id: string;
    host_epoch: string;
    issuer: string;
    signer_policy_epoch: string;
    ols_listener: string | null;
    backup_destination: string | null;
    /** Enrolled day count. Absent on observations taken before it was recorded. */
    backup_retention_days?: number | null;
    /** RPM package pins; null or absent when the observer could not read them. */
    packages?: unknown;
    signer?: unknown;
    /** W392: the host receipt key's public facts. Absent on older observations. */
    receipt_key?: unknown;
    /** W483: whether the installed ssh-keygen has the enrolled digest. Absent on older observations. */
    signature_verifier?: unknown;
  };
  journal_last_time: number;
  sites: {
    site_id: string;
    hostname: string;
    operation_id: string;
    /** `adopted` (W372): a re-adoption verified this site; Rustiron did not create it. */
    state: "running" | "succeeded" | "quarantined" | "adopted";
    steps_done: number;
    steps_recorded: number;
    /** Failed provision step, when the observation records one. */
    failed_step?: string | null;
    /** Whether the derived account exists. Absent when this observation did not check. */
    host_account?: "present" | "absent";
    /** Whether the derived site directory exists. Absent when this observation did not check. */
    host_directory?: "present" | "absent";
    /** Identity-file status from the enrolled listener, when this observation checked. */
    http_status?: number;
    /** D-073 (W487): the site's own PHP health answer. Absent when not asked. */
    php_health?: { status?: number; account_matches?: boolean };
    ejected: boolean;
    /** W379: latest succeeded page-cache change; null when none. Absent on older observations. */
    page_cache?: "opted_in" | "cache_on" | "opted_out" | null;
    /** W379: the quota the journal recorded (W335, W372). Absent on older observations. */
    quota?: RecordedQuota;
    /** W491/D-075: optional alias hostname on static/WP sites. */
    alias_hostname?: string | null;
    /** W597/P27 + W655/D-102: runtime profile for modern apps (node_22_v1, bun_1_v1, static_v1). */
    app_runtime?: string | null;
    /** W597/P27: active release ID for modern apps. */
    app_active_release?: string | null;
    /** W656/D-102: optional schema v2 topology (static_spa, backend_api, fullstack_split, fullstack_dual_ssr). */
    app_topology?: string | null;
    /** W656/D-102: optional schema v2 edge ingress (ols, caddy). */
    app_ingress?: string | null;
    /** W656/D-102: optional schema v2 database engine (none, sqlite, mariadb, postgresql_18). */
    app_database?: string | null;
    /** W572/CP08: loopback ports forwarded by proxy or app sites. */
    proxy_ports?: number[];
  }[];
  operations: {
    operation_id: string;
    /** W379 names page-cache changes; journal v44 adds import, DNS, maintenance, and app verbs. */
    kind:
      | "config_activate"
      | "site_eject"
      | "page_cache_opt_in"
      | "page_cache_opt_out"
      | "site_import"
      | "import_scrub"
      | "site_clone"
      | "clone_scrub"
      | "dns_zone_import"
      | "dns_change"
      | "site_credential_rotate"
      | "app_provision"
      | "app_deploy"
      | "app_lifecycle";
    resource_id: string;
    site_id: string | null;
    state: string;
    effect_attempted: boolean;
  }[];
  captures: {
    operation_id: string;
    site_id: string;
    state: "running" | "succeeded" | "failed";
    snapshot_id: string | null;
    started_at: number;
    finished_at: number | null;
    /** Days copied onto this capture. Absent on observations taken before the copy. */
    retention_days?: number | null;
    /** Files in the restic summary. Absent when not stored. */
    snapshot_files?: number | null;
    /** Bytes in the restic summary. Absent when not stored. */
    snapshot_bytes?: number | null;
    /** Artifact manifest summary (schema 10). Null or absent when not recorded. */
    manifest?: unknown;
    fields?: Record<string, Field> | null;
    /** W379: D-021 marker label of a succeeded capture. Absent on older observations. */
    consistency?: { label: string; reason: string | null } | null;
    /** W379: a settled failed capture's tagged snapshot (W366). Never a backup of record. */
    unclaimed_snapshot_id?: string | null;
    /** W391: per-version retention evidence summary (journal v18). Absent on older observations. */
    retention?: CaptureRetention | null;
    /** W391: the stored refusal code of a refused capture (journal v18). Absent on older observations. */
    refusal?: string | null;
  }[];
  probes: {
    operation_id: string;
    site_id: string;
    snapshot_id: string;
    state: "running" | "passed" | "failed" | "cleanup_incomplete";
    started_at: number;
    finished_at: number | null;
    fields: Record<string, Field> | null;
    /** W379: the stored refusal code of a refused probe. Absent on older observations. */
    refusal?: string | null;
  }[];
  /** W372: re-adoption records. Absent on older observations. */
  readoptions?: Readoption[];
  /** W396 (journal v20): each admission's recorded digests and signed bytes. Absent on older observations. */
  admissions?: unknown;
  /** W396: every stored canonical object once, keyed by its SHA-256. Absent on older observations. */
  signed_objects?: unknown;
  /** W594/D-098: operator-visible authority budget and all-site OLS impact summary. */
  authority_budget?: {
    enrolled: boolean;
    all_site_ols_impact?: string;
    consumed?: {
      recent_admissions?: number;
      recent_ols_reloads?: number;
      served_sites?: number;
      total_admissions?: number;
      total_ols_reloads?: number;
    };
  };
};

/** W391: what the lock reader read back for one succeeded capture. */
export type CaptureRetention = {
  status: "recorded";
  before_days: number;
  after_days: number;
  objects: number;
  earliest_retain_until: number;
  latest_retain_until: number;
};

export type RecordedQuota = {
  state: "enforced" | "not_enforced" | "not_recorded" | "not_attempted" | "malformed";
  source?: "policy" | "plan" | "readoption";
  block_hard_kib?: number;
  inode_hard?: number;
};

export type Readoption = {
  operation_id: string;
  form: "site" | "generation";
  site_id: string | null;
  state: "verifying" | "adopted" | "refused";
  previous_epoch: string;
  evidence_sha256: string;
  refusal: string | null;
  rule: string | null;
};

/** W347: the executor's own refusal, forwarded by the lab bridge instead of an observation. */
export type ExecutorRefusal = {
  schema: "rustiron-executor-refusal/1";
  error: "EXECUTOR_NOT_ENROLLED";
};

export function isExecutorRefusal(value: unknown): value is ExecutorRefusal {
  const candidate = value as Partial<ExecutorRefusal> | null;
  return (
    typeof candidate === "object" &&
    candidate !== null &&
    candidate.schema === "rustiron-executor-refusal/1" &&
    candidate.error === "EXECUTOR_NOT_ENROLLED" &&
    Object.keys(candidate).length === 2
  );
}

/** The seven fields in display order, as the executor's receipt names them. */
const evidenceFields = [
  ["artifacts_complete", "Artifacts complete"],
  ["repository_integrity_checked", "Repository integrity checked"],
  ["decryption_tested", "Decryption tested"],
  ["application_consistency_assessed", "Application consistency assessed"],
  ["restored_in_isolation", "Restored in isolation"],
  ["health_checks_passed", "Health checks passed"],
  ["independent_copy_confirmed", "Independent copy confirmed"],
] as const;

/** Live settings text. A missing count stays unobserved. The fixture screen has its own sample. */
export function enrolledRetentionText(days: number | null | undefined): string {
  if (typeof days !== "number" || !Number.isInteger(days) || days < 1 || days > 3650) {
    return "Target 30 days (D-010). Not in this observation.";
  }
  return `${days} days enrolled on the backup policy. D-010 target is 30 days. Older captures do not gain this number.`;
}

export type PackagePin = { name: string; version: string | null; signing_key: string | null };

const pinToken = /^[A-Za-z0-9._:+~-]{1,128}$/;

/** Validated package pins, or null when the observation does not carry them. */
export function packagePins(host: Observation["host"] | null | undefined): PackagePin[] | null {
  const value = host?.packages;
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) return null;
  const pins: PackagePin[] = [];
  for (const item of value as Partial<PackagePin>[]) {
    const { name, version, signing_key } = item ?? {};
    if (typeof name !== "string" || !pinToken.test(name)) return null;
    if (version !== null && (typeof version !== "string" || !pinToken.test(version))) return null;
    if (
      signing_key !== null &&
      (typeof signing_key !== "string" || !/^[0-9a-f]{16}$/.test(signing_key))
    )
      return null;
    pins.push({ name, version, signing_key });
  }
  return pins;
}

export type SignerFacts = {
  principal: string;
  namespace: string;
  algorithm: string;
  fingerprint: string;
  revocations_bytes: number;
  revocations_sha256: string;
};

const signerKeys = [
  "algorithm",
  "fingerprint",
  "namespace",
  "principal",
  "revocations_bytes",
  "revocations_sha256",
];

/** W233: validated signer facts, or null when the observation does not carry exactly them. */
export function signerFacts(host: Observation["host"] | null | undefined): SignerFacts | null {
  const value = host?.signer as Partial<SignerFacts> | null | undefined;
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  if (Object.keys(value).sort().join() !== signerKeys.join()) return null;
  const { principal, namespace, algorithm, fingerprint, revocations_bytes, revocations_sha256 } =
    value;
  const id = /^[A-Za-z0-9_.-]{1,64}$/;
  if (typeof principal !== "string" || !id.test(principal)) return null;
  if (typeof namespace !== "string" || !id.test(namespace)) return null;
  if (algorithm !== "ssh-ed25519") return null;
  if (typeof fingerprint !== "string" || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(fingerprint))
    return null;
  if (
    typeof revocations_bytes !== "number" ||
    !Number.isSafeInteger(revocations_bytes) ||
    revocations_bytes < 0
  )
    return null;
  if (typeof revocations_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(revocations_sha256))
    return null;
  return { principal, namespace, algorithm, fingerprint, revocations_bytes, revocations_sha256 };
}

export function isObservation(value: unknown): value is Observation {
  const candidate = value as Partial<Observation> | null;
  return (
    typeof candidate === "object" &&
    candidate !== null &&
    candidate.schema === "rustiron-lab-observation/1" &&
    Array.isArray(candidate.sites) &&
    Array.isArray(candidate.operations) &&
    Array.isArray(candidate.captures) &&
    Array.isArray(candidate.probes)
  );
}

const month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function utc(seconds: number) {
  const date = new Date(seconds * 1000);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getUTCDate()} ${month[date.getUTCMonth()]}, ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}`;
}

function duration(start: number, end: number | null) {
  if (end === null) return "—";
  const total = Math.max(0, end - start);
  return total < 60 ? `${total} s` : `${Math.floor(total / 60)} m ${total % 60} s`;
}

function mark(field: Field | undefined): Mark {
  if (field?.status === "pass") return "pass";
  if (field?.status === "fail") return "fail";
  if (field?.status === "unknown") return "unknown";
  return "not_run";
}

/** The newest finished probe's fields; a running or fieldless probe proves nothing. */
function latestMarks(observation: Observation, siteId: string): Mark[] {
  const probe = observation.probes
    .filter((item) => item.site_id === siteId && item.fields && Object.keys(item.fields).length)
    .at(-1);
  return evidenceFields.map(([key]) => mark(probe?.fields?.[key]));
}

type ObservedSite = Observation["sites"][number];

/** The newest capture or probe for a site, else its provision. */
function lastActivity(observation: Observation, site: ObservedSite): [string, string, string] {
  const capture = observation.captures.filter((item) => item.site_id === site.site_id).at(-1);
  const probe = observation.probes.filter((item) => item.site_id === site.site_id).at(-1);
  const newest = [
    // W382: the outcome words of the operations page, so a settled capture
    // names its unclaimed snapshot here too.
    capture && {
      name: "Backup capture",
      state: outcome(capture.state, captureFailure(capture)).outcome,
      at: capture.started_at,
      id: capture.operation_id,
    },
    probe && {
      name: "Restore probe",
      state: outcome(probe.state, "Failed · probe did not pass").outcome,
      at: probe.started_at,
      id: probe.operation_id,
    },
  ]
    .filter((item) => item !== undefined)
    .sort((a, b) => b.at - a.at)[0];
  if (newest) return [newest.name, `${newest.state} · ${utc(newest.at)} UTC`, newest.id];
  if (site.state === "adopted") {
    return ["Site re-adoption", "adopted · not created by Rustiron", site.operation_id];
  }
  return [
    "Site provision",
    stoppedAt(site) ?? `${site.state} · ${site.steps_done} of ${site.steps_recorded} steps`,
    site.operation_id,
  ];
}

const FAILED_STEPS: Record<string, string> = {
  account: "account",
  directories: "directories",
  labels: "labels",
  database: "database",
  credentials: "credentials",
  recipe: "recipe",
  phpunits: "PHP units",
  verify: "verify",
};

function failedStepLabel(site: ObservedSite): string | null {
  if (site.state !== "quarantined" || !site.failed_step) return null;
  return FAILED_STEPS[site.failed_step] ?? null;
}

function stoppedAt(site: ObservedSite): string | null {
  const label = failedStepLabel(site);
  if (!label) return null;
  return `${site.state} · stopped at ${label}`;
}

function quarantinedResources(site: ObservedSite): string {
  const account = site.host_account;
  const directory = site.host_directory;
  if (account === "absent" && directory === "absent") return "No account or directory";
  if (account === "present" && directory === "present") return "Account and directory present";
  if (account === "absent") return "No account";
  if (directory === "absent") return "No directory";
  if (account === "present") return "Account present";
  if (directory === "present") return "Directory present";
  return "Resources not observed";
}

function siteStatus(site: ObservedSite): Pick<Site, "serving" | "servingKind" | "ownership"> {
  if (site.ejected) return { serving: "Ejected", servingKind: "muted", ownership: "Ejected" };
  if (site.state === "quarantined") {
    return { serving: "Quarantined", servingKind: "err", ownership: quarantinedResources(site) };
  }
  if (site.state === "adopted") {
    return { serving: "Not observed", servingKind: "unknown", ownership: "Adopted" };
  }
  return { serving: "Not observed", servingKind: "unknown", ownership: "Created" };
}

const decimal = new Intl.NumberFormat("en", { maximumFractionDigits: 1 });
const integer = new Intl.NumberFormat("en");

function kibText(value: number): string {
  if (value >= 1_048_576) return `${decimal.format(value / 1_048_576)} GiB`;
  if (value >= 1024) return `${decimal.format(value / 1024)} MiB`;
  return `${integer.format(value)} KiB`;
}

const quotaSources: Record<NonNullable<RecordedQuota["source"]>, string> = {
  policy: "enrolled policy",
  plan: "signed site plan",
  readoption: "verified by re-adoption",
};

const MALFORMED_QUOTA = "Recorded limits are malformed; not shown";

const quotaStates: Record<Exclude<RecordedQuota["state"], "enforced">, string> = {
  malformed: MALFORMED_QUOTA,
  not_enforced: "Not enforced (the enrolled policy sets no quota)",
  not_recorded: "Not recorded (provisioned before per-site quotas)",
  not_attempted: "Not recorded (the directories step never began)",
};

function positive(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function enforcedQuotaText(quota: RecordedQuota): string {
  const { block_hard_kib: block, inode_hard: inodes, source } = quota;
  if (!positive(block) || !positive(inodes)) return MALFORMED_QUOTA;
  const from = source ? ` · ${quotaSources[source] ?? source}` : "";
  return `${kibText(block)}, ${integer.format(inodes)} inodes${from}`;
}

/** W379: the quota the journal recorded. Usage is a live read the observation does not make. */
export function quotaLimitText(quota: RecordedQuota | undefined): string {
  if (quota === undefined) return "Not in this observation";
  if (quota.state === "enforced") return enforcedQuotaText(quota);
  return quotaStates[quota.state] ?? MALFORMED_QUOTA;
}

const quotaUsageText =
  "Not in this observation. The site export (export SITE) reads live usage with repquota.";

function pageCacheText(observation: Observation, site: ObservedSite): string {
  const latest = observation.operations
    .filter(
      (item) =>
        item.site_id === site.site_id &&
        (item.kind === "page_cache_opt_in" || item.kind === "page_cache_opt_out"),
    )
    .at(-1);
  const pending =
    latest && latest.state !== "succeeded"
      ? ` · latest change ${latest.operation_id} is ${latest.state}`
      : "";
  if (site.page_cache === undefined) return "Not in this observation";
  if (site.page_cache === "opted_in") return `Opted in${pending}`;
  // W395: the cache-on recipe (D-044).
  if (site.page_cache === "cache_on")
    return `Opted in · page cache on for anonymous visitors${pending}`;
  if (site.page_cache === "opted_out") return `Opted out${pending}`;
  return `Not opted in (no change recorded)${pending}`;
}

function siteAdoption(observation: Observation, site: ObservedSite): SiteJournal["adoption"] {
  if (site.state !== "adopted") return null;
  const record = (observation.readoptions ?? []).find(
    (item) => item.form === "site" && item.site_id === site.site_id && item.state === "adopted",
  );
  if (!record) return null;
  return {
    operationId: record.operation_id,
    previousEpoch: record.previous_epoch,
    evidence: `sha256 ${record.evidence_sha256.slice(0, 12)}`,
  };
}

function siteJournal(observation: Observation, site: ObservedSite): SiteJournal {
  return {
    pageCache: pageCacheText(observation, site),
    quotaLimit: quotaLimitText(site.quota),
    quotaUsage: quotaUsageText,
    adoption: siteAdoption(observation, site),
  };
}

export function liveSites(observation: Observation): Site[] {
  return observation.sites.map((site) => {
    const [operation, operationDetail, operationId] = lastActivity(observation, site);
    return {
      id: site.site_id,
      domain: site.hostname,
      ...siteStatus(site),
      runtime: "Not observed",
      operation,
      operationDetail,
      operationHref: `/operations/${operationId}`,
      marks: latestMarks(observation, site.site_id),
      ...httpFact(site),
      journal: siteJournal(observation, site),
    };
  });
}

function httpFact(site: ObservedSite): Pick<Site, "http" | "httpKind"> {
  if (typeof site.http_status !== "number") return { http: "Not observed", httpKind: "muted" };
  const http = String(site.http_status);
  if (site.http_status === 200) return { http, httpKind: "ok" };
  if (site.state === "succeeded" && !site.ejected) return { http, httpKind: "warn" };
  return { http, httpKind: "muted" };
}

type Outcome = { outcome: string; kind: OperationRow["kind"]; icon: LucideIcon };

/** Every state the observation types declare; `satisfies` below makes a new one need a row. */
type ObservedState =
  | ObservedSite["state"]
  | Observation["captures"][number]["state"]
  | Observation["probes"][number]["state"]
  | Readoption["state"];

/** Journal operation states. `operations[].state` stays a string: unknown ones render as-is. */
type JournalOperationState =
  | "intent"
  | "needs_attention"
  | "compensating"
  | "failed_compensated"
  | "untouched";

const outcomes: Readonly<Record<string, Outcome>> = {
  succeeded: { outcome: "Succeeded", kind: "ok", icon: CircleCheck },
  passed: { outcome: "Succeeded", kind: "ok", icon: CircleCheck },
  running: { outcome: "Running", kind: "info", icon: LoaderCircle },
  intent: { outcome: "Running", kind: "info", icon: LoaderCircle },
  needs_attention: { outcome: "Needs attention", kind: "err", icon: CircleAlert },
  cleanup_incomplete: { outcome: "Needs attention", kind: "err", icon: CircleAlert },
  compensating: { outcome: "Needs attention", kind: "err", icon: CircleAlert },
  // W751 (QA-20): rolled back, not a success, so not a check mark.
  failed_compensated: { outcome: "Failed, compensated", kind: "warn", icon: RotateCcw },
  failed: { outcome: "Failed · no snapshot", kind: "err", icon: CircleX },
  quarantined: { outcome: "Failed · partial effects", kind: "err", icon: CircleX },
  untouched: { outcome: "Failed · untouched", kind: "muted", icon: CircleMinus },
  adopted: { outcome: "Succeeded", kind: "ok", icon: CircleCheck },
  verifying: { outcome: "Running", kind: "info", icon: LoaderCircle },
  refused: { outcome: "Failed · refused", kind: "err", icon: CircleX },
} satisfies Record<ObservedState | JournalOperationState, Outcome>;

const operationActions: Record<Observation["operations"][number]["kind"], string> = {
  config_activate: "Config activation",
  site_eject: "Site eject",
  page_cache_opt_in: "Page cache opt-in",
  page_cache_opt_out: "Page cache opt-out",
  site_import: "Site import",
  import_scrub: "Import scrub",
  site_clone: "Staging clone",
  clone_scrub: "Clone scrub",
  dns_zone_import: "DNS zone import",
  dns_change: "DNS change",
  site_credential_rotate: "Credential rotation",
  app_provision: "App provision",
  app_deploy: "App deploy",
  app_lifecycle: "App lifecycle",
};

/** A failed capture with an unclaimed snapshot is not "no snapshot": one exists, unclaimed. */
function captureFailure(item: Observation["captures"][number]): string {
  return item.unclaimed_snapshot_id ? "Failed · unclaimed snapshot" : "Failed · no snapshot";
}

function operationResources(item: Observation["operations"][number]): string {
  if (item.kind === "page_cache_opt_in" || item.kind === "page_cache_opt_out") {
    return `${item.site_id ?? "site not recorded"} · global OLS`;
  }
  return item.site_id ? `${item.site_id} · global OLS` : "global OLS";
}

function readoptionRow(item: Readoption, requester: string): OperationRow {
  const known = outcome(item.state);
  return {
    id: item.operation_id,
    action: item.form === "site" ? "Site re-adoption" : "Generation re-adoption",
    ...known,
    outcome:
      item.state === "refused" && item.refusal ? `Failed · refused ${item.refusal}` : known.outcome,
    resources: item.form === "site" ? (item.site_id ?? "site not recorded") : "global OLS",
    requester,
    started: "—",
    duration: "—",
    linked: true,
  };
}

function outcome(state: string, failed = "Failed · no snapshot"): Outcome {
  const known = outcomes[state] ?? { outcome: state, kind: "muted", icon: CircleMinus };
  return state === "failed" ? { ...known, outcome: failed } : known;
}

/** Timed rows (captures, probes) newest first, then untimed rows newest recorded first. */
export function liveOperations(observation: Observation): OperationRow[] {
  // W429: from each operation's recorded signed plan; never a fixed label.
  const requesterOf = (id: string) => {
    const named = signedRequester(observation, id);
    return named ? `${named} (signed plan)` : "Not in this observation";
  };
  const timed = [
    ...observation.captures.map((item) => ({
      at: item.started_at,
      row: {
        id: item.operation_id,
        action: "Backup capture",
        ...outcome(item.state, captureFailure(item)),
        resources: item.site_id,
        requester: requesterOf(item.operation_id),
        started: utc(item.started_at),
        duration: duration(item.started_at, item.finished_at),
        linked: true,
      },
    })),
    ...observation.probes.map((item) => ({
      at: item.started_at,
      row: {
        id: item.operation_id,
        action: "Restore probe",
        ...outcome(item.state, "Failed · probe did not pass"),
        resources: `${item.site_id} · sandbox`,
        requester: requesterOf(item.operation_id),
        started: utc(item.started_at),
        duration: duration(item.started_at, item.finished_at),
        linked: true,
      },
    })),
  ].sort((a, b) => b.at - a.at);
  const readoptions = observation.readoptions ?? [];
  const readoptionIds = new Set(readoptions.map((item) => item.operation_id));
  const untimed: OperationRow[] = [
    // An adopted site's provision row shares its re-adoption's id; the re-adoption row tells it.
    ...observation.sites
      .filter((site) => !readoptionIds.has(site.operation_id))
      .map((site) => ({
        id: site.operation_id,
        action: site.state === "adopted" ? "Site re-adoption" : "Site provision",
        ...outcome(site.state),
        resources: site.site_id,
        requester: requesterOf(site.operation_id),
        started: "—",
        duration: "—",
        linked: true,
      })),
    ...observation.operations.map((item) => ({
      id: item.operation_id,
      action: operationActions[item.kind] ?? "Config activation",
      ...outcome(item.state),
      resources: operationResources(item),
      requester: requesterOf(item.operation_id),
      started: "—",
      duration: "—",
      linked: true,
    })),
    ...readoptions.map((item) => readoptionRow(item, requesterOf(item.operation_id))),
  ].reverse();
  return [...timed.map((item) => item.row), ...untimed];
}

export type LiveOperation = {
  id: string;
  title: string;
  outcome: string;
  kind: OperationRow["kind"];
  icon: LucideIcon;
  timing: string;
  siteId: string | null;
  hostname: string | null;
  marks: Mark[] | null;
  facts: { label: string; value: string }[];
  observed: string[];
  unknown: string[];
  /** W379: a stake that must stay visible above the record (an unclaimed snapshot, an uncertain capture). */
  notice: string | null;
};

const omittedFromObservation = [
  "The detached signature and any approval review are not in this observation",
  "Step-by-step executor timeline is not in this observation",
];

function hostnameOf(observation: Observation, siteId: string | null): string | null {
  if (!siteId) return null;
  return observation.sites.find((site) => site.site_id === siteId)?.hostname ?? null;
}

function snapshotShort(id: string | null | undefined): string | null {
  return id ? id.slice(0, 8) : null;
}

function timedCaption(startedAt: number, finishedAt: number | null): string {
  const start = `${utc(startedAt)} UTC`;
  return finishedAt === null
    ? `Started ${start} · not finished`
    : `Started ${start} · ${duration(startedAt, finishedAt)}`;
}

type JournalExtras = {
  siteId: string | null;
  timing: string;
  marks: Mark[] | null;
  extraFacts: LiveOperation["facts"];
  observed: string[];
  unknown: string[];
  notice?: string;
};

function noTimes(): Pick<JournalExtras, "timing" | "unknown"> {
  return {
    timing: "Times not in this observation",
    unknown: ["Started and finished times are not in this observation"],
  };
}

function recordedEvidence(
  fields: Record<string, Field> | null | undefined,
  noun: "capture" | "restore",
) {
  const marks =
    fields && Object.keys(fields).length > 0
      ? evidenceFields.map(([key]) => mark(fields[key]))
      : null;
  return {
    marks,
    line: marks
      ? `Seven-field ${noun} evidence is recorded`
      : `Seven-field ${noun} evidence is not in this observation`,
  };
}

function sharedObservedAt(fields: Record<string, Field> | null | undefined): number | null {
  const times = Object.values(fields ?? {}).map((field) => field.observed_at);
  const first = times[0];
  if (typeof first !== "number" || !Number.isInteger(first) || first < 0) return null;
  return times.every((time) => time === first) ? first : null;
}

function refsAreEmpty(fields: Record<string, Field> | null | undefined): boolean {
  const entries = Object.values(fields ?? {});
  return (
    entries.length > 0 &&
    entries.every((field) => Array.isArray(field.evidence_refs) && field.evidence_refs.length === 0)
  );
}

function evidenceRecord(fields: Record<string, Field> | null | undefined): {
  facts: LiveOperation["facts"];
  unknown: string[];
} {
  const observedAt = sharedObservedAt(fields);
  return {
    facts:
      observedAt === null ? [] : [{ label: "Evidence recorded", value: `${utc(observedAt)} UTC` }],
    unknown: refsAreEmpty(fields) ? ["No evidence refs are recorded for these fields"] : [],
  };
}

function captureRetentionFact(
  days: number | null | undefined,
): { label: string; value: string } | null {
  if (days === undefined) return null;
  if (typeof days !== "number" || !Number.isInteger(days) || days < 1 || days > 3650) {
    return { label: "Retention", value: "Not recorded on this capture" };
  }
  return { label: "Retention", value: `${days} days recorded on this capture` };
}

function captureExtentFact(
  files: number | null | undefined,
  bytes: number | null | undefined,
): { label: string; value: string } | null {
  if (files === undefined && bytes === undefined) return null;
  if (
    typeof files !== "number" ||
    typeof bytes !== "number" ||
    !Number.isInteger(files) ||
    !Number.isInteger(bytes) ||
    files < 0 ||
    bytes < 0
  ) {
    return { label: "Snapshot size", value: "Not recorded on this capture" };
  }
  return { label: "Snapshot size", value: `${files} files, ${bytes} bytes` };
}

function captureManifestFact(manifest: unknown): { label: string; value: string } {
  const label = "Artifact manifest";
  const missing = {
    label,
    value: "Not recorded (captured before schema 10 or the listing was refused)",
  };
  if (typeof manifest !== "object" || manifest === null) return missing;
  const m = manifest as Record<string, unknown>;
  const count = (value: unknown): value is number =>
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
  if (
    typeof m.sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(m.sha256) ||
    !count(m.entries) ||
    !count(m.regular_bytes) ||
    typeof m.truncated !== "boolean"
  ) {
    return missing;
  }
  const head = m.truncated ? "Recorded (truncated at a bound)" : "Recorded";
  return {
    label,
    value: `${head}: sha256 ${m.sha256.slice(0, 12)}, ${m.entries} entries, ${m.regular_bytes} bytes`,
  };
}

const consistencyReasons: Record<string, string> = {
  database_changed: "the database changed during the capture window",
  marker_unavailable: "a marker could not be read",
  freeze_not_held: "the freeze was not proved to hold",
  not_checked: "no marker check is recorded",
};

/** W379: the D-021 marker label, stated as recorded; never an application freeze. */
export function consistencyText(
  value: Observation["captures"][number]["consistency"],
): string | null {
  if (value === undefined) return null;
  if (value === null) return "Not recorded for this capture";
  if (value.label === "matched") {
    return "Matched: the database marker read before the dump equals the one after the snapshot check";
  }
  if (value.label === "unmatched") {
    const why = value.reason ? (consistencyReasons[value.reason] ?? value.reason) : null;
    return why ? `Unmatched: ${why}` : "Unmatched";
  }
  return "Recorded label is not recognised; not shown";
}

/** W391: a stored refusal code, shown only when it has the bounded shape. */
function refusalCode(value: string | null | undefined): string | null {
  return typeof value === "string" && /^[A-Z0-9_]{1,64}$/.test(value) ? value : null;
}

const dayText = (days: number) => `${days} ${days === 1 ? "day" : "days"}`;

/**
 * W391: the per-version retention evidence of a succeeded capture, as the
 * lock reader read it back. `null` when the observation predates the field.
 */
export function captureRetentionEvidence(
  item: Observation["captures"][number],
): { facts: LiveOperation["facts"]; observed: string[]; unknown: string[] } | null {
  if (item.state !== "succeeded" || item.retention === undefined) return null;
  const r = item.retention;
  const whole = (value: unknown, min: number): value is number =>
    typeof value === "number" && Number.isSafeInteger(value) && value >= min;
  if (
    r === null ||
    r.status !== "recorded" ||
    !whole(r.before_days, 1) ||
    !whole(r.after_days, 1) ||
    !whole(r.objects, 1) ||
    !whole(r.earliest_retain_until, 0) ||
    !whole(r.latest_retain_until, r.earliest_retain_until)
  ) {
    return {
      facts: [{ label: "Retention evidence", value: "Not recorded on this capture" }],
      observed: [],
      unknown: [
        "Per-object retention was checked, but the journal holds no per-version record for this capture (recorded before schema 18)",
      ],
    };
  }
  const versions = r.objects === 1 ? "1 object version" : `${r.objects} object versions`;
  const range =
    r.earliest_retain_until === r.latest_retain_until
      ? `${utc(r.earliest_retain_until)} UTC`
      : `${utc(r.earliest_retain_until)} to ${utc(r.latest_retain_until)} UTC`;
  return {
    facts: [
      { label: "Retention evidence", value: `${versions} read back, COMPLIANCE` },
      { label: "Retained until", value: range },
      {
        label: "Bucket lock",
        value: `COMPLIANCE ${dayText(r.before_days)} before, ${dayText(r.after_days)} after`,
      },
    ],
    observed: [
      `The lock postcheck read back ${versions} with COMPLIANCE retention; the receipt lists each version`,
    ],
    unknown: [
      "Retention after the postcheck is not observed; packs reused from earlier captures keep only their own capture's retention",
    ],
  };
}

type OutcomeLines = {
  facts: LiveOperation["facts"];
  observed: string[];
  unknown: string[];
  notice?: string;
};

/** W391: a failed capture states its stored refusal code, or that none is stored. */
function refusedCaptureLines(item: Observation["captures"][number]): OutcomeLines {
  const code = refusalCode(item.refusal);
  if (code) {
    return {
      facts: [{ label: "Refusal code", value: code }],
      observed: [`Refused with ${code} before the snapshot step; no snapshot was written`],
      unknown: ["No snapshot id is recorded"],
    };
  }
  return {
    facts: [{ label: "Refusal code", value: "Not recorded in the journal" }],
    observed: [],
    unknown: [
      "No snapshot id is recorded",
      "This capture's refusal code is not in the journal (recorded before schema 18); the CLI reply and the system journal carry it",
    ],
  };
}

/** A succeeded capture: its D-021 label and, from W391, its retention evidence. */
function succeededCaptureLines(item: Observation["captures"][number]): OutcomeLines {
  const consistency = consistencyText(item.consistency);
  const retention = captureRetentionEvidence(item);
  return {
    facts: [
      ...(consistency ? [{ label: "Consistency label", value: consistency }] : []),
      ...(retention?.facts ?? []),
    ],
    observed: retention?.observed ?? [],
    unknown: [
      ...(item.snapshot_id ? [] : ["No snapshot id is recorded"]),
      ...(retention?.unknown ?? []),
    ],
  };
}

/** W379: what the journal says about a capture's outcome, beyond its state word. */
function captureOutcomeLines(item: Observation["captures"][number]): {
  facts: LiveOperation["facts"];
  observed: string[];
  unknown: string[];
  notice?: string;
} {
  const unclaimed = item.unclaimed_snapshot_id ?? null;
  if (item.state === "running") {
    return {
      facts: [],
      observed: [],
      unknown: [
        "No snapshot id is recorded yet",
        "Outcome not recorded yet: a tagged snapshot may or may not exist until the capture finishes or an operator settles it",
      ],
      notice:
        "Outcome uncertain. This capture is still running in the journal; no snapshot is claimed until it finishes or an operator settles it.",
    };
  }
  if (item.state === "failed" && unclaimed) {
    return {
      notice: `Snapshot ${unclaimed.slice(0, 8)} is not a backup of record. An operator settled this capture after an uncertain outcome; the snapshot is kept only as evidence and is not checked, retained or listed as a recovery point.`,
      facts: [
        {
          label: "Unclaimed snapshot",
          value: `${unclaimed.slice(0, 8)} · not a backup of record`,
        },
      ],
      observed: [
        `An operator settled this capture after an uncertain outcome. Snapshot ${unclaimed.slice(0, 8)} carries its tag and is kept only as evidence`,
      ],
      unknown: [
        "No snapshot id is recorded",
        "The unclaimed snapshot's completeness, restic check, retention and manifest are not recorded",
      ],
    };
  }
  if (item.state === "failed") return refusedCaptureLines(item);
  return succeededCaptureLines(item);
}

function captureExtras(item: Observation["captures"][number]): JournalExtras {
  const snapshot = snapshotShort(item.snapshot_id);
  const evidence = recordedEvidence(item.fields, "capture");
  const record = evidenceRecord(item.fields);
  const outcomeLines = captureOutcomeLines(item);
  return {
    notice: outcomeLines.notice,
    siteId: item.site_id,
    timing: timedCaption(item.started_at, item.finished_at),
    marks: evidence.marks,
    extraFacts: [
      { label: "Journal state", value: item.state },
      { label: "Snapshot", value: snapshot ?? "None recorded" },
      ...outcomeLines.facts,
      ...[captureRetentionFact(item.retention_days)].filter((fact) => fact !== null),
      ...[captureExtentFact(item.snapshot_files, item.snapshot_bytes)].filter(
        (fact) => fact !== null,
      ),
      captureManifestFact(item.manifest),
      ...record.facts,
    ],
    observed: [
      ...(snapshot
        ? [`Backup capture ${item.state}`, `Snapshot ${snapshot} is recorded`]
        : [`Backup capture ${item.state}`]),
      ...outcomeLines.observed,
      ...(evidence.marks ? [evidence.line] : []),
    ],
    unknown: [
      ...outcomeLines.unknown,
      ...(evidence.marks ? [] : [evidence.line]),
      ...record.unknown,
    ],
  };
}

function probeExtras(item: Observation["probes"][number]): JournalExtras {
  const snapshot = snapshotShort(item.snapshot_id);
  const evidence = recordedEvidence(item.fields, "restore");
  const record = evidenceRecord(item.fields);
  const refusal = item.refusal ?? null;
  return {
    siteId: item.site_id,
    timing: timedCaption(item.started_at, item.finished_at),
    marks: evidence.marks,
    extraFacts: [
      { label: "Journal state", value: item.state },
      ...(snapshot ? [{ label: "Snapshot", value: snapshot }] : []),
      ...(refusal ? [{ label: "Refusal code", value: refusal }] : []),
      ...record.facts,
    ],
    observed: [
      `Restore probe ${item.state}`,
      ...(refusal ? [`Refused with ${refusal} before any sandbox; no check is claimed`] : []),
      ...(evidence.marks ? [evidence.line] : []),
    ],
    unknown: [...(evidence.marks ? [] : [evidence.line]), ...record.unknown],
  };
}

function readoptionExtras(item: Readoption): JournalExtras {
  return {
    siteId: item.site_id,
    ...noTimes(),
    marks: null,
    extraFacts: [
      { label: "Journal state", value: item.state },
      { label: "Form", value: item.form },
      { label: "Previous epoch", value: item.previous_epoch },
      { label: "Evidence", value: `sha256 ${item.evidence_sha256.slice(0, 12)}` },
      ...(item.refusal ? [{ label: "Refusal code", value: item.refusal }] : []),
      ...(item.rule ? [{ label: "First failed rule", value: item.rule }] : []),
    ],
    observed: [
      item.state === "adopted"
        ? "Re-adoption adopted: the executor verified the named facts; Rustiron did not create this resource"
        : `Re-adoption ${item.state}`,
    ],
  };
}

function provisionExtras(item: Observation["sites"][number]): JournalExtras {
  const stopped = failedStepLabel(item);
  return {
    siteId: item.site_id,
    ...noTimes(),
    marks: null,
    extraFacts: [
      { label: "Journal state", value: item.state },
      { label: "Steps", value: `${item.steps_done} of ${item.steps_recorded}` },
      ...(stopped ? [{ label: "Stopped at", value: stopped }] : []),
      { label: "Ejected", value: item.ejected ? "Yes" : "No" },
    ],
    observed: [
      stoppedAt(item) ??
        `Site provision ${item.state} · ${item.steps_done} of ${item.steps_recorded} steps`,
    ],
  };
}

function recordedExtras(item: Observation["operations"][number], action: string): JournalExtras {
  return {
    siteId: item.site_id,
    ...noTimes(),
    marks: null,
    extraFacts: [
      { label: "Journal state", value: item.state },
      { label: "Kind", value: item.kind },
      { label: "Resource", value: item.resource_id },
      { label: "Effect attempted", value: item.effect_attempted ? "Yes" : "No" },
    ],
    observed: [`${action} ${item.state}`],
  };
}

function journalExtras(observation: Observation, id: string, action: string): JournalExtras {
  const capture = observation.captures.find((item) => item.operation_id === id);
  if (capture) return captureExtras(capture);
  const probe = observation.probes.find((item) => item.operation_id === id);
  if (probe) return probeExtras(probe);
  const readoption = observation.readoptions?.find((item) => item.operation_id === id);
  if (readoption) return readoptionExtras(readoption);
  const provision = observation.sites.find((item) => item.operation_id === id);
  if (provision) return provisionExtras(provision);
  const recorded = observation.operations.find((item) => item.operation_id === id);
  if (recorded) return recordedExtras(recorded, action);
  return { siteId: null, ...noTimes(), marks: null, extraFacts: [], observed: [] };
}

/** Journal facts for one operation id. Null when that id is not in the observation. */
export function liveOperation(observation: Observation, id: string): LiveOperation | null {
  const row = liveOperations(observation).find((item) => item.id === id);
  if (!row) return null;
  const extras = journalExtras(observation, id, row.action);
  const hostname = hostnameOf(observation, extras.siteId);
  return {
    id: row.id,
    title: `${row.action} · ${hostname ?? extras.siteId ?? row.resources}`,
    outcome: row.outcome,
    kind: row.kind,
    icon: row.icon,
    timing: extras.timing,
    siteId: extras.siteId,
    hostname,
    marks: extras.marks,
    facts: [
      { label: "Action", value: row.action },
      { label: "Requester", value: row.requester },
      { label: "Resources", value: row.resources },
      ...extras.extraFacts,
    ],
    observed: extras.observed,
    unknown: [...omittedFromObservation, ...extras.unknown],
    notice: extras.notice ?? null,
  };
}

function fieldedProbe(observation: Observation, siteId: string) {
  return observation.probes
    .filter((item) => item.site_id === siteId && item.fields && Object.keys(item.fields).length > 0)
    .at(-1);
}

export type LiveReceipt = {
  id: string;
  siteId: string;
  hostname: string | null;
  snapshotId: string;
  stateLabel: string;
  stateKind: "ok" | "err" | "unknown";
  timing: string;
  fields: { name: string; mark: Mark; scope: string | null }[];
  /** W379: why an independent copy is not confirmed, when it is not. */
  independence: string | null;
};

/** D-026 defers independent and off-site copies; a probe of the enrolled store never claims one. */
const D026_NOTE =
  "Independent copy is not confirmed. D-026 defers independent and off-site copies until after v1.0, so this probe restored from the enrolled store only. A passed probe is not an independent recovery.";

/** A probe is a receipt only when the journal stored its seven fields. */
export function liveReceipt(observation: Observation, id: string): LiveReceipt | null {
  const probe = observation.probes.find((item) => item.operation_id === id);
  if (!probe?.fields || Object.keys(probe.fields).length === 0) return null;
  const state = restoreState(probe.state);
  return {
    id: probe.operation_id,
    siteId: probe.site_id,
    hostname: hostnameOf(observation, probe.site_id),
    snapshotId: probe.snapshot_id,
    stateLabel: state.label,
    stateKind: state.kind === "notrun" ? "unknown" : state.kind,
    timing: probe.finished_at
      ? `${utc(probe.started_at)} – ${utc(probe.finished_at)} UTC`
      : `${utc(probe.started_at)} UTC · still running`,
    fields: evidenceFields.map(([key, name]) => ({
      name,
      mark: mark(probe.fields?.[key]),
      scope: probe.fields?.[key]?.scope ?? null,
    })),
    independence: mark(probe.fields?.independent_copy_confirmed) === "pass" ? null : D026_NOTE,
  };
}

const RPO_TARGET_SECONDS = 86_400;

function ageSpan(seconds: number): string {
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} m`;
  if (seconds < RPO_TARGET_SECONDS) {
    return `${Math.floor(seconds / 3600)} h ${Math.floor((seconds % 3600) / 60)} m`;
  }
  return `${Math.floor(seconds / RPO_TARGET_SECONDS)} d ${Math.floor((seconds % RPO_TARGET_SECONDS) / 3600)} h`;
}

function newestSucceededCapture(observation: Observation, siteId: string) {
  return observation.captures
    .filter(
      (item) =>
        item.site_id === siteId &&
        item.state === "succeeded" &&
        item.finished_at !== null &&
        item.snapshot_id !== null,
    )
    .reduce<(typeof observation.captures)[number] | null>((best, item) => {
      if (best === null || (item.finished_at ?? -1) >= (best.finished_at ?? -1)) return item;
      return best;
    }, null);
}

export type CaptureExposure = {
  siteId: string;
  seconds: number | null;
  withinTarget: boolean | null;
  text: string;
};

/** Age of the newest succeeded capture against the journal clock. Not an independent-copy RPO. */
export function liveCaptureExposure(observation: Observation, siteId: string): CaptureExposure {
  const capture = newestSucceededCapture(observation, siteId);
  if (capture?.finished_at == null) {
    return {
      siteId,
      seconds: null,
      withinTarget: null,
      text: "No succeeded capture is recorded. The data-loss window is unmeasured.",
    };
  }
  const age = observation.journal_last_time - capture.finished_at;
  if (!Number.isInteger(age) || age < 0) {
    return {
      siteId,
      seconds: null,
      withinTarget: null,
      text: "Journal last time is before this capture finished. Age is not computed.",
    };
  }
  const withinTarget = age <= RPO_TARGET_SECONDS;
  const relation = withinTarget ? "within" : "past";
  return {
    siteId,
    seconds: age,
    withinTarget,
    text: `Newest succeeded capture is ${ageSpan(age)} before the journal's last time, ${relation} the 24 h D-010 target. This is the local gap, not an independent-copy RPO.`,
  };
}

const restoreState = (state: Observation["probes"][number]["state"]): RecoveryState =>
  state === "passed"
    ? { label: "Passed", kind: "ok" }
    : state === "running"
      ? { label: "Running", kind: "unknown" }
      : { label: state === "failed" ? "Failed" : "Cleanup incomplete", kind: "err" };

/** W366: an unclaimed snapshot is named so it is never mistaken for a backup of record. */
function noSnapshotNote(observation: Observation, siteId: string): string {
  const unclaimed = observation.captures.filter(
    (item) => item.site_id === siteId && item.state === "failed" && item.unclaimed_snapshot_id,
  ).length;
  if (unclaimed === 0) return "No snapshot";
  return `No snapshot of record · ${unclaimed} unclaimed, not a backup of record`;
}

export function liveRecovery(observation: Observation): RecoveryRow[] {
  return observation.sites.map((site) => {
    const snapshot = observation.captures
      .filter((item) => item.site_id === site.site_id && item.snapshot_id)
      .at(-1);
    const probe = observation.probes.filter((item) => item.site_id === site.site_id).at(-1);
    return {
      siteId: site.site_id,
      snapshot: snapshot
        ? `${snapshot.snapshot_id?.slice(0, 8)} · ${utc(snapshot.started_at)}`
        : null,
      snapshotNote: snapshot ? undefined : noSnapshotNote(observation, site.site_id),
      restore: probe
        ? {
            ...restoreState(probe.state),
            label: `${restoreState(probe.state).label} · ${utc(probe.started_at)}`,
          }
        : snapshot
          ? { label: "Never", kind: "notrun" }
          : null,
      copy: snapshot ? { label: "Not independent (lab store)", kind: "err" } : null,
      exposure: liveCaptureExposure(observation, site.site_id).text,
      receipt: fieldedProbe(observation, site.site_id)?.operation_id ?? null,
    };
  });
}

export function liveSiteSnapshots(observation: Observation): Record<string, SiteSnapshot[]> {
  const repository = `${observation.host.backup_destination ?? "lab_pc_store"} · not independent`;
  const result: Record<string, SiteSnapshot[]> = {};
  for (const site of observation.sites) {
    const captures = observation.captures
      .filter((item) => item.site_id === site.site_id && item.snapshot_id)
      .slice()
      .reverse();
    result[site.site_id] = captures.map((capture) => {
      const fullId = capture.snapshot_id as string;
      const probes = observation.probes.filter(
        (item) => item.site_id === site.site_id && item.snapshot_id === fullId,
      );
      const latestProbe = probes.at(-1);
      const probeWithFields = probes
        .filter((item) => item.fields && Object.keys(item.fields).length)
        .at(-1);
      const marks: Mark[] = probeWithFields
        ? evidenceFields.map(([key]) => mark(probeWithFields.fields?.[key]))
        : ["pass", "pass", "not_run", "not_run", "not_run", "not_run", "unknown"];
      const restore: RecoveryState = latestProbe
        ? {
            ...restoreState(latestProbe.state),
            label: `${restoreState(latestProbe.state).label} · ${utc(latestProbe.started_at)}`,
          }
        : { label: "Not run", kind: "notrun" };
      return {
        id: fullId.slice(0, 8),
        artifactId: fullId,
        note: `Files + DB · ${capture.operation_id} (${duration(capture.started_at, capture.finished_at)})`,
        captured: utc(capture.started_at),
        repository,
        size: "—",
        marks,
        restore,
      };
    });
  }
  return result;
}

export type LiveSnapshot = {
  id: string;
  shortId: string;
  siteId: string;
  hostname: string | null;
  operationId: string;
  stateLabel: string;
  timing: string;
  repository: string;
  receiptId: string | null;
  marks: Mark[] | null;
  restoreLabel: string;
};

/** A snapshot page shows one capture. A short id matches only when it is unique. */
export function liveSnapshot(observation: Observation, id: string): LiveSnapshot | null {
  const matches = observation.captures.filter(
    (item) => item.snapshot_id === id || item.snapshot_id?.startsWith(id) === true,
  );
  const capture =
    matches.find((item) => item.snapshot_id === id) ?? (matches.length === 1 ? matches[0] : null);
  if (!capture?.snapshot_id) return null;
  const fullId = capture.snapshot_id;
  const probes = observation.probes.filter((item) => item.snapshot_id === fullId);
  const fielded = probes
    .filter((item) => item.fields && Object.keys(item.fields).length > 0)
    .at(-1);
  const latest = probes.at(-1);
  return {
    id: fullId,
    shortId: fullId.slice(0, 8),
    siteId: capture.site_id,
    hostname: hostnameOf(observation, capture.site_id),
    operationId: capture.operation_id,
    stateLabel: capture.state,
    timing: capture.finished_at
      ? `${utc(capture.started_at)} – ${utc(capture.finished_at)} UTC`
      : `${utc(capture.started_at)} UTC · still running`,
    repository: `${observation.host.backup_destination ?? "lab_pc_store"} · not independent`,
    receiptId: fielded?.operation_id ?? null,
    marks: fielded ? evidenceFields.map(([key]) => mark(fielded.fields?.[key])) : null,
    restoreLabel: latest ? restoreState(latest.state).label : "Not run",
  };
}

export type OverviewMetrics = {
  cpu: { value: string; unit: string; detail: string; width: string };
  memory: { value: string; unit: string; detail: string; width: string };
  disk: { extra: string; value: string; unit: string; detail: string; width: string };
  uptime: { value: string; unit: string; detail: string; kernel: string };
};

function gib(bytes: number) {
  return `${(bytes / 1073741824).toFixed(1)} GiB`;
}

function usedPercent(total: number | null, available: number | null): number | null {
  if (total === null || available === null || total <= 0) return null;
  return Math.max(0, Math.min(100, Math.round(((total - available) / total) * 100)));
}

function uptimeDisplay(seconds: number | null): { value: string; unit: string } {
  if (seconds === null || seconds < 0) return { value: "—", unit: "" };
  if (seconds >= 86400) return { value: String(Math.floor(seconds / 86400)), unit: " days" };
  if (seconds >= 3600) return { value: String(Math.floor(seconds / 3600)), unit: " hours" };
  return { value: String(Math.max(1, Math.floor(seconds / 60))), unit: " min" };
}

/** The executor's SELinux context, or why it was not read. */
export function executorSelinuxText(value: Machine["executor_selinux"]): string {
  if (!value) return "Executor SELinux context was not read";
  if (!value.readable || !value.context) {
    return "Executor SELinux context is not readable by this observer";
  }
  return `Executor SELinux context ${value.context}`;
}

export function olsMapText(
  map: Machine["ols_map"],
  sites: Observation["sites"] | undefined,
): string | null {
  if (!map) return null;
  if (!map.readable || !map.hosts) return "Active OLS map was not readable";
  const mapped = new Set(map.hosts);
  const omitted = (sites ?? [])
    .filter((site) => site.state === "succeeded" && !site.ejected && !mapped.has(site.hostname))
    .map((site) => site.hostname);
  if (omitted.length === 0)
    return "Succeeded sites in the journal are covered by the active OLS map";
  return `Not in the active OLS map: ${omitted.join(", ")}`;
}

export function failedUnitsText(value: Machine["failed_units"]): string {
  if (!value) return "Failed units were not read";
  if (!value.readable || !value.units) return "Failed units were not readable by this observer";
  if (value.units.length === 0) return "No failed units";
  if (value.truncated) return `${value.units.length} or more units failed`;
  if (value.units.length === 1) return `Failed unit ${value.units[0]}`;
  return `${value.units.length} units failed`;
}

/** Installed OpenLiteSpeed, MariaDB, and PHP versions. Missing pieces stay out. */
export function stackText(stack: Machine["stack"]): string {
  if (!stack) return "Stack versions were not read";
  const parts = [
    stack.openlitespeed ? `OpenLiteSpeed ${stack.openlitespeed}` : null,
    stack.mariadb ? `MariaDB ${stack.mariadb}` : null,
    stack.php.length > 0 ? `PHP ${stack.php.join(", ")}` : null,
  ].filter((part) => part !== null);
  return parts.length > 0 ? parts.join(" · ") : "Stack versions were not read";
}

/** MariaDB ping on the compiled default socket. A response is not a query. */
export function databaseText(database: Machine["database"]): string {
  if (!database) return "MariaDB ping was not run";
  if (database.ping === "responding") {
    return "MariaDB responded on the default socket. This is not a query.";
  }
  if (database.ping === "not_responding") {
    return "MariaDB did not respond on the default socket.";
  }
  return "MariaDB ping was not run";
}

/** Firewalld default zone. Missing means the read was not attempted. */
export function firewallText(firewall: Machine["firewall"]): string {
  if (!firewall) return "Firewall policy was not read";
  if (!firewall.readable || !firewall.state || !firewall.default_zone) {
    return "Firewall policy not readable by this observer";
  }
  const services = firewall.services?.length ? firewall.services.join(", ") : "none listed";
  return `Firewall ${firewall.state} · zone ${firewall.default_zone} · services ${services}`;
}

/** Port 443 listeners. A count is not a certificate expiry. */
export function tlsListenerText(tls: Machine["tls"]): string {
  const count = tls?.listeners_443;
  if (typeof count !== "number" || !Number.isInteger(count) || count < 0) {
    return "TLS listeners not observed. Certificate expiry was not read.";
  }
  if (count === 0) return "No TLS listener on port 443. Certificate expiry was not read.";
  const noun = count === 1 ? "listener" : "listeners";
  return `${count} TLS ${noun} on port 443. Certificate expiry was not read.`;
}

/**
 * W702 (W689 candidate 5): the host-fact lines of the Services screen, in
 * display order. A fact the observer did not report has no line.
 */
export function serviceFactLines(
  machine: Machine | null,
  journalSites: Observation["sites"] | undefined,
): string[] {
  if (!machine) return [];
  return [
    machine.ssh ? sshPolicyText(machine.ssh) : null,
    machine.tls ? tlsListenerText(machine.tls) : null,
    machine.firewall ? firewallText(machine.firewall) : null,
    machine.database ? databaseText(machine.database) : null,
    machine.stack ? stackText(machine.stack) : null,
    machine.executor_selinux ? executorSelinuxText(machine.executor_selinux) : null,
    machine.failed_units ? failedUnitsText(machine.failed_units) : null,
    olsMapText(machine.ols_map, journalSites),
  ].filter((line) => line !== null);
}

/** Effective SSH settings, or an explicit unread result. Missing means the read was not attempted. */
export function sshPolicyText(ssh: Machine["ssh"]): string {
  if (!ssh) return "SSH policy was not read";
  if (!ssh.readable) return "SSH policy not readable by this observer";
  const value = (item: string | null) => item ?? "unobserved";
  return `SSH root login ${value(ssh.permit_root_login)} · password ${value(ssh.password_authentication)} · public key ${value(ssh.pubkey_authentication)} · keyboard-interactive ${value(ssh.kbd_interactive_authentication)}`;
}

function offsetText(microseconds: number | null | undefined): string | null {
  if (typeof microseconds !== "number" || !Number.isInteger(microseconds)) return null;
  if (microseconds === 0) return "offset 0 µs";
  const direction = microseconds < 0 ? "slow" : "fast";
  return `${Math.abs(microseconds)} µs ${direction} of NTP`;
}

/** NTP sync from timedatectl, plus a chrony offset when that read succeeded. */
export function clockSyncText(clock: Machine["clock"] | undefined): string {
  const sync =
    clock?.synchronized === true
      ? "NTP synchronized"
      : clock?.synchronized === false
        ? "NTP not synchronized"
        : "Clock sync not observed";
  const offset = offsetText(clock?.offset_us);
  return offset ? `${sync} · ${offset}` : sync;
}

/** Inode use for one filesystem. Missing or inconsistent counts stay unobserved. */
export function inodeUseText(disk: Machine["disk"]): string | null {
  const total = disk.inode_total;
  const available = disk.inode_available;
  if (typeof total !== "number" || typeof available !== "number") return null;
  if (!Number.isInteger(total) || !Number.isInteger(available)) return null;
  if (total <= 0 || available < 0 || available > total) return null;
  const used = total - available;
  const percent = Math.round((used / total) * 100);
  return `${used} of ${total} inodes in use (${percent}%)`;
}

export type ResourcePressure = { resource: "Memory" | "Disk" | "Inodes"; percent: number };

const PRESSURE_PERCENT = 90;

/** Memory, disk, or inode use at or past 90%. Missing counts are not pressure. */
export function resourcePressure(machine: Machine | undefined): ResourcePressure[] {
  if (!machine) return [];
  const rows: ResourcePressure[] = [];
  const memory = usedPercent(machine.memory.total_bytes, machine.memory.available_bytes);
  const disk = usedPercent(machine.disk.total_bytes, machine.disk.available_bytes);
  if (memory !== null && memory >= PRESSURE_PERCENT)
    rows.push({ resource: "Memory", percent: memory });
  if (disk !== null && disk >= PRESSURE_PERCENT) rows.push({ resource: "Disk", percent: disk });
  if (inodeUseText(machine.disk)) {
    const inodes = usedPercent(
      machine.disk.inode_total ?? null,
      machine.disk.inode_available ?? null,
    );
    if (inodes !== null && inodes >= PRESSURE_PERCENT) {
      rows.push({ resource: "Inodes", percent: inodes });
    }
  }
  return rows;
}

function metricValue(percent: number | null) {
  return {
    value: percent === null ? "—" : String(percent),
    unit: percent === null ? "" : "%",
    width: `${percent ?? 0}%`,
  };
}

export function liveOverviewMetrics(machine: Machine): OverviewMetrics {
  const cpuCount = machine.cpu.count;
  const load5 = machine.cpu.load?.[1] ?? null;
  const cpuPct =
    cpuCount && cpuCount > 0 && load5 !== null
      ? Math.max(0, Math.min(100, Math.round((load5 / cpuCount) * 100)))
      : null;
  const memPct = usedPercent(machine.memory.total_bytes, machine.memory.available_bytes);
  const diskPct = usedPercent(machine.disk.total_bytes, machine.disk.available_bytes);
  const up = uptimeDisplay(machine.uptime_seconds);
  const memDetail =
    machine.memory.total_bytes !== null && machine.memory.available_bytes !== null
      ? `${gib(machine.memory.total_bytes - machine.memory.available_bytes)} of ${gib(machine.memory.total_bytes)} in use`
      : "—";
  const byteDetail =
    machine.disk.total_bytes !== null && machine.disk.available_bytes !== null
      ? `${gib(machine.disk.total_bytes - machine.disk.available_bytes)} of ${gib(machine.disk.total_bytes)} in use`
      : null;
  const inodes = inodeUseText(machine.disk);
  const diskDetail = [byteDetail, inodes].filter((part) => part !== null).join(" · ") || "—";
  return {
    cpu: {
      ...metricValue(cpuPct),
      detail: `5-min load ${load5 !== null ? load5.toFixed(2) : "—"} · ${cpuCount ?? "?"} vCPU`,
    },
    memory: { ...metricValue(memPct), detail: memDetail },
    disk: { ...metricValue(diskPct), extra: machine.disk.path, detail: diskDetail },
    uptime: {
      ...up,
      detail: `${machine.os.name ?? "Linux"} ${machine.os.version ?? ""}`.trim(),
      kernel: `Kernel ${machine.os.kernel ?? "unknown"}`,
    },
  };
}

export function isMachine(value: unknown): value is Machine {
  const candidate = value as Partial<Machine> | null;
  return (
    typeof candidate === "object" &&
    candidate !== null &&
    candidate.schema === "rustiron-host-status/1" &&
    Array.isArray(candidate.services) &&
    (candidate.samples === undefined || isHostSamples(candidate.samples))
  );
}

function isNullableNumber(value: unknown): value is number | null {
  return value === null || typeof value === "number";
}

function isHostSample(value: unknown): value is HostSample {
  if (value === null || typeof value !== "object") return false;
  const item = value as Partial<HostSample>;
  return (
    isNullableNumber(item.t) &&
    isNullableNumber(item.cpu) &&
    isNullableNumber(item.mem) &&
    isNullableNumber(item.disk)
  );
}

function isHostSamples(value: unknown): value is HostSample[] {
  return Array.isArray(value) && value.every(isHostSample);
}

export type HostHistory = {
  samples: { t: number; cpu: number | null; mem: number | null; disk: number | null }[];
  from: number;
  to: number;
};

export function liveHostHistory(machine: Machine): HostHistory | null {
  const samples = (machine.samples ?? [])
    .filter((item): item is HostSample & { t: number } => item.t !== null)
    .sort((left, right) => left.t - right.t);
  const first = samples[0];
  const last = samples[samples.length - 1];
  if (samples.length < 2 || first === undefined || last === undefined) return null;
  return { samples, from: first.t, to: last.t };
}

const utcWindow = new Intl.DateTimeFormat("en-GB", {
  timeZone: "UTC",
  dateStyle: "medium",
  timeStyle: "short",
});

export function hostHistoryCaption(history: HostHistory): string {
  return `${history.samples.length} samples · ${utcWindow.format(new Date(history.from * 1000))} to ${utcWindow.format(new Date(history.to * 1000))} UTC`;
}

function serviceState(active: string | null, sub: string | null): ServiceState {
  if (active === "active") return "Running";
  if (active === "failed") return "Failed";
  if (active === "activating" || active === "reloading") return "Starting";
  if (active === "inactive" || active === "deactivating")
    return sub === "dead" ? "Stopped" : "Starting";
  return "Not checked";
}

const roles: Record<string, [string, string]> = {
  "lshttpd.service": ["Web server", "Owned includes"],
  "mariadb.service": ["Database", "Observed only"],
  "rustiron-s02-lab-executor.service": ["Privileged executor", "Rustiron"],
  "logrotate.timer": ["Log rotation", "Observed only"],
};

function serviceWhen(service: Machine["services"][number]): string {
  if (service.unit?.endsWith(".timer") === true) {
    return typeof service.last_trigger === "number"
      ? `Last trigger ${utc(service.last_trigger)} UTC`
      : "No trigger recorded";
  }
  return service.since ? `${utc(service.since)} UTC` : "—";
}

export function liveServices(machine: Machine): HostService[] {
  return machine.services.map((service) => {
    const unit = service.unit ?? "unknown unit";
    const site = /^rustiron-site-php@(.+)\.service$/.exec(unit)?.[1];
    const [role, management] = site
      ? [`PHP for ${site}`, "Rustiron-managed"]
      : (roles[unit] ?? ["Host service", "Observed only"]);
    return {
      name: site ? `PHP pool · ${site}` : (service.label ?? unit),
      unit,
      role,
      state: serviceState(service.active, service.sub),
      since: serviceWhen(service),
      management,
      selinux: Object.hasOwn(service, "selinux_context")
        ? (service.selinux_context ?? null)
        : undefined,
    };
  });
}

export type AttentionItem = { href: string; label: string };

export type LiveAttention = { count: number; items: AttentionItem[] };

function attentionSites(observation: Observation): Site[] {
  return liveSites(observation).filter((site) => site.servingKind === "err");
}

function attentionOperations(observation: Observation): OperationRow[] {
  return liveOperations(observation).filter((row) => row.kind === "err" || row.kind === "warn");
}

function pressureAttention(machine: Machine | undefined): AttentionItem | null {
  const pressure = resourcePressure(machine);
  const first = pressure[0];
  if (pressure.length === 1 && first) {
    return { href: "/host/metrics", label: `${first.resource} is ${first.percent}% used` };
  }
  if (pressure.length > 1) {
    return { href: "/host/metrics", label: `${pressure.length} resources are past 90% used` };
  }
  return null;
}

function oneNotice(show: boolean, item: AttentionItem): AttentionItem | null {
  return show ? item : null;
}

function mapDrift(
  sites: Observation["sites"],
  labelForOne: (hostname: string) => string,
  labelForMany: (count: number) => string,
): AttentionItem | null {
  const first = sites[0];
  if (!first) return null;
  if (sites.length === 1) {
    return { href: `/sites/${first.site_id}`, label: labelForOne(first.hostname) };
  }
  return { href: "/sites", label: labelForMany(sites.length) };
}

function olsDrift(observation: Observation): { items: AttentionItem[]; count: number } {
  const map = observation.machine?.ols_map;
  if (!map?.readable || !map.hosts) return { items: [], count: 0 };
  const mapped = new Set(map.hosts);
  const omitted = observation.sites.filter(
    (site) => site.state === "succeeded" && !site.ejected && !mapped.has(site.hostname),
  );
  return {
    items: [
      mapDrift(
        omitted,
        (hostname) => `${hostname} is not in the active OLS map`,
        (count) => `${count} succeeded sites are not in the active OLS map`,
      ),
    ].filter((item) => item !== null),
    count: omitted.length,
  };
}

function listedFailedUnits(value: Machine["failed_units"]): string[] {
  return value?.readable ? (value.units ?? []) : [];
}

function failedUnitCount(value: Machine["failed_units"]): number {
  const units = listedFailedUnits(value);
  if (units.length === 0) return 0;
  return value?.truncated ? units.length + 1 : units.length;
}

function failedUnitLabel(value: Machine["failed_units"]): string | null {
  const units = listedFailedUnits(value);
  const first = units[0];
  if (!first) return null;
  if (units.length === 1 && !value?.truncated) return `${first} failed`;
  if (value?.truncated) return `${units.length} or more units failed`;
  return `${units.length} units failed`;
}

function failedUnitNotice(machine: Machine | undefined): {
  item: AttentionItem | null;
  count: number;
} {
  const label = failedUnitLabel(machine?.failed_units);
  if (!label) return { item: null, count: 0 };
  return {
    item: { href: "/host/services", label },
    count: failedUnitCount(machine?.failed_units),
  };
}

function clockSkewNotice(machine: Machine | undefined): AttentionItem | null {
  const offset = machine?.clock?.offset_us;
  if (typeof offset !== "number" || Math.abs(offset) < 1_000_000) return null;
  return { href: "/host/services", label: "Clock offset is at least 1 s" };
}

function groupedExtra(count: number): number {
  return count > 1 ? count - 1 : 0;
}

function phpConfinement(machine: Machine | undefined): {
  item: AttentionItem | null;
  count: number;
} {
  const outside = (machine?.services ?? []).flatMap((service) => {
    const site = /^rustiron-site-php@(.+)\.service$/.exec(service.unit ?? "")?.[1];
    const type = service.selinux_context?.split(":")[2];
    return site && type && type !== "rustiron_php_t" ? [{ site, type }] : [];
  });
  const first = outside[0];
  if (outside.length === 1 && first) {
    return {
      item: {
        href: "/host/services",
        label: `PHP pool ${first.site} SELinux type is ${first.type}`,
      },
      count: 1,
    };
  }
  if (outside.length > 1) {
    return {
      item: {
        href: "/host/services",
        label: `${outside.length} PHP pools are outside rustiron_php_t`,
      },
      count: outside.length,
    };
  }
  return { item: null, count: 0 };
}

function selinuxNotices(machine: Machine | undefined): AttentionItem[] {
  const items: AttentionItem[] = [];
  if (machine?.selinux === "permissive") {
    items.push({ href: "/host/services", label: "SELinux is permissive" });
  }
  const type = machine?.executor_selinux?.context?.split(":")[2];
  if (type === "unconfined_t" || type === "unconfined_service_t") {
    items.push({ href: "/host/services", label: "Executor SELinux type is unconfined" });
  }
  return items;
}

function hostAttention(machine: Machine | undefined): { items: AttentionItem[]; count: number } {
  const php = phpConfinement(machine);
  const failed = failedUnitNotice(machine);
  const notices = [
    oneNotice(machine?.ssh?.password_authentication === "yes", {
      href: "/host/services",
      label: "SSH password authentication is enabled",
    }),
    oneNotice(machine?.database?.ping === "not_responding", {
      href: "/host/services",
      label: "MariaDB did not respond",
    }),
    oneNotice(machine?.firewall?.readable === true && machine.firewall.state === "not running", {
      href: "/host/services",
      label: "Firewall is not running",
    }),
    oneNotice(machine?.clock?.synchronized === false, {
      href: "/host/services",
      label: "NTP is not synchronized",
    }),
    clockSkewNotice(machine),
    ...selinuxNotices(machine),
    php.item,
    failed.item,
    pressureAttention(machine),
  ];
  const items = notices.filter((item) => item !== null);
  const extra =
    groupedExtra(resourcePressure(machine).length) +
    groupedExtra(php.count) +
    groupedExtra(failed.count);
  return { items, count: items.length + extra };
}

/** Count and grouped links for the notifications dialog. Never invents fixture shop stories. */
export function liveAttention(observation: Observation): LiveAttention {
  const sites = attentionSites(observation);
  const ops = attentionOperations(observation);
  const items: AttentionItem[] = [];
  const site = sites[0];
  if (sites.length === 1 && site) {
    items.push({ href: `/sites/${site.id}`, label: `${site.serving} site ${site.domain}` });
  } else if (sites.length > 1) {
    items.push({ href: "/sites", label: `${sites.length} sites quarantined or blocked` });
  }
  const row = ops[0];
  if (ops.length === 1 && row) {
    items.push({ href: `/operations/${row.id}`, label: `${row.action} ${row.id}` });
  } else if (ops.length > 1) {
    items.push({ href: "/operations", label: `${ops.length} operations need attention` });
  }
  const stale = observation.sites.filter(
    (candidate) => liveCaptureExposure(observation, candidate.site_id).withinTarget === false,
  );
  const host = hostAttention(observation.machine);
  const drift = olsDrift(observation);
  items.push(...host.items, ...drift.items);
  const staleSite = stale[0];
  if (stale.length === 1 && staleSite) {
    items.push({
      href: `/sites/${staleSite.site_id}/recovery`,
      label: `${staleSite.hostname} is past the 24 h local capture gap`,
    });
  } else if (stale.length > 1) {
    items.push({
      href: "/recovery",
      label: `${stale.length} sites past the 24 h local capture gap`,
    });
  }
  return {
    count: sites.length + ops.length + stale.length + host.count + drift.count,
    items,
  };
}

export type LiveHelpItem = {
  title: string;
  detail: string;
  href: string;
};

export type SearchTarget = { href: string; label: string };

/** Console pages that exist without fixture host stories. */
export const consoleSearchPages: SearchTarget[] = [
  { href: "/", label: "Host overview" },
  { href: "/host/metrics", label: "Host metrics" },
  { href: "/host/services", label: "Services" },
  { href: "/host/diagnoses", label: "Host diagnoses" },
  { href: "/host/updates", label: "Host updates" },
  { href: "/host/alerts", label: "Alerts" },
  { href: "/host/firewall", label: "Firewall" },
  { href: "/host/cron", label: "Cron jobs" },
  { href: "/host/logs", label: "Server logs" },
  { href: "/sites", label: "Websites" },
  { href: "/sites/new", label: "Add website" },
  { href: "/apps", label: "Apps" },
  { href: "/databases", label: "Databases" },
  { href: "/domains", label: "Domains" },
  { href: "/domains/new", label: "Add domain & DNS zone" },
  { href: "/mail", label: "Email" },
  { href: "/migration", label: "Migration" },
  { href: "/operations", label: "Operations" },
  { href: "/recovery", label: "Backups" },
  { href: "/recovery/schedules", label: "Scheduled capture" },
  { href: "/recovery/store", label: "Backup store" },
  { href: "/users", label: "Users & access" },
  { href: "/settings", label: "Settings" },
  { href: "/help", label: "Docs & Knowledge Base" },
  { href: "/states", label: "Shared states" },
];

function siteSearch(sites: Site[]): SearchTarget[] {
  return sites.map((site) => ({ href: `/sites/${site.id}`, label: site.domain }));
}

function operationSearch(rows: OperationRow[]): SearchTarget[] {
  return rows.map((row) => ({ href: `/operations/${row.id}`, label: `${row.action} ${row.id}` }));
}

function recoverySearch(
  rows: RecoveryRow[],
  snapshots: Record<string, SiteSnapshot[]>,
): SearchTarget[] {
  const targets: SearchTarget[] = [];
  for (const row of rows) {
    if (row.receipt) {
      targets.push({ href: `/recovery/evidence/${row.receipt}`, label: `Receipt ${row.receipt}` });
    }
  }
  for (const list of Object.values(snapshots)) {
    for (const snap of list) {
      if (snap.artifactId) {
        targets.push({
          href: `/recovery/artifacts/${snap.artifactId}`,
          label: `Snapshot ${snap.id}`,
        });
      }
    }
  }
  return targets;
}

/** Search hits from this observation. Never lists fixture shop, plans or receipts. */
export function liveSearchTargets(observation: Observation): SearchTarget[] {
  return [
    ...consoleSearchPages,
    ...siteSearch(liveSites(observation)),
    ...operationSearch(liveOperations(observation)),
    ...recoverySearch(liveRecovery(observation), liveSiteSnapshots(observation)),
  ];
}

/** Up to two current host facts for Help. Never invents fixture incidents. */
export function liveHelpItems(observation: Observation): LiveHelpItem[] {
  const items: LiveHelpItem[] = [];
  for (const site of observation.sites) {
    if (site.state === "quarantined") {
      items.push({
        title: `Quarantined site ${site.hostname}`,
        detail: failedStepLabel(site)
          ? `${site.site_id} is quarantined. Stopped at ${failedStepLabel(site)}.`
          : `${site.site_id} is quarantined. ${site.steps_done} of ${site.steps_recorded} steps are recorded.`,
        href: `/sites/${site.site_id}`,
      });
    }
    if (site.ejected) {
      items.push({
        title: `Ejected site ${site.hostname}`,
        detail: `${site.site_id} is ejected. Serving data stays on the host.`,
        href: `/sites/${site.site_id}`,
      });
    }
  }
  for (const row of liveOperations(observation)) {
    if (row.kind !== "err" && row.kind !== "warn") continue;
    items.push({
      title: `${row.action} · ${row.outcome}`,
      detail: `${row.id} · ${row.resources}`,
      href: `/operations/${row.id}`,
    });
  }
  return items.slice(0, 2);
}
