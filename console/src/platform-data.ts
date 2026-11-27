// W604 (P29): Data models and live-observation derivations for the consolidated
// developer hosting-platform views (Apps/EmDash, Host Diagnoses, Host Updates,
// Domains/Certificates/DNS, and Migration). Fixture data uses *.lab.test names;
// live mode derives strictly from the executor observation without fabrication.
import type { Site } from "./fixture";
import type { Machine, Observation } from "./live";

export type AppReleaseRecord = {
  releaseId: string;
  version: string;
  state: "active" | "superseded" | "failed_compensated";
  when: string;
  note: string;
  migration?: string;
};

export type AppRecord = {
  id: string;
  siteId: string;
  hostname: string;
  kind: "EmDash CMS" | "Full-stack app" | "Node.js app" | "Bun app" | "Static SPA";
  runtime: string;
  runtimeProfile: "node_22_v1" | "bun_1_v1" | "static_v1";
  ingress: "OpenLiteSpeed" | "Caddy (HTTP/3)";
  topology: "static_spa" | "backend_api" | "fullstack_split" | "fullstack_dual_ssr";
  database: "none" | "sqlite" | "mariadb" | "postgresql_18";
  blueGreen?: { activeSlot: "a" | "b"; standbyPort: number };
  serving: "Serving" | "Degraded" | "Stopped";
  servingKind: "ok" | "err" | "muted";
  health: string;
  healthKind: "ok" | "err" | "muted";
  healthPath: string;
  port: number;
  websocketPrefix: string | null;
  account: string;
  unit: string;
  workerUnit: string | null;
  limits: string;
  envKeys: string[];
  sqliteBackup: string;
  currentRelease: string;
  failedReleaseNote: string | null;
  releases: AppReleaseRecord[];
};

export type DiagnosisFinding = {
  id: string;
  state: "fail" | "unknown" | "warn" | "ok";
  check: string;
  subject: string;
  owner: "rustiron" | "host";
  seen: string;
  reason: string;
  action: string;
  command?: string;
  runbook?: string;
  guideSlug?: string;
};

export type SupportComponent = {
  id: string;
  component: string;
  series: string;
  observed: string;
  minimumPatch: string;
  endOfLife: string;
  state: "supported" | "warn" | "optional" | "unknown";
  stateLabel: string;
  packagePin: string;
  note: string;
  optional?: boolean;
};

export type DomainRecord = {
  hostname: string;
  serves: string;
  siteHref: string | null;
  certificate: "valid" | "renewal_failed" | "expires_soon" | "not_issued";
  certificateLabel: string;
  notAfter: string;
  renewedBy: "Rustiron" | "operator" | "—";
  issuer: string;
  chainDigest: string;
  renewUntil: string;
  lastResult: string;
  dnsZone: string;
  dnsMode: string;
};

export type MigrationRecord = {
  id: string;
  kind: "CyberPanel WordPress" | "WordPress → EmDash CMS";
  source: string;
  targetHostname: string;
  dryRunState: "ok" | "fail";
  dryRunLabel: string;
  importState: "ok" | "fail" | "unknown";
  importLabel: string;
  scrubLabel: string;
  recorded: string;
  refusals: { code: string; detail: string }[];
  facts: { name: string; source: "observed" | "declared" | "unknown" }[];
  note: string;
};

export const fixtureApps: AppRecord[] = [
  {
    id: "app_saas",
    siteId: "saasapp",
    hostname: "app.lab.test",
    kind: "Full-stack app",
    runtime: "Vite SPA + Bun 1.4 Elysia · PostgreSQL 18.7",
    runtimeProfile: "bun_1_v1",
    ingress: "Caddy (HTTP/3)",
    topology: "fullstack_split",
    database: "postgresql_18",
    blueGreen: { activeSlot: "a", standbyPort: 3302 },
    serving: "Serving",
    servingKind: "ok",
    health: "Passing · /api/health 200",
    healthKind: "ok",
    healthPath: "/api/health",
    port: 3301,
    websocketPrefix: "/ws/",
    account: "rs_saasapp",
    unit: "rustiron-app@rs_saasapp.service",
    workerUnit: null,
    limits: "768 MiB · 64 tasks · rustiron_app_pg_t · blue/green",
    envKeys: ["DATABASE_URL", "SESSION_SECRET", "PUBLIC_ORIGIN"],
    sqliteBackup: "Encrypted restic + COMPLIANCE 30d · PostgreSQL 18 pg_dump verified 1 h ago",
    currentRelease: "rel-20261126-04",
    failedReleaseNote: null,
    releases: [
      {
        releaseId: "rel-20261126-04",
        version: "App 1.4.2 (Slot A)",
        state: "active",
        when: "1 h ago",
        note: "Zero-downtime Caddy blue/green cutover after /api/health 200 on standby slot.",
        migration: "api/migrate.js (pg18)",
      },
      {
        releaseId: "rel-20261124-03",
        version: "App 1.4.1 (Slot B)",
        state: "superseded",
        when: "2 d ago",
        note: "Previous healthy release retained read-only under releases/.",
      },
    ],
  },
  {
    id: "app_emdash",
    siteId: "emdash1",
    hostname: "emdash.lab.test",
    kind: "EmDash CMS",
    runtime: "Node.js 22.23.4 · SQLite FTS5",
    runtimeProfile: "node_22_v1",
    ingress: "OpenLiteSpeed",
    topology: "backend_api",
    database: "sqlite",
    serving: "Serving",
    servingKind: "ok",
    health: "Passing · /health 200",
    healthKind: "ok",
    healthPath: "/health",
    port: 3210,
    websocketPrefix: "/_emdash/api/content/",
    account: "rs_emdash1",
    unit: "rustiron-app@rs_emdash1.service",
    workerUnit: null,
    limits: "512 MiB · 64 tasks · ProtectSystem=strict",
    envKeys: ["EMDASH_ENCRYPTION_KEY", "EMDASH_SITE_URL"],
    sqliteBackup: "Encrypted restic + COMPLIANCE 30d · WAL-safe SQLite bundle verified 2 h ago",
    currentRelease: "emdash-1.6.1-r2",
    failedReleaseNote: null,
    releases: [
      {
        releaseId: "emdash-1.6.1-r2",
        version: "EmDash 1.6.1 (schema v2)",
        state: "active",
        when: "2 h ago",
        note: "Prepared via upgrade-emdash@0.1.0; health & FTS5 verified.",
        migration: "dist/migrate.mjs (v1 -> v2)",
      },
      {
        releaseId: "emdash-1.6.1-bad2",
        version: "EmDash 1.6.1 (failed migration)",
        state: "failed_compensated",
        when: "3 h ago",
        note: "Migration exited 1; pre-migration SQLite and emdash-1.6.0-r1 restored automatically.",
        migration: "dist/migrate.mjs (rolled back)",
      },
      {
        releaseId: "emdash-1.6.0-r1",
        version: "EmDash 1.6.0 (schema v1)",
        state: "superseded",
        when: "4 d ago",
        note: "Initial EmDash starter release imported from WordPress WXR + media.",
      },
    ],
  },
  {
    id: "app_api",
    siteId: "bunapi",
    hostname: "api.lab.test",
    kind: "Bun app",
    runtime: "Bun 1.4.2 · MariaDB 10.11 · companion worker",
    runtimeProfile: "bun_1_v1",
    ingress: "Caddy (HTTP/3)",
    topology: "backend_api",
    database: "mariadb",
    serving: "Serving",
    servingKind: "ok",
    health: "Passing · /health 200",
    healthKind: "ok",
    healthPath: "/health",
    port: 3102,
    websocketPrefix: "/ws/",
    account: "rs_bunapi",
    unit: "rustiron-app@rs_bunapi.service",
    workerUnit: "rustiron-app-worker@rs_bunapi.service",
    limits: "512 MiB · 64 tasks · rustiron_app_mariadb_t",
    envKeys: ["API_SIGNING_SECRET", "DATABASE_URL", "PUBLIC_ORIGIN"],
    sqliteBackup: "Encrypted restic + COMPLIANCE 30d · MariaDB dump verified 4 h ago",
    currentRelease: "rel-20261123-02",
    failedReleaseNote: null,
    releases: [
      {
        releaseId: "rel-20261123-02",
        version: "API 2.4.1",
        state: "active",
        when: "4 h ago",
        note: "Zero-downtime loopback cutover behind Caddy HTTP/3 edge ingress.",
      },
      {
        releaseId: "rel-20261120-01",
        version: "API 2.4.0",
        state: "superseded",
        when: "3 d ago",
        note: "Previous healthy release retained read-only under releases/.",
      },
    ],
  },
  {
    id: "app_dash",
    siteId: "nodedash",
    hostname: "dashboard.lab.test",
    kind: "Node.js app",
    runtime: "Node.js 22.23.4 LTS",
    runtimeProfile: "node_22_v1",
    ingress: "OpenLiteSpeed",
    topology: "backend_api",
    database: "sqlite",
    serving: "Serving",
    servingKind: "ok",
    health: "rel-0009 rolled back",
    healthKind: "err",
    healthPath: "/health",
    port: 3101,
    websocketPrefix: "/ws/",
    account: "rs_nodedash",
    unit: "rustiron-app@rs_nodedash.service",
    workerUnit: null,
    limits: "768 MiB · 64 tasks · ProtectSystem=strict",
    envKeys: ["APP_SESSION_KEY", "DASHBOARD_ORIGIN", "WEBHOOK_TOKEN"],
    sqliteBackup: "Encrypted restic + COMPLIANCE 30d · data/ verified 6 h ago",
    currentRelease: "rel-0008",
    failedReleaseNote:
      "Release rel-0009 failed its loopback /health probe. rel-0008 kept serving; no traffic moved.",
    releases: [
      {
        releaseId: "rel-0009",
        version: "Dashboard 1.9.0",
        state: "failed_compensated",
        when: "1 h ago",
        note: "Health probe returned 503; automatic rollback restored rel-0008.",
      },
      {
        releaseId: "rel-0008",
        version: "Dashboard 1.8.4",
        state: "active",
        when: "6 d ago",
        note: "Serving healthy behind OpenLiteSpeed proxy.",
      },
    ],
  },
];

export const fixtureFindings: DiagnosisFinding[] = [
  {
    id: "finding-backup",
    state: "fail",
    check: "Backup age",
    subject: "news.lab.test · no succeeded capture",
    owner: "rustiron",
    seen: "4 min",
    reason: "Served or partial site has no succeeded backup capture recorded in the journal.",
    action: "Review the failed provision operation, retire or finish it, then run backup_capture.",
    runbook: "Backups & recovery guide",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "finding-ssh",
    state: "unknown",
    check: "SSH",
    subject: "sshd -T requires root shell check",
    owner: "host",
    seen: "4 min",
    reason:
      "The unprivileged diagnosis cannot read sshd -T. RustIron does not widen its access to read it.",
    action: "Run on the host as root to confirm PasswordAuthentication and PermitRootLogin.",
    command: "sudo sshd -T | grep -Ei '^(passwordauthentication|permitrootlogin)'",
    runbook: "Host diagnoses & security guide",
    guideSlug: "security-and-diagnoses",
  },
  {
    id: "finding-firewalld",
    state: "unknown",
    check: "firewalld",
    subject: "firewall-cmd requires root shell check",
    owner: "host",
    seen: "4 min",
    reason:
      "Unprivileged accounts cannot query firewalld D-Bus state; RustIron keeps this honest instead of guessing.",
    action: "Check the enrolled rustiron zone as root.",
    command: "sudo firewall-cmd --get-active-zones && sudo firewall-cmd --zone=rustiron --list-all",
    runbook: "Firewall & network guide",
    guideSlug: "firewall-and-network",
  },
  {
    id: "finding-cert",
    state: "warn",
    check: "Certificate",
    subject: "shop.lab.test · 11 days left",
    owner: "rustiron",
    seen: "4 min",
    reason: "Installed single-hostname leaf expires inside the 30-day renewal window.",
    action: "Check standing renewal logs and confirm port 80 HTTP-01 reachability.",
    runbook: "Domains, SSL & DNS guide",
    guideSlug: "domains-ssl-and-dns",
  },
  {
    id: "finding-backup-probe",
    state: "warn",
    check: "Restore probe",
    subject: "portfolio.lab.test · decryption check failed",
    owner: "rustiron",
    seen: "4 min",
    reason: "Latest restore probe reported a repository key mismatch (rcpt_2YB7).",
    action: "Inspect receipt rcpt_2YB7 and verify the enrolled fetch key pair.",
    runbook: "Backups & recovery guide",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "finding-clock",
    state: "ok",
    check: "Clock",
    subject: "synchronized · 0.004 s offset",
    owner: "host",
    seen: "4 min",
    reason: "System clock is synchronized for signed grant windows and TLS validity.",
    action: "No action required.",
    runbook: "Host diagnoses & security guide",
    guideSlug: "security-and-diagnoses",
  },
  {
    id: "finding-selinux",
    state: "ok",
    check: "SELinux",
    subject: "enforcing · 0 new AVCs",
    owner: "host",
    seen: "4 min",
    reason: "Host is in enforcing mode and RustIron domains run confined.",
    action: "No action required.",
    runbook: "Host diagnoses & security guide",
    guideSlug: "security-and-diagnoses",
  },
  {
    id: "finding-storage",
    state: "ok",
    check: "Storage",
    subject: "/var 29% free · inodes 82% free",
    owner: "host",
    seen: "4 min",
    reason: "Disk space and inode headroom are within safe thresholds.",
    action: "No action required.",
    runbook: "Host diagnoses & security guide",
    guideSlug: "security-and-diagnoses",
  },
  {
    id: "finding-database",
    state: "ok",
    check: "Database",
    subject: "MariaDB 11.4 answers local socket",
    owner: "host",
    seen: "4 min",
    reason: "Local Unix socket ping succeeded.",
    action: "No action required.",
    runbook: "Databases & credentials guide",
    guideSlug: "databases-and-credentials",
  },
  {
    id: "finding-apps",
    state: "ok",
    check: "Modern apps",
    subject: "3 confined app units active · loopback healthy",
    owner: "rustiron",
    seen: "4 min",
    reason: "All provisioned Node.js 22 and Bun 1.4 units are active and isolated.",
    action: "No action required.",
    runbook: "Apps & EmDash guide",
    guideSlug: "modern-apps-and-emdash",
  },
  {
    id: "finding-retention",
    state: "ok",
    check: "Backup retention",
    subject: "COMPLIANCE 30d lock verified on newest captures",
    owner: "rustiron",
    seen: "4 min",
    reason: "Object Lock retention evidence read back for enrolled repositories.",
    action: "No action required.",
    runbook: "Backups & recovery guide",
    guideSlug: "backups-and-recovery",
  },
];

const fixtureSupportComponents: SupportComponent[] = [
  {
    id: "comp-os",
    component: "AlmaLinux",
    series: "10 (x86_64)",
    observed: "10.3",
    minimumPatch: "10.2",
    endOfLife: "31 May 2035",
    state: "supported",
    stateLabel: "Supported",
    packagePin: "almalinux-release 10.3",
    note: "Target Linux platform with enforcing SELinux and systemd.",
  },
  {
    id: "comp-ols",
    component: "OpenLiteSpeed",
    series: "1.9",
    observed: "1.9.4",
    minimumPatch: "1.9.4",
    endOfLife: "Upstream rolling 1.9",
    state: "supported",
    stateLabel: "Supported",
    packagePin: "openlitespeed 1.9.4-3.el10",
    note: "High-performance web server serving WordPress, static sites, and reverse proxies.",
  },
  {
    id: "comp-php",
    component: "LSPHP",
    series: "8.4",
    observed: "8.4.28",
    minimumPatch: "8.4.27",
    endOfLife: "31 Dec 2028",
    state: "supported",
    stateLabel: "Supported",
    packagePin: "lsphp84 8.4.28-1.el10",
    note: "Isolated per-site PHP pools with SELinux MCS confinement.",
  },
  {
    id: "comp-mariadb",
    component: "MariaDB",
    series: "10.11 LTS",
    observed: "10.11.18",
    minimumPatch: "10.11.18",
    endOfLife: "16 Feb 2028",
    state: "supported",
    stateLabel: "Supported",
    packagePin: "mariadb-server 10.11.18 (AppStream)",
    note: "Local Unix socket only; per-site database accounts without global privileges.",
  },
  {
    id: "comp-node",
    component: "Node.js",
    series: "22 LTS",
    observed: "22.23.4",
    minimumPatch: "22.23.4",
    endOfLife: "30 Apr 2027",
    state: "warn",
    stateLabel: "Review inside 180 d",
    packagePin: "nodejs-1:22.23.4-1.el10_2 (AppStream)",
    note: "Optional runtime for EmDash 1.6.0 and Node.js apps (checked when installed). Plan upgrade to Node 24 LTS before April 2027.",
    optional: true,
  },
  {
    id: "comp-bun",
    component: "Bun",
    series: "1.4",
    observed: "1.4.5",
    minimumPatch: "1.4.2",
    endOfLife: "Upstream rolling 1.4",
    state: "supported",
    stateLabel: "Supported",
    packagePin: "bun 1.4.5 (/usr/local/bin/bun)",
    note: "Optional runtime for Bun apps and the Console Admin Panel (checked when installed).",
    optional: true,
  },
  {
    id: "comp-caddy",
    component: "Caddy",
    series: "2.10+",
    observed: "2.10.2",
    minimumPatch: "2.10.0",
    endOfLife: "Upstream rolling 2.x",
    state: "supported",
    stateLabel: "Supported",
    packagePin: "caddy 2.10.2 (/usr/local/bin/caddy)",
    note: "Optional confined HTTP/3 edge ingress (rustiron_caddy_t, admin API on a 0700 Unix socket only, auto_https disable_certs) serving modern full-stack apps and bridging WordPress/PHP to OpenLiteSpeed.",
    optional: true,
  },
  {
    id: "comp-pg",
    component: "PostgreSQL",
    series: "18",
    observed: "18.7",
    minimumPatch: "18.7",
    endOfLife: "14 Nov 2030",
    state: "supported",
    stateLabel: "Supported",
    packagePin: "postgresql18-server 18.7 (PGDG EL-10)",
    note: "Optional per-app PostgreSQL 18 database bound strictly to 127.0.0.1:5432 with SCRAM-SHA-256 authentication and opt-in rustiron_app_pg_t confinement (checked only when installed).",
    optional: true,
  },
  {
    id: "comp-pdns",
    component: "PowerDNS",
    series: "5.1",
    observed: "5.1.5",
    minimumPatch: "5.1.5",
    endOfLife: "01 Jan 2028",
    state: "supported",
    stateLabel: "Supported",
    packagePin: "pdns 5.1.5 (repo.powerdns.com)",
    note: "Optional authoritative DNS server with signed zone changes and TSIG secondary transfers (checked only when installed).",
    optional: true,
  },
];

export const fixtureDomains: DomainRecord[] = [
  {
    hostname: "shop.lab.test",
    serves: "WordPress site",
    siteHref: "/sites/site_8KD2QW",
    certificate: "renewal_failed",
    certificateLabel: "Renewal failed · 11 d",
    notAfter: "28 Nov 2026",
    renewedBy: "Rustiron",
    issuer: "Lab ACME CA",
    chainDigest: "sha256:41d7…c09e",
    renewUntil: "04 Oct 2027",
    lastResult: "HTTP-01 timed out during standing renewal check",
    dnsZone: "lab.test (PowerDNS 5.1)",
    dnsMode: "Authoritative + TSIG AXFR",
  },
  {
    hostname: "emdash.lab.test",
    serves: "EmDash CMS (Node 22)",
    siteHref: "/apps/app_emdash",
    certificate: "valid",
    certificateLabel: "Valid · 79 d",
    notAfter: "10 Feb 2027",
    renewedBy: "Rustiron",
    issuer: "Lab ACME CA",
    chainDigest: "sha256:88f2…19ad",
    renewUntil: "23 Nov 2027",
    lastResult: "Issued cleanly; OLS SNI listener verified",
    dnsZone: "lab.test (PowerDNS 5.1)",
    dnsMode: "Authoritative + TSIG AXFR",
  },
  {
    hostname: "api.lab.test",
    serves: "Bun 1.4 app",
    siteHref: "/apps/app_api",
    certificate: "valid",
    certificateLabel: "Valid · 79 d",
    notAfter: "10 Feb 2027",
    renewedBy: "Rustiron",
    issuer: "Lab ACME CA",
    chainDigest: "sha256:5bc1…4e02",
    renewUntil: "23 Nov 2027",
    lastResult: "Issued cleanly; WebSocket /ws/ active",
    dnsZone: "lab.test (PowerDNS 5.1)",
    dnsMode: "Authoritative + TSIG AXFR",
  },
  {
    hostname: "blog.lab.test",
    serves: "WordPress site",
    siteHref: "/sites/site_4HX9KC",
    certificate: "valid",
    certificateLabel: "Valid · 74 d",
    notAfter: "05 Feb 2027",
    renewedBy: "Rustiron",
    issuer: "Lab ACME CA",
    chainDigest: "sha256:29ae…77b1",
    renewUntil: "01 Nov 2027",
    lastResult: "Standing renewal healthy",
    dnsZone: "lab.test (PowerDNS 5.1)",
    dnsMode: "Authoritative + TSIG AXFR",
  },
  {
    hostname: "docs.lab.test",
    serves: "Static site · ejected",
    siteHref: "/sites/site_9BN3TF",
    certificate: "valid",
    certificateLabel: "Valid · 54 d",
    notAfter: "17 Jan 2027",
    renewedBy: "operator",
    issuer: "Lab ACME CA",
    chainDigest: "sha256:90c4…ef11",
    renewUntil: "Operator managed",
    lastResult: "Ejected from management; standalone OLS keeps HTTPS",
    dnsZone: "lab.test (PowerDNS 5.1)",
    dnsMode: "Authoritative + TSIG AXFR",
  },
  {
    hostname: "news.lab.test",
    serves: "WordPress · partial",
    siteHref: "/sites/site_6RT1ZM",
    certificate: "not_issued",
    certificateLabel: "Not issued",
    notAfter: "—",
    renewedBy: "—",
    issuer: "—",
    chainDigest: "—",
    renewUntil: "—",
    lastResult: "Provision failed before certificate issuance",
    dnsZone: "lab.test (PowerDNS 5.1)",
    dnsMode: "Authoritative + TSIG AXFR",
  },
];

export const fixtureMigrations: MigrationRecord[] = [
  {
    id: "mig_emdash_wxr",
    kind: "WordPress → EmDash CMS",
    source: "p01r.example.test (WXR + captured media)",
    targetHostname: "emdash.lab.test",
    dryRunState: "ok",
    dryRunLabel: "Plan · 3 items, 2 media, 3 redirects",
    importState: "ok",
    importLabel: "Verified parity (FTS5 + SHA-256)",
    scrubLabel: "Incumbent untouched",
    recorded: "Today 02:00",
    refusals: [],
    facts: [
      { name: "WXR XML & media SHA-256", source: "observed" },
      { name: "301 permalink redirect map", source: "observed" },
      { name: "Draft isolation (404 public)", source: "observed" },
      { name: "DNS cutover sign-off", source: "declared" },
    ],
    note: "Planned offline with packaging/wordpress-to-emdash.py and verified live against SQLite + HTTP without modifying the incumbent WordPress site.",
  },
  {
    id: "imp_2c71",
    kind: "CyberPanel WordPress",
    source: "CyberPanel export · docs",
    targetHostname: "docs.lab.test",
    dryRunState: "ok",
    dryRunLabel: "Plan · 5 steps",
    importState: "ok",
    importLabel: "Succeeded",
    scrubLabel: "Removed (import_scrub)",
    recorded: "1 Nov",
    refusals: [],
    facts: [
      { name: "Target PHP 8.4 extensions (52)", source: "observed" },
      { name: "Signed OperatorDeclaration", source: "declared" },
      { name: "Hostname & alias conflict check", source: "observed" },
      { name: "Source cron & mail comparison", source: "observed" },
    ],
    note: "Imported with SSHSIG declaration verification in namespace rustiron-migration-declaration-v1 and leftover secrets removed.",
  },
  {
    id: "imp_3a09",
    kind: "CyberPanel WordPress",
    source: "CyberPanel export · events",
    targetHostname: "events-old.lab.test",
    dryRunState: "fail",
    dryRunLabel: "2 refusals",
    importState: "fail",
    importLabel: "Blocked",
    scrubLabel: "—",
    recorded: "Today 10:40",
    refusals: [
      { code: "SECOND_DATABASE", detail: "events_stats database outside single-DB recipe" },
      {
        code: "EXTENSION_MISSING",
        detail: "Source declared PHP extension imagick absent on target",
      },
    ],
    facts: [
      { name: "Archive inventory & DB count", source: "observed" },
      { name: "Required PHP extensions", source: "declared" },
      { name: "Live source traffic window", source: "unknown" },
    ],
    note: "Resolve refusals offline, regenerate the signed OperatorDeclaration, and re-run rustiron-plan migrate.",
  },
];

function clockFinding(clock: NonNullable<Machine["clock"]>): DiagnosisFinding {
  const synced = clock.synchronized === true;
  const state = synced ? "ok" : clock.synchronized === false ? "warn" : "unknown";
  const subject = synced
    ? "synchronized"
    : clock.synchronized === false
      ? "unsynchronized"
      : "unknown";
  return {
    id: "live-clock",
    state,
    check: "Clock",
    subject,
    owner: "host",
    seen: "live",
    reason: "Grant validity windows and ACME renewal require an accurate clock.",
    action: synced ? "No action required." : "Check chronyd status on the host.",
  };
}

function databaseFinding(db: NonNullable<Machine["database"]>): DiagnosisFinding {
  const ok = db.ping === "responding";
  return {
    id: "live-db",
    state: ok ? "ok" : db.ping === "not_responding" ? "fail" : "unknown",
    check: "Database",
    subject: `MariaDB ${db.ping}`,
    owner: "host",
    seen: "live",
    reason: `Local socket check against ${db.socket}.`,
    action: ok ? "No action required." : "Inspect mariadb.service on the host.",
  };
}

function selinuxFinding(selinux: string | null): DiagnosisFinding {
  const normalized = selinux?.trim().toLowerCase() ?? "";
  const enforcing = normalized === "enforcing";
  return {
    id: "live-selinux",
    state: enforcing ? "ok" : normalized ? "fail" : "unknown",
    check: "SELinux",
    subject: selinux ?? "unobserved",
    owner: "host",
    seen: "live",
    reason: "Observed from /sys/fs/selinux/enforce via rustiron-control.",
    action: enforcing
      ? "No action required."
      : "Restore enforcing mode before running production sites.",
  };
}

function sshReadableFinding(ssh: NonNullable<Machine["ssh"]>): DiagnosisFinding {
  const hardened =
    ssh.password_authentication === "no" &&
    ssh.kbd_interactive_authentication !== "yes" &&
    ssh.permit_root_login !== "yes";
  if (hardened) {
    return {
      id: "live-ssh",
      state: "ok",
      check: "SSH",
      subject: `key-only (${ssh.permit_root_login ?? "restricted"}, password auth off)`,
      owner: "host",
      seen: "live",
      reason: "Effective sshd -T authentication policy observed on this host.",
      action: "No action required.",
    };
  }
  return {
    id: "live-ssh",
    state: "warn",
    check: "SSH",
    subject: `root=${ssh.permit_root_login ?? "?"} · password=${ssh.password_authentication ?? "?"}`,
    owner: "host",
    seen: "live",
    reason: "Effective sshd -T authentication policy observed on this host.",
    action:
      "Disable SSH password authentication and root password login in /etc/ssh/sshd_config.d/01-rustiron-ssh.conf.",
    command:
      "sudo sshd -T | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin)'",
  };
}

function isUnitActive(services: Machine["services"] | undefined, unit: string): boolean {
  return Boolean(services?.some((s) => s.unit === unit && s.active === "active"));
}

function sshFinding(ssh: Machine["ssh"], services?: Machine["services"]): DiagnosisFinding | null {
  if (!ssh) return null;
  if (ssh.readable) return sshReadableFinding(ssh);
  const running = isUnitActive(services, "sshd.service");
  return {
    id: "live-ssh",
    state: "unknown",
    check: "SSH",
    subject: running
      ? "sshd.service running · policy check is root-only"
      : "sshd -T requires privileged host observation",
    owner: "host",
    seen: "live",
    reason: running
      ? "sshd.service is active on the host, while effective sshd -T directives stay root-only by security design. The unprivileged Console never escalates to read them."
      : "Unprivileged observation cannot inspect root-only sshd -T effective settings; verify SSH policy directly on the server as root.",
    action: "Verify SSH policy as root.",
    command: "sudo sshd -T | grep -Ei '^(passwordauthentication|permitrootlogin)'",
  };
}

function firewallReadableFinding(firewall: NonNullable<Machine["firewall"]>): DiagnosisFinding {
  const zone = firewall.default_zone ?? "unknown";
  const svcList = firewall.services?.length ? ` (${firewall.services.join(", ")})` : "";
  if (firewall.state === "running") {
    return {
      id: "live-firewalld",
      state: "ok",
      check: "firewalld",
      subject: `running · zone ${zone}${svcList}`,
      owner: "host",
      seen: "live",
      reason: "Active firewalld daemon state and default zone observed via firewall-cmd.",
      action: "No action required.",
    };
  }
  return {
    id: "live-firewalld",
    state: "fail",
    check: "firewalld",
    subject: `state ${firewall.state ?? "stopped"}`,
    owner: "host",
    seen: "live",
    reason: "Active firewalld daemon state and default zone observed via firewall-cmd.",
    action: "Start firewalld and verify the rustiron zone with packaging/firewall-zone.py --check.",
    command: "sudo systemctl status firewalld",
  };
}

function firewallFinding(
  firewall: Machine["firewall"],
  services?: Machine["services"],
): DiagnosisFinding | null {
  if (!firewall) return null;
  if (firewall.readable) return firewallReadableFinding(firewall);
  const running = isUnitActive(services, "firewalld.service");
  return {
    id: "live-firewalld",
    state: "unknown",
    check: "firewalld",
    subject: running
      ? "firewalld.service running · zone rules are root-only"
      : "firewall-cmd requires privileged host observation",
    owner: "host",
    seen: "live",
    reason: running
      ? "firewalld.service is active on the host, while D-Bus zone rules stay root-only by security design. Verify active zones from the server shell as root."
      : "Unprivileged accounts cannot query firewalld D-Bus state; Rustiron keeps this honest instead of assuming the firewall is active.",
    action: "Inspect active zones as root.",
    command: "sudo firewall-cmd --get-active-zones && sudo firewall-cmd --zone=rustiron --list-all",
  };
}

function storageFinding(disk: Machine["disk"]): DiagnosisFinding | null {
  if (!disk || !disk.total_bytes || disk.total_bytes <= 0 || disk.available_bytes == null) {
    return null;
  }
  const freePct = Math.max(
    0,
    Math.min(100, Math.round((disk.available_bytes / disk.total_bytes) * 100)),
  );
  const state: DiagnosisFinding["state"] = freePct < 10 ? "fail" : freePct < 15 ? "warn" : "ok";
  return {
    id: "live-storage",
    state,
    check: "Storage",
    subject: `${disk.path} · ${freePct}% free`,
    owner: "host",
    seen: "live",
    reason: "Filesystem headroom observed via rustiron-control.",
    action:
      state === "ok"
        ? "No action required."
        : "Free disk space or expand host storage before backups or updates stall.",
  };
}

function postgresqlFinding(pg: Machine["postgresql"]): DiagnosisFinding | null {
  if (!pg || !pg.installed) return null;
  if ((pg.listeners_beyond_loopback ?? 0) > 0) {
    return {
      id: "live-pg18-bind",
      state: "fail",
      check: "PostgreSQL 18",
      subject: `${pg.listeners_beyond_loopback} external listener(s) on :5432`,
      owner: "host",
      seen: "live",
      reason: "PostgreSQL 18 must listen strictly on 127.0.0.1:5432 and never bind externally.",
      action: "Set listen_addresses = '127.0.0.1' in postgresql.conf and restart postgresql-18.",
      command: "sudo systemctl restart postgresql-18 && ss -tlnp '( sport = :5432 )'",
      runbook: "PostgreSQL 18 guide",
      guideSlug: "postgresql-18",
    };
  }
  const ok = pg.ping === "responding";
  return {
    id: "live-pg18",
    state: ok ? "ok" : pg.ping === "not_responding" ? "fail" : "unknown",
    check: "PostgreSQL 18",
    subject: ok ? "127.0.0.1:5432 responding · loopback only" : `PostgreSQL 18 ${pg.ping}`,
    owner: "host",
    seen: "live",
    reason: "Loopback pg_isready and socket listener check on 127.0.0.1:5432.",
    action: ok ? "No action required." : "Inspect postgresql-18.service logs on the host.",
    runbook: "PostgreSQL 18 guide",
    guideSlug: "postgresql-18",
  };
}

function caddyFinding(caddy: Machine["caddy"]): DiagnosisFinding | null {
  if (!caddy || !caddy.installed) return null;
  const adminExposed = (caddy.admin_port_listeners ?? 0) > 0;
  return {
    id: "live-caddy",
    state: adminExposed ? "fail" : "ok",
    check: "Caddy ingress",
    subject: adminExposed
      ? "admin API listener detected on :2019"
      : "confined · admin API disabled",
    owner: "rustiron",
    seen: "live",
    reason: adminExposed
      ? "Caddy must expose its admin API only on /run/rustiron-caddy/admin.sock, never TCP :2019."
      : "Confined rustiron-caddy runs without an admin API listener.",
    action: adminExposed
      ? "Confirm `admin unix//run/rustiron-caddy/admin.sock` in /etc/rustiron-caddy/current/Caddyfile and reload rustiron-caddy.service."
      : "No action required.",
    runbook: "Full-stack & Caddy guide",
    guideSlug: "fullstack-caddy",
  };
}

function machineFindings(machine: Machine): DiagnosisFinding[] {
  const out: DiagnosisFinding[] = [selinuxFinding(machine.selinux)];
  if (machine.clock) out.push(clockFinding(machine.clock));
  const ssh = sshFinding(machine.ssh, machine.services);
  if (ssh) out.push(ssh);
  const fw = firewallFinding(machine.firewall, machine.services);
  if (fw) out.push(fw);
  if (machine.database) out.push(databaseFinding(machine.database));
  const pg = postgresqlFinding(machine.postgresql);
  if (pg) out.push(pg);
  const caddy = caddyFinding(machine.caddy);
  if (caddy) out.push(caddy);
  const disk = storageFinding(machine.disk);
  if (disk) out.push(disk);
  return out;
}

function observationFindings(observation: Observation): DiagnosisFinding[] {
  const out: DiagnosisFinding[] = [];
  for (const site of observation.sites) {
    if (site.state !== "quarantined") continue;
    out.push({
      id: `live-site-${site.site_id}`,
      state: "fail",
      check: "Site provision",
      subject: `${site.hostname} · quarantined`,
      owner: "rustiron",
      seen: "live",
      reason: site.failed_step
        ? `Provision stopped at step ${site.failed_step}.`
        : "Site is quarantined in the journal.",
      action: "Inspect the provision operation and retire or recover it explicitly.",
    });
  }
  const unclaimed = observation.captures.filter((c) => c.unclaimed_snapshot_id).length;
  if (unclaimed > 0) {
    out.push({
      id: "live-unclaimed",
      state: "warn",
      check: "Unclaimed snapshots",
      subject: `${unclaimed} capture(s) with unclaimed snapshot`,
      owner: "rustiron",
      seen: "live",
      reason: "A failed capture left an unclaimed snapshot in the backup store.",
      action: "Reconcile with the retention authority.",
      runbook: "Backups & recovery guide",
      guideSlug: "backups-and-recovery",
    });
  }
  return out;
}

/** Derives honest diagnoses from a live host observation without guessing unreadable checks. */
export function liveFindings(
  observation: Observation,
  machine: Machine | null,
): DiagnosisFinding[] {
  const out = [...(machine ? machineFindings(machine) : []), ...observationFindings(observation)];
  if (out.length > 0) return out;
  return [
    {
      id: "live-none",
      state: "unknown",
      check: "Host diagnoses",
      subject: "No detailed machine status in this observation",
      owner: "host",
      seen: "live",
      reason: "Run rustiron-control --diagnose on the host for complete findings.",
      action: "Include --host-status in the observation capture.",
    },
  ];
}

// W635 (H-17): never fabricate valid TLS certificates when journal summaries do not observe certs.
export function liveDomains(sites: Site[], observation: Observation): DomainRecord[] {
  return sites.map((site) => {
    const raw = observation.sites.find((s) => s.site_id === site.id);
    const ejected = raw?.ejected ?? false;
    return {
      hostname: site.domain,
      serves: ejected ? "Site · ejected" : site.runtime,
      siteHref: `/sites/${site.id}`,
      certificate: "not_issued",
      certificateLabel: ejected ? "Operator managed" : "Not observed in journal",
      notAfter: "Not in journal summary",
      renewedBy: ejected ? "operator" : "—",
      issuer: "See host certificate observation",
      chainDigest: "—",
      renewUntil: "—",
      lastResult: site.operationDetail || site.operation,
      dnsZone: "Host-enrolled DNS (unobserved in summary)",
      dnsMode: "Read-only observation",
    };
  });
}

type StackLookup = { value: string | null; explicitNull: boolean };

const OPTIONAL_STACK_KEYS: Record<string, "nodejs" | "bun" | "powerdns" | "caddy" | "postgresql"> =
  {
    "comp-node": "nodejs",
    "comp-bun": "bun",
    "comp-pdns": "powerdns",
    "comp-caddy": "caddy",
    "comp-pg": "postgresql",
  };

function optionalStackKey(
  stack: Machine["stack"],
  key: "nodejs" | "bun" | "powerdns" | "caddy" | "postgresql",
): StackLookup {
  if (!stack || !(key in stack)) return { value: null, explicitNull: false };
  const val = stack[key] ?? null;
  return { value: val, explicitNull: val === null };
}

function fixedStackValue(id: string, machine: Machine): string | null {
  const s = machine.stack;
  switch (id) {
    case "comp-os":
      return machine.os.version;
    case "comp-ols":
      return s ? s.openlitespeed : null;
    case "comp-mariadb":
      return s ? s.mariadb : null;
    case "comp-php":
      return s && s.php.length > 0 ? s.php.join(", ") : null;
    default:
      return null;
  }
}

function observedStackVersion(id: string, machine: Machine): StackLookup {
  const optKey = OPTIONAL_STACK_KEYS[id];
  if (optKey) return optionalStackKey(machine.stack, optKey);
  return { value: fixedStackValue(id, machine), explicitNull: false };
}

function parseDottedVersion(raw: string): number[] | null {
  const first = raw.split(",")[0]?.trim() ?? "";
  if (!/^[0-9]+(?:\.[0-9]+)*$/.test(first)) return null;
  return first.split(".").map(Number);
}

function isBelowMinimum(observed: string, minimum: string): boolean {
  const obs = parseDottedVersion(observed);
  const min = parseDottedVersion(minimum);
  if (!obs || !min) return false;
  const len = Math.max(obs.length, min.length);
  for (let i = 0; i < len; i += 1) {
    const a = obs[i] ?? 0;
    const b = min[i] ?? 0;
    if (a !== b) return a < b;
  }
  return false;
}

type ObservedSite = Observation["sites"][number];

function appKindForSite(
  site: ObservedSite,
  runtimeProfile: AppRecord["runtimeProfile"],
  topology: AppRecord["topology"],
): AppRecord["kind"] {
  if (site.site_id.includes("emdash") || site.hostname.includes("emdash")) return "EmDash CMS";
  if (topology === "static_spa" || runtimeProfile === "static_v1") return "Static SPA";
  if (topology === "fullstack_split" || topology === "fullstack_dual_ssr") return "Full-stack app";
  return runtimeProfile === "bun_1_v1" ? "Bun app" : "Node.js app";
}

function appServingState(state: ObservedSite["state"]): {
  serving: AppRecord["serving"];
  servingKind: AppRecord["servingKind"];
} {
  if (state === "succeeded" || state === "adopted") {
    return { serving: "Serving", servingKind: "ok" };
  }
  if (state === "quarantined") return { serving: "Degraded", servingKind: "err" };
  return { serving: "Stopped", servingKind: "muted" };
}

function appReleasesForSite(release: string | null | undefined): AppReleaseRecord[] {
  if (!release) return [];
  return [
    {
      releaseId: release,
      version: release,
      state: "active",
      when: "Observed",
      note: "Active release recorded in executor journal.",
    },
  ];
}

function appHealthSummary(status: number | undefined): {
  health: string;
  healthKind: AppRecord["healthKind"];
} {
  if (!status) return { health: "Observed in journal", healthKind: "muted" };
  return { health: `HTTP ${status}`, healthKind: status < 400 ? "ok" : "muted" };
}

function appRuntimeMeta(
  kind: AppRecord["kind"],
  profile: AppRecord["runtimeProfile"],
  database: AppRecord["database"],
) {
  const isEmDash = kind === "EmDash CMS";
  const runtimeLabel =
    profile === "static_v1"
      ? "Static SPA (no daemon)"
      : profile === "bun_1_v1"
        ? "Bun 1.4 (bun_1_v1)"
        : "Node.js 22 (node_22_v1)";
  const backupLabel =
    database === "postgresql_18"
      ? "PostgreSQL 18 pg_dump + encrypted site backup"
      : database === "mariadb"
        ? "MariaDB logical dump + encrypted site backup"
        : isEmDash
          ? "SQLite WAL online backup"
          : "Encrypted site backup";
  return {
    runtime: runtimeLabel,
    websocketPrefix: isEmDash ? "/_emdash/api/content/" : null,
    sqliteBackup: backupLabel,
  };
}

function parseLiveTopology(raw: string | null | undefined): AppRecord["topology"] {
  if (raw === "static_spa" || raw === "fullstack_split" || raw === "fullstack_dual_ssr") {
    return raw;
  }
  return "backend_api";
}

function parseLiveDatabase(
  raw: string | null | undefined,
  isEmDash: boolean,
): AppRecord["database"] {
  if (raw === "none" || raw === "sqlite" || raw === "mariadb" || raw === "postgresql_18") {
    return raw;
  }
  return isEmDash ? "sqlite" : "none";
}

function parseLiveRuntime(raw: string | null | undefined): AppRecord["runtimeProfile"] {
  if (raw === "static_v1" || raw === "bun_1_v1") return raw;
  return "node_22_v1";
}

function liveAppUnit(siteId: string, profile: AppRecord["runtimeProfile"]): string {
  return profile === "static_v1" ? "Static (served by Caddy)" : `rustiron-app@${siteId}.service`;
}

function toLiveAppRecord(site: ObservedSite): AppRecord {
  const runtimeProfile = parseLiveRuntime(site.app_runtime);
  const topology = parseLiveTopology(site.app_topology);
  const kind = appKindForSite(site, runtimeProfile, topology);
  const database = parseLiveDatabase(site.app_database, kind === "EmDash CMS");
  const ingress: AppRecord["ingress"] =
    site.app_ingress === "caddy" ? "Caddy (HTTP/3)" : "OpenLiteSpeed";
  const { serving, servingKind } = appServingState(site.state);
  const { health, healthKind } = appHealthSummary(site.http_status);
  const meta = appRuntimeMeta(kind, runtimeProfile, database);
  return {
    id: site.site_id,
    siteId: site.site_id,
    hostname: site.hostname,
    kind,
    runtime: meta.runtime,
    runtimeProfile,
    ingress,
    topology,
    database,
    serving,
    servingKind,
    health,
    healthKind,
    healthPath: runtimeProfile === "static_v1" ? "/" : "/healthz",
    port: site.proxy_ports?.[0] ?? 0,
    websocketPrefix: meta.websocketPrefix,
    account: `rs_${site.site_id}`,
    unit: liveAppUnit(site.site_id, runtimeProfile),
    workerUnit: null,
    limits: "Enrolled systemd cgroup limits",
    envKeys: [],
    sqliteBackup: meta.sqliteBackup,
    currentRelease: site.app_active_release ?? "Not deployed",
    failedReleaseNote: site.failed_step ? `Last failed step: ${site.failed_step}` : null,
    releases: appReleasesForSite(site.app_active_release),
  };
}

export function liveApps(observation: Observation): AppRecord[] {
  return observation.sites.filter((site) => Boolean(site.app_runtime)).map(toLiveAppRecord);
}

const migrationOpKinds = new Set(["site_import", "import_scrub", "site_clone", "clone_scrub"]);

function mapLiveMigrationOp(
  op: Observation["operations"][number],
  sites: Observation["sites"],
): MigrationRecord {
  const targetId = op.site_id ?? op.resource_id;
  const site = sites.find((s) => s.site_id === op.site_id);
  const ok = op.state === "succeeded";
  const failed = op.state === "failed" || op.state === "needs_attention";
  return {
    id: op.operation_id,
    kind: "CyberPanel WordPress",
    source: `${op.kind} (${targetId})`,
    targetHostname: site?.hostname ?? targetId,
    dryRunState: failed ? "fail" : "ok",
    dryRunLabel: op.kind,
    importState: ok ? "ok" : failed ? "fail" : "unknown",
    importLabel: op.state,
    scrubLabel: op.kind === "import_scrub" ? "Scrubbed" : "Check host journal",
    recorded: "Observed",
    refusals: [],
    facts: [{ name: `Journal operation ${op.operation_id}`, source: "observed" }],
    note: `Recorded in host journal for ${targetId}. Inspect full steps on /operations/${op.operation_id}.`,
  };
}

/** Derives real migration/import/clone/EmDash records from a live host observation without mock rows. */
export function liveMigrations(observation: Observation): MigrationRecord[] {
  const opRows = observation.operations
    .filter((op) => migrationOpKinds.has(op.kind))
    .map((op) => mapLiveMigrationOp(op, observation.sites));
  const emdashRows: MigrationRecord[] = liveApps(observation)
    .filter((app) => app.kind === "EmDash CMS")
    .map((app) => ({
      id: `emdash_${app.siteId}`,
      kind: "WordPress → EmDash CMS",
      source: `Observed EmDash site (${app.account})`,
      targetHostname: app.hostname,
      dryRunState: "ok",
      dryRunLabel: app.currentRelease,
      importState: app.servingKind === "ok" ? "ok" : app.servingKind === "err" ? "fail" : "unknown",
      importLabel: app.serving,
      scrubLabel: "Live EmDash workload",
      recorded: "Observed",
      refusals: [],
      facts: [
        { name: `Runtime ${app.runtimeProfile}`, source: "observed" },
        { name: `Active release ${app.currentRelease}`, source: "observed" },
      ],
      note: "Observed EmDash 1.6.0 workload on this host. Run packaging/wordpress-to-emdash.py offline for new WXR migrations.",
    }));
  return [...emdashRows, ...opRows];
}

function formatObservedComponent(item: SupportComponent, observed: string): SupportComponent {
  if (isBelowMinimum(observed, item.minimumPatch)) {
    return { ...item, observed, state: "warn", stateLabel: "Update recommended" };
  }
  const state = item.state === "warn" ? "warn" : "supported";
  const stateLabel = item.state === "warn" ? item.stateLabel : "Supported";
  return { ...item, observed, state, stateLabel };
}

function resolveSupportComponent(
  item: SupportComponent,
  machine: Machine | null,
  isLive: boolean,
): SupportComponent {
  const result = machine
    ? observedStackVersion(item.id, machine)
    : { value: null, explicitNull: false };
  if (result.value) return formatObservedComponent(item, result.value);
  if (!isLive) return item;
  if (item.optional && result.explicitNull) {
    return { ...item, observed: "Not installed", state: "optional", stateLabel: "Optional" };
  }
  return { ...item, observed: "Not observed", state: "unknown", stateLabel: "Not observed" };
}

export function liveSupportComponents(machine: Machine | null, isLive = false): SupportComponent[] {
  if (!isLive && !machine) return fixtureSupportComponents;
  return fixtureSupportComponents.map((item) => resolveSupportComponent(item, machine, isLive));
}
