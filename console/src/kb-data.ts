// W649: Integrated RustIron Documentation & Knowledge Base data model.
// All commands match real repository CLIs (rustiron, rustiron-plan, rustiron-control,
// packaging/rustiron-install-wizard.py, packaging/rustiron-updater.py,
// packaging/firewall-zone.py, packaging/wordpress-to-emdash.py, scripts/release/bundle_release.py).

export type KbCategoryId =
  | "getting-started"
  | "hosting"
  | "domains-mail"
  | "recovery-migration"
  | "security-ops"
  | "updates-releases";

export type KbCategory = {
  id: KbCategoryId;
  label: string;
  description: string;
};

export type KbCommand = {
  label: string;
  where:
    | "Server (root)"
    | "Workstation (operator)"
    | "Server (unprivileged)"
    | "Build / maintainer";
  code: string;
};

export type KbCallout = {
  tone: "info" | "warn";
  title: string;
  body: string;
};

export type KbSection = {
  id: string;
  heading: string;
  paragraphs: string[];
  bullets?: string[];
  callout?: KbCallout;
  commands?: KbCommand[];
};

export type KbArticle = {
  slug: string;
  category: KbCategoryId;
  title: string;
  summary: string;
  readMinutes: number;
  runbooks: string[];
  keywords: string[];
  consoleLinks: { to: string; label: string }[];
  sections: KbSection[];
};

export type OperatorRunbookRef = {
  id: string;
  title: string;
  group: string;
  file: string;
  summary: string;
  guideSlug: string;
};

export const kbCategories: KbCategory[] = [
  {
    id: "getting-started",
    label: "Getting Started",
    description:
      "Architecture, installation wizard, host enrollment, and the signed-plan workflow.",
  },
  {
    id: "hosting",
    label: "Websites & Apps",
    description: "WordPress sites, EmDash CMS, Node.js 22 & Bun 1.4 apps, quotas, and databases.",
  },
  {
    id: "domains-mail",
    label: "Domains, SSL & Email",
    description:
      "Let's Encrypt HTTPS, PowerDNS authoritative zones, outbound relay, and mailboxes.",
  },
  {
    id: "recovery-migration",
    label: "Backups & Migration",
    description:
      "Encrypted restic backups, retention locks, site restores, and CyberPanel / WXR moves.",
  },
  {
    id: "security-ops",
    label: "Security & Server Ops",
    description: "SELinux confinement, Host Diagnoses, firewalld zones, cron timers, and logs.",
  },
  {
    id: "updates-releases",
    label: "Updates & Releases",
    description:
      "One-command host updates, rollbacks, signed release bundling, and break-glass recovery.",
  },
];

export const kbArticles: KbArticle[] = [
  {
    slug: "how-rustiron-works",
    category: "getting-started",
    title: "How RustIron Works: Architecture & Security Model",
    summary:
      "Understand the coordinator-to-executor trust boundary, why website traffic bypasses RustIron, how per-site SELinux MCS isolation works, and why signing keys stay off the server.",
    readMinutes: 4,
    runbooks: ["Runbook 03", "Runbook 05", "Runbook 34"],
    keywords: [
      "architecture",
      "coordinator",
      "executor",
      "selinux",
      "mcs",
      "sshsign",
      "custody",
      "security",
      "webadmin",
    ],
    consoleLinks: [
      { to: "/", label: "Host overview" },
      { to: "/host/services", label: "Services" },
      { to: "/operations", label: "Operations" },
    ],
    sections: [
      {
        id: "management-path",
        heading: "The strict management path",
        paragraphs: [
          "RustIron is a hosting control plane built around mature Linux infrastructure — OpenLiteSpeed (OLS), LSPHP, MariaDB, systemd, firewalld, PowerDNS, restic, and enforcing SELinux on AlmaLinux 10.",
          "Every privileged change flows through one narrow chain: CLI -> unprivileged coordinator -> independently validating executor -> fixed scoped operations. The executor never accepts raw shell commands, arbitrary SQL, or arbitrary config text.",
        ],
        bullets: [
          "Website traffic bypasses RustIron completely: visitors connect straight to OpenLiteSpeed, PHP pools, or loopback apps. Even if the Console or coordinator is stopped, hosted sites keep serving.",
          "OpenLiteSpeed WebAdmin (:7080) remains permanently disabled under the managed profile so there is no second privileged admin plane.",
          "The Console Admin Panel runs strictly unprivileged, defaults to read-only observation, and never holds SSHSIG production signing keys.",
        ],
      },
      {
        id: "isolation-layers",
        heading: "Per-site isolation (Unix UID + SELinux MCS + systemd)",
        paragraphs: [
          "Each WordPress website and modern app gets its own dedicated non-root Linux account (rs_<site_id>), its own XFS project disk/inode quota, and a unique SELinux Multi-Category Security (MCS) category.",
        ],
        bullets: [
          "WordPress PHP pools run in rustiron_php_t:s0:c<N> with isolated sockets and no cross-site filesystem access.",
          "Node.js 22, Bun 1.4, and EmDash CMS apps run in rustiron_app_t:s0:c<N> with ProtectSystem=strict, NoNewPrivileges=yes, and IPAddressDeny=any (allowing only loopback 127.0.0.1/::1 behind OpenLiteSpeed).",
          "MariaDB binds strictly to the local Unix socket with per-site accounts; port 3306 is never exposed externally.",
        ],
      },
      {
        id: "separate-custody",
        heading: "Separate signing custody & durable journals",
        paragraphs: [
          "Plans are deterministic JSON documents signed offline on your workstation with OpenSSH SSHSIG (namespace rustiron-plan-v1). Before executing anything, the executor checks peer identity, exact signed SHA-256 digest, grant expiry, host/epoch binding, replay admission mark, and live preconditions.",
        ],
        callout: {
          tone: "info",
          title: "Unknown outcomes are never silently retried",
          body: "If an operation is interrupted mid-flight, the executor records the exact step state in its durable journal and marks the operation as Needs attention until reconciled explicitly.",
        },
      },
    ],
  },
  {
    slug: "install-and-setup",
    category: "getting-started",
    title: "Installing RustIron on AlmaLinux 10",
    summary:
      "Bring up a fresh AlmaLinux 10 server with the interactive installation wizard, enroll your operator signing key, configure ACME certificates, and lock down your first Console Admin account.",
    readMinutes: 5,
    runbooks: ["Runbook 05", "Runbook 09", "Runbook 38"],
    keywords: [
      "install",
      "wizard",
      "almalinux",
      "enroll",
      "setup",
      "token",
      "admin",
      "bootstrap",
      "first-run",
    ],
    consoleLinks: [
      { to: "/users", label: "Users & access" },
      { to: "/host/diagnoses", label: "Host diagnoses" },
    ],
    sections: [
      {
        id: "install-wizard",
        heading: "1. Run the AlmaLinux 10 installation wizard",
        paragraphs: [
          "On a fresh AlmaLinux 10 x86_64 server with Enforcing SELinux, run the guided installation wizard. It checks OS/SELinux prerequisites, verifies or installs the stack (OpenLiteSpeed, LSPHP 8.4, MariaDB, firewalld, Certbot), deploys binaries and SELinux policies, enrolls your operator signing key, hardens SSH, applies the rustiron firewalld zone, and configures the Console service.",
        ],
        commands: [
          {
            label: "Interactive installation wizard (recommended)",
            where: "Server (root)",
            code: "sudo python3 packaging/rustiron-install-wizard.py",
          },
          {
            label: "Dry-run plan without modifying the server",
            where: "Server (root)",
            code: "sudo python3 packaging/rustiron-install-wizard.py --dry-run",
          },
          {
            label: "Non-interactive install with explicit operator key & Console domain",
            where: "Server (root)",
            code: "sudo python3 packaging/rustiron-install-wizard.py --non-interactive \\\n  --host-id prod-01 \\\n  --signer-id operator \\\n  --signer-pubkey /path/to/operator.pub \\\n  --console-domain console.example.com \\\n  --apply",
          },
        ],
      },
      {
        id: "first-admin",
        heading: "2. Create your Console Admin account",
        paragraphs: [
          "When RUSTIRON_CONSOLE_AUTH_REQUIRED=1 and RUSTIRON_CONSOLE_SETUP_TOKEN are set in /etc/rustiron-console/env, the Console stays completely locked behind a standalone setup gate until the first Admin account is created. Public self-registration is permanently disabled (403).",
        ],
        commands: [
          {
            label: "Inspect the one-time setup token on the server (never share publicly)",
            where: "Server (root)",
            code: "sudo grep '^RUSTIRON_CONSOLE_SETUP_TOKEN=' /etc/rustiron-console/env",
          },
        ],
        callout: {
          tone: "warn",
          title: "Keep signing keys on your workstation",
          body: "Your Better Auth Console account controls access to the web UI. Production infrastructure changes still require offline SSHSIG signatures from your operator key.",
        },
      },
      {
        id: "verify-health",
        heading: "3. Verify enrollment and host health",
        paragraphs: [
          "After installation completes, confirm the executor, coordinator, SELinux confinement, and firewall zone are healthy.",
        ],
        commands: [
          {
            label: "Run read-only diagnosis and firewall zone check",
            where: "Server (root)",
            code: "sudo python3 packaging/firewall-zone.py --check\nsudo systemctl is-active rustiron-executor rustiron-coordinator rustiron-console",
          },
        ],
      },
    ],
  },
  {
    slug: "signing-and-plans",
    category: "getting-started",
    title: "How Signed Plans & Grants Work",
    summary:
      "Learn the 4-step operator workflow used for every host change: create a plan, review its canonical bytes and blast radius, sign offline with ssh-keygen, and apply through the coordinator.",
    readMinutes: 4,
    runbooks: ["Runbook 05", "Runbook 34"],
    keywords: [
      "plan",
      "grant",
      "sign",
      "ssh-keygen",
      "sshsign",
      "canonical",
      "apply",
      "blast radius",
      "workflow",
    ],
    consoleLinks: [
      { to: "/plans/new", label: "New plan wizard" },
      { to: "/operations", label: "Operations" },
    ],
    sections: [
      {
        id: "four-step-flow",
        heading: "The 4-step signed-change lifecycle",
        paragraphs: [
          "Every Console wizard generates exact CLI commands for you. Rather than executing privileged mutations directly from the browser, RustIron separates drafting from cryptographic approval.",
        ],
        bullets: [
          "Step 1 — Create: build a deterministic canonical plan.json and matching grant.json bound to one operation ID, host ID, host epoch, and short expiry window.",
          "Step 2 — Inspect: review the human-readable blast-radius summary (affected sites, global OLS reload impact, authority budget) before signing.",
          "Step 3 — Sign offline: sign grant.json with your operator SSH key in the dedicated rustiron-plan-v1 namespace.",
          "Step 4 — Apply & verify: submit plan.json, grant.json, and grant.json.sig to the coordinator and inspect the recorded operation outcome.",
        ],
        commands: [
          {
            label: "Inspect, sign offline, and apply a prepared plan directory",
            where: "Workstation (operator)",
            code: "rustiron plan review-file ./plan-dir/plan.json\nssh-keygen -Y sign -f ~/.ssh/rustiron-operator -n rustiron-plan-v1 ./plan-dir/grant.json\nrustiron plan apply --plan ./plan-dir/plan.json --grant ./plan-dir/grant.json --sig ./plan-dir/grant.json.sig",
          },
        ],
      },
      {
        id: "replay-protection",
        heading: "Replay protection & expiry",
        paragraphs: [
          "Each grant carries a unique operation_id, host_epoch, signer policy epoch, and strict not_before / expires_at timestamps. Once admitted by the executor, the same grant cannot be replayed on another host or after an epoch rotation.",
        ],
      },
    ],
  },
  {
    slug: "wordpress-sites",
    category: "hosting",
    title: "Host & Manage WordPress Websites",
    summary:
      "Provision isolated WordPress sites, tune PHP 8.4 workers and LiteSpeed Page Cache, adjust quotas, run updates with automatic rollback, and safely eject or delete sites.",
    readMinutes: 5,
    runbooks: ["Runbook 15", "Runbook 24", "Runbook 25", "Runbook 34"],
    keywords: [
      "wordpress",
      "site",
      "provision",
      "lsphp",
      "php",
      "lscache",
      "page cache",
      "quota",
      "eject",
      "delete",
      "clone",
    ],
    consoleLinks: [
      { to: "/sites", label: "Sites" },
      { to: "/sites/new", label: "Add website wizard" },
    ],
    sections: [
      {
        id: "provision-wp",
        heading: "Provision a new WordPress website",
        paragraphs: [
          "Use the Add Website wizard (/sites/new) or run rustiron plan create site-provision to generate a signed provisioning plan. RustIron creates a dedicated system user, unique SELinux MCS context, isolated LSPHP 8.4 pool, per-site MariaDB database and credentials, OpenLiteSpeed vhost, and XFS disk quota.",
        ],
        commands: [
          {
            label: "Generate a WordPress site-provision plan",
            where: "Workstation (operator)",
            code: "rustiron plan create site-provision \\\n  --site-id wpblog \\\n  --hostname blog.example.com \\\n  --out-dir ./plans/wpblog",
          },
        ],
      },
      {
        id: "tuning-updates",
        heading: "PHP workers, LiteSpeed Page Cache & WordPress updates",
        paragraphs: [
          "Per-site maintenance controls live under Sites -> [Site] -> Maintenance. Config changes (PHP worker limits, LiteSpeed Page Cache opt-in/out) run through config-activate; WordPress core, plugin, and theme updates run unprivileged as the site account and roll back cleanly if post-update health probes fail.",
        ],
        commands: [
          {
            label: "Tune PHP workers and activate configuration",
            where: "Workstation (operator)",
            code: "rustiron plan create config-activate \\\n  --site-id wpblog \\\n  --php-max-children 6 \\\n  --out-dir ./plans/wpblog-cfg",
          },
        ],
      },
      {
        id: "eject-vs-delete",
        heading: "Eject vs. Delete a site",
        paragraphs: [
          "RustIron separates handing a site back to manual administration (eject) from removing it permanently (delete).",
        ],
        bullets: [
          "Eject (site-eject): stops RustIron management while preserving the website files, MariaDB database, standalone OLS vhost, and TLS certificates intact.",
          "Delete: requires a fresh (< 24 h) verified backup capture before removing the live site root, PHP pool, and database.",
        ],
        commands: [
          {
            label: "Prepare a non-destructive site-eject plan",
            where: "Workstation (operator)",
            code: "rustiron plan create site-eject --site-id wpblog --out-dir ./plans/wpblog-eject",
          },
        ],
      },
    ],
  },
  {
    slug: "modern-apps-and-emdash",
    category: "hosting",
    title: "Deploy EmDash CMS, Node.js 22 & Bun 1.4 Apps",
    summary:
      "Provision confined Node.js 22 and Bun 1.4 applications and EmDash CMS behind OpenLiteSpeed with loopback-only networking, immutable releases, 0400 secrets, and automatic rollback.",
    readMinutes: 5,
    runbooks: ["Runbook 30", "Runbook 32", "Runbook 33"],
    keywords: [
      "emdash",
      "cms",
      "node",
      "nodejs",
      "bun",
      "app",
      "deploy",
      "rollback",
      "websocket",
      "sqlite",
      "fts5",
      "proxy",
    ],
    consoleLinks: [
      { to: "/apps", label: "Apps" },
      { to: "/sites/new", label: "Deploy app wizard" },
    ],
    sections: [
      {
        id: "provision-app",
        heading: "1. Provision an isolated app runtime",
        paragraphs: [
          "Every modern app runs under its own systemd service (rustiron-app@rs_<site_id>.service) confined by rustiron_app_t:s0:c<N> and IPAddressDeny=any + IPAddressAllow=localhost. OpenLiteSpeed proxies public HTTPS traffic (and optional WebSocket paths) to the app's private 127.0.0.1 port.",
        ],
        commands: [
          {
            label: "Provision an EmDash CMS / Node.js 22 app",
            where: "Workstation (operator)",
            code: "rustiron plan create app-provision \\\n  --site-id emdash1 \\\n  --hostname cms.example.com \\\n  --runtime node_22_v1 \\\n  --port 3210 \\\n  --out-dir ./plans/emdash1-prov",
          },
          {
            label: "Provision a Bun 1.4 API app",
            where: "Workstation (operator)",
            code: "rustiron plan create app-provision \\\n  --site-id bunapi \\\n  --hostname api.example.com \\\n  --runtime bun_1_v1 \\\n  --port 3102 \\\n  --out-dir ./plans/bunapi-prov",
          },
        ],
      },
      {
        id: "deploy-and-rollback",
        heading: "2. Deploy immutable releases with automatic rollback",
        paragraphs: [
          "App builds run off-host so no compiler or npm install ever runs privileged on the server. Package your built artifact into a verified tarball (or use packaging/emdash-recipe.py for EmDash 1.6.0), then deploy with app-deploy.",
        ],
        bullets: [
          "Before running any schema migration, RustIron snapshots the EmDash SQLite database into a root-only 0700 directory.",
          "If the migration exits non-zero or the loopback /health probe fails, RustIron automatically restores the previous release symlink and pre-migration SQLite snapshot.",
          "Secret values live in root-prepared 0400 files on the host — only declared key names ever appear in plans or the Console.",
        ],
        commands: [
          {
            label: "Deploy a new app release bundle",
            where: "Workstation (operator)",
            code: "rustiron plan create app-deploy \\\n  --site-id emdash1 \\\n  --release-id emdash-1.6.1-r1 \\\n  --bundle-path /srv/staging/emdash-1.6.1-r1.tar.gz \\\n  --out-dir ./plans/emdash1-deploy",
          },
        ],
      },
    ],
  },
  {
    slug: "fullstack-caddy",
    category: "hosting",
    title: "Full-Stack Bun & Node.js Apps with Confined Caddy HTTP/3",
    summary:
      "Deploy modern front-end + back-end applications (Vite + Elysia, React + Hono, Next.js, Astro, TanStack Start, Static SPA) behind confined Caddy HTTP/3 with zero-downtime blue/green cutover and Dual-Mode Edge-over-OLS.",
    readMinutes: 6,
    runbooks: ["Runbook 32", "Runbook 34"],
    keywords: [
      "caddy",
      "fullstack",
      "full-stack",
      "spa",
      "vite",
      "react",
      "elysia",
      "hono",
      "nextjs",
      "astro",
      "tanstack",
      "blue-green",
      "http3",
      "sse",
      "websocket",
      "rustiron-app-pack",
    ],
    consoleLinks: [
      { to: "/sites/new", label: "Deploy full-stack app wizard" },
      { to: "/apps", label: "Apps" },
      { to: "/host/logs", label: "Caddy logs" },
    ],
    sections: [
      {
        id: "four-topologies",
        heading: "Four supported full-stack topologies",
        paragraphs: [
          "RustIron v0.1.1 supports four closed modern-app topologies behind confined Caddy 2.10+ (HTTP/2, HTTP/3 QUIC on 443/udp, Brotli/Zstd compression, WebSockets, and unbuffered SSE) without ever reloading OpenLiteSpeed or interrupting WordPress traffic.",
        ],
        bullets: [
          "static_spa — Static SPA assets (Vite/React/Vue/Svelte) served directly by Caddy with SPA index.html fallback and zero background daemon.",
          "backend_api — Single Bun 1.4 or Node.js 22 backend or full-stack SSR app (Next.js Standalone, Astro SSR, Elysia/Hono API) on a loopback port.",
          "fullstack_split — Static SPA front-end served directly by Caddy alongside a confined Bun/Node API backend on /api/ (with optional prefix stripping and WebSocket/SSE routes).",
          "fullstack_dual_ssr — Dedicated SSR frontend service (rustiron-app-web@) plus a separate API backend service (rustiron-app@), each with optional blue/green standby slots.",
        ],
      },
      {
        id: "dual-mode-and-tls",
        heading: "Dual-Mode Caddy Ingress & Shared TLS Custody",
        paragraphs: [
          "On single-IP servers running both WordPress and modern apps, enable caddy_edge_over_ols in the installation wizard. Caddy binds :80/:443 (TCP + 443/udp), serves modern apps directly, and transparently bridges WordPress/PHP domains to OpenLiteSpeed on 127.0.0.1:8080 with authentic X-Forwarded-* headers — preserving .htaccess, LSPHP 8.4, and LiteSpeed Cache.",
        ],
        bullets: [
          "Single TLS custody (Decision B1): Caddy keeps its admin API on a 0700 Unix socket (never TCP :2019) and runs with auto_https disable_certs, reading certificates read-only from /etc/rustiron-tls/<account>/live/ managed by rustiron-acme.",
          "Confined SELinux domain (rustiron_caddy_t): Caddy cannot bind outbound HTTP/HTTPS, cannot write certificates, and runs with ProtectSystem=strict and CapabilityBoundingSet=CAP_NET_BIND_SERVICE.",
        ],
        commands: [
          {
            label: "Enable Dual-Mode Caddy Edge-over-OLS with HTTP/3",
            where: "Server (root)",
            code: "sudo python3 packaging/rustiron-install-wizard.py --ingress-mode caddy_edge_over_ols --dry-run",
          },
        ],
      },
      {
        id: "pack-and-blue-green",
        heading: "Off-host packaging & zero-downtime blue/green deploys",
        paragraphs: [
          "Never run npm install or bundlers as root on the server. Build locally or in CI, pack a deterministic tarball with packaging/rustiron-app-pack.py (which refuses symlinks, .env secrets, and missing entrypoints), upload it, and sign an app-deploy plan.",
          "When blue/green is enabled, RustIron unpacks the new release, starts the standby slot (Slot B or A), probes its loopback health endpoint, reloads Caddy atomically onto the healthy standby port, and drains the old slot — rolling back automatically if health checks fail.",
        ],
        commands: [
          {
            label: "List built-in presets and pack a Vite + Elysia full-stack bundle off-host",
            where: "Workstation (operator)",
            code: "python3 packaging/rustiron-app-pack.py presets\npython3 packaging/rustiron-app-pack.py pack \\\n  --preset vite-elysia \\\n  --frontend-dist ./frontend/dist \\\n  --backend-dist ./backend/dist \\\n  --out ./release-out \\\n  --site-id saasapp \\\n  --release-id rel-20261126-01 \\\n  --database postgresql_18 \\\n  --blue-green-cutover",
          },
        ],
      },
    ],
  },
  {
    slug: "postgresql-18",
    category: "hosting",
    title: "PostgreSQL 18.7 Setup, Hardening & Multi-DB Selection",
    summary:
      "Enable optional PostgreSQL 18 (18.7+) alongside MariaDB and SQLite, give each full-stack app its own least-privilege role and DATABASE_URL, rotate passwords locally, and verify pg_dump backups.",
    readMinutes: 5,
    runbooks: ["Runbook 27", "Runbook 32", "Runbook 35"],
    keywords: [
      "postgresql",
      "postgres",
      "pg18",
      "18.7",
      "scram-sha-256",
      "database_url",
      "pg_dump",
      "pg_restore",
      "pgdg",
      "mariadb",
      "sqlite",
      "rotate",
    ],
    consoleLinks: [
      { to: "/databases", label: "Databases" },
      { to: "/sites/new", label: "Deploy app with DB" },
      { to: "/host/updates", label: "Stack versions" },
    ],
    sections: [
      {
        id: "selectable-db",
        heading: "Choose the right database engine per app",
        paragraphs: [
          "When provisioning a modern app, select one of four closed database modes: none (stateless), sqlite (local WAL file in site data/), mariadb (isolated 127.0.0.1:3306 account), or postgresql_18 (PostgreSQL 18.7+ on 127.0.0.1:5432 with SCRAM-SHA-256).",
        ],
        bullets: [
          "Opt-in SELinux database confinement: stateless and SQLite apps remain in rustiron_app_t with zero TCP connect permissions. Apps choosing MariaDB run in rustiron_app_mariadb_t (loopback 3306 only); apps choosing PostgreSQL 18 run in rustiron_app_pg_t (loopback 5432 only).",
          "PostgreSQL 18 is pinned via AlmaLinux 10 PGDG EL-10 repositories with SHA-256 key verification, listen_addresses = '127.0.0.1', and strict scram-sha-256 pg_hba.conf rules.",
        ],
        commands: [
          {
            label: "Enable hardened PostgreSQL 18.7 during host setup",
            where: "Server (root)",
            code: "sudo python3 packaging/rustiron-install-wizard.py --enable-postgres --dry-run",
          },
        ],
      },
      {
        id: "database-url-rotation",
        heading: "Zero-exposure DATABASE_URL provisioning & password rotation",
        paragraphs: [
          "RustIron creates one isolated role (rs_<site_id>) and database (rs_<site_id>_app) per app, generates a high-entropy password locally inside the executor, and writes DATABASE_URL atomically into /srv/sites/<site_id>/private/app.env (mode 0400). Passwords never enter plans, logs, or the browser.",
        ],
        commands: [
          {
            label: "Rotate an app's PostgreSQL 18 password and update DATABASE_URL",
            where: "Workstation (operator)",
            code: "rustiron plan create site-credential-rotate \\\n  --plan-id <plan_id> --host-id <host_id> --host-epoch <epoch> \\\n  --profile-digest <sha256> --requester <requester> \\\n  --site-id saasapp --hostname app.example.com \\\n  --target app_postgresql_18_password \\\n  --valid-from <unix> --expires-at <unix> > ./plan.json",
          },
        ],
      },
      {
        id: "pg-backups-migrations",
        heading: "Pre-migration snapshots & encrypted restic backups",
        paragraphs: [
          "Before running any schema migration during app-deploy, RustIron captures a consistent custom-format pg_dump (-Fc) into a root-only 0700 staging directory and automatically runs pg_restore --clean if the migration or post-deploy health check fails. Backup captures include the PostgreSQL 18 dump inside the encrypted restic snapshot alongside site files.",
        ],
        callout: {
          tone: "info",
          title: "Never expose port 5432 externally",
          body: "Host Diagnoses and the Firewall Rule Builder continuously guard TCP port 5432 so PostgreSQL 18 stays loopback-only (127.0.0.1).",
        },
      },
    ],
  },
  {
    slug: "domains-ssl-and-dns",
    category: "domains-mail",
    title: "Domains, Let's Encrypt HTTPS & PowerDNS Zones",
    summary:
      "Issue ECDSA Let's Encrypt certificates, manage authoritative PowerDNS 5.1 zones and DNS records safely, and expose the Console Admin Panel on a custom HTTPS domain.",
    readMinutes: 5,
    runbooks: ["Runbook 21", "Runbook 29", "Runbook 38"],
    keywords: [
      "domain",
      "ssl",
      "tls",
      "https",
      "acme",
      "letsencrypt",
      "certbot",
      "dns",
      "powerdns",
      "zone",
      "mx",
      "spf",
      "dmarc",
    ],
    consoleLinks: [
      { to: "/domains", label: "Domains" },
      { to: "/domains/new", label: "Add domain wizard" },
    ],
    sections: [
      {
        id: "ssl-certificates",
        heading: "HTTPS certificates & automatic renewal",
        paragraphs: [
          "RustIron issues single-hostname ECDSA P-256 certificates using confined HTTP-01 challenges under the rustiron-acme account. Private keys never leave the host, and certbot-renew.timer renews certificates inside the 30-day window before triggering a graceful OLS reload.",
        ],
        bullets: [
          "Make sure DNS A/AAAA records point to your server's public IP and TCP ports 80 & 443 are open in the rustiron firewalld zone.",
          "Verify the active ACME directory (Let's Encrypt production vs. staging) with packaging/enrollment-policy.py.",
        ],
        commands: [
          {
            label: "Check enrolled ACME configuration on the server",
            where: "Server (root)",
            code: "sudo python3 packaging/enrollment-policy.py acme --show\nsudo systemctl status certbot-renew.timer",
          },
        ],
      },
      {
        id: "powerdns-zones",
        heading: "Authoritative PowerDNS 5.1 zones & safe DNS record edits",
        paragraphs: [
          "Use Add Domain (/domains/new) to generate a canonical sorted .zone file and dns-zone-import command, and use Domains -> [Hostname] -> DNS records to stage A, AAAA, CNAME, MX, TXT, CAA, SRV, and NS updates with automatic mail-record protection.",
        ],
        commands: [
          {
            label: "Import a canonical DNS zone or apply compare-and-set record edits",
            where: "Workstation (operator)",
            code: "rustiron plan create dns-zone-import --zone example.com --zone-file ./example.com.zone --out-dir ./plans/zone-import\nrustiron plan create dns-change --zone example.com --operations ./dns-ops.json --out-dir ./plans/dns-edit",
          },
        ],
      },
      {
        id: "console-https-origin",
        heading: "Hosting the Console on a custom HTTPS domain",
        paragraphs: [
          "By default the Console listens on 127.0.0.1:4319 only. To serve it behind OpenLiteSpeed at a custom subdomain such as console.example.com, set RUSTIRON_CONSOLE_ORIGIN=https://console.example.com and RUSTIRON_CONSOLE_AUTH_REQUIRED=1 in /etc/rustiron-console/env and provision a loopback proxy site with HTTPS.",
        ],
      },
    ],
  },
  {
    slug: "databases-and-credentials",
    category: "hosting",
    title: "Databases, Password Rotation & Offline SQL Exports",
    summary:
      "Manage isolated per-site MariaDB and EmDash SQLite databases, rotate database passwords without revealing secrets in plans, and extract SQL dumps offline from encrypted backups.",
    readMinutes: 4,
    runbooks: ["Runbook 27", "Runbook 35"],
    keywords: [
      "database",
      "mariadb",
      "mysql",
      "sqlite",
      "password",
      "rotate",
      "credentials",
      "export",
      "dump",
      "sql",
    ],
    consoleLinks: [
      { to: "/databases", label: "Databases" },
      { to: "/recovery", label: "Recovery" },
    ],
    sections: [
      {
        id: "db-isolation",
        heading: "How per-site database isolation works",
        paragraphs: [
          "MariaDB is bound strictly to localhost via zz-rustiron-loopback.cnf (zero external TCP listeners on port 3306). Each WordPress site gets its own database (rs_<site_id>_wp) and least-privilege user with credentials stored in a 0400 db.cnf file readable only by that site's PHP user. EmDash CMS apps use local WAL-mode SQLite databases with native FTS5 inside their confined data/ directory.",
        ],
      },
      {
        id: "password-rotation",
        heading: "Rotate a MariaDB password with zero secret exposure",
        paragraphs: [
          "site-credential-rotate generates a new high-entropy password locally inside the executor, updates MariaDB, atomically swaps the site's db.cnf, and restarts the site's PHP pool — so the password never touches plans, logs, shell history, or the browser.",
        ],
        commands: [
          {
            label: "Create a signed database password rotation plan",
            where: "Workstation (operator)",
            code: "rustiron plan create site-credential-rotate \\\n  --site-id wpblog \\\n  --hostname blog.example.com \\\n  --out-dir ./plans/wpblog-rotate",
          },
        ],
      },
      {
        id: "offline-sql-export",
        heading: "Export a clean SQL dump safely offline",
        paragraphs: [
          "Rather than exposing phpMyAdmin on the public internet, extract consistent SQL dumps directly from any verified restic backup snapshot on your operator workstation.",
        ],
        commands: [
          {
            label: "Dump a site's SQL database from an encrypted restic snapshot",
            where: "Workstation (operator)",
            code: "restic -r <repo> dump <snapshot_id> /db.sql.zst | zstd -d > ./wpblog-dump.sql",
          },
        ],
      },
    ],
  },
  {
    slug: "email-and-relay",
    category: "domains-mail",
    title: "Outbound Mail Relay & Mailbox Catalog",
    summary:
      "Send reliable transactional WordPress email through RustIron's confined per-site Postfix Unix-socket relay, manage optional mailbox catalogs, and verify MX/SPF/DKIM/DMARC records.",
    readMinutes: 4,
    runbooks: ["Runbook 36", "Runbook 38"],
    keywords: [
      "email",
      "mail",
      "postfix",
      "dovecot",
      "relay",
      "smtp",
      "mailbox",
      "alias",
      "spf",
      "dkim",
      "dmarc",
    ],
    consoleLinks: [
      { to: "/mail", label: "Email" },
      { to: "/domains", label: "Domains & DNS" },
    ],
    sections: [
      {
        id: "outbound-relay",
        heading: "Per-site outbound mail relay (D-071)",
        paragraphs: [
          "PHP pools run without arbitrary outbound network access or shell execution, preventing compromised plugins from turning your server into a spam botnet. Instead, transactional mail routes through a confined per-site Postfix Unix socket and authenticated upstream smarthost.",
        ],
        commands: [
          {
            label: "Check per-site mail relay policy and confinement on the server",
            where: "Server (root)",
            code: "sudo python3 packaging/mail-relay.py --check",
          },
        ],
      },
      {
        id: "mailbox-catalog",
        heading: "Optional Console mailbox & alias catalog",
        paragraphs: [
          "By default under D-090 read-only mode, mailbox writes in the Console return 405 MAIL_WRITES_DISABLED. When explicitly enabled with RUSTIRON_CONSOLE_MAIL_WRITES=1, Admin/Operator accounts can maintain a local Argon2id-hashed Postfix/Dovecot mailbox & alias catalog and export virtual maps via /api/mail/export for host synchronization.",
        ],
        callout: {
          tone: "info",
          title: "Mail DNS stays protected",
          body: "Site changes never silently alter MX, SPF, DKIM, or DMARC records. Any change to mail-sensitive records triggers an explicit warning in the DNS editor.",
        },
      },
    ],
  },
  {
    slug: "backups-and-recovery",
    category: "recovery-migration",
    title: "Encrypted Backups, Retention Locks & Site Restore",
    summary:
      "Capture encrypted restic backups with Object Lock COMPLIANCE retention, configure standing schedules, read the 7-field Recovery Evidence strip, and run contained restore probes or live site restores.",
    readMinutes: 5,
    runbooks: ["Runbook 01", "Runbook 10", "Runbook 13", "Runbook 22", "Runbook 26"],
    keywords: [
      "backup",
      "restore",
      "restic",
      "snapshot",
      "retention",
      "compliance",
      "object lock",
      "probe",
      "recovery",
      "schedule",
    ],
    consoleLinks: [
      { to: "/recovery", label: "Recovery" },
      { to: "/recovery/schedules", label: "Scheduled capture" },
      { to: "/recovery/store", label: "Backup store" },
    ],
    sections: [
      {
        id: "immutable-backups",
        heading: "Why RustIron backups survive a compromised host",
        paragraphs: [
          "Backup captures use restic client-side encryption to an S3-compatible store (such as RustFS) with Object Lock COMPLIANCE retention. Crucially, the source host holds append-only credentials and cannot delete, forget, or shorten retention on existing snapshots.",
        ],
        commands: [
          {
            label: "Create a one-off backup capture plan",
            where: "Workstation (operator)",
            code: "rustiron plan create product-backup-capture --site-id wpblog --out-dir ./plans/wpblog-cap",
          },
          {
            label: "Create a daily standing capture grant (D-035, <= 35 days)",
            where: "Workstation (operator)",
            code: "rustiron plan create product-standing-capture \\\n  --site-id wpblog \\\n  --period-seconds 86400 \\\n  --window-seconds 3600 \\\n  --max-runs 30 \\\n  --out-dir ./plans/wpblog-sched",
          },
        ],
      },
      {
        id: "seven-evidence-fields",
        heading: "Reading the 7-field Recovery Evidence strip",
        paragraphs: [
          "A snapshot file alone does not prove recoverability. RustIron tracks seven independent verification fields for every site — shown on Sites and Recovery:",
        ],
        bullets: [
          "1. Artifacts present — encrypted files and database dump recorded in the store.",
          "2. Integrity verified — SHA-256 and restic repository checksums match.",
          "3. Decryption tested — repository key decrypted the capture cleanly.",
          "4. App consistency — database marker matched the captured site state.",
          "5. Isolated restore — contained restore probe unpacked cleanly without touching the live site.",
          "6. Health checks — restored workload answered HTTP/database verification probes.",
          "7. Independent copy — retention lock / off-host copy confirmed.",
        ],
        commands: [
          {
            label: "Run a non-destructive contained restore probe",
            where: "Workstation (operator)",
            code: "rustiron plan create product-restore-probe --site-id wpblog --out-dir ./plans/wpblog-probe",
          },
        ],
      },
    ],
  },
  {
    slug: "migrations",
    category: "recovery-migration",
    title: "Migrating from CyberPanel & WordPress to EmDash CMS",
    summary:
      "Import existing CyberPanel WordPress sites with dry-run refusal checks and signed declarations, or rehearse WordPress-to-EmDash WXR content and media migrations without touching the live source.",
    readMinutes: 5,
    runbooks: ["Runbook 33", "Runbook 37"],
    keywords: [
      "migrate",
      "migration",
      "cyberpanel",
      "import",
      "wxr",
      "emdash",
      "cutover",
      "declaration",
      "scrub",
    ],
    consoleLinks: [
      { to: "/migration", label: "Migration" },
      { to: "/apps", label: "Apps" },
    ],
    sections: [
      {
        id: "cyberpanel-import",
        heading: "Import a WordPress site from CyberPanel",
        paragraphs: [
          "CyberPanel migrations never modify your source VPS, DNS, or email. Export the site offline, inventory it against live target host observations, sign an OperatorDeclaration (SSHSIG), and inspect every dry-run refusal (such as extra databases or missing PHP extensions) before importing.",
        ],
        commands: [
          {
            label: "Generate a CyberPanel migration dry-run & import plan",
            where: "Workstation (operator)",
            code: "rustiron-plan migrate \\\n  --inventory ./source-inventory.json \\\n  --target-observation ./target-observation.json \\\n  --declaration ./declaration.json \\\n  --declaration-sig ./declaration.json.sig",
          },
        ],
        callout: {
          tone: "info",
          title: "Post-import cleanup (import_scrub)",
          body: "After verifying HTTP parity on the target server, run import_scrub to remove staged archives and leftover source credentials cleanly.",
        },
      },
      {
        id: "wp-to-emdash",
        heading: "Migrate WordPress content to EmDash CMS",
        paragraphs: [
          "Use packaging/wordpress-to-emdash.py to convert a WordPress WXR XML export and captured uploads into an EmDash 1.6.0 migration plan with SHA-256 media verification, 301 permalink redirect maps, and strict draft isolation (unpublished drafts stay 404 publicly).",
        ],
        commands: [
          {
            label: "Plan an offline WordPress -> EmDash WXR migration",
            where: "Workstation (operator)",
            code: "python3 packaging/wordpress-to-emdash.py plan \\\n  --wxr ./wordpress-export.xml \\\n  --uploads ./wp-content/uploads \\\n  --out ./emdash-migration-plan",
          },
        ],
      },
    ],
  },
  {
    slug: "security-and-diagnoses",
    category: "security-ops",
    title: "Host Diagnoses, SELinux & Root-Only Checks",
    summary:
      "Understand every health check on Host Diagnoses, why SSH and firewalld appear as root-only checks in the unprivileged Console, and how to inspect redacted logs and alerts.",
    readMinutes: 4,
    runbooks: ["Runbook 04", "Runbook 23", "Runbook 28"],
    keywords: [
      "diagnoses",
      "diagnosis",
      "unknown",
      "selinux",
      "ssh",
      "firewalld",
      "logs",
      "alerts",
      "uptime kuma",
      "unprivileged",
    ],
    consoleLinks: [
      { to: "/host/diagnoses", label: "Host diagnoses" },
      { to: "/host/logs", label: "Server logs" },
      { to: "/host/alerts", label: "Alerts" },
    ],
    sections: [
      {
        id: "why-root-only",
        heading: "Why SSH and firewalld show as root-only checks",
        paragraphs: [
          "By security design, rustiron-control refuses to run as root (uid 0) and the Console never widens its privileges. On AlmaLinux 10, unprivileged users can verify that sshd.service and firewalld.service are active via systemd, but cannot inspect root-only sshd -T effective directives or firewall-cmd D-Bus zone rules.",
          "Rather than guessing or faking a green badge, RustIron reports those two policy checks honestly as root-only until verified from an SSH root shell.",
        ],
        commands: [
          {
            label: "Verify SSH policy and rustiron firewalld zone directly on the server",
            where: "Server (root)",
            code: "sudo sshd -T | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin)'\nsudo python3 packaging/firewall-zone.py --check",
          },
        ],
      },
      {
        id: "selinux-and-logs",
        heading: "SELinux confinement, server logs & alert check-ins",
        paragraphs: [
          "Server Logs (/host/logs) exposes bounded, secret-redacted journalctl output for a closed allowlist of services (executor, control, OLS, MariaDB, PowerDNS, Postfix, Dovecot). Alerts (/host/alerts) pairs with rustiron-alert-checkin.timer to push redacted dead-man heartbeats to Uptime Kuma.",
        ],
        commands: [
          {
            label: "Run CLI host diagnosis and print the redacted alert check-in line",
            where: "Server (unprivileged)",
            code: "rustiron-control --diagnose --alert-line",
          },
        ],
      },
    ],
  },
  {
    slug: "firewall-and-network",
    category: "security-ops",
    title: "Firewalld Zone, Cron Timers & Traffic Budget",
    summary:
      "Lock down external ports with the enrolled rustiron firewalld zone, manage scheduled WordPress cron and backup timers, and understand traffic-aware background job deferral.",
    readMinutes: 4,
    runbooks: ["Runbook 13", "Runbook 28"],
    keywords: [
      "firewall",
      "firewalld",
      "ports",
      "cron",
      "timer",
      "wp-cron",
      "traffic",
      "budget",
      "3306",
      "7080",
      "4319",
    ],
    consoleLinks: [
      { to: "/host/firewall", label: "Firewall" },
      { to: "/host/cron", label: "Cron jobs" },
      { to: "/host/metrics", label: "Host metrics" },
    ],
    sections: [
      {
        id: "firewall-zone",
        heading: "The rustiron firewalld zone",
        paragraphs: [
          "packaging/firewall-zone.py creates and verifies a dedicated rustiron zone that opens only public web ports (80/tcp, 443/tcp, 443/udp for HTTP/3) and your active SSH port — keeping MariaDB (3306), OpenLiteSpeed WebAdmin (7080), the Console loopback listener (4319), and internal app ports closed to the internet.",
        ],
        commands: [
          {
            label: "Check or apply the rustiron firewalld zone safely (verifies sshd first)",
            where: "Server (root)",
            code: "sudo python3 packaging/firewall-zone.py --check\nsudo python3 packaging/firewall-zone.py --apply",
          },
        ],
      },
      {
        id: "cron-and-budget",
        heading: "Managed systemd timers & traffic-budget deferral",
        paragraphs: [
          "RustIron ships packaged systemd timers for site WP-Cron (rustiron-site-cron.timer), standing backup captures (rustiron-scheduled-capture.timer), and Uptime Kuma heartbeats (rustiron-alert-checkin.timer). Under bursty traffic, the traffic-budget evaluator defers non-urgent background work while enforcing strict RPO deadlines.",
        ],
        commands: [
          {
            label: "Evaluate current traffic-budget decision for a background job",
            where: "Server (unprivileged)",
            code: "rustiron-control --background-budget /path/to/observation.json --job backup_capture --human",
          },
        ],
      },
    ],
  },
  {
    slug: "updates-and-releases",
    category: "updates-releases",
    title: "Updating RustIron & Cutting Signed Releases",
    summary:
      "Update a running RustIron host in one verified command with automatic rollback, and learn how maintainers pack, SSHSIG-sign, verify, and publish versioned release bundles.",
    readMinutes: 5,
    runbooks: ["Runbook 14", "Runbook 16", "Runbook 31"],
    keywords: [
      "update",
      "upgrade",
      "rollback",
      "release",
      "bundle",
      "updater",
      "version",
      "advisory",
      "journal",
    ],
    consoleLinks: [
      { to: "/host/updates", label: "Host updates" },
      { to: "/host/services", label: "Services" },
    ],
    sections: [
      {
        id: "one-command-updater",
        heading: "Updating a host with rustiron-updater.py",
        paragraphs: [
          "packaging/rustiron-updater.py updates both the Rust control plane (binaries, helper, coordinator, SELinux policies, systemd units via update-product.py) and the Console Admin Panel atomically — always preserving /etc/rustiron-console/env, Better Auth & Mail SQLite databases, and node_modules.",
        ],
        bullets: [
          "Every update verifies two layers of rustiron-release-v1 OpenSSH signatures (both the outer bundle tarball and the inner SHA256SUMS manifest) before touching the host.",
          "Anti-downgrade protection refuses older versions by default; journal schema changes require explicit --migrate-journal.",
          "If anything fails or misbehaves, rollback restores both the previous control plane and previous Console directory cleanly.",
        ],
        commands: [
          {
            label: "Check current version, preview update plan, apply, or roll back",
            where: "Server (root)",
            code: "sudo python3 packaging/rustiron-updater.py status\nsudo python3 packaging/rustiron-updater.py plan --bundle ./rustiron-0.2.0-almalinux10-x86_64.tar.gz --release-signers /etc/rustiron/release_signers --release-signer-id release\nsudo python3 packaging/rustiron-updater.py apply --bundle ./rustiron-0.2.0-almalinux10-x86_64.tar.gz --release-signers /etc/rustiron/release_signers --release-signer-id release\nsudo python3 packaging/rustiron-updater.py rollback --to <previous-version>",
          },
        ],
      },
      {
        id: "release-bundler",
        heading: "Cutting & signing a release bundle (maintainers)",
        paragraphs: [
          "When you are ready to publish a new RustIron release, run scripts/release/bundle_release.py to pack a reproducible tarball, sign it offline with your release key in namespace rustiron-release-v1, verify it, and update your releases.json channel index.",
        ],
        commands: [
          {
            label: "Pack, sign offline, verify, and index a release bundle",
            where: "Build / maintainer",
            code: "python3 scripts/release/bundle_release.py pack --version 0.2.0 --staged-dir ./staged --include-console --out-dir ./releases\npython3 scripts/release/bundle_release.py sign --bundle ./releases/rustiron-0.2.0-almalinux10-x86_64.tar.gz --key ~/.ssh/rustiron-release\npython3 scripts/release/bundle_release.py verify --bundle ./releases/rustiron-0.2.0-almalinux10-x86_64.tar.gz --release-signers ./release_signers --release-signer-id release\npython3 scripts/release/bundle_release.py index --dir ./releases --base-url https://releases.example.com/rustiron --out ./releases/releases.json",
          },
        ],
      },
    ],
  },
  {
    slug: "troubleshooting-and-recovery",
    category: "updates-releases",
    title: "Troubleshooting, Power Loss & Break-Glass Recovery",
    summary:
      "Handle Needs attention operations safely, recover after a host crash or power loss, explain manual drift without automatic resets, and uninstall cleanly without losing site data.",
    readMinutes: 5,
    runbooks: ["Runbook 07", "Runbook 11", "Runbook 12", "Runbook 17"],
    keywords: [
      "troubleshoot",
      "troubleshooting",
      "crash",
      "power loss",
      "needs attention",
      "quarantined",
      "drift",
      "break-glass",
      "uninstall",
      "reconcile",
    ],
    consoleLinks: [
      { to: "/operations", label: "Operations" },
      { to: "/host/diagnoses", label: "Host diagnoses" },
      { to: "/states", label: "Shared states" },
    ],
    sections: [
      {
        id: "needs-attention",
        heading: "Handling Needs attention & quarantined states",
        paragraphs: [
          "When a power cut, reload timeout, or interrupted step prevents RustIron from proving an operation's exact outcome, it stops further conflicting writes and flags the operation as Needs attention (or marks a partially provisioned site as Quarantined).",
        ],
        bullets: [
          "Never blindly re-submit a failing or uncertain operation; open Operations -> [Operation ID] first to inspect every recorded step.",
          "After verifying live service state on the host, run the explicit reconciliation or retirement procedure for that verb (Runbook 11).",
        ],
      },
      {
        id: "drift-and-breakglass",
        heading: "Emergency manual edits & drift explanation",
        paragraphs: [
          "If you ever have to edit a host configuration file manually during an incident (break-glass), RustIron detects the drift and refuses to overwrite your edit silently (auto_reset: false). Use --explain-drift to classify each difference and choose whether to adopt, restore, ignore, or eject.",
        ],
        commands: [
          {
            label: "Explain observed host drift without modifying anything",
            where: "Server (unprivileged)",
            code: "rustiron-control --explain-drift /path/to/observation.json --human",
          },
        ],
      },
      {
        id: "clean-uninstall",
        heading: "Cleanly uninstalling RustIron while keeping sites alive",
        paragraphs: [
          "packaging/uninstall-product.py removes RustIron control-plane services, binaries, and SELinux policy modules while keeping all hosted site files, MariaDB databases, and a root-only archive intact.",
        ],
        commands: [
          {
            label: "Preview a safe product uninstall",
            where: "Server (root)",
            code: "sudo python3 packaging/uninstall-product.py --dry-run",
          },
        ],
      },
    ],
  },
];

export const operatorRunbooks: OperatorRunbookRef[] = [
  {
    id: "01",
    title: "Recovery objectives",
    group: "Decisions & custody",
    file: "docs/operator/01-RECOVERY-OBJECTIVES.md",
    summary: "Settled RPO, RTO, retention, and capture targets.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "02",
    title: "Off-site copy",
    group: "Decisions & custody",
    file: "docs/operator/02-OFFSITE-COPY.md",
    summary: "Independent backup destination guide (deferred after v1.0).",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "03",
    title: "Key custody",
    group: "Decisions & custody",
    file: "docs/operator/03-KEY-CUSTODY.md",
    summary: "Production and recovery key custody rules.",
    guideSlug: "how-rustiron-works",
  },
  {
    id: "04",
    title: "Independent review",
    group: "Decisions & custody",
    file: "docs/operator/04-INDEPENDENT-REVIEW.md",
    summary: "Critical human security review procedure.",
    guideSlug: "security-and-diagnoses",
  },
  {
    id: "05",
    title: "Operator key",
    group: "Decisions & custody",
    file: "docs/operator/05-OPERATOR-KEY.md",
    summary: "Create and sign plans with an operator SSHSIG key.",
    guideSlug: "signing-and-plans",
  },
  {
    id: "06",
    title: "Lab backup enrollment",
    group: "Enrollment & updates",
    file: "docs/operator/06-LAB-BACKUP-ENROLLMENT.md",
    summary: "Lab-only backup metadata and credential-file contract.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "07",
    title: "Epoch re-adoption",
    group: "Enrollment & updates",
    file: "docs/operator/07-EPOCH-READOPTION.md",
    summary: "Re-adopt sites after authorized host epoch recovery.",
    guideSlug: "troubleshooting-and-recovery",
  },
  {
    id: "08",
    title: "Capture freeze limits",
    group: "Backups & recovery",
    file: "docs/operator/08-CAPTURE-FREEZE-LIMITS.md",
    summary: "Freeze window and consistency rules for backups.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "09",
    title: "Product enrollment",
    group: "Enrollment & updates",
    file: "docs/operator/09-PRODUCT-ENROLLMENT.md",
    summary: "Enroll an installed host and operator signing policy.",
    guideSlug: "install-and-setup",
  },
  {
    id: "10",
    title: "Product store enrollment",
    group: "Enrollment & updates",
    file: "docs/operator/10-PRODUCT-STORE-ENROLLMENT.md",
    summary: "Enroll an append-only restic backup destination.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "11",
    title: "After power loss",
    group: "Backups & recovery",
    file: "docs/operator/11-AFTER-POWER-LOSS.md",
    summary: "Recovery and reconcile commands for every verb after a crash.",
    guideSlug: "troubleshooting-and-recovery",
  },
  {
    id: "12",
    title: "Uninstall",
    group: "Backups & recovery",
    file: "docs/operator/12-UNINSTALL.md",
    summary: "Remove RustIron while preserving live site data and archives.",
    guideSlug: "troubleshooting-and-recovery",
  },
  {
    id: "13",
    title: "Scheduled capture",
    group: "Backups & recovery",
    file: "docs/operator/13-SCHEDULED-CAPTURE.md",
    summary: "Enable daily backup captures under a signed standing grant.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "14",
    title: "OLS package upgrade",
    group: "Enrollment & updates",
    file: "docs/operator/14-OLS-UPGRADE.md",
    summary: "Upgrade OpenLiteSpeed and verify the shipped parent config.",
    guideSlug: "updates-and-releases",
  },
  {
    id: "15",
    title: "Page cache on",
    group: "Sites & apps",
    file: "docs/operator/15-PAGE-CACHE-ON.md",
    summary: "Enable or disable LiteSpeed Page Cache for a WordPress site.",
    guideSlug: "wordpress-sites",
  },
  {
    id: "16",
    title: "Product update",
    group: "Enrollment & updates",
    file: "docs/operator/16-PRODUCT-UPDATE.md",
    summary: "Update RustIron, migrate journal schema, cut bundles, or roll back.",
    guideSlug: "updates-and-releases",
  },
  {
    id: "17",
    title: "Break-glass",
    group: "Backups & recovery",
    file: "docs/operator/17-BREAK-GLASS.md",
    summary: "Make an emergency manual host change and return to management.",
    guideSlug: "troubleshooting-and-recovery",
  },
  {
    id: "18",
    title: "Owner choices",
    group: "Decisions & custody",
    file: "docs/operator/18-OWNER-CHOICES.md",
    summary: "Recorded owner v1.0 choices for host, store, mail, alerts, and console.",
    guideSlug: "install-and-setup",
  },
  {
    id: "19",
    title: "Risk acceptance",
    group: "Decisions & custody",
    file: "docs/operator/19-RISK-ACCEPTANCE.md",
    summary: "Line-by-line acceptance of known v1.0 limits.",
    guideSlug: "how-rustiron-works",
  },
  {
    id: "20",
    title: "Homelab VPS backup",
    group: "Backups & recovery",
    file: "docs/operator/20-HOMELAB-VPS-BACKUP.md",
    summary: "Verify, restore, or undo nightly pull backups to RustFS.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "21",
    title: "Pilot DNS record",
    group: "DNS, firewall & mail",
    file: "docs/operator/21-PILOT-DNS-RECORD.md",
    summary: "Add, check, and remove a pilot DNS A record.",
    guideSlug: "domains-ssl-and-dns",
  },
  {
    id: "22",
    title: "Backup retention",
    group: "Backups & recovery",
    file: "docs/operator/22-BACKUP-RETENTION.md",
    summary: "Prune expired snapshots safely with retention authority.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "23",
    title: "Alert check-in",
    group: "Backups & recovery",
    file: "docs/operator/23-ALERT-CHECKIN.md",
    summary: "Connect a host to Uptime Kuma redacted heartbeat alerts.",
    guideSlug: "security-and-diagnoses",
  },
  {
    id: "24",
    title: "WordPress update",
    group: "Sites & apps",
    file: "docs/operator/24-WORDPRESS-UPDATE.md",
    summary: "Apply signed WordPress core, plugin, or theme updates with rollback.",
    guideSlug: "wordpress-sites",
  },
  {
    id: "25",
    title: "Delete a live site",
    group: "Sites & apps",
    file: "docs/operator/25-DELETE-LIVE-SITE.md",
    summary: "Delete a site behind a fresh verified capture or settle an open deletion.",
    guideSlug: "wordpress-sites",
  },
  {
    id: "26",
    title: "Site restore",
    group: "Backups & recovery",
    file: "docs/operator/26-SITE-RESTORE.md",
    summary: "Restore a live website behind a safety capture or revert.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "27",
    title: "Database export",
    group: "Backups & recovery",
    file: "docs/operator/27-DATABASE-EXPORT.md",
    summary: "Extract a SQL dump offline from an encrypted backup capture.",
    guideSlug: "databases-and-credentials",
  },
  {
    id: "28",
    title: "Firewall zone",
    group: "DNS, firewall & mail",
    file: "docs/operator/28-FIREWALL-ZONE.md",
    summary: "Apply or check the rustiron firewalld zone without losing SSH.",
    guideSlug: "firewall-and-network",
  },
  {
    id: "29",
    title: "DNS (PowerDNS 5.1)",
    group: "DNS, firewall & mail",
    file: "docs/operator/29-DNS.md",
    summary: "Enroll PowerDNS 5.1, import zones, apply dns_change, and reconcile.",
    guideSlug: "domains-ssl-and-dns",
  },
  {
    id: "30",
    title: "Proxy site",
    group: "Sites & apps",
    file: "docs/operator/30-PROXY-SITE.md",
    summary: "Provision and manage loopback HTTP or WebSocket proxy sites.",
    guideSlug: "modern-apps-and-emdash",
  },
  {
    id: "31",
    title: "Advisory watch",
    group: "Enrollment & updates",
    file: "docs/operator/31-ADVISORY-WATCH.md",
    summary: "Check Rust, Bun, AlmaLinux 10, and stack versions against advisories.",
    guideSlug: "updates-and-releases",
  },
  {
    id: "32",
    title: "Modern apps",
    group: "Sites & apps",
    file: "docs/operator/32-MODERN-APPS.md",
    summary: "Provision, deploy, diagnose, roll back, and delete Node.js 22 / Bun 1.4 apps.",
    guideSlug: "modern-apps-and-emdash",
  },
  {
    id: "33",
    title: "EmDash CMS",
    group: "Sites & apps",
    file: "docs/operator/33-EMDASH.md",
    summary: "Run EmDash 1.6.0, rehearse WordPress WXR migration, back up, and upgrade.",
    guideSlug: "modern-apps-and-emdash",
  },
  {
    id: "34",
    title: "Developer platform",
    group: "Sites & apps",
    file: "docs/operator/34-DEVELOPER-PLATFORM.md",
    summary: "Unified Day-0 to Day-2 workflow across sites, apps, DNS, backups, and Console.",
    guideSlug: "how-rustiron-works",
  },
  {
    id: "35",
    title: "Site credential rotation",
    group: "Sites & apps",
    file: "docs/operator/35-SITE-CREDENTIAL-ROTATION.md",
    summary: "Rotate per-site MariaDB passwords locally with atomic db.cnf swap.",
    guideSlug: "databases-and-credentials",
  },
  {
    id: "36",
    title: "Mail relay & cutover",
    group: "DNS, firewall & mail",
    file: "docs/operator/36-MAIL-RELAY-AND-CUTOVER.md",
    summary: "Enable per-site Postfix Unix-socket relay and plan mail cutover.",
    guideSlug: "email-and-relay",
  },
  {
    id: "37",
    title: "Replacement migration",
    group: "Migration & cutover",
    file: "docs/operator/37-M6-REPLACEMENT-MIGRATION.md",
    summary: "Fresh-host wave plan, cutover budgets, rollback triggers, and verification.",
    guideSlug: "migrations",
  },
  {
    id: "38",
    title: "Console deployment & hardening",
    group: "Sites & apps",
    file: "docs/operator/38-CONSOLE-PRODUCTION-DEPLOYMENT.md",
    summary: "Deploy and harden the Console with Better Auth, HTTPS origin, and P16 access.",
    guideSlug: "install-and-setup",
  },
];

export const glossaryTerms: [string, string][] = [
  [
    "Plan",
    "Immutable canonical JSON list of intended host effects. Reviewing a plan is not approving it.",
  ],
  [
    "Approval / Grant",
    "Short-lived SSHSIG-signed scope binding one exact plan SHA-256 digest to one host and epoch.",
  ],
  [
    "Coordinator",
    "Unprivileged local daemon (rustiron-coordinator) that validates read requests and forwards signed plans.",
  ],
  [
    "Executor",
    "Privileged service (rustiron-executor) that independently verifies peer identity, signature, replay, and preconditions before running fixed scoped operations.",
  ],
  [
    "Operation",
    "Durable execution record of one approved plan in the executor journal, identified by an operation ID.",
  ],
  [
    "Needs attention",
    "An interrupted or ambiguous operation outcome. Never treated as succeeded or safe to blindly retry.",
  ],
  [
    "Quarantined site",
    "A site whose provisioning or recovery stopped midway; stays isolated until explicitly reconciled or retired.",
  ],
  [
    "Eject",
    "Stop RustIron management for a site while keeping its files, database, OLS vhost, and TLS certificates serving.",
  ],
  [
    "SELinux MCS",
    "Multi-Category Security labels (s0:c<N>) confining each PHP pool and app unit so compromised sites cannot read peers.",
  ],
  [
    "Snapshot",
    "Encrypted restic backup artifact in the backup store. Proven recoverable only after restore-probe verification.",
  ],
  [
    "Unclaimed snapshot",
    "Backup data uploaded during a failed or interrupted capture; kept visible for retention reconciliation, never counted as a backup of record.",
  ],
  [
    "Drift",
    "Observed difference between host state and managed configuration. RustIron explains drift instead of silently resetting it.",
  ],
  [
    "Root-only / Not checked",
    "A check requiring root privileges (such as sshd -T or firewall-cmd) that the unprivileged observer refuses to guess.",
  ],
  [
    "Blast-radius envelope",
    "Pre-signing summary showing affected sites, global OpenLiteSpeed reload impact, and durable authority budget.",
  ],
];

export function articleBySlug(slug: string): KbArticle | undefined {
  return kbArticles.find((article) => article.slug === slug);
}

export function articleCategory(id: KbCategoryId): KbCategory {
  return kbCategories.find((c) => c.id === id) ?? kbCategories[0]!;
}

export function kbSearchTargets(): { href: string; label: string }[] {
  return kbArticles.map((a) => ({
    href: `/help/${a.slug}`,
    label: `Docs: ${a.title}`,
  }));
}

export function articleMatchesQuery(article: KbArticle, needle: string): boolean {
  if (!needle) return true;
  if (
    article.title.toLowerCase().includes(needle) ||
    article.summary.toLowerCase().includes(needle) ||
    article.keywords.some((k) => k.toLowerCase().includes(needle)) ||
    article.runbooks.some((r) => r.toLowerCase().includes(needle))
  ) {
    return true;
  }
  return article.sections.some(
    (s) =>
      s.heading.toLowerCase().includes(needle) ||
      s.paragraphs.some((p) => p.toLowerCase().includes(needle)) ||
      (s.bullets?.some((b) => b.toLowerCase().includes(needle)) ?? false) ||
      (s.commands?.some(
        (c) => c.label.toLowerCase().includes(needle) || c.code.toLowerCase().includes(needle),
      ) ??
        false),
  );
}
