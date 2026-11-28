# Changelog

All notable changes to RustIron are recorded here, newest first.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

RustIron is experimental pre-release software. No version below is a supported production release.

## [Unreleased]

### Added

- **Docs & KB in Markdown.** The Console's guides are Markdown files in `console/kb/`, the same source as the documentation site.
- **Guides for the Console web interface**, in a new "Using the Console" category: a tour, making changes, sites and apps, domains and email, backups, server pages, and users and sign-in.
- **Guides for AI agents**: what an agent can and cannot do, connecting one through the read-only `rustiron-mcp` server over SSH, and the agent skill.
- **RustIron agent skill** in `skills/rustiron/`, in the [Agent Skills](https://agentskills.io) format.
- **`rustiron-mcp` ships with the product** as `/usr/libexec/rustiron/rustiron-mcp`. The installer, the product update, and the uninstaller handle it like the other product files, so a host has the MCP server without a source build.
- **A supported SSH connection for AI agents.** The product installs `/etc/sudoers.d/rustiron-mcp`, which lets members of the new, empty `rustiron-agents` group start `rustiron-mcp` read-only as the coordinator, with its exact arguments and nothing else. Add your SSH account with `usermod -aG rustiron-agents ACCOUNT`. If you wrote that file yourself from the earlier guide, delete it before updating.
- **Host summary for the CLI and AI agents.** `rustiron host summary` and three new read-only MCP tools (`rustiron_host_summary`, `rustiron_certificate_status`, `rustiron_backup_status`) show each site's recorded state, certificates that expire or failed to renew, and each site's newest backup and restore test. The summary holds no paths, keys, plans, or receipts.
- **Plan drafts for AI agents.** `rustiron_plan_draft` builds an unsigned plan with the same code as `rustiron plan create`, and returns its fields and blast radius for you to review and sign; `rustiron_plan_draft_help` lists the verbs and their flags. Drafts sign, store, and submit nothing. The DNS verbs that read files stay CLI-only.
- **Host diagnoses for AI agents.** `rustiron_diagnoses` runs the server's own `rustiron-control --host-status --diagnose` and lists the problems it finds with what to do about each.
- **Newer MCP protocol, guides, and prompts.** `rustiron-mcp` negotiates MCP `2025-06-18` (and still speaks `2025-03-26` and `2024-11-05`), gives every tool a title and an output schema, serves every RustIron guide as a read-only resource (`rustiron://guides/<slug>`), and offers five ready-made prompts: health check, look into a site, backup readiness, prepare a change, and follow a change.
- **How to let an agent submit signed changes on a test server.** The AI agent guides now show the optional nonproduction write mode, with a sudoers rule you write yourself, and say to read a plan with `rustiron plan review-file` before you sign it. The production write mode is not recommended yet.

### Changed

- **A simpler Host overview.** One sentence says how the server is doing, four tiles show CPU, memory, disk, and uptime with a word and a meter, the resource chart draws in, and services and recent operations fold away under "Server details". Motion stops when the system or the Console asks for reduced motion.
- **Server pages say how things are first.** Metrics, services, firewall, timers, logs, diagnoses, alerts, and updates each start with one sentence built from what the server reports, with details folded away.
- **Websites, apps, databases, migrations, domains, email, backups, operations, users, and settings say how they are first**, in one sentence each.
- **Lists for a few entries or hundreds.** Websites, Domains, Apps, Databases, Backups, and Operations are lists with problems first. Search and sorting appear once a list has more than 8 entries, and pages once it is longer than one page; Settings → Rows per page now defaults to 50.
- **Choose several entries at once.** On Websites and Backups (back up now, test a restore) and Apps (restart), check the entries and pick an action: the Console shows one `rustiron plan create` command per entry to review and sign offline, then submit on the Plans page. Nothing changes from the browser, and removal is never offered in bulk.
- **"Websites" and "Backups".** The Sites and Recovery pages are now called Websites and Backups in the sidebar, the titles, the breadcrumbs, and the search. Addresses are unchanged.
- Shorter guide titles and summaries, simpler category names, and guides grouped by category.
- **Guides for lists and bulk actions.** The Console tour, "Make changes from the Console", "Websites & apps in the Console", and "Backups in the Console" explain long lists, choosing several entries, and the Websites and Backups names.
- New Console screenshots in the README.

### Fixed

- **The details drawer opens above the top bar.** On desktop its title and close button were hidden under the top bar.
- **No scrollbar beside the Console's tab rows.** Recovery, a domain's details, and an app's details showed a small vertical scrollbar at the end of their tab row.
- **Site list and site inspect work on a fresh server.** Without an imported inventory, the CLI and the MCP server now list the sites RustIron created or adopted, read from the executor journal (`inventory.source: executor_journal`), instead of answering "dependency unavailable".

### Security

- The Console can no longer connect to the executor socket. The coordinator's user is no longer a member of `rustiron-requesters`; only the coordinator service gets that group. The product update removes the membership on existing hosts; restart the Console after the update ([Runbook 38](docs/operator/38-CONSOLE-PRODUCTION-DEPLOYMENT.md)).

## [0.2.0] — 2026-11-27

### Added

- **Second factor for Admin accounts.** An Admin signs in with a TOTP code from an authenticator app. Setup shows a QR code and gives ten one-use recovery codes, stored encrypted. The server refuses an Admin's other requests until the factor is on. A host-shell command resets a lost factor ([Runbook 38](docs/operator/38-CONSOLE-PRODUCTION-DEPLOYMENT.md)).
- **Sign-in limits** per address, per account, and in total, with wait messages and no account lockout. Sign-in over the SSH tunnel is never paused.
- **Console observation feed.** The install wizard ships `rustiron-console-observe.timer`, which refreshes the host observation every 30 seconds.
- A list of all error codes in [ERROR-CODES.md](docs/technical/ERROR-CODES.md).

### Changed

- The install wizard runs the Console as the coordinator's user, the only peer that the coordinator socket accepts, so a new host shows live data.
- A Console without a live source shows "Unavailable" with the cause and what to check. It never shows sample data on a real host, and pages do not show sample content while the first observation loads.
- Console requests and coordinator replies are checked with strict Zod v4 schemas. An unknown or mistyped field gets `400`.
- The production build contains only React's production runtime, and hashed assets are served gzip-compressed.
- The Console is split by route, with view transitions between routes and drawers.
- A session expires after 12 hours without use.
- Internal refactors: one admission path for signed verbs, one generation module for OpenLiteSpeed and Caddy configuration, and streamed database dumps and restores.

### Fixed

All 25 findings of the v0.2 QA run (exploratory testing and Bombadil property-based fuzzing), each with its own change. Among them:

- The product updater creates the product and state folders that an older install lacks, and removes them on rollback. Hosts installed before 0.1.1 now update without manual steps.
- Confirmation before an account or a mail forwarder is deleted.
- Mail forwarders cannot loop or hide a mailbox, and mailbox domains must be domains that the host serves.
- Account forms show a message on each field. Sign-in keeps the page that was requested.
- Wizards show a command only for valid input.
- Coordinator reply errors keep their HTTP status. Host log line counts outside 10–200 are clamped instead of reset.
- An unknown domain shows a "not found" state. Breadcrumbs show values as written.

### Security

- The Better Auth endpoints that return or take a raw session token (`/get-session`, `/list-sessions`, `/revoke-session`) answer `404`.
- The root helper unit has a tighter systemd sandbox.
- The MCP adapter has a deadline per stdio line, and its write gate decodes only closed contract grants.

## [0.1.1] — 2026-11-27

### Added

- **Full-stack app topologies** on Node.js 22 or Bun 1.4. There are four signed app shapes: `static_spa`, `backend_api`, `fullstack_split` (static frontend and `/api` backend), and `fullstack_dual_ssr` (SSR frontend and API backend).
- **Confined Caddy edge.** Optional Caddy 2.10 ingress with HTTP/3, WebSockets, and unbuffered SSE, confined in `rustiron_caddy_t`. Modes: `caddy_only`, `caddy_multi_ip`, and `caddy_edge_over_ols`, which bridges WordPress sites to OpenLiteSpeed over loopback. The admin API listens only on a `0700` Unix socket, and `rustiron-acme` stays the only certificate issuer.
- **Blue/green cutover.** A deploy starts and health-checks a standby slot, then reloads Caddy onto it without a restart.
- **Database per app:** `none`, `sqlite`, `mariadb`, or `postgresql_18` (PGDG 18.7 or later, loopback and SCRAM-SHA-256 only), each in its own SELinux app domain.
- **Deterministic packager.** `packaging/rustiron-app-pack.py` turns a build output into a byte-reproducible bundle and manifest, with 6 framework presets. It refuses symlinks, special files, and `.env` files.

### Security

- An app port with an SELinux type that the app cannot use is refused at plan creation and at admission.
- The Console refuses a request body over 1 MiB.
- Database restores and PostgreSQL dumps run as the site role, never as a superuser.

See [Modern Apps](docs/technical/MODERN-APPS.md) and [Runbook 32: Modern Apps](docs/operator/32-MODERN-APPS.md).

## [0.1.0] — 2026-11-26

First public pre-release.

### Added

- Rust control plane workspace (`contracts`, `core`, `control`, `cli`, `journal`, `executor`). Every privileged change needs an off-host SSHSIG-signed plan, and tenants are isolated with enforcing SELinux and MCS categories.
- Console Admin Panel built with React 19, strict TypeScript, Bun, Tailwind CSS v4, and Coss UI. It has a full-screen Better Auth sign-in, strict CSP and HSTS headers, 43 routes, and built-in documentation.
- AlmaLinux 10 installation wizard, signed release bundler, updater with rollback, SELinux policy modules, and public technical and operator documentation.

[0.2.0]: https://github.com/PerkyZZ999/RustIron/commit/09f43bc
[0.1.1]: https://github.com/PerkyZZ999/RustIron/commit/f551f4f
[0.1.0]: https://github.com/PerkyZZ999/RustIron/commit/443e904
