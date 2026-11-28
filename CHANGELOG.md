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

### Changed

- Shorter guide titles and summaries, simpler category names, and guides grouped by category.

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
