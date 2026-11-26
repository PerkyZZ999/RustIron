# Developer Hosting Platform Guide

Updated: 2026-11-24 (America/Toronto).
Status: P29 consolidation guide covering lab-verified v1.0 workflows on AlmaLinux 10 x86_64 ([D-058](../decisions/D-058-v1-scope.md)).

Rustiron is an open-source Rust/TypeScript hosting panel designed as a safer, developer-friendly CyberPanel alternative. This guide brings together the CLI, read-only Console, and operator runbooks into one start-to-finish path across WordPress sites, static sites, proxy sites, Node.js 22 / Bun 1.4 apps, EmDash 1.6.0 CMS, PowerDNS 5.1, encrypted backups, and safe ejection.

## 1. Mental model

- **Management path:** `CLI -> unprivileged coordinator -> independently validating executor -> fixed scoped operations`.
- **Serving path bypasses Rustiron:** Website and app traffic flows directly through OpenLiteSpeed (OLS), per-site LSPHP 8.4 pools, MariaDB, or confined `rustiron-app@.service` units. If Rustiron stops or is removed, served sites keep running.
- **No implicit authority:** Every mutating plan is reviewed offline (`rustiron-plan inspect` / `rustiron-plan envelope`), signed outside the host with the operator's SSH key, and checked by the executor for peer identity, exact signed scope, replay, blast-radius budgets (D-098), and current preconditions.
- **Honest unknowns:** Read-only diagnostics (`rustiron-control --diagnose`) and the local read-only Console label unreadable or unrun checks as `unknown` or `not_run` rather than guessing `ok`.

## 2. Choose the right workload type

| Workload | When to use it | Primary runbook / spec |
| --- | --- | --- |
| **WordPress site** | Native WordPress or CyberPanel WordPress import (LSPHP 8.4, MariaDB, LSCache, WP-Cron, signed core/plugin/theme updates) | [24-WORDPRESS-UPDATE.md](24-WORDPRESS-UPDATE.md), [26-SITE-RESTORE.md](26-SITE-RESTORE.md) |
| **Static site (+ optional alias)** | Prebuilt HTML/CSS/JS exports (`enableScript 0`), single hostname or certified exact pair, independent static eject (D-097) | [12-UNINSTALL.md](12-UNINSTALL.md), [D-097](../decisions/D-097-eject-static-single-name.md) |
| **Proxy site (CP08)** | Reverse-proxying an external loopback HTTP/WebSocket service behind OLS path routes | [30-PROXY-SITE.md](30-PROXY-SITE.md) |
| **Modern Node.js 22 / Bun 1.4 app (P27)** | Off-host built JS/TS web apps + optional worker running in confined `rustiron-app@.service` units with `0400` `app.env` secrets and automatic rollback | [32-MODERN-APPS.md](32-MODERN-APPS.md) |
| **EmDash 1.6.0 CMS (P30)** | Pinned Node.js 22 Starter EmDash CMS with native SQLite FTS5, WAL-safe P03 capture/restore, `upgrade-emdash` migrations, and WordPress WXR + media migration | [33-EMDASH.md](33-EMDASH.md) |

## 3. Day-0 host setup (order of operations)

1. **Enroll the host and signer policy** — [09-PRODUCT-ENROLLMENT.md](09-PRODUCT-ENROLLMENT.md).
2. **Enroll the S3-compatible backup store with COMPLIANCE Object Lock** — [10-PRODUCT-STORE-ENROLLMENT.md](10-PRODUCT-STORE-ENROLLMENT.md) (and review retention custody in [22-BACKUP-RETENTION.md](22-BACKUP-RETENTION.md)).
3. **Apply the enrolled `rustiron` firewalld zone and verify MariaDB stays loopback-only** — [28-FIREWALL-ZONE.md](28-FIREWALL-ZONE.md).
4. **Optionally install and enroll PowerDNS 5.1 authoritative DNS with TSIG AXFR** — [29-DNS.md](29-DNS.md).
5. **Connect Uptime Kuma heartbeat and diagnosis alerts** — [23-ALERT-CHECKIN.md](23-ALERT-CHECKIN.md).
6. **Enable daily scheduled captures via a D-035 standing grant** — [13-SCHEDULED-CAPTURE.md](13-SCHEDULED-CAPTURE.md).

## 4. Day-1 & Day-2 developer workflows

- **Inspect blast radius before signing any plan:**
  - `rustiron-plan inspect <plan.json>` and `rustiron-plan envelope <plan.json>` show exact resource scope, D-098 authority budget consumption, and whether an OLS reload affects all served sites.
- **Check host & site health without mutating anything:**
  - `rustiron-control --diagnose` checks SELinux enforcing state, clock sync, OLS maps, MariaDB socket, per-site PHP pools, P27/P30 app units, proxy listeners, certificates, and P03 backup/restore evidence (P04).
- **Deploy or upgrade modern apps and EmDash sites:**
  - Build release archives off-host, stage in `/var/lib/rustiron/app-intake`, sign `app_deploy` (referencing a recent P03 capture whenever migrations run), and rely on loopback health probes + automatic rollback ([32-MODERN-APPS.md](32-MODERN-APPS.md), [33-EMDASH.md](33-EMDASH.md)).
- **Update WordPress sites safely:**
  - Run read-only `update-inventory` + `wordpress-update-watch.py` on the operator PC, then apply signed pinned recipes with automatic code+database rollback ([24-WORDPRESS-UPDATE.md](24-WORDPRESS-UPDATE.md)).
- **Watch upstream security advisories:**
  - Run `scripts/release/advisory_watch.py` on the operator PC against pinned `Cargo.lock`, `console/bun.lock`, AlmaLinux 10 errata, and `support-matrix.json` ([31-ADVISORY-WATCH.md](31-ADVISORY-WATCH.md)).
- **Restore, export, break-glass, or eject:**
  - Live site restore behind a safety capture: [26-SITE-RESTORE.md](26-SITE-RESTORE.md); offline DB export to PC: [27-DATABASE-EXPORT.md](27-DATABASE-EXPORT.md); emergency manual edits: [17-BREAK-GLASS.md](17-BREAK-GLASS.md); full uninstall keeping sites serving: [12-UNINSTALL.md](12-UNINSTALL.md).

## 5. Local read-only Console over SSH tunnel (D-090)

The Rustiron Console (`console/`) runs strictly read-only on loopback behind an SSH port forward (`ssh -N -L 127.0.0.1:4173:127.0.0.1:4173 <host>`). Every route maps directly to a read-only CLI observation:

| Console route | Backing CLI / contract |
| --- | --- |
| `/` (`Overview`) & `/host/diagnoses` | `rustiron-control --host-status` and `--diagnose` (P04) |
| `/sites` & `/sites/:siteId` | `Executor::observe` journal state, quotas, and 7-field recovery evidence |
| `/apps` & `/apps/:appId` | P27/P30 app unit status, release history, and `app.env` key names only (`0400` values hidden) |
| `/domains` & `/domains/:hostname/dns` | P02 TLS certificate status and CP05 PowerDNS 5.1 zone ownership boundaries |
| `/migration` | P01 CyberPanel & P30 WordPress-to-EmDash offline rehearsal reports |
| `/recovery`, `/recovery/schedules`, `/recovery/store` | P03 capture records, D-035 standing grants, and COMPLIANCE Object Lock store summary |
| `/host/updates` | P06/P09 observed stack versions vs. D-063 support matrix & D-082 advisory watch |

## 6. Explicit v1.0 boundaries

- **Lab verified today:** M1 Core (S01–S10, B01–B15), P01, P04, P05, CP01–CP03, P23 (D-098), P26/P27 (D-099), P30 EmDash (D-096), CP05 PowerDNS 5.1 (lab), CP08 firewalld + proxy sites, and D-097 static ejection.
- **Human checkpoints before production:** Production signing custody, real ACME CA / public DNS / external mail choice, homelab RustFS P03 checks, independent security review & risk acceptance (P10), owner console design review (P14/CP04), and authorized pilot cutover (P11).
- **Explicitly after v1.0:** Console approval/write actions (P15, D-090), remote console auth (P16), second PHP profile (P20, D-081), multi-user delegation (CP07, D-094), DNSSEC & external DNS provider APIs (D-091), and independent off-site/USB key escrow (D-026).
