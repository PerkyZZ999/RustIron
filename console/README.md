# Rustiron console

Local management console for Rustiron (`127.0.0.1:4319`, D-090 hardened loopback server).
In live mode (`RUSTIRON_OBSERVATION`, `RUSTIRON_COORDINATOR_SOCKET`, or `RUSTIRON_CONSOLE_NO_FIXTURE=1`), every screen reads real host, journal, and coordinator data with zero mock or fixture fallback.
Private signing keys stay outside the browser and Console server (D-005 / D-090); write actions submit externally signed SSHSIG grants via `RUSTIRON_CONSOLE_WRITE_WORKFLOWS=1`.

```sh
bun install
bun run dev           # development server (fixture preview when no live source is set)
bun run start:live    # production live server (never falls back to fixture data)
bun run verify        # oxfmt + oxlint + tsc + fallow + bun test + production build
bun run check:browser # Chromium + axe WCAG 2.2 AA gate across all routes and themes
```

## Production / live host startup

Connect the Console directly to the unprivileged coordinator socket, a saved host observation, or both:

```sh
# Read-only live mode directly against the coordinator Unix socket (no fixture fallback)
RUSTIRON_COORDINATOR_SOCKET=/run/rustiron/coordinator.sock \
  bun run start:live

# Full live telemetry + journal observation + optional separate-custody signed-plan apply
RUSTIRON_OBSERVATION=/home/rustiron-build/rustiron-observe/observation.json \
RUSTIRON_COORDINATOR_SOCKET=/run/rustiron/coordinator.sock \
RUSTIRON_CONSOLE_WRITE_WORKFLOWS=1 \
  bun run start:live
```

When `RUSTIRON_OBSERVATION`, `RUSTIRON_COORDINATOR_SOCKET`, or `RUSTIRON_CONSOLE_NO_FIXTURE=1` is set:

- `/api/observation` refuses fixture fallback (`503 LIVE_SOURCE_NOT_CONFIGURED`) if no file is present, and the UI automatically hydrates live host/site state from `/api/coordinator/live` (`doctor` + `site_list`).
- Site overview and operation detail screens query `/api/coordinator/sites/:siteId`, `/api/coordinator/operations/:operationId`, and `/api/coordinator/evidence/:operationId` on demand, including redacted JSON export.
- `/plans/new` and `/plans/new/review` build bounded plans across all 6 catalogue actions, compute the D-098 blast radius, generate exact offline `rustiron plan create` + `ssh-keygen -Y sign` commands, and accept loaded/pasted `plan.json` + `grant.json` + `grant.json.sig` files for separate-custody apply.
- **Console accounts & RBAC (`/api/auth/*`, `/api/accounts/*`):** powered by Better Auth (`better-auth`) + Bun's built-in `bun:sqlite` (`RUSTIRON_CONSOLE_AUTH_DB`, `RUSTIRON_CONSOLE_ORIGIN`). Once `RUSTIRON_CONSOLE_AUTH_REQUIRED=1` or the first Admin exists, the entire panel locks behind a standalone full-screen authentication gate (zero sidebar, topbar, or background polling while signed out), enforces `HttpOnly; SameSite=Strict` cookies (`Secure` on HTTPS origins), rate-limits failed setup-token and sign-in attempts (`429`), and enforces `admin`/`operator`/`viewer` RBAC.
- **Production HTML & asset hardening (`dist/`):** `bun run start:live` builds `dist/` with root-relative `publicPath: "/"` and serves every HTML page, hashed asset, and API route through the D-090 `Host` allowlist (`421`) with CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, and `Strict-Transport-Security` (when `RUSTIRON_CONSOLE_ORIGIN` uses `https://`).
- **Integrated Docs & Knowledge Base (`/help`, `/help/$slug`):** 26 step-by-step guides across 8 categories (including "Using the Console" and "AI agents") with copyable CLI recipes, searchable 38-runbook directory, glossary, and global `Ctrl+K` indexing (43 Built routes total). The guides and the glossary are Markdown files in [`kb/`](kb/), the same source as the public docs site; see [Docs & KB source](#docs--kb-source).
- **Self-hosted mail registry (`/api/mail/*`, `/mail`):** Postfix + Dovecot virtual domains, mailboxes (Argon2id hashed passwords via `Bun.password.hash`), aliases/forwarders, and map exports backed by `bun:sqlite` (`RUSTIRON_CONSOLE_MAIL_DB`; read-only `405` by default unless `RUSTIRON_CONSOLE_MAIL_WRITES=1`).
- **Redacted server logs (`/api/host/logs`, `/host/logs`):** strictly allowlisted (`executor`, `coordinator`, `admin`, `console`, `ols`, `mariadb`, `pdns`, `postfix`, `dovecot`, `sitecron`), bounded (`10..200` lines, `128 KiB`), read-only `journalctl` viewer with severity filtering, auto-refresh, `.log` download, exit-0 permission-hint detection (`SupplementaryGroups=systemd-journal`), and secret redaction.
- **Host updates & stack matrix (`/host/updates`):** aligned with `crates/control/support-matrix.json` (AlmaLinux 10, OpenLiteSpeed 1.9, LSPHP 8.4, MariaDB 10.11 LTS, optional Node.js 22 LTS, Bun 1.4, and PowerDNS 5.1); optional uninstalled services display calmly as `Not installed` (`Optional`) while unobserved views stay honest with zero fixture fallback.
- For full production deployment, P16 SSH/WireGuard/reverse-proxy hardening, and Postfix/Dovecot sync, follow [Runbook 38](../docs/operator/38-CONSOLE-PRODUCTION-DEPLOYMENT.md).

## Docs & KB source

Each guide is `kb/<slug>.md`; the glossary is `kb/glossary.md`. `src/kb-data.ts` imports them as text, and `src/kb-markdown.ts` parses them. The public docs site (Astro Starlight) reads the same files. The parser accepts only this subset and fails the tests and the build on anything else:

- Frontmatter: one `key: <JSON value>` per line, with `title`, `description` (the summary), `category`, `order` (the position in the Console), `readMinutes`, `runbooks`, `keywords`, and `consoleLinks`. `title` and `order` must match `src/kb-index.ts`.
- `## Heading {#section-id}` starts a section. The id is the page anchor.
- Within a section, in this order: plain paragraphs, `- ` bullets, at most one callout, then commands. The parser refuses any other order and numbered lists, because the Console always shows a section in that order.
- Plain paragraphs and `- ` bullets. Escape Markdown syntax in text with a backslash (`\<`, `\*`, `\[`).
- One callout per section: `:::note[Title]` or `:::caution[Title]`, the body, and `:::`.
- Commands: a fenced block whose info string has `title="…"` and `where="…"` (`Server (root)`, `Server (unprivileged)`, `Workstation (operator)`, or `Build / maintainer`).

A new guide also needs its title in `src/kb-index.ts` and an import in `src/kb-data.ts`. `oxfmt` skips `kb/`, because it would rewrite the one-line frontmatter.

`bun run dev` serves http://127.0.0.1:4319. Quality command: format check, Oxlint, `bun check`, Fallow, `bun test`, and a production `bun build`.

`patches/@tanstack%2Frouter-core@1.171.39.patch` defers router-core's dev-only HMR install to a microtask.
Bun's dev bundler otherwise reads `replaceRouteChunk` while the router/load-client cycle is still null and the page throws before first paint.
Production `bun build` does not hit that path.

`bun run check:browser` serves a production bundle on a random local port.
Chromium opens every route in both themes at 1440×900 and 375×812.
Use `/usr/bin/chromium` or `RUSTIRON_CHROMIUM`.
It fails on axe WCAG 2.2 AA violations, horizontal page scroll, console errors, a missing h1, or a broken keyboard path.
In both modes it also serves the synthetic observations in `e2e/states/` ([W379](../docs/validation/S10-W379/README.md)).
It fails when a journal state's text is absent or when the not-enrolled empty state is missing.
Fallow reports a reviewed warning that this tooling imports dev dependencies; it is not shipped code.

## Live read-only data from the lab VM

```sh
bun run lab:pull   # every 15 s: ssh.sh → rustiron-s02-executor observe + rustiron-control --host-status → .live/observation.json
bun run dev:live   # serves the console with /api/observation reading that file
```

`observe` runs beside the serving executor with a read-only journal connection and no writer lease.
The report contains recorded sites, operations, captures, and restore probes with their seven fields.
The report omits nonces, idempotency keys, grant ids, and digests.

The report also carries these journal facts:

- Capture consistency labels and unclaimed snapshots.
- Probe refusal codes.
- Page-cache state and page-cache operation kinds.
- Recorded quota limits.
- Re-adoptions.

Live quota usage is not in the report; `export SITE` reads it.
A capture's refusal code is not journaled, so the console names it as missing.
When `observe` answers `EXECUTOR_NOT_ENROLLED`, `lab:pull` saves a `rustiron-executor-refusal/1` document.
The console then shows its not-enrolled empty state instead of old data.

`rustiron-control --host-status` runs unprivileged and reports OS, CPU/load, memory, root disk, uptime, SELinux and systemd units.
On the host, `lab/dev/observe-local.sh` (installed as `observe-local`) merges those two reads, appends one sample to `samples.json` (cap 2880) and writes `observation.json`.
`lab:pull` prefers that host-local command and falls back to the two SSH calls.

The observation supplies Overview, Services, Sites, Operations, Operation detail, Recovery, and recovery receipts.
**Host metrics**, **Settings**, **Help**, **States**, **Plan detail**, and non-fixture site pages also read the observation.
Site pages include per-site operations and snapshot history.

Search lists those observed rows and omits fixture shop, plan and snapshot stories.
A snapshot link opens the capture record and says the artifact file list is not in the observation.
A receipt link is the probe operation whose journal stored the seven fields.

Scope is shown when the journal recorded it.
Sandbox, timings, the attester key and the signed bytes are named as absent.
Operation rows link to `/operations/<id>` and show only journal facts (no fixture shop story).

An unknown id says it is not in the observation.
`/plans/new` and `/plans/new/review` build real plans against live sites and carry separate-custody offline signing commands and file upload.
Serving, HTTP and runtime are not observed yet and say so.

Notifications list quarantined sites and failed operations from the observation.
The overview refresh button re-reads `/api/observation`.
Older than 60 s counts as stale.

If the source fails, the last observation stays on screen marked stale.
With no observation at all, nothing is shown.
`RUSTIRON_OBSERVATION=$PWD/.live/observation.json bun run check:browser` runs the browser gate against live data.

On the host, point `RUSTIRON_OBSERVATION` at the file `observe-local` writes (`/home/rustiron-build/rustiron-observe/observation.json` in the lab).
A lab timer (`rustiron-observe-local.timer`) runs that command about once a minute so `/host/metrics` keeps samples even when `lab:pull` is not running.
