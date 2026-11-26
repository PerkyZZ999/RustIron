# Runbook 38 — Rustiron Console Deployment & Hardening

**Status:** Experimental pre-release software (2026-11-26). Production readiness is **not** reached: independent human security review (P10), human screen-reader accessibility testing (D-040), focused P15 UI review, and explicit P16 remote-exposure sign-off remain open before internet-facing or production VPS deployment.

**Scope:** Deploying and hardening the Rustiron Console Admin Panel (`console/`) in strict zero-mock live mode with Better Auth accounts, full-screen auth lockdown, coordinator Unix-socket integration, live journald Server Logs, opt-in Console-local mailbox catalog, and secure remote access.

## 1. Security Model

- The Console listens on **loopback only** (`127.0.0.1:4319`), enforces a strict `Host` allowlist (`421`) across both API and production HTML/asset routes (`dist/`), forbids CORS (`403`), enforces same-origin checks on all mutating routes (`403`), bounds JSON and auth payloads (`415` / `413` at `32 KiB`), and sets strict CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, and `Strict-Transport-Security` (when `RUSTIRON_CONSOLE_ORIGIN` uses `https://`).
- **Better Auth** (`better-auth@1.7.28` + `bun:sqlite`) manages Console accounts (`Admin`, `Operator`, `Viewer`) with a full-screen standalone authentication gate when signed out (zero sidebar, topbar, or background polling), `HttpOnly; SameSite=Strict` cookies (`useSecureCookies: true` on HTTPS origins), a `0600` persisted signing secret, unconditional `429` rate limiting on both sign-in and setup-token attempts, permanently blocked public signup (`403 SIGNUP_DISABLED`, case-insensitive), and transactional user mutations with immediate session revocation on role downgrade.
- **Read-only by default (D-090):** Both separate-custody signed plan submission (`RUSTIRON_CONSOLE_WRITE_WORKFLOWS`) and Console-local mailbox catalog mutations (`RUSTIRON_CONSOLE_MAIL_WRITES`) are disabled (`405`) unless explicitly opted in.
- **Systemd service hardening & Server Logs:** The generated `rustiron-console.service` unit (`packaging/rustiron-install-wizard.py`) runs unprivileged with `SupplementaryGroups=systemd-journal` (for read-only allowlisted `/api/host/logs` journald inspection), `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`, `LockPersonality=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, and `ReadWritePaths=/var/lib/rustiron-console`.
- **Separate signing custody stays intact:** Console login sessions control access to the web panel and RBAC permissions; privileged host mutations still require offline SSHSIG grants signed outside the browser and Console server (D-005 / D-090).

## 2. Environment Variables

| Variable | Purpose | Recommended hardened value |
| --- | --- | --- |
| `NODE_ENV` | Enables `Secure` cookies and production auth behavior | `production` (automatic via `bun run start:live`) |
| `RUSTIRON_CONSOLE_NO_FIXTURE` | Refuses fixture fallback (`503` if no live source) | `1` (automatic via `bun run start:live`) |
| `RUSTIRON_OBSERVATION` | Path to `observe-local` merged JSON observation (opened with `O_NOFOLLOW`) | `/home/rustiron-build/rustiron-observe/observation.json` |
| `RUSTIRON_COORDINATOR_SOCKET` | Path to local `rustiron-control` Unix socket | `/run/rustiron/coordinator.sock` |
| `RUSTIRON_CONSOLE_AUTH_DB` | Path to Better Auth SQLite database (`0600`) | `/var/lib/rustiron-console/auth.sqlite` |
| `RUSTIRON_CONSOLE_SETUP_TOKEN` | Out-of-band bootstrap secret required on `POST /api/accounts/setup` to prevent local first-run takeover | Random 24-byte hex token (unset after first Admin is created) |
| `RUSTIRON_CONSOLE_MAIL_DB` | Path to Console-local mailbox catalog SQLite database (`0600`) | `/var/lib/rustiron-console/mail.sqlite` |
| `RUSTIRON_CONSOLE_MAIL_WRITES` | Opt-in write access for Console-local `/api/mail/*` catalog edits | Omit or `0` (disabled `405` by default under D-090); `1` to opt in |
| `RUSTIRON_CONSOLE_WRITE_WORKFLOWS` | Opt-in separate-custody signed `plan_apply` endpoint | Omit or `0` (strict read-only default); `1` to opt in |
| `RUSTIRON_CONSOLE_ORIGIN` | Allowed HTTPS origin when behind a TLS reverse proxy | `https://panel.example.com` |
| `RUSTIRON_CONSOLE_PORT` | Loopback listen port | `4319` |

## 3. First-Run Admin Account Setup

1. Generate an out-of-band bootstrap token and start the Console in strict live mode:
   ```sh
   SETUP_TOKEN="$(openssl rand -hex 24)"
   printf 'One-time setup token: %s\n' "$SETUP_TOKEN"
   RUSTIRON_OBSERVATION=/home/rustiron-build/rustiron-observe/observation.json \
   RUSTIRON_COORDINATOR_SOCKET=/run/rustiron/coordinator.sock \
   RUSTIRON_CONSOLE_AUTH_DB=/var/lib/rustiron-console/auth.sqlite \
   RUSTIRON_CONSOLE_MAIL_DB=/var/lib/rustiron-console/mail.sqlite \
   RUSTIRON_CONSOLE_SETUP_TOKEN="$SETUP_TOKEN" \
     bun run --cwd console start:live
   ```
   Until the first Admin exists, privileged data endpoints fail closed (`401 SETUP_REQUIRED`), unauthenticated `/api/backend/status` exposes only capability booleans, and public signup (`POST /api/auth/sign-up/email`) is permanently blocked (`403 SIGNUP_DISABLED`).
2. Open `/login` or `/users` over your SSH tunnel or private overlay, supply the setup token if configured, and create the first **Admin** account (minimum 10-character password). First-run setup is serialized to prevent concurrent two-admin races.
3. Once the first Admin exists, repeat setup (`POST /api/accounts/setup`) returns `409`, all Console data endpoints require an authenticated session (`401`), and `RUSTIRON_CONSOLE_SETUP_TOKEN` may be removed from the service environment.

## 4. Secure Remote Access Options (P16)

1. **SSH Local Port Forward (zero public exposure — recommended baseline):**
   ```sh
   ssh -N -L 4319:127.0.0.1:4319 operator@your-vps.example.com
   ```
   Then browse to `http://127.0.0.1:4319/`.
2. **Tailscale / WireGuard Private Overlay:**
   Bind a local TLS proxy on the private overlay interface forwarding to `127.0.0.1:4319` with `RUSTIRON_CONSOLE_ORIGIN` set to the overlay hostname.
3. **Public HTTPS Reverse Proxy (requires explicit exposure decision under P16):**
   Terminate TLS 1.3 at a hardened reverse proxy (with mTLS or VPN IP allowlist recommended), pass `Host: 127.0.0.1:4319`, and set `RUSTIRON_CONSOLE_ORIGIN=https://panel.example.com`. Never expose raw port `4319` directly to the internet.

## 5. Console-Local Mailbox Catalog & Host Sync Boundary (D-093)

- The **Email** (`/mail`) mailbox and alias store is a **Console-local SQLite catalog** (`sync_state: "pending_host_sync"`). It does **not** directly modify host Postfix/Dovecot configurations or activate live IMAPS/Submission authentication.
- By default (`RUSTIRON_CONSOLE_MAIL_WRITES` unset or `0`), all `/api/mail/*` write routes return `405 MAIL_WRITES_DISABLED` to preserve the D-090 read-only default.
- When opted in (`RUSTIRON_CONSOLE_MAIL_WRITES=1`):
  1. Create and manage domains, mailboxes, quotas, and forwarders under **Email** (`/mail`).
  2. Click **Export Postfix / Dovecot maps** (`GET /api/mail/export`) to download `rustiron-postfix-dovecot-bundle.json` containing virtual domain, virtual mailbox, alias, and Dovecot Maildir quota mappings. Password hashes are intentionally omitted from the HTTP export.
  3. Applying virtual maps, provisioning Dovecot `passdb`/`userdb` credentials, reloading `postfix` + `dovecot`, opening `993/tcp` (IMAPS) and `587/tcp` (Submission) in firewalld, and publishing MX/SPF/DKIM/DMARC records remain explicit host-side operator procedures.

## 6. SQLite Durability, Schema Versioning & Online Backup

- Both `auth.sqlite` (`console/src/auth-backend.ts`) and `mail.sqlite` (`console/src/mail-backend.ts`) open with `PRAGMA journal_mode = WAL`, `PRAGMA synchronous = FULL`, `PRAGMA foreign_keys = ON`, `PRAGMA busy_timeout = 5000`, and `0600` file permissions.
- Startup enforces a fail-closed `PRAGMA user_version` check (`1`): opening a database created by a newer Console schema fails closed rather than silently mutating or downgrading tables.
- **Online backup (safe while the Console is running; never copy raw `.sqlite` files alone while WAL is active):**
  ```sh
  BACKUP_DIR="/var/backups/rustiron-console/$(date -u +%Y%m%dT%H%M%SZ)"
  install -d -m 0700 "$BACKUP_DIR"
  sqlite3 /var/lib/rustiron-console/auth.sqlite ".backup '$BACKUP_DIR/auth.sqlite'"
  sqlite3 /var/lib/rustiron-console/mail.sqlite ".backup '$BACKUP_DIR/mail.sqlite'"
  install -m 0600 /var/lib/rustiron-console/auth.sqlite.secret "$BACKUP_DIR/auth.sqlite.secret"
  sqlite3 "$BACKUP_DIR/auth.sqlite" "PRAGMA integrity_check;"
  sqlite3 "$BACKUP_DIR/mail.sqlite" "PRAGMA integrity_check;"
  ```
- **Restore procedure:**
  1. Stop the Console service so no process holds open handles or stale `-wal`/`-shm` sidecars.
  2. Remove `/var/lib/rustiron-console/{auth,mail}.sqlite-{wal,shm}` if present.
  3. Restore `auth.sqlite`, `auth.sqlite.secret`, and `mail.sqlite` with `0600` permissions, then start the Console and verify `GET /api/accounts/status` and `/api/mail/state`.
