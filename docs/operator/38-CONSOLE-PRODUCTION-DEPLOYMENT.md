# Runbook 38 — Rustiron Console Deployment & Hardening

**Status:** Experimental pre-release software (2026-11-27).
The Console is **not** ready for production.
These items stay open before an internet-facing or production VPS deployment:

- independent human security review (P10);
- human screen-reader accessibility testing (D-040);
- focused P15 UI review;
- explicit P16 remote-exposure sign-off.

**Scope:** This runbook deploys and hardens the Rustiron Console Admin Panel (`console/`) in strict zero-mock live mode.
It covers Better Auth accounts, the full-screen sign-in gate, the coordinator Unix socket, live journald Server Logs, the opt-in Console-local mailbox catalog, and remote access.

## 1. Security Model

- **Listener and request guards.**
  - The Console listens on **loopback only** (`127.0.0.1:4319`).
  - A strict `Host` allowlist (`421`) covers the API and the production HTML and asset routes (`dist/`).
  - The Console refuses CORS (`403`) and checks the same origin on every mutating route (`403`).
  - JSON and auth bodies have a content-type check and a `32 KiB` limit (`415` / `413`). The server refuses any request body over `1 MiB`.
  - Each JSON route parses its body with one strict schema. An unknown or mistyped field gets `400` ([W681](../validation/S10-W681/README.md)).
- **Security headers.** The Console sets a strict CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, and `Cross-Origin-Resource-Policy`. It adds `Strict-Transport-Security` when `RUSTIRON_CONSOLE_ORIGIN` uses `https://`.
- **Assets.** The production build contains React's production runtime only, and the build fails if the development runtime is present. Hashed JS and CSS chunks are served gzip-compressed to a client that accepts gzip ([W683](../validation/S10-W683/README.md)).
- **Better Auth** (`better-auth@1.7.28` + `bun:sqlite`) manages Console accounts (`Admin`, `Operator`, `Viewer`).
  - Signed out, the Console shows only a full-screen sign-in gate: no sidebar, no top bar, no background polling.
  - Cookies are `HttpOnly; SameSite=Strict`, with `useSecureCookies: true` on HTTPS origins.
  - The Better Auth endpoints that return or take a raw session token (`/get-session`, `/list-sessions`, `/revoke-session`) answer `404` ([W755](../validation/S10-W755/README.md)).
  - The signing secret is persisted with mode `0600`.
  - A session expires after 12 hours without use ([W678](../validation/S10-W678/README.md)).
  - Sign-in has three limits ([W694](../validation/S10-W694/README.md)). None of them locks the owner out:
    - **Per address:** 5 failures in 1 minute get `429` with `Retry-After`, and Better Auth adds its own 3 sign-ins per 10 seconds. Behind Caddy, the address is the last `X-Forwarded-For` entry, trusted only from a loopback peer.
    - **Per account:** each failure in the last 15 minutes delays the next attempt, from 250 ms up to 8 s. The account is never locked.
    - **Global:** 100 failures in 1 minute pause sign-in, except over the SSH tunnel (a loopback peer with no forwarded header).
  - Admin accounts need a second factor (TOTP) at each sign-in; see [Second factor](#second-factor).
  - Setup-token attempts have their own `429` limit.
  - Public signup is always blocked (`403 SIGNUP_DISABLED`, case-insensitive).
  - User changes are transactional, and a role downgrade revokes sessions at once.
- **Read-only by default (D-090).** Separate-custody signed plan submission (`RUSTIRON_CONSOLE_WRITE_WORKFLOWS`) and Console-local mailbox catalog changes (`RUSTIRON_CONSOLE_MAIL_WRITES`) are disabled (`405`) until you opt in.
- **Systemd service hardening and Server Logs.** The generated `rustiron-console.service` unit (`packaging/rustiron-install-wizard.py`) runs unprivileged as `rustiron-coordinator` with these settings ([W733](../validation/S10-W733/README.md)):
  - `User=rustiron-coordinator`: the coordinator socket accepts only its own UID, as for its other clients.
    The unit does not add `rustiron-requesters`, but `User=` loads the coordinator user's membership in that group.
    So the Console has the coordinator's access, and it can also reach the executor socket ([W758](../validation/S10-W758/README.md)).
    The executor admits only the enrolled `requester_uid` and verifies the offline-signed grant, scope, and replay of each change itself;
  - `SupplementaryGroups=systemd-journal`, for read-only allowlisted `/api/host/logs` journald inspection;
  - `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`;
  - `LockPersonality=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`;
  - `StateDirectory=rustiron-console` (`0700`). On the first start, systemd moves an older `rustiron-build` folder to the new owner.
- **Observation feed.** `rustiron-console-observe.timer` runs `/usr/local/libexec/rustiron-console/rustiron-console-observe` every 30 s. Root reads the executor journal; `rustiron-coordinator` merges host status and one resource sample into `/var/lib/rustiron-console/observe/observation.json`.
- **Separate signing custody stays intact.** Console sessions control access to the web panel and its role permissions. A privileged host change still needs an offline SSHSIG grant, signed outside the browser and the Console server (D-005 / D-090).

## 2. Environment Variables

| Variable | Purpose | Recommended hardened value |
| --- | --- | --- |
| `NODE_ENV` | Enables `Secure` cookies and production auth behavior | `production` (automatic via `bun run start:live`) |
| `RUSTIRON_CONSOLE_NO_FIXTURE` | Refuses fixture fallback (`503` if no live source) | `1` (automatic via `bun run start:live`) |
| `RUSTIRON_OBSERVATION` | Path to the merged JSON observation that `rustiron-console-observe.timer` writes (opened with `O_NOFOLLOW`) | `/var/lib/rustiron-console/observe/observation.json` |
| `RUSTIRON_COORDINATOR_SOCKET` | Path to the coordinator control socket (accepts only the `rustiron-coordinator` UID) | `/run/rustiron-coordinator/control.sock` |
| `RUSTIRON_CONSOLE_AUTH_DB` | Path to Better Auth SQLite database (`0600`) | `/var/lib/rustiron-console/auth.sqlite` |
| `RUSTIRON_CONSOLE_SETUP_TOKEN` | Out-of-band bootstrap secret that `POST /api/accounts/setup` requires, so a local user cannot take over the first run | Random 24-byte hex token; unset it after you create the first Admin. With `NODE_ENV=production` and no token set, the Console writes a one-time token to `<RUSTIRON_CONSOLE_AUTH_DB>.setup-token` (`0600`), logs only that path, and removes the file when the first Admin exists ([W663](../validation/S10-W663/README.md)). The Console refuses `RUSTIRON_CONSOLE_AUTH_DISABLED=1` in production |
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
   RUSTIRON_OBSERVATION=/var/lib/rustiron-console/observe/observation.json \
   RUSTIRON_COORDINATOR_SOCKET=/run/rustiron-coordinator/control.sock \
   RUSTIRON_CONSOLE_AUTH_DB=/var/lib/rustiron-console/auth.sqlite \
   RUSTIRON_CONSOLE_MAIL_DB=/var/lib/rustiron-console/mail.sqlite \
   RUSTIRON_CONSOLE_SETUP_TOKEN="$SETUP_TOKEN" \
     bun run --cwd console start:live
   ```
   Until the first Admin exists:
   - privileged data endpoints fail closed (`401 SETUP_REQUIRED`);
   - unauthenticated `/api/backend/status` shows only capability booleans;
   - public signup (`POST /api/auth/sign-up/email`) stays blocked (`403 SIGNUP_DISABLED`).
2. Open `/login` or `/users` over your SSH tunnel or private overlay.
3. Enter the setup token: yours, or the contents of the generated file.
4. Create the first **Admin** account with a password of 10 characters or more.
   The Console serializes first-run setup, so two concurrent requests cannot both create an Admin.

When the first Admin exists:

- a repeated setup (`POST /api/accounts/setup`) returns `409`;
- every Console data endpoint requires a signed-in session (`401`);
- you can remove `RUSTIRON_CONSOLE_SETUP_TOKEN` from the service environment.

### Account roles

The Console reads the role of each request from its account database.
A role change applies from the next request.
Every role must sign in.

| Action | Viewer | Operator | Admin |
| --- | --- | --- | --- |
| Read observations, coordinator status, evidence, and redacted host logs | Yes | Yes | Yes |
| Read and export the mailbox catalog (no password hashes) | Yes | Yes | Yes |
| Change mailboxes and aliases (needs `RUSTIRON_CONSOLE_MAIL_WRITES=1` or `RUSTIRON_CONSOLE_WRITE_WORKFLOWS=1`) | No | Yes | Yes |
| Review and submit signed plans (needs `RUSTIRON_CONSOLE_WRITE_WORKFLOWS=1`) | No | Yes | Yes |
| Create, change, or delete Console accounts | No | No | Yes |
| Sign out your own other sessions | Yes | Yes | Yes |

- A Viewer or Operator that calls an Admin-only route gets `403 ADMIN_REQUIRED`.
- A role too low for a write route gets `403 INSUFFICIENT_ROLE`.
- You cannot demote or delete the last Admin (`409 LAST_ADMIN`).
- An Admin cannot delete their own account (`409 CANNOT_DELETE_SELF`).
- A demotion or deletion revokes the sessions of that account at once.
- A role change must name `admin`, `operator`, or `viewer`. Any other value gets `400 INVALID_ROLE`.
- The Better Auth endpoints cannot change a role: `update-user` refuses `role`, and `delete-user` and `change-email` are not enabled.
- Console roles do not sign plans. Only a plan and grant signed offline can authorize a host change.

### Second factor

Every Admin account needs a second factor: a 6-digit code from an authenticator app at each sign-in ([W727](../validation/S10-W727/README.md), [W729](../validation/S10-W729/README.md)).

- An Admin without the factor, for example the first Admin or an account from before v0.2, sees only the setup page after the password. Until the setup is done, every other request gets `403 SECOND_FACTOR_REQUIRED`.
- The setup asks for the current password, shows a QR code and a key, and turns the factor on after one correct code. It then shows ten recovery codes once. The Console stores the codes encrypted. Save them outside the server.
- Each recovery code signs in once, in place of the app code.
- The Console never remembers a browser. Every sign-in asks for a code.
- After 10 wrong codes in a row, the code check of that account stops for 15 minutes.
- Operators and Viewers may turn the factor on through the same `/api/auth/two-factor/*` endpoints. The Console does not require it of them.

#### Reset a lost second factor

Use this only when the account has lost both the authenticator app and all recovery codes.
The reset needs a shell on the host, so it is the owner's way back in, not a remote one.

1. Confirm the email address of the account.
2. Run the reset as the Console service user:
   ```sh
   sudo -u rustiron-coordinator env RUSTIRON_CONSOLE_AUTH_DB=/var/lib/rustiron-console/auth.sqlite \
     /usr/local/bin/bun run --cwd /opt/rustiron/console reset-second-factor owner@example.com
   ```
   In one transaction, the command:
   - removes the account's second factor and recovery codes;
   - clears the 15-minute code lock;
   - ends all sessions of the account.

   It changes nothing for an unknown email (exit status `1`), and it never creates a database.
3. Sign in with the password. An Admin account then sets up a new second factor and gets new recovery codes.

The Console can keep running during the reset.

## 4. Secure Remote Access Options (P16)

1. **SSH Local Port Forward (zero public exposure — recommended baseline):**
   ```sh
   ssh -N -L 4319:127.0.0.1:4319 operator@your-vps.example.com
   ```
   Then browse to `http://127.0.0.1:4319/`.
2. **Tailscale / WireGuard Private Overlay:**
   Bind a local TLS proxy on the private overlay interface that forwards to `127.0.0.1:4319`.
   Set `RUSTIRON_CONSOLE_ORIGIN` to the overlay hostname.
3. **Public HTTPS Reverse Proxy (requires explicit exposure decision under P16):**
   End TLS 1.3 at a hardened reverse proxy. mTLS or a VPN IP allowlist is recommended.
   Pass `Host: 127.0.0.1:4319` and set `RUSTIRON_CONSOLE_ORIGIN=https://panel.example.com`.

WARNING: Never expose raw port `4319` directly to the internet.

## 5. Console-Local Mailbox Catalog & Host Sync Boundary (D-093)

- The **Email** (`/mail`) mailbox and alias store is a **Console-local SQLite catalog** (`sync_state: "pending_host_sync"`).
  The catalog does **not** change host Postfix/Dovecot configurations or activate live IMAPS/Submission authentication.
- By default (`RUSTIRON_CONSOLE_MAIL_WRITES` unset or `0`), all `/api/mail/*` write routes return `405 MAIL_WRITES_DISABLED`, to keep the D-090 read-only default.
- When you opt in (`RUSTIRON_CONSOLE_MAIL_WRITES=1`):
  1. Create and manage domains, mailboxes, quotas, and forwarders under **Email** (`/mail`).
  2. Click **Export Postfix / Dovecot maps** (`GET /api/mail/export`) to download `rustiron-postfix-dovecot-bundle.json`.
     The bundle contains the virtual domain, virtual mailbox, alias, and Dovecot Maildir quota mappings. The HTTP export never contains password hashes.
  3. Do the host-side steps yourself. They stay explicit operator procedures:
     - apply the virtual maps;
     - provision the Dovecot `passdb`/`userdb` credentials;
     - reload `postfix` + `dovecot`;
     - open `993/tcp` (IMAPS) and `587/tcp` (Submission) in firewalld;
     - publish the MX/SPF/DKIM/DMARC records.

## 6. SQLite Durability, Schema Versioning & Online Backup

- Both `auth.sqlite` (`console/src/auth-backend.ts`) and `mail.sqlite` (`console/src/mail-backend.ts`) open with these settings and `0600` file permissions:
  - `PRAGMA journal_mode = WAL`;
  - `PRAGMA synchronous = FULL`;
  - `PRAGMA foreign_keys = ON`;
  - `PRAGMA busy_timeout = 5000`.
- At startup the Console checks `PRAGMA user_version` (`1`).
  A database that a newer Console schema created fails closed; the Console does not change or downgrade its tables.
- **Online backup:** safe while the Console runs.

  CAUTION: Never copy the raw `.sqlite` files alone while WAL is active.

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
  1. Stop the Console service, so no process holds open handles or stale `-wal`/`-shm` sidecars.
  2. Remove `/var/lib/rustiron-console/{auth,mail}.sqlite-{wal,shm}` if present.
  3. Restore `auth.sqlite`, `auth.sqlite.secret`, and `mail.sqlite` with `0600` permissions.
  4. Start the Console.
  5. Check that `GET /api/accounts/status` and `/api/mail/state` answer.
