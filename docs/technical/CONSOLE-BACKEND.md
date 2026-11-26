# Console backend adapter and D-090 security boundary (CP04 / P14 / P15 / P29)

Updated: 2026-11-26, America/Toronto.
Decisions: [D-090](../decisions/D-090-cp04-v1-scope.md).
Roadmap: [CP04](../planning/ROADMAP.md#cp04--console-and-api), [P14](../planning/ROADMAP.md#p14--deliver-a-local-read-only-rustiron-console), [P15](../planning/ROADMAP.md#p15--add-reviewed-console-approval-and-write-workflows), [P29](../planning/ROADMAP.md#p29--consolidate-the-developer-hosting-platform-experience).

This contract specifies how the Rustiron Console (`console/`) connects to the local host backend without weakening executor authority or key custody.

## 1. Two-tier backend wiring model

| Tier | Roadmap slice | Authority | Transport & custody |
| --- | --- | --- | --- |
| **Read-only live wiring (v1.0 default)** | **P29 Slice 4** (CP04 / P14, W612–W651) | **Read-only.** Zero mutation methods, zero signing keys. | Loopback-only Bun HTTP server (`127.0.0.1:4319`) behind SSH local forward or explicit HTTPS reverse proxy (`RUSTIRON_CONSOLE_ORIGIN`); reads `RUSTIRON_OBSERVATION` (`O_NOFOLLOW`) and queries `RUSTIRON_COORDINATOR_SOCKET` using [READ-PROTOCOL.md](READ-PROTOCOL.md) v1 length-prefixed framing. |
| **Reviewed approval & write wiring (post-v1.0 opt-in)** | **P29 Slice 5** (P15, W613–W651) | **Separate-custody signed apply.** Server and browser NEVER hold signing keys and NEVER mint grants. | Explicitly enabled via `RUSTIRON_CONSOLE_WRITE_WORKFLOWS=1`; previews framed `plan_digest`, D-098 global OLS impact, and expiry for offline PC SSHSIG signing, verifies detached `grant.json.sig`, and submits byte-exact `plan_apply` frames over `RUSTIRON_COORDINATOR_SOCKET`. |

## 2. D-090 loopback browser security boundary (enforced in `console/src/backend-server.ts` & `console/src/server.ts`)

Every HTTP endpoint on the Console listener — including production HTML SPA pages and static chunks served via `createProdDistHandler` — MUST enforce all six D-090 checks:

1. **`Host` allowlist (anti-DNS-rebinding):** Accept only `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`, and (when explicitly configured) the exact `host` of `RUSTIRON_CONSOLE_ORIGIN`. Reject any other `Host` with `421 Misdirected Request` (`{"error":"HOST_NOT_ALLOWED"}`) and zero data.
2. **Zero CORS:** Never emit `Access-Control-Allow-Origin` or `Access-Control-Allow-Credentials`. Reject any cross-origin `Origin` header (`!= http://<allowed-host>` and `!= https://<allowed-host>`) with `403 Forbidden` (`{"error":"CROSS_ORIGIN_FORBIDDEN"}`).
3. **Method enforcement:** Read-only routes accept only `GET` and `HEAD`. Any `POST`, `PUT`, `PATCH`, `DELETE`, or `OPTIONS` returns `405 Method Not Allowed` with `Allow: GET, HEAD`.
4. **Strict Content Security Policy & framing headers (HTML, assets, and API):**
   - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Referrer-Policy: no-referrer`
   - `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`
   - `Cross-Origin-Opener-Policy: same-origin`
   - `Cross-Origin-Resource-Policy: same-origin`
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains` (when `RUSTIRON_CONSOLE_ORIGIN` uses `https://`)
   - `Cache-Control: no-store` (immutable hashed `/chunk-*` assets retain `public, max-age=31536000, immutable`)
5. **Bounded error responses without data:** All 4xx/5xx responses return fixed machine error codes without filesystem paths, stack traces, or secret values.
6. **Direct Unix-socket IPC verification (`console/src/coordinator-client.ts`):** Matches `crates/contracts/src/local.rs` with canonical path, mode `0700` parent, and mode `0600` socket owned by the same non-root UID. Framing uses 4-byte big-endian lengths (`<= 262,144` B request, `<= 1,048,576` B response), exact EOF, `request_id` correlation, and a `5,000 ms` deadline.

## 3. Read-only & account backend HTTP routes

| Route | Backend source | Notes |
| --- | --- | --- |
| `GET /api/accounts/status`, `POST /api/accounts/setup`, `/api/auth/*`, `/api/accounts/users*` | `auth-backend.ts` (Better Auth + `bun:sqlite`) | Full-screen auth lockdown when initialized or `RUSTIRON_CONSOLE_AUTH_REQUIRED=1`; `useSecureCookies` on HTTPS; `429` rate limits on both sign-in and setup-token failures; case-insensitive `/sign-up` `403`; `32 KiB` body cap; transactional role/delete with session revocation on downgrade. |
| `GET /api/observation` | `RUSTIRON_OBSERVATION` (`O_NOFOLLOW`) | Max `4 MiB`; bounded refusal on oversized/unreadable file. |
| `GET /api/backend/status` | Local config + `coordinatorDoctor()` | Unauthenticated requests return capability flags only (`publicStatus`); authenticated requests include live `doctor`. |
| `GET /api/host/logs` | `logs-backend.ts` (`journalctl`) | Closed 10-service unit allowlist (`executor`, `coordinator`, `admin`, `console`, `ols`, `mariadb`, `pdns`, `postfix`, `dovecot`, `sitecron`), `10..200` lines, `128 KiB` cap, secret redaction, exit-0 `stderr` permission-hint detection (`SupplementaryGroups=systemd-journal`). |
| `GET /api/coordinator/live`, `/doctor`, `/sites`, `/sites/:siteId`, `/operations/:operationId`, `/evidence/:operationId` | Coordinator IPC | Authenticated only; validates opaque ID (`^[A-Za-z0-9_-]{1,64}$`), integer `limit` (`1..=100`), and bounded `cursor` before opening socket. |

## 4. P15 opt-in separate-custody write routes (P29 Slice 5, `console/src/write-backend.ts`)

Write endpoints remain **disabled by default** (`405 WRITE_WORKFLOWS_DISABLED`, `Allow: GET, HEAD`) unless `RUSTIRON_CONSOLE_WRITE_WORKFLOWS=1` is explicitly set.

| Route | Method | Security boundary & behavior |
| --- | --- | --- |
| `/api/write/session` | `GET` | D-090 `Host` + zero-CORS check; returns ephemeral per-boot 32-byte hex `csrf_token` only when enabled (`null` when disabled) and `custody: "external_sshsig_only"`. |
| `/api/write/plan/review` | `POST` | Enforces `Host` (`421`), mandatory exact same-origin `Origin` (`http://` or `https://` matching allowed `Host`, `403`), `Sec-Fetch-Site: same-origin` (`403`), `Content-Type: application/json` (`415`), constant-time `X-Rustiron-Csrf` (`403`), and `<= 262,144` B (`413`). Strips ASCII control and Unicode Bidi override characters in display fields and returns canonical digest, grant binding check, expiry check, D-098 global OLS impact flag, and offline `ssh-keygen -Y sign` command. |
| `/api/write/plan/apply` | `POST` | Enforces all 6 P15 guards plus opaque ID validation (`400 INVALID_ID`), framed digest match (`400 DIGEST_MISMATCH`), non-expired grant window (`409 STALE_GRANT`), and SSHSIG armor (`400 INVALID_SIGNATURE`) BEFORE touching `RUSTIRON_COORDINATOR_SOCKET`. Preserves raw `plan.json` and `grant.json` bytes verbatim in `plan_apply` and returns truthful `executor_reply`, `not_sent`, or `outcome_unknown` (never reports disconnects/timeouts as success). |
