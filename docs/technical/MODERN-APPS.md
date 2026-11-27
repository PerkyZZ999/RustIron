# Modern app hosting: Node.js and Bun contract (P26 / P27)

This guide is the technical contract for [D-099](../decisions/D-099-modern-app-hosting.md) ([P26](../planning/ROADMAP.md#p26--design-modern-app-hosting) and [P27](../planning/ROADMAP.md#p27--deliver-nodejs-and-bun-hosting)).
It defines options, threat controls, runtime profiles, systemd confinement, signed plans, rollback semantics, backups, logs, and delivery slices.

## Design comparison across required dimensions

| Dimension | Option A: Thin systemd + CP08 OLS proxy (Selected for v1.0) | Option B: Thin systemd + Caddy ingress (Post-v1.0 dedicated/multi-IP) | Option C: Coolify / external PaaS adapter (Rejected) |
| --- | --- | --- | --- |
| **Ingress & listeners** | Reuses verified OLS 80/443 listeners, SNI TLS, certbot HTTP-01, HTTP & WebSocket contexts ([PROXY-SITE.md](PROXY-SITE.md)). Zero port conflict with WordPress. | Requires dedicated public IP or app-only host (OLS owns 80/443 on single-IP WordPress hosts; D-056 item 3 deferred Caddy-in-front-of-OLS). | Requires its own Traefik/Caddy proxy on 80/443 plus Docker bridge networking. |
| **Isolation** | Per-app `rs_<site>` UID/GID, per-site SELinux MCS category, systemd `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, `MemoryMax`, `TasksMax`, `CPUQuota`, loopback-only `127.0.0.1:<port>`. | Identical app isolation; adds confined `rustiron-caddy` process (`CAP_NET_BIND_SERVICE` only) with immutable generated `Caddyfile`. | Root-equivalent Docker daemon + SSH root/sudo host access; weakens single-executor boundary. |
| **Build & deploy secrets** | Prebuilt off-host (operator PC / zero-secret builder). Host verifies signed archive + SHA-256 manifest and unpacks as `rs_<site>`. Runtime secrets live in `0400` `private/app.env`; signed plans name `env_keys` only. | Identical off-host build and `private/app.env` secret separation. | Pulls Git repos and runs container builds on host; mixes build/deploy authority with host control. |
| **Process & network boundaries** | `rustiron-app@<site>.service` + optional `rustiron-app-worker@<site>.service` (for companion workers such as `api.creativeserp.com`). Kernel listener table check verifies `127.0.0.1:<port>` only. | Identical process boundary; Caddy also injects `X-Forwarded-For` and `X-Forwarded-Proto`. | Manages arbitrary compose stacks, ports, and helper containers outside Rustiron's journal. |
| **Backups & restore** | Reuses P03 restic repository and site store credentials. Captures `data/` + consistent SQLite `.backup` snapshot + release metadata. `private/app.env` has an explicit operator recovery path. | Identical P03 backup and restore boundary. | Separate PaaS database/volume backup model; duplicates P03 retention authority. |
| **Logs** | `systemd-journald` per unit (`rustiron-app@<site>`, `rustiron-app-worker@<site>`), read-only bounded queries via `rustiron-control`, no root log-file parsing. | Identical app logs plus confined Caddy access/error journal. | Container log streams owned by Docker/Coolify UI. |
| **Supply chain** | Pinned `node_22_v1` (>= 22.23.4 LTS) and `bun_1_v1` binaries with SHA-256 verification; locked `package-lock.json`/`bun.lock` watched by P09 `advisory_watch.py`; zero host-side `npm`/`bun` install scripts. | Identical app supply chain plus pinned Caddy binary SHA-256. | Tracks upstream PaaS image updates, Traefik/Caddy, Postgres, Redis, and Docker daemon. |
| **Maintenance & EOL** | Tracked in `crates/control/support-matrix.json` with explicit EOL dates. Clean eject: standalone OLS proxy vhost + standalone systemd unit. | Same app EOL model plus Caddy version pin. | Unbounded PaaS upgrade lifecycle; hard to eject cleanly without re-architecting. |

## Runtime profiles and EOL policy

| Profile ID | Runtime | Minimum version | Pinning and verification | Upstream EOL | Migration path |
| --- | --- | --- | --- | --- | --- |
| `node_22_v1` | Node.js 22 LTS | `22.23.4` (required by [D-096](../decisions/D-096-emdash-node-recipe.md) with SQLite FTS5) | AlmaLinux 10 AppStream RPM or pinned official Linux x64 binary verified by SHA-256 and `node --version` | `2027-04-30` | Prepared rebuild and signed profile switch to `node_24_v1` (Node.js 24 LTS) |
| `bun_1_v1` | Bun 1.x | `1.2.x` / `1.4.3+` (matches `api.creativeserp.com` and `steamupdatetracker.xyz`) | Exact release binary SHA-256 pinned in `support-matrix.json` once approved for host install | Rolling 1.x (reviewed every 120 days with support matrix) | Prepared rebuild and signed release activation on newer pinned Bun 1.x binary |

Adding another language or runtime version requires a new reviewed profile ID and `support-matrix.json` entry; signed plans cannot specify arbitrary interpreter paths.

## Filesystem layout and confinement

An enrolled app site reuses the standard site root `/srv/sites/rs_<site_id>` ([HOST-LAYOUT.md](HOST-LAYOUT.md)) and site account `rs_<site_id>`:

```text
/srv/sites/rs_<site_id>/
├── html/                  # identity file (rustiron-site.txt) + ACME challenge webroot only
├── releases/
│   ├── <release_id>/      # unpacked as rs_<site_id>, chmod a-w (read-only after verification)
│   └── <prev_release_id>/ # retained for instant rollback
├── current -> releases/<release_id>
├── data/                  # writable persistent state (SQLite DB, uploads, app caches), owned rs_<site_id>
├── private/
│   └── app.env            # 0400 rs_<site_id>:rs_<site_id> runtime secrets (never in plans/journal/logs)
├── tmp/                   # private scratch dir (quota-accounted)
├── logs/                  # optional site-scoped non-sensitive artifacts
└── errors/                # shared site skeleton
```

### Systemd unit contract (`rustiron-app@.service`)

Each app runs under an immutable, template-driven unit instantiated by account (`%i = rs_<site_id>`, matching `rustiron-site-php@.service`), plus an optional companion worker unit `rustiron-app-worker@%i.service` when `worker_entrypoint` is declared:

- `User=%i` and `Group=%i`
- `SELinuxContext=system_u:system_r:rustiron_app_t:s0:c<N>` (generated into `10-rustiron-app.conf` for both app and worker units, plus transient `Migrate` and `restore_app_sqlite` runs; `Unpack` runs under `rustiron_unpack_t:s0:c<N>`; `{root}/data(/.*)?` carries `httpd_sys_rw_content_t:s0:c<N>`)
- `WorkingDirectory=/srv/sites/%i/current`
- `EnvironmentFile=/srv/sites/%i/private/app.env` (plus a root-owned drop-in `10-rustiron-app.conf` setting non-secret `PORT`, `HOST=127.0.0.1`, `NODE_ENV=production`, `TMPDIR=/srv/sites/%i/tmp`, `RUSTIRON_APP_DATA=/srv/sites/%i/data`, and the exact pinned `ExecStart`)
- `UMask=0027`, `NoNewPrivileges=yes`, `CapabilityBoundingSet=`, `AmbientCapabilities=`
- `PrivateTmp=yes`, `PrivateDevices=yes`, `PrivateIPC=yes`, `ProtectProc=invisible`
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `IPAddressDeny=any`, `IPAddressAllow=localhost` on `rustiron-app@.service`; `PrivateNetwork=yes` on `rustiron-app-worker@.service` (combined with `rustiron_app_t` denying outbound `name_connect` so compromised apps cannot reach sibling app ports or host loopback services)
- `ProtectSystem=strict`, `ProtectHome=yes`
- `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes`, `ProtectHostname=yes`
- `RestrictNamespaces=yes`, `RestrictSUIDSGID=yes`, `RestrictRealtime=yes`, `LockPersonality=yes`, `RemoveIPC=yes`, `SystemCallArchitectures=native`, `SystemCallFilter=@system-service`
- `MemoryDenyWriteExecute=no` (explicitly required by V8 and JavaScriptCore JIT; all other hardening stays enforced)
- `InaccessiblePaths=-/etc/rustiron -/var/lib/rustiron -/run/rustiron -/run/rustiron-admin -/run/rustiron-coordinator -/var/lib/rustiron-coordinator -/run/rustiron-sites`
- `TemporaryFileSystem=/dev/shm:mode=1777,nosuid,nodev,noexec`
- `ReadOnlyPaths=/srv/sites/%i/releases /srv/sites/%i/current`
- `ReadWritePaths=/srv/sites/%i/data /srv/sites/%i/tmp`
- `MemoryMax=<memory_max_mib>M`, `MemorySwapMax=0`, `TasksMax=<tasks_max>`, `CPUQuota=100%`, and `/srv/sites` I/O limits matching `rustiron-site-php@.service`
- `KillMode=control-group`, `Restart=on-failure`, `RestartSec=3s`
- `StandardOutput=journal`, `StandardError=journal`, `SyslogIdentifier=rustiron-app-%i`

Network policy:
- The app MUST bind only to `127.0.0.1:<port>`.
- `rustiron-control` diagnosis reuses the CP08 kernel listener-table check to verify `127.0.0.1:<port>` is listening and warn immediately if the process binds `0.0.0.0` or `[::]`.
- Because OLS proxy sites do not inject `X-Forwarded-Proto` or `X-Forwarded-For`, non-secret configuration supplies explicit origin settings (such as `EMDASH_SITE_URL=https://<hostname>`).

## Closed signed deployment contracts

All three verbs are bound by [D-098](../decisions/D-098-blast-radius-envelopes.md) blast-radius envelopes and durable authority budgets.

### 1. `app_provision` (schema 1)

Creates one isolated Node.js or Bun app site and reserves its hostname, loopback port, and CP08 proxy routes without yet switching live OLS config.

| Field | Rule |
| --- | --- |
| `site_id`, `hostname` | Same grammar as `site_provision`; hostname and site ID must be free |
| `runtime` | Closed enum: `node_22_v1` or `bun_1_v1` |
| `port` | `1024..=65535`; never `3306`, SSH port, enrolled OLS/TLS/WebAdmin ports, or another app's reserved port |
| `routes` | 1 to 8 `{prefix, port}` CP08 proxy routes (same grammar as `proxy_site_provision`; `/` required; every port must equal `port`) |
| `websockets` | 0 to 8 `{prefix, port}` CP08 WebSocket paths (every port must equal `port`) |
| `entrypoint` | Relative path inside the release bundle (no leading `/`, no `..`, no control chars or shell metacharacters, e.g. `dist/server.js` or `src/index.ts`) |
| `worker_entrypoint` | Optional relative path inside the release bundle for one companion background worker (e.g. `src/worker.ts`) |
| `health_path` | Absolute HTTP path starting with `/` (no whitespace, `?`, `#`, or `..`), probed on `127.0.0.1:<port>` during deploy |
| `env_keys` | 0 to 64 sorted unique POSIX uppercase env var names (`[A-Z_][A-Z0-9_]*`). **Names only — never values** |
| `memory_max_mib` | `64..=8192` |
| `tasks_max` | `16..=1024` |
| `quota_mib` | `128..=65536` (bounded by enrolled policy cap) |

Fixed effects: creates `rs_<site_id>`, site directories, SELinux MCS labels, `rustiron-app@<site_id>.service` drop-in, ACME webroot, and journal proxy routes.
It does **not** reload OLS (`config_activate` stays separate) and runs no package scripts.

Blast-radius envelope (D-098): `sites_touched: 1`, `ols_reload: false`, `all_site_ols_impact: false`, `network_exposure: false`, `privilege_tier: app_provision`.

### 2. `app_deploy` (schema 1)

Activates one prepared, signed release bundle for an enrolled app site with bounded health verification and automatic rollback.

| Field | Rule |
| --- | --- |
| `site_id` | Enrolled app site ID |
| `release_id` | Strict identifier `[a-z0-9][a-z0-9._-]{0,63}`, unique per site |
| `runtime` | Must match the site's enrolled runtime profile (`node_22_v1` or `bun_1_v1`) |
| `artifact_sha256` | 64 lowercase hex SHA-256 of the prepared `.tar.gz` release intake bundle |
| `manifest_sha256` | 64 lowercase hex SHA-256 of the sorted per-file SHA-256 manifest inside the release intake |
| `file_count` | `1..=50000` |
| `total_bytes` | `1..=536870912` (512 MiB cap; checked against site quota before unpack) |
| `migration_entrypoint` | Optional relative path inside the release bundle to run once as `rs_<site_id>` before cutover (e.g. EmDash core migration script) |
| `capture_operation_id` | Required when `migration_entrypoint` is set (binds a completed P03 capture from the last 24 hours for atomic rollback) |
| `health_path` | Must match the site's enrolled `health_path` (or explicit reviewed override) |

Execution steps (recorded in journal v43 `app_releases` and `app_steps`):
1. **Preflight:** Verify the active app site, free deployment slot, matching runtime, `2 * total_bytes` quota headroom, and any required `< 24 h` capture.
2. **Verify intake:** Check `artifact_sha256`, `manifest_sha256`, and `private/app.env` key presence without reading or logging secret values.
3. **Unpack (unprivileged):** Unpack as `rs_<site_id>` into `releases/<release_id>` with no escaping symlinks or special nodes. Verify the manifest, then run `chmod a-w`.
4. **Migration (optional, unprivileged):** If `migration_entrypoint` is set, snapshot `data/` SQLite files. Run the pinned script as `rs_<site_id>` with bounded limits.
5. **Activate:** Atomically switch `current` to `releases/<release_id>` and restart `rustiron-app@<site_id>.service` (and any companion worker).
6. **Health probe:** Probe `GET http://127.0.0.1:<port><health_path>` for `2xx`/`3xx` and confirm `ActiveState=active` on each unit.
7. **Automatic rollback on failure:** On migration, start, or health failure, restore `current` and any pre-migration snapshot, restart the prior release, and settle as `rolled_back`. Interrupted rollbacks wait for `app-reconcile`.

Blast-radius envelope (D-098): `sites_touched: 1`, `ols_reload: false`, `all_site_ols_impact: false`, `privilege_tier: app_deploy`.

### 3. `app_lifecycle` (schema 1)

Explicit signed `start`, `stop`, or `restart` of an enrolled app's service(s):

| Field | Rule |
| --- | --- |
| `site_id` | Enrolled app site ID |
| `action` | Closed enum: `start`, `stop`, `restart` |

Blast-radius envelope (D-098): `sites_touched: 1`, `ols_reload: false`, `all_site_ols_impact: false`, `privilege_tier: app_lifecycle`.

## Runtime-specific threat review (P27 prerequisite)

| Threat surface | Attack scenario | Control enforced by contract |
| --- | --- | --- |
| **Dependency builds & postinstall scripts** | Malicious npm/Bun `postinstall` script executes as root or steals host/other-site secrets during deploy. | Zero `npm install`/`bun install` on the host. Releases are built off-host with zero runtime secrets; host verifies signed manifest and unpacks read-only as `rs_<site_id>`. |
| **Runtime version drift / EOL** | Unpatched Node.js or Bun binary remains running past security EOL. | `support-matrix.json` tracks minimum version and EOL; `advisory_watch.py` (P09) alerts on CVEs in lockfiles and runtimes; upgrades require signed rebuild + deploy. |
| **Deployment activation & partial failure** | Broken build, crashing migration, or hung port leaves site down or half-migrated. | Atomic `current` symlink switch + bounded loopback health probe + automatic rollback of symlink and pre-migration SQLite snapshot + durable journal settlement (`app-reconcile`). |
| **Secret exposure** | API keys, DB URLs, or EmDash encryption key leak into signed plans, systemd unit files, CLI argv, or logs. | Plans sign `env_keys` names only; values live in `0400` `private/app.env`; executor verifies key presence without reading/printing values; unit files reference `EnvironmentFile=` only. |
| **Cross-site & host escape** | Compromised Node.js/Bun process reads sibling WordPress `wp-config.php`, MariaDB sockets, or executor journal. | Per-site `rs_<site_id>` UID/GID + SELinux MCS category + `ProtectSystem=strict` + `NoNewPrivileges` + `PrivateTmp` + read-only `releases/` + loopback-only listener check. |
| **Background workers & DoS** | Runaway worker spawns processes or exhausts host RAM/disk. | Hard `MemoryMax`, `TasksMax`, `CPUQuota`, `KillMode=control-group`, and filesystem quota enforced before unpack and at runtime. |
| **Header spoofing through OLS proxy** | Client sends fake `X-Forwarded-For` or `X-Forwarded-Proto` to bypass auth or poison redirect URLs. | Documented contract: apps use explicit configured origin (`EMDASH_SITE_URL`) and do not trust client `X-Forwarded-For` on Option A hosts. |

## Backup, restore, logs, and removal

- **Backup (P03 extension):** `backup_capture` saves `data/` via consistent SQLite online `.backup` plus a non-secret release descriptor. `private/app.env` stays outside app-readable exports and uses separate secret custody.
- **Restore:** `site_restore` stops the app unit, restores `data/` as `rs_<site_id>`, checks `private/app.env` key presence, restarts the app, and probes health.
- **Logs:** `rustiron-control` exposes bounded read-only unit logs (`journalctl -u rustiron-app@<site_id> --no-pager -n <limit>`) and systemd unit status (`ActiveState`, `SubState`, `NRestarts`, `MemoryCurrent`).
- **Removal:** Uses two-step D-085 removal: offline `config_activate`, then signed `site_delete` (requiring a `< 24 h` capture once deployed, or schema 2 if undeployed). Units, drop-ins, directories, labels, TLS, and account are removed while backups stay.

## Option B: Caddy ingress contract (dedicated or multi-IP hosts)

Reserved for dedicated app-only hosts or multi-IP hosts (post-v1.0 / P28) under [D-056](../decisions/D-056-web-server-per-workload.md), and expanded for `v0.1.1` under [D-102](../decisions/D-102-caddy-fullstack-and-postgres18.md) (owner-approved **A1 + B1 + C2**):

- **Identity and confinement:** Runs as unprivileged `rustiron-caddy` with `CAP_NET_BIND_SERVICE`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, and dedicated SELinux domain `rustiron_caddy_t`. The admin API listens only on the `0700` Unix socket `/run/rustiron-caddy/admin.sock` (zero port `2019` exposure), so `systemctl reload` swaps generations without a restart ([D-102 revision W662](../decisions/D-102-caddy-fullstack-and-postgres18.md#revision-2026-11-26-w662)).
- **Shared TLS custody (B1):** Keeps `rustiron-acme` / Certbot as the single TLS issuer; Caddy runs with `auto_https disable_certs` and reads `/etc/rustiron-tls/<account>/live/` read-only so `rustiron_caddy_t` requires zero outbound internet access.
- **Proxy headers:** Caddy's defaults replace any client `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` with authentic values, and every `reverse_proxy` overwrites `X-Real-IP`. The renderer adds no `header_up -…` deletions, because Caddy applies them after its own values ([W662-F1](../validation/S10-W662/README.md)).
- **Trusted generation rendering:** The executor renders an immutable `Caddyfile` from trusted journal records and validates it with `caddy validate --adapter caddyfile`. Reloads swap atomically and roll back on health failure.
- **Dual-mode port ownership (A1):** Supports `caddy_only` (app-only host), `caddy_multi_ip` (separate public IP), and `caddy_edge_over_ols` (single-IP mixed host where Caddy owns `:80/:443` and proxies WordPress domains to OLS on `127.0.0.1:8080`).
- **Schema 2 full-stack topologies & selectable databases (C2):** `app_provision` schema 2 adds `static_spa` (`runtime: static_v1`), `backend_api`, `fullstack_split` (static `frontend_dir` + `/api/*` backend), and `fullstack_dual_ssr` (SSR frontend + API backend), optional blue/green standby ports (`standby_port`, `frontend_standby_port`), Caddy SSE (`flush_interval -1`) and prefix stripping, plus selectable `database` (`none`, `sqlite`, `mariadb`, `postgresql_18` `>= 18.7`, EOL `2030-11-14`) with dedicated least-privilege SELinux sub-types (`rustiron_app_mariadb_t`, `rustiron_app_pg_t`).
- **Runtime compatibility:** Runs the exact same `rustiron-app@<site_id>.service`, release bundle, `data/`, and P03 backup formats as Option A while preserving full schema 1 compatibility.

## P27 incremental delivery slices

1. **Done ([W596](../validation/S10-W596/README.md)) — Slice 1 (Contracts and CLI):** Closed `app_provision`, `app_deploy`, and `app_lifecycle` contracts in `crates/contracts/src/approval/app.rs` with `BlastRadiusEnvelope` and `rustiron plan create`.
2. **Done ([W597](../validation/S10-W597/README.md)) — Slice 2 (Journal v43):** Added `apps`, `app_releases`, `app_release_steps`, and `app_lifecycles` with v3–v42 migration, co-inserted `proxy_routes`, port uniqueness, and capture checks.
3. **Done ([W598](../validation/S10-W598/README.md)) — Slice 3 (Executor and units):** Added `rustiron-app@.service`, `rustiron-app-worker@.service`, `crates/executor/src/app_site.rs`, admin-helper steps, `site_delete` cleanup, and app unit diagnoses.
4. **Done ([W599](../validation/S10-W599/README.md)) — Slice 4 (VM lab proof):** Proved `node_22_v1` (`v22.23.4`) and `bun_1_v1` (`1.4.2`) with workers on `w599-app`: deploy, WebSocket, confinement, rollback, upgrade, deletion, 0 AVCs. Fixed W599-F1 to F5 and added [runbook 32](../operator/32-MODERN-APPS.md). **P27 is Lab verified.**
5. **Done ([W603](../validation/S10-W603/README.md)) — P30 follow-on:** Layered pinned EmDash 1.6.0, `upgrade-emdash` rollback, and WordPress WXR + media migration on top of Slice 4.
6. **Done ([W640](../validation/S10-W640/README.md)) — Dedicated SELinux MCS `rustiron_app_t` hardening (`C-01`):** Added `packaging/selinux/rustiron_app.{te,fc}` (`mcs_constrained(rustiron_app_t)`, loopback `name_bind` only, zero `name_connect`, zero `corecmd_exec_bin`), `SELinuxContext=system_u:system_r:rustiron_app_t:s0:c<N>` in app/worker drop-ins and `Migrate`/`restore_app_sqlite` (`rustiron_unpack_t` on `Unpack`), `{root}/data(/.*)?` `httpd_sys_rw_content_t` fcontext install and `site_delete`/`site_retire` cleanup, fixed `W640-F1` (`IPAddressDeny=0.0.0.0/0 ::/0` diagnosis), and proved cross-app MCS (even with DAC relaxed to `0755`/`0644`), cross-app/host TCP, worker `PrivateNetwork=yes`, and shell/binary exec denials on disposable overlay `w640-appmac` with `0` normal raw AVCs.
