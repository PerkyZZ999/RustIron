# Deploy and operate a modern Node.js or Bun app

Use a P27 modern app site to run one Node.js (`node_22_v1`) or Bun (`bun_1_v1`) application behind OpenLiteSpeed (OLS). Rustiron creates the site account, resource limits, confined systemd unit(s), and loopback proxy vhost. Build dependencies outside the managed host (on a build host or operator PC) and stage only the verified prebuilt release archive. [D-099](../decisions/D-099-modern-app-hosting.md) and [MODERN-APPS](../technical/MODERN-APPS.md) define the full contract.

## Runtime prerequisites

Confirm the pinned runtime binary is installed on the host as a root-owned, non-world-writable executable:

| Profile | Pinned path | Host source |
| --- | --- | --- |
| `node_22_v1` | `/usr/bin/node` (symlink inside `/usr/bin` to `/usr/bin/node-22` allowed) | AlmaLinux 10 AppStream `nodejs` (`>= 22.23.4` LTS with SQLite FTS5) |
| `bun_1_v1` | `/usr/local/bin/bun` | Pinned Bun 1.x release binary verified by SHA-256 |

No package manager (`npm`, `pnpm`, `bun install`) or user install script ever runs as root on the managed host.

## Full-stack apps behind Caddy (`v0.1.1`)

`v0.1.1` adds schema 2 apps under [D-102](../decisions/D-102-caddy-fullstack-and-postgres18.md): four topologies (`static_spa`, `backend_api`, `fullstack_split`, `fullstack_dual_ssr`), Caddy edge ingress with HTTP/3, blue/green cutover, and a selectable database (`none`, `sqlite`, `mariadb`, `postgresql_18`). The [lab proof](../validation/S10-W662/README.md) lists what was tested on a disposable AlmaLinux 10.3 host and what was not.

1. **Caddy.** Install `caddy` (`>= 2.10.0`) as root-owned `/usr/local/bin/caddy` (mode `0755`, one link). Enroll its SHA-256 with `--caddy-binary-sha256` and pick the ingress mode with the installation wizard. Caddy runs as `rustiron-caddy` in `rustiron_caddy_t`. Its admin API listens only on `/run/rustiron-caddy/admin.sock`; port `2019` never listens. `rustiron-acme` stays the only certificate issuer.
2. **PostgreSQL 18.** For `postgresql_18` apps, run the wizard step `postgresql_18_setup`. It verifies the pinned PGDG key, installs `postgresql18-server` `>= 18.7`, relabels `/usr/pgsql-18/bin` so the server runs as `postgresql_t`, and installs the loopback and SCRAM-SHA-256 templates. Check with `ps -eZ | grep postgres` (expect `postgresql_t`) and `ss -ltn 'sport = :5432'` (expect `127.0.0.1` only).
3. **Ports.** A confined app can bind only `unreserved_port_t` ports: TCP 1024–32767 and 61000–65535, except the ports the policy gives their own type. Common framework defaults are among them: `3000`/`3001` (Express, Next.js), `4200` (Angular), `4321` (Astro), `5000`, `8000`, `8080`, and `9000`. The 32768–60999 range is `ephemeral_port_t`. `rustiron plan create app-provision` and the executor refuse such ports (`APP_PORT_NOT_UNRESERVED`, naming the type), and the Console warns about the common ones. Ports such as `3402`, `4000`, `5173`, or `20000`–`29999` are free on AlmaLinux 10.3 unless something else listens there ([W664](../validation/S10-W664/README.md)).
4. **Package off-host.** Build the app on a build host, then pack the build output deterministically:
   ```sh
   python3 packaging/rustiron-app-pack.py presets
   python3 packaging/rustiron-app-pack.py pack --preset vite-elysia --site-id <site_id> --release-id <release_id> --frontend-dist ./web/dist --backend-dist ./api/dist --out ./release
   ```
   The packager refuses symlinks, special files, setuid or setgid bits, unsafe paths, and `.env` files. It writes `bundle.tar.gz`, `manifest.sha256`, and `release-meta.json`, which holds the intake copy command and the exact `rustiron plan create app-deploy` arguments.
5. **Deploy.** Stage, sign, and submit as in [Stage and deploy a prebuilt release](#stage-and-deploy-a-prebuilt-release). With `--blue-green-cutover`, the executor starts the standby slot, probes its health, and reloads Caddy onto it without a restart.
6. **Database backups.** Captures of `postgresql_18` apps hold a `pg_dump` custom-format dump. Restores and pre-migration rollbacks replay it as the site role (password from `private/app.env`), never as the `postgres` superuser.

## Provision the app site

1. Choose a free site ID, hostname, loopback port (`1024–65535`, excluding 3306, SSH, OLS, and active proxy/app ports), HTTP routes (must include `/`), optional WebSocket prefixes, relative release entrypoint, optional companion worker entrypoint, health check path, sorted uppercase environment variable key names (`env_keys` — names only, never values), and cgroup/disk limits (`memory_max_mib`, `tasks_max`, `quota_mib`).
2. Generate the canonical `app_provision` plan offline with `rustiron plan create app-provision ...`.
3. Inspect the plan and D-098 blast-radius envelope before signing:
   ```sh
   rustiron-plan inspect plan.json
   rustiron-plan envelope plan.json
   ```
   Confirm `runs_package_scripts: false`, `traffic_activation: false`, exact port, routes, WebSockets, limits, and `env_keys`.
4. Sign the grant with the host's enrolled signing authority and submit through the coordinator (`rustiron plan apply-file`). Wait for `succeeded`.
5. Provision creates `rs_<site_id>`, `/srv/sites/rs_<site_id>/{releases,data,private,tmp,html,acme}`, an empty `0400` `private/app.env`, and `10-rustiron-app.conf` drop-ins under `/etc/systemd/system/rustiron-app@rs_<site_id>.service.d/` (and `rustiron-app-worker@` when a worker entrypoint is configured). No database or PHP unit is created.

## Populate scoped runtime secrets

Write required `KEY=VALUE` lines into `/srv/sites/rs_<site_id>/private/app.env` directly on the host as root, owned by `rs_<site_id>:rs_<site_id>` with mode `0400`:

```sh
install -o rs_<site_id> -g rs_<site_id> -m 0400 /dev/stdin /srv/sites/rs_<site_id>/private/app.env
```

Never place secret values in plans, grants, CLI arguments, logs, or evidence. The app runtime loads `private/app.env` inside the site account's own process (`--env-file-if-exists=` for Node 22, `--env-file=` for Bun 1).

## Stage and deploy a prebuilt release

1. Build the release off-host, package the release tree into `bundle.tar.gz` (regular files only — no symlinks, traversal, or setuid/setgid bits), and write a sorted per-file SHA-256 manifest `manifest.sha256` (`<64-hex>  <relative-path>`).
2. Stage `bundle.tar.gz` and `manifest.sha256` into the root-only intake directory:
   ```sh
   /var/lib/rustiron/app-intake/<site_id>/<release_id>/bundle.tar.gz
   /var/lib/rustiron/app-intake/<site_id>/<release_id>/manifest.sha256
   ```
   Keep permissions `0700` / `0600` (`root:root`) and run `restorecon -R /var/lib/rustiron/app-intake`.
3. Build the `app_deploy` plan with `rustiron plan create app-deploy ...` naming the exact `release_id`, `artifact_sha256`, `manifest_sha256`, `file_count`, `total_bytes`, and `health_path`. When setting `--migration-entrypoint`, you must also bind a recent (`<= 24 h`) `capture_operation_id`.
4. Review with `rustiron-plan inspect plan.json`, sign, and submit.
5. The executor and admin helper:
   - Verify intake SHA-256 digests, manifest entries, and `0400` `private/app.env` key presence before committing intent.
   - Unpack `bundle.tar.gz` inside a confined `PrivateNetwork=yes` transient unit as `rs_<site_id>`, verify every unpacked file's SHA-256 and total byte count, and mark `releases/<release_id>` read-only (`chmod -R a-w`).
   - Run any optional migration in a confined `PrivateNetwork=yes` unit after copying SQLite files in `data/` to a pre-migration snapshot.
   - Atomically switch `current -> releases/<release_id>`, enable and restart `rustiron-app@rs_<site_id>.service` (and companion worker), and probe `http://127.0.0.1:<port><health_path>` from a confined loopback-only transient unit.
   - On health or migration failure, automatically restore `current` (and pre-migration SQLite files), restart the previous release, verify previous health, and return `failed_compensated` (`rolled_back`).

## Serve through OLS and verify

1. Activate traffic with a separate signed `config_activate` plan that includes the new app site and every site that should stay online (see [page 25, step 2](25-DELETE-LIVE-SITE.md#step-2-take-the-site-offline)).
2. Check `/rustiron-site.txt` and application HTTP/WebSocket routes through OLS, plus neighboring sites.
3. Inspect logs with `journalctl -u rustiron-app@rs_<site_id>.service` (and `rustiron-app-worker@rs_<site_id>.service`).
4. Run read-only diagnosis:
   ```sh
   /usr/libexec/rustiron/rustiron-control --merge-observation FILE --diagnose --human
   ```
   Check both the `app` unit finding (active with verified systemd filesystem, loopback network, and `rustiron_app_t:s0:c<N>` SELinux MCS confinement) and the `proxy` loopback listener finding for the app's port.

## Start, stop, or restart an app

Use a signed `app_lifecycle` plan (`rustiron plan create app-lifecycle --action start|stop|restart ...`). `app_lifecycle` changes only the site's app unit (and companion worker) without reloading OLS or modifying files. Stopping an active app causes OLS to return HTTP `503` and `rustiron-control --diagnose` to report `warn` on both the `app` unit and `proxy` loopback port until started again.

## Take offline and delete

1. Submit a signed `config_activate` plan omitting the app site (retaining all other served sites) and confirm `/rustiron-site.txt` returns `404`.
2. Submit a signed `site_delete` plan:
   - Schema 2 (`--no-capture`) if no release was ever deployed (`active_release_id` is absent).
   - Schema 1 (`--capture-op <id>`) with a fresh (`<= 24 h`) capture when a release has been deployed, or after taking a safety capture.
3. Deletion disables and stops `rustiron-app@` and `rustiron-app-worker@`, removes drop-ins, SELinux fcontexts, site root, TLS folder, account, group, and quota, and frees the app's loopback port for future sites while reserving the site ID and hostname.
