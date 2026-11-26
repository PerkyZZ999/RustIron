# Create, update, back up, and migrate an EmDash CMS site

Use this procedure to host a pinned EmDash CMS site on AlmaLinux 10 under Rustiron ([D-096](../decisions/D-096-emdash-node-recipe.md), [EMDASH](../technical/EMDASH.md)). An EmDash site runs as a confined P27 `node_22_v1` application behind a CP08 OpenLiteSpeed (OLS) proxy site, stores SQLite and local uploads strictly under `/srv/sites/rs_<site_id>/data/`, and uses the enrolled P03 restic + Object Lock store for consistent SQLite and media capture and restore.

## Prerequisites

- Host Node.js 22 LTS from AlmaLinux 10 AppStream (`nodejs >= 22.23.4` with SQLite FTS5).
- Off-host build workspace with the pinned EmDash 1.6.0 Node.js Starter (`emdash@1.6.0`, MIT `LICENSE`, lockfile) packaged with [`packaging/emdash-recipe.py`](../../packaging/emdash-recipe.py).
- Enrolled P03 backup destination and per-site store credentials for `rs_<site_id>` (needed before captures, migrating upgrades, restores, or schema 1 deletion).

## Create and serve an EmDash site

1. Build and package the prebuilt candidate off-host:
   - Pin `"emdash": "1.6.0"` exact in `package.json`, remove any scaffolded `.env` secret file (`emdash-recipe.py` refuses `.env` / `.env.*` except `.env.example`), and configure `astro.config.mjs` so SQLite (`file:${dataDir}/emdash.sqlite`), local media (`${dataDir}/uploads`), and Astro sessions (`driver: "fs-lite"`, `base: "${dataDir}/sessions"`) all point inside `/srv/sites/rs_<site_id>/data` (since `releases/` is mounted read-only under `ProtectSystem=strict`).
   - Run `npm run build` off-host, stage production dependencies with `npm ci --omit=dev --ignore-scripts`, remove `node_modules/.bin` symlinks (and optional `*.map` / `*.d.*ts` files), include the pinned MIT `LICENSE`, and package:
   ```sh
   python3 packaging/emdash-recipe.py package-release \
       --src ./emdash-prod --out ./release-1.6.0 \
       --release-id emdash-1.6.0-r1 --entrypoint dist/server/entry.mjs \
       --require-upstream-license
   ```
   Confirm `emdash_version`, `lockfile_sha256`, `license_sha256`, `artifact_sha256`, and `manifest_sha256` in `release-meta.json`.
2. Provision the app site with a signed `app_provision` plan (`runtime: node_22_v1`, HTTP route `/`, WebSocket `/_emdash/api/content/`, `entrypoint: dist/server/entry.mjs`, `health_path: /_emdash/api/health`, `env_keys: ["EMDASH_ENCRYPTION_KEY", "EMDASH_SITE_URL"]`, `quota_mib >= 2048`). Review with `rustiron-plan inspect` and `rustiron-plan envelope` before signing.
3. Write `EMDASH_SITE_URL` and a freshly generated `EMDASH_ENCRYPTION_KEY` in upstream EmDash format (`emdash_enc_v1_` followed by 43 base64url characters from 32 random bytes, or `emdash secrets generate`) into `/srv/sites/rs_<site_id>/private/app.env` (`0400 rs_<site_id>:rs_<site_id>`). Keep a separate offline recovery copy of `EMDASH_ENCRYPTION_KEY`; Rustiron intentionally keeps `private/app.env` outside the restic data snapshot.
4. Stage `bundle.tar.gz` and `manifest.sha256` into `/var/lib/rustiron/app-intake/<site_id>/emdash-1.6.0-r1/` (`0700`/`0600 root:root`, `restorecon -R`), then sign and submit `app_deploy`.
5. Activate traffic with a separate signed `config_activate` plan including the EmDash site and every site that should stay online. Verify `/rustiron-site.txt`, `/_emdash/api/health`, `/`, `/_emdash/admin`, `/_emdash/api/content/` WebSocket upgrade, and `rustiron-control --diagnose` (`rustiron_app_t:s0:c<N>` MCS confinement).

## Rehearse a WordPress migration (WXR + captured media)

1. Export the WordPress site's WXR XML and copy its captured `wp-content/uploads/` tree from a local lab copy (never fetch media directly from a live production site).
2. Plan the migration offline:
   ```sh
   python3 packaging/wordpress-to-emdash.py plan \
       --wxr export.xml --media-dir uploads/ \
       --source-origin https://old.example --target-origin https://new.example \
       --out ./migration-bundle --capture-op op_cap_source
   ```
   The tool refuses if any WXR attachment is missing from `uploads/`. Review `migration-manifest.json` counts (`posts`, `pages`, `published`, `drafts`, `attachments`, `rewritten_links`, `redirects`).
3. Import `content.json`, `redirects.json`, and captured media through EmDash's authenticated import endpoint.
4. Verify parity against the serving EmDash site:
   ```sh
   python3 packaging/wordpress-to-emdash.py verify \
       --bundle ./migration-bundle --base-url http://127.0.0.1:8090 --host new.example
   ```
   Confirm 100% published content parity, draft non-leakage (drafts do not answer HTTP 200), media SHA-256 parity, zero unrewritten source-origin links, and exact 301 redirects. Keep the source WordPress site untouched until operator sign-off.

## Back up and restore EmDash data (SQLite + uploads)

- **Capture:** Submit a signed `backup_capture` plan for `<site_id>`. Rustiron runs a confined `PrivateNetwork=yes` SQLite Online Backup (`sqlite3.Connection.backup()`) of every database under `data/` into `tmp/rustiron-app-sqlite.tar` (WAL-safe and FTS5-safe), checks consistency markers (with optional 10-second `AppFreeze` under the frozen recipe), and snapshots `data/` + `tmp/rustiron-app-sqlite.tar` through `capture-manifest backup-app` with full P03 Object Lock and manifest verification.
- **Restore:** After taking a safety capture, submit a signed `site_restore` plan naming the target capture and safety capture. Rustiron stops `rustiron-app@rs_<site_id>.service`, fetches and verifies the snapshot manifest, restores verified SQLite databases (stripping stale `-wal`/`-shm` sidecars), atomically exchanges `data/` via `RENAME_EXCHANGE`, restarts the app unit, and verifies loopback health.

## Prepare and apply an `upgrade-emdash` update

1. Run pinned `upgrade-emdash@0.1.0` off-host on a candidate build copy, review the resolved lockfile and migration entrypoint, and package the candidate:
   ```sh
   python3 packaging/emdash-recipe.py prepare-upgrade \
       --baseline-meta ./release-1.6.0/release-meta.json \
       --src ./emdash-upgraded --out ./release-1.6.1 \
       --release-id emdash-1.6.1-r1 --entrypoint dist/server/entry.mjs \
       --migration-entrypoint dist/migrate.mjs --to-version 1.6.1
   ```
2. Take a fresh (`<= 24 h`) `backup_capture` of the EmDash site.
3. Stage `release-1.6.1` into `/var/lib/rustiron/app-intake/<site_id>/emdash-1.6.1-r1/` and submit a signed `app_deploy` plan binding both `--migration-entrypoint dist/migrate.mjs` and `--capture-op <capture_op_id>`.
4. If the confined migration or post-cutover loopback health check fails, Rustiron automatically restores both the previous release symlink and the pre-migration SQLite snapshot, restarts the prior release, verifies health, and settles `failed_compensated`.

## Take offline and delete

1. Submit a signed `config_activate` omitting `<site_id>` and verify `/rustiron-site.txt` returns `404`.
2. Ensure a fresh (`<= 24 h`) `backup_capture` exists, then submit a signed schema 1 `site_delete` plan naming `<site_id>`, its hostname, and that `capture_operation_id`. Deletion stops and disables `rustiron-app@rs_<site_id>.service`, removes drop-ins, SELinux fcontexts, site root, TLS folder, account, group, and quota, and frees the loopback port while keeping backups and store credentials intact.
