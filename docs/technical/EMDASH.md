# EmDash CMS hosting and WordPress migration (P30)

Updated: 2026-11-26. Governs [P30](../planning/ROADMAP.md#p30--create-emdash-cms-sites-and-migrate-wordpress-to-them) under [D-096](../decisions/D-096-emdash-node-recipe.md) and [D-099](../decisions/D-099-modern-app-hosting.md).

## Recipe pin and runtime profile

- **Pinned release:** `emdash@1.6.0` + `create-emdash@1.6.0` (`templates/starter` at commit `bbe73edfcf5f8045dd6362568ff9840acebf7e82`, MIT license) and `upgrade-emdash@0.1.0` for update preparation, with exact npm SHA-512 integrity hashes recorded in [D-096](../decisions/D-096-emdash-node-recipe.md#recipe-pin-and-license).
- **Host runtime:** P27 `node_22_v1` (AlmaLinux 10 AppStream `nodejs-1:22.23.4` LTS, verified in [W599](../validation/S10-W599/README.md) with native `node:sqlite` FTS5 support).
- **Ingress & WebSocket:** CP08 loopback proxy vhost with HTTP route `/` and WebSocket prefix `/_emdash/api/content/` forwarding to `127.0.0.1:<port>`.
- **Runtime configuration (`0400` `private/app.env`):** Plans declare `EMDASH_ENCRYPTION_KEY` and `EMDASH_SITE_URL` in `env_keys` by name only. Values stay in `0400` `/srv/sites/rs_<site_id>/private/app.env` and load via `--env-file-if-exists=`.
- **Persistent state:** SQLite databases and uploaded media stay under `/srv/sites/rs_<site_id>/data/` (`ReadWritePaths=`). Built code under `releases/<release_id>/` stays read-only (`ProtectSystem=strict` and `chmod -R a-w`).

## P03 app-data capture and restore (Slice 1 — W601)

P27/EmDash apps reuse the signed `backup_capture` and `site_restore` verbs and the enrolled P03 restic + Object Lock store without MariaDB:

1. **Consistent SQLite online backup (`AppDump`):** `capture-manifest app-sqlite-backup <account>` runs in `rustiron_capture_t:{level}` with `PrivateNetwork=yes`. It copies `*.sqlite`, `*.sqlite3`, `*.db`, and `-wal` files from `data/` into `tmp/` and opens them with `PRAGMA locking_mode = EXCLUSIVE`. After `PRAGMA integrity_check` and `sqlite3.Connection.backup()`, it writes `/srv/sites/rs_<site_id>/tmp/rustiron-app-sqlite.tar` with `manifest.json`.
2. **Consistency marker (`AppMarker`):** Before and after the restic walk, `capture-manifest app-sqlite-marker <account>` hashes SQLite headers and `-wal` metadata to classify `Matched` or `Unmatched(DatabaseChanged)`. Under `SiteFilesDbFrozenV1`, `AppFreeze` stops `rustiron-app@rs_<site_id>.service` behind a 10-second unfreeze timer.
3. **Encrypted snapshot and Object Lock (`backup-app`):** `capture-manifest backup-app` backs up `data/` and `tmp/rustiron-app-sqlite.tar` through the store namespace with Object Lock and manifest checks. `private/app.env` stays outside the restic snapshot and uses separate secret recovery (D-096).
4. **Verified restore (`site_restore`):**
   - `Maintenance`: stops `rustiron-app@rs_<site_id>.service` (and companion worker).
   - `Fetch`: fetches the signed or safety snapshot into `tmp/clone/` and verifies the `data/` + `rustiron-app-sqlite.tar` manifest.
   - `Database`: a confined `rs_<site_id>` unit checks `manifest.json` SHA-256 digests, refuses symlinks or traversal, removes stale `-wal`/`-shm` files, and restores SQLite databases into `data/`.
   - `Files`: atomically exchanges fetched `data/` with live `/srv/sites/rs_<site_id>/data` via `renameat2(RENAME_EXCHANGE)`, sets `0750` `rs_<site_id>:rs_<site_id>`, and runs `restorecon -R -F`.
   - `Reopen` & `Health`: clears `tmp/clone`, starts the app unit(s), and verifies `127.0.0.1:<port><health_path>` via the confined loopback-only probe.

## Prepared EmDash updates and WordPress WXR migration

- **Prepared updates (`upgrade-emdash@0.1.0`):** Off-host builds pin the lockfile, `bundle.tar.gz`, `manifest.sha256`, and migration entrypoint into a signed `app_deploy` plan with a `<= 24 h` `capture_operation_id`. Failed migrations or health checks roll back `current` and SQLite automatically.
- **WordPress WXR migration:** Offline tooling hashes WXR XML and media, rewrites links and 301 redirects, and verifies post, media, taxonomy, and search parity. The source WordPress site stays untouched until operator sign-off.

## Incremental slices

1. **Done ([W601](../validation/S10-W601/README.md)) — Slice 1 (App-data capture and restore):** Consistent SQLite online backup (`rustiron-app-sqlite.tar`), `AppFreeze`, `capture-manifest backup-app`, `data/` manifest checks, and atomic `site_restore`.
2. **Done ([W602](../validation/S10-W602/README.md)) — Slice 2 (Recipe and WXR tooling):** Added [`packaging/emdash-recipe.py`](../../packaging/emdash-recipe.py) and [`packaging/wordpress-to-emdash.py`](../../packaging/wordpress-to-emdash.py) with D-096 pins, deterministic packaging, WXR rewriting, and parity verification.
3. **Done ([W603](../validation/S10-W603/README.md)) — Slice 3 (Harness VM lab proof):** Proved EmDash creation, WebSocket serving, WXR import, P03 capture/restore, `upgrade-emdash` rollback/upgrade, and deletion on `w603-emdash` (0 AVCs). Fixed W603-F1 to F5 and added [runbook 33](../operator/33-EMDASH.md).
4. **Done ([W641](../validation/S10-W641/README.md)) — Real upstream EmDash 1.6.0 verification (`H-13`):** Following owner download approval, verified all four D-096 pins (`emdash@1.6.0`, `create-emdash@1.6.0`, `upgrade-emdash@0.1.0`, MIT `LICENSE`) byte-for-byte against npm and GitHub; scaffolded and built the real Node.js Starter off-host; verified `upgrade-emdash@0.1.0 --json` (`98` core migrations and migration commands); fixed real-world findings `W641-F1..F4` (`valid_manifest_path` for scoped `@org/pkg` and Astro `[slug]` files, `.env` refusal in `packaging/emdash-recipe.py`, `RUSTIRON_APP_DATA` SQLite/uploads/sessions wiring, `emdash_enc_v1_` key format, and `16 x 250ms` health grace); packaged (`30,501` files, `396.3 MiB`, `--require-upstream-license`), deployed, and served the real EmDash 1.6.0 app on disposable overlay `w641-emdash-real` behind OLS under Enforcing SELinux MCS `rustiron_app_t:s0:c233` (`/_emdash/api/health` `1.6.0`, SSR `/`, `/_emdash/admin/setup`, `87` SQLite tables / `97` migrations / FTS5 in `data/`, `rustiron-control --diagnose` `ok` with verified SELinux MCS confinement, `0` `rustiron_app_t` AVCs and `0` serving-window raw AVCs).
