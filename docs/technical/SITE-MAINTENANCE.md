# Approved Site-Maintenance Catalogue

Updated: 2026-11-24 (America/Toronto).
Roadmap item: [P13](../planning/ROADMAP.md#p13--add-approved-site-maintenance-workflows).
Governing decision: [D-100](../decisions/D-100-site-maintenance-and-credential-rotation.md).

This document is the explicit per-operation catalogue review required by P13.
Every v1.0 site-maintenance action is a closed, signed operation with fixed preconditions, confined execution, honest rollback limits, and health checks.

## 1. Non-negotiable maintenance boundaries

1. **No generic WP-CLI endpoint:** Rustiron exposes no shell or arbitrary WP-CLI runner. Every WordPress maintenance action uses an inspected PHP script run as `rs_<site>` inside its confined pool.
2. **No arbitrary SQL endpoint:** Rustiron accepts no caller-supplied SQL statements. Database mutations run only fixed, identifier-validated queries derived from trusted journal records (such as `ALTER USER` or capture restore).
3. **No root execution of tenant code:** Unpack, file swaps, `wp_upgrade()`, update inventory, and EmDash migrations run as `rs_<site>`. They never run as `root`.
4. **No universal rollback claims:** Every operation below states its exact rollback boundary and what requires a P03 capture restore or explicit operator reconciliation.

## 2. Explicit per-operation catalogue

| Operation / Verb | Decision | Execution Identity | Prerequisites & Backup Guard | Non-Atomic Boundary & Rollback | Refused Cases | Evidence & Runbook |
| --- | --- | --- | --- | --- | --- | --- |
| **WordPress plugin & theme updates** (`site_update`) | [D-084](../decisions/D-084-wordpress-update.md) | Confined site user (`rs_<site>`) for unpack, census, swap, and health | Owned active WP site; pinned SHA-256 recipe in `update-intake`; succeeded P03 capture within 24 h | Code swap + DB schema change are non-atomic; failed health rolls back swapped extensions AND restores DB from the signed capture; interrupted rollback -> `update-reconcile` | Unpinned releases, wrong `from_version`, missing/stale capture, quota overflow, static/proxy/app/ejected sites | W512–W518; [24-WORDPRESS-UPDATE.md](../operator/24-WORDPRESS-UPDATE.md) |
| **WordPress core updates** (`site_update` kind `core`) | [D-086](../decisions/D-086-wordpress-core-update.md) | Confined site user (`rs_<site>`) for core swap and fixed `wp_upgrade()` script | Owned active WP site; core alone in plan; WordPress.org MD5 file list pinned; >= ~2x release quota headroom; P03 capture within 24 h | Maintenance file + `wp-admin`/`wp-includes`/root swap + `wp_upgrade()` DB upgrade; failed health restores previous core files and capture DB | Combined core + plugin plan, insufficient quota headroom, mismatched MD5/SHA-1, non-WP sites | W524–W528; [24-WORDPRESS-UPDATE.md](../operator/24-WORDPRESS-UPDATE.md) |
| **Read-only update inventory & watch** (`update-inventory` + `wordpress-update-watch.py`) | [D-087](../decisions/D-087-prepared-wordpress-updates.md) | Confined site user (read-only header inspection) + operator PC watch tool | No host mutation; replaces standing update grants | Read-only; zero rollback needed | Ejected/quarantined/deleted sites | W529–W531; [24-WORDPRESS-UPDATE.md](../operator/24-WORDPRESS-UPDATE.md) |
| **Per-site DB credential rotation** (`site_credential_rotate`) | [D-100](../decisions/D-100-site-maintenance-and-credential-rotation.md) | Root admin helper (`ALTER USER` for trusted `rs_<site>` + atomic `0600 private/db.cnf` + PHP pool restart) + site-user/loopback health probe | Owned active WP site with MariaDB account and `private/db.cnf`; zero secret values in plan, grant, logs, or argv | MariaDB `ALTER USER` and `private/db.cnf` swap are non-atomic; helper retains prior password in memory only and executes 1 bounded compensation rollback on file/restart/health failure; uncertain rollback -> `needs_attention` (`credential-rotate-reconcile`) | Static sites, proxy sites, P27/P30 apps (SQLite), ejected/quarantined/deleted sites, secrets in plan | W608–W609; [35-SITE-CREDENTIAL-ROTATION.md](../operator/35-SITE-CREDENTIAL-ROTATION.md) |
| **Site quota change** (`site_quota`) | [D-088](../decisions/D-088-site-quota-change.md) | Root admin helper (`setquota` + readback) | Owned non-ejected site; new hard limits within enrolled policy cap and strictly above current disk/inode usage | Single filesystem quota mutation; interrupted intent -> `quota-reconcile` | Limits above enrolled cap or at/below current use, ejected/deleted sites | W532–W536 |
| **Live site restore** (`site_restore`) | [D-089](../decisions/D-089-cp03-v1-scope.md) | Confined site user for fetch/DB import + root `RENAME_EXCHANGE` for `html/` or `data/` | Owned active site; fresh safety capture within 24 h; restored capture older than safety capture | Drop/import tables + atomic directory swap are non-atomic across DB & files; failed step reverts to the signed safety capture (`restore-reconcile OP safety`) | Stale safety capture, cross-site capture, open conflicting op, ejected sites | W541–W544, W601, W603; [26-SITE-RESTORE.md](../operator/26-SITE-RESTORE.md) |
| **Staging clone & scrub** (`site_clone`, `clone_scrub`) | [D-078](../decisions/D-078-managed-wordpress-clone.md) | Confined target site user for fetch/unpack/DB import/URL rewrite | Succeeded source capture; fresh target site ID & hostname | Target stays unserved until separate `config_activate`; failed clone auto-scrubs or scrubs via `clone_scrub` | Source == target, duplicate hostname, uncaptured source | W497–W501, W537–W539; [SITE-CLONE.md](SITE-CLONE.md) |
| **Modern app & EmDash releases** (`app_deploy`, `upgrade-emdash`, `app_lifecycle`) | [D-099](../decisions/D-099-modern-app-hosting.md), [D-096](../decisions/D-096-emdash-node-recipe.md) | Confined `rs_<site>` unpack & `PrivateNetwork=yes` migration + systemd `rustiron-app@.service` | Off-host SHA-256 release bundle in `app-intake`; P03 capture within 24 h whenever `migration_entrypoint` is set | Release symlink switch + SQLite migration are non-atomic; failed migration or loopback health restores previous `current` and pre-migration SQLite (`failed_compensated`) | Unpinned/symlinked archives, missing capture for migrating release, root package scripts | W596–W603; [32-MODERN-APPS.md](../operator/32-MODERN-APPS.md), [33-EMDASH.md](../operator/33-EMDASH.md) |

## 3. Explicitly unsupported & refused maintenance operations

The following are permanently out of bounds for v1.0 maintenance endpoints:
- Arbitrary WP-CLI commands (`wp eval`, `wp db query`, arbitrary plugin install from URL).
- Arbitrary SQL execution or web database administration (phpMyAdmin / Adminer — excluded by [D-089](../decisions/D-089-cp03-v1-scope.md)).
- Web file managers or FTP/SFTP servers (excluded by [D-089](../decisions/D-089-cp03-v1-scope.md)).
- Standing auto-update grants for WordPress core/plugins/themes (excluded by [D-087](../decisions/D-087-prepared-wordpress-updates.md)).
- Automatic silent repair of break-glass configuration drift (excluded by [D-038](../decisions/DECISIONS.md) and [17-BREAK-GLASS.md](../operator/17-BREAK-GLASS.md)).
