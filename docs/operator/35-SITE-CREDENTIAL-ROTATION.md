# Rotate a WordPress site's database credentials

This runbook rotates the per-site MariaDB password for one owned, live, non-ejected WordPress site under [D-100](../decisions/D-100-site-maintenance-and-credential-rotation.md) and [SITE-MAINTENANCE](../technical/SITE-MAINTENANCE.md).

No secret ever enters a plan, grant, journal row, log line, or command-line argument. The host generates a fresh 48-hex-digit password locally, updates MariaDB over the local socket, atomically swaps `/srv/sites/rs_<site>/private/db.cnf` (`0600`, site-owned), restarts `rustiron-site-php@rs_<site>.service`, verifies the new login, verifies the old password is rejected, and probes WordPress health.

## Prerequisites

1. The site is an owned, active, non-ejected WordPress site (static imports, proxy sites, and P27/P30 apps are refused before intent).
2. No other mutation (`site_update`, `site_restore`, `site_delete`, `backup_capture`, or unresolved `site_credential_rotate`) is open for the site.
3. The host journal is migrated to schema v44 (`rustiron-executor migrate`).
4. Both `rustiron-admin-helper.service` and `rustiron-executor.service` are active.

## 1. Create and inspect the plan on the operator PC

```sh
rustiron plan create site-credential-rotate \
  --plan-id plan_rot_01 \
  --host-id "$HOST_ID" \
  --host-epoch "$HOST_EPOCH" \
  --profile-digest "$PROFILE_DIGEST" \
  --site-id cp02 \
  --hostname cp02.example.test \
  --valid-from "$NOW" \
  --expires-at "$((NOW + 900))" \
  > plan.json

rustiron-plan inspect plan.json
rustiron-plan envelope plan.json
```

Verify that:
- `verb` is `site_credential_rotate`,
- `target` is `mariadb_user_password`,
- `secret_in_plan` is `false`,
- `ols_reloads` is `0` and `all_served_sites` is `false`.

## 2. Sign the matching grant and submit

Sign the grant offline with your production key (or lab key on disposable local VMs) using namespace `rustiron-plan-v1`, copy `plan.json`, `grant.json`, and `grant.json.sig` to the host, and submit through `rustiron-cli apply`:

```sh
rustiron apply \
  --operation-id op_rot_01 \
  --idempotency-key key_rot_01 \
  --plan plan.json \
  --grant grant.json \
  --signature grant.json.sig
```

Expected outcomes:
- `succeeded` (`done`): MariaDB password rotated, `private/db.cnf` atomically swapped, `rustiron-site-php@rs_<site>.service` restarted, new login verified, old password rejected, and WordPress `/rustiron-php-health.php`, `/wp-login.php`, and `/` verified.
- `failed_compensated`: A step after `ALTER USER` failed (for example, `private/db.cnf` could not be swapped or health failed), and the single bounded compensation attempt restored the prior MariaDB password and `private/db.cnf`, restarted site PHP, and re-verified WordPress health.
- `needs_attention`: Compensation failed or could not verify health. The site remains locked against new rotations, updates, restores, and deletions until reconciled.
- `failed`: Pre-check failed before MariaDB was modified; the site is untouched.

Re-submitting the exact same `operation_id`, `idempotency_key`, plan, and grant returns the recorded state (`replay: true`) without rotating the password again.

## 3. Inspect status and reconcile an unresolved rotation

If the executor stopped mid-rotation (`intent`) or compensation could not verify live health (`needs_attention`):

1. Stop `rustiron-executor.service` so the operator holds the journal lock exclusively, while leaving `rustiron-admin-helper.service` running.
2. Check the recorded state:
   ```sh
   sudo -u rustiron-exec rustiron-executor credential-rotate-status op_rot_01
   ```
3. Verify MariaDB and `/srv/sites/rs_<site>/private/db.cnf` manually if needed (never echo passwords into shell history or logs), ensuring `private/db.cnf` is `0600` owned by `rs_<site>:rs_<site>` and matches the MariaDB account password.
4. Settle the rotation through the admin helper:
   ```sh
   sudo -u rustiron-exec rustiron-executor credential-rotate-reconcile \
     op_rot_01 done --admin-helper
   ```
   Use `done`, `failed_compensated`, or `failed` according to verified reality. For `done` and `failed_compensated`, the admin helper re-verifies `private/db.cnf` MariaDB login and WordPress HTTP health before allowing settlement.
5. Start `rustiron-executor.service` again.
