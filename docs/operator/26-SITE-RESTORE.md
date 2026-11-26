# Restore a live site from its capture

This procedure brings one served site back to an earlier capture of its own on the same host ([D-089](../decisions/D-089-cp03-v1-scope.md#signed-restore-design)). A signed `site_restore` replaces the site's database, or its files and its database. [W544](../validation/S10-W544/README.md) rehearsed it on a lab host.

A restore loses what changed on the site after the restored capture. The safety capture keeps that state, and an operator command can bring it back.

## Before you start

- The site is served by Rustiron from its own provision. It is not ejected and not adopted.
- The product store is enrolled for the site ([page 10](10-PRODUCT-STORE-ENROLLMENT.md)). Both captures must have been written to the destination as it is enrolled now. After a change of the enrolled destination, older captures cannot be restored this way; use the [manual recovery](../technical/MANUAL-RECOVERY.md).
- Nothing else is open on the site: no running capture or restore probe, and no open update, quota change, certificate issue or renewal, or restore.
- Choose the scope:
  - `database` replaces only the database. The site's files stay as they are.
  - `files_and_database` also replaces the document root. The site keeps its own `wp-config.php`, so its credentials and salts stay. Both captures need a complete file manifest.

## Step 1: take the safety capture

Take a signed `backup_capture` of the site and check that it is `succeeded`. The restore must name the site's newest succeeded capture, finished within the last 24 hours, as its safety capture.

## Step 2: choose the capture to restore

Read the capture's record with `capture-status OPERATION` (with the coordinator and the executor stopped). Note its snapshot ID and manifest digest. It must be an older succeeded capture of the same site.

## Step 3: sign and submit the restore

1. Sign and submit the `site_restore` plan. It names the site, its hostname, the scope, the capture to restore with its snapshot, manifest, destination, destination policy digest, and repository ID, and the safety capture. `rustiron-plan inspect` shows them with the effects. Read them before you sign.
2. Read the result:

| State | Meaning |
| --- | --- |
| `succeeded` | Every step finished and the site answers its marker, its login, and its home page |
| `intent` with an error | A step failed. The site is still in WordPress maintenance mode. Read `journalctl -u rustiron-admin-helper` for the `restore_step` line, its step, and any `site_restore` or `fixed_command` line before it, then settle the restore as below |
| `intent` without an error | The outcome was not read, for example after a restart. Settle it as below |

A restore usually runs longer than the coordinator's 5-second reply deadline; the CLI then reads the recorded state. A restore left open, also after a failed step, stays `intent`, so the CLI reports `outcome_unknown` for it. Read its record with `restore-status OPERATION` (coordinator and executor stopped) before you act.

A request whose site, hostname, captures, or destination pins do not match the host is refused before anything is recorded.

## Settle an open restore

Stop the coordinator and the executor; keep the admin helper running. Then run the next attempt, from the signed capture again or from the safety capture:

```sh
systemctl stop rustiron-coordinator.service rustiron-executor.service
systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor restore-reconcile OPERATION safety --admin-helper
systemctl start rustiron-executor.service rustiron-coordinator.service
```

Use `signed` instead of `safety` to try the restore again after you corrected the cause. The command first records an interrupted attempt as `failed`; the new attempt runs every step again. Its output is the restore's record. A restore that ends from the safety capture is `reverted`. `restore-status OPERATION` prints the record without changing it. A restore takes at most 8 attempts.

## Limits

- An adopted site is refused for now.
- The restored files may hold older plugin or theme code. The next update inventory reads the files on disk.
- Only the site's database tables and views are removed before the import; stored procedures and events stay.
