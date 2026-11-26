# Delete a live site

This procedure removes one served site from the host in two signed steps ([D-085](../decisions/D-085-delete-live-site.md)). First a signed activation takes the site offline. Then a signed `site_delete` removes it. [W523](../validation/S10-W523/README.md) rehearsed it on a lab host.

A deletion cannot be undone on the host. Its capture is the way back. The site's backups stay in the store until their retention ends.

## Before you start

- The site is served by Rustiron. It is not ejected and not adopted. A quarantined site that never served uses `site_retire` ([D-080](../decisions/D-080-retire-quarantined-site.md)).
- The product store is enrolled for the site ([page 10](10-PRODUCT-STORE-ENROLLMENT.md)), so the site can take a capture.
- Decide what happens to the site's DNS record. The deletion changes no DNS record.

### A proxy site

Follow [page 30](30-PROXY-SITE.md#take-the-site-offline-and-delete-it) for a proxy site. The proxy site uses a schema 2 deletion without a capture.

## Step 1: take a capture

Take a signed `backup_capture` of the site, and check that it is `succeeded`. The deletion must name the site's newest succeeded capture, finished within the last 24 hours.

## Step 2: take the site offline

1. Read the live generation and its digest. `ols-status` needs the journal writer lock, so stop the coordinator and the executor for it:

   ```sh
   systemctl stop rustiron-coordinator.service rustiron-executor.service
   systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor ols-status --admin-helper
   systemctl start rustiron-executor.service rustiron-coordinator.service
   ```

2. Sign and submit an OLS activation (`config_activate`) that names `generation` and `digest` as its expected predecessor and lists every served site except this one.
3. Check the result. The site answers 404, and every other site still answers its marker. The site's files and database are still on the host. To bring it back, sign an activation that names it again.

## Step 3: delete the site

1. Sign and submit the `site_delete` plan. It names the site, its hostname, and the capture operation. `rustiron-plan inspect` shows them with the effects. Read them before you sign.
2. Read the result:

| State | Meaning |
| --- | --- |
| `succeeded` | The site's PHP units, database and user, file contexts, site root, TLS folder, certbot lineage, update intake, account, group, and quota are gone |
| `failed` | A part of the removal failed. The site is already `deleted` and is never served again. Read `journalctl -u rustiron-admin-helper` for the `site_delete` line and its phase, correct the cause, then sign a new `site_delete` that names the same capture. The 24-hour limit does not apply to this retry |
| `intent` | The outcome was not read, for example after a restart. Settle it as below |

A request that names a served site, another hostname, or a capture that is not the site's newest succeeded one is refused before anything is recorded.

## Settle an open deletion

Stop the coordinator and the executor; keep the admin helper running. Then run the removal again:

```sh
systemctl stop rustiron-coordinator.service rustiron-executor.service
systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor delete-reconcile OPERATION --admin-helper
systemctl start rustiron-executor.service rustiron-coordinator.service
```

The output is the deletion's record: `done` or `failed`. `delete-status OPERATION` prints the record without changing it.

## After the deletion

- Remove or change the site's DNS record, if that was the decision.
- The host keeps the site's store credentials in `/etc/rustiron/credentials/sites/<account>`, so its backups stay readable. After the last backup's retention ends ([page 22](22-BACKUP-RETENTION.md)), remove the site's principals in the store and then its host credentials.
- To bring the site back, restore it from its capture with the [manual recovery](../technical/MANUAL-RECOVERY.md) under another hostname. The site ID and hostname stay consumed.

## Limits

- An adopted site is refused for now.
- A re-created site cannot use the deleted site's hostname until a later decision.
