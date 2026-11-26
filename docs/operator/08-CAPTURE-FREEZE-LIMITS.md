# Frozen backups: what they cover

Updated: 2026-11-04, America/Toronto. Decision: [D-021](../decisions/D-021-capture-freeze.md).

A frozen backup (`site_files_db_frozen_v1`) pauses one site's web PHP while its files and database are copied, so the two match. In lab runs on one site with a quiet load, the pause was 1.4–1.7 s ([W258](../validation/S10-W258/README.md), [W262](../validation/S10-W262/README.md)). Other sites and loads can differ.

**What visitors see.** Pages that need PHP return `503` with `Retry-After: 10` and a short "Back in a moment" page. Static files still load. Other sites are not affected. The first page after the pause may be slow while PHP starts. In W258, that first response took 0.9 s to more than 2 s. If the backup tool stops responding, PHP comes back by itself after the 10 s timer. In [W261](../validation/S10-W261/README.md), the timer restored PHP at +10.04 s.

**What it does not cover.** The pause only stops writes that come through the site's web PHP. The pause does **not** stop:
- scheduled jobs run from the command line (system cron, WP-CLI, `wp cron`);
- direct database clients (`mysql`, database admin tools, replication);
- other servers or applications writing to the same database.

If any of these write during the backup, the backup is still kept, but it is labelled not matched (`database_changed` or `freeze_not_held`) instead of `matched`. A restore from such a backup can contain files without their database rows, or the other way round.

**To get a matched backup:** schedule backups outside cron and import windows, and keep other writers off the site's database while a backup runs. Check the label on the receipt; only `matched` means files and database agree.

## After a reboot

A reboot during a freeze is safe for the site: its PHP socket starts at boot, so it serves again without the unfreeze timer (W264). The executor, admin helper and coordinator stay stopped until you start them.

Before you start the executor, reconcile each capture that a submit reply or the console still shows as `running`.
The executor must be stopped, because the journal writer lock refuses a second process.
On the lab VM, [W175](../validation/S10-W175/README.md) used these commands. Replace `<operation>` with the operation ID:

```sh
systemctl start rustiron-s10-lab-admin-helper
/usr/local/libexec/rustiron-s02-lab/rustiron-s02-executor capture-status <operation>
/usr/local/libexec/rustiron-s02-lab/rustiron-s02-executor capture-reconcile <operation>
systemctl start rustiron-s02-lab-executor
```

`capture-reconcile` prints the capture row as JSON.
The `state` field changes from `running` to `succeeded` with a `snapshot_id`, or to `failed` when the store holds no snapshot with the operation tag.
A frozen capture that the executor finds after an interruption reads `unmatched` with reason `freeze_not_held` ([W261](../validation/S10-W261/README.md)).
No product host procedure for reconciliation is verified yet.
