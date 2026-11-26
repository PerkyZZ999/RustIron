# Export a site's database from a capture

This procedure copies the database dump of one recorded capture to the operator PC ([D-089](../decisions/D-089-cp03-v1-scope.md#database-export-on-the-operator-pc)). The host takes no part: restic reads the store with the site's read-only fetch key, and `rustiron backup export-plan` checks the capture offline. [W545](../validation/S10-W545/README.md) rehearsed it on the lab store.

The dump holds the site's whole database, including user accounts and password hashes. Keep it only as long as you need it, in a folder only you can read.

## Before you start

- On the PC: the site's `fetch-aws` and `repo.password` ([page 10](10-PRODUCT-STORE-ENROLLMENT.md)), restic 0.18.0 or later, and the Rustiron CLI.
- Point restic at the site's repository with the fetch key, as for retention ([page 22](22-BACKUP-RETENTION.md)): `RESTIC_REPOSITORY`, `AWS_SHARED_CREDENTIALS_FILE` for `fetch-aws`, `RESTIC_PASSWORD_FILE` for `repo.password`, and the store's CA when it uses a private one. Never put a secret in a command line.
- The fetch key cannot create a lock, so every restic command needs `--no-lock`.

## Step 1: plan the export

1. On the host, export the observation: `systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor observe > observation.json`. Copy it to the PC. It holds no secret.
2. On the PC, list the site repository: `restic snapshots --no-lock --json > snapshots.json`.
3. Run:

   ```sh
   rustiron --output json backup export-plan --snapshots snapshots.json --observation observation.json --site SITE --capture OPERATION
   ```

   On exit 0 the output names the `snapshot_id`, the journal's `finished_at`, the `dump_path`, and the `restic_args`. On exit 3 it names the `refusal`:

| Refusal | Meaning |
| --- | --- |
| `capture_not_recorded` | The observation has no succeeded capture of this site with this operation. Choose another capture |
| `snapshot_not_listed` | The repository does not show the capture's snapshot. It was forgotten or hidden; see [a hidden snapshot](22-BACKUP-RETENTION.md#a-hidden-snapshot) |
| `dump_not_in_snapshot` | The snapshot does not hold the site's dump. Do not use it |

## Step 2: write the dump

Run the planned `restic` arguments with the output in a private file:

```sh
umask 077
restic dump --no-lock SNAPSHOT_ID DUMP_PATH > site.sql
sha256sum site.sql
```

restic checks every block it reads against its hash. A non-zero exit means the file is incomplete; remove it.

## Step 3: use the dump

The file is a plain MariaDB dump of the site's own database. Import it only into a database that you create for it, never into a database that Rustiron manages; a live site goes back to a capture through the signed [restore](26-SITE-RESTORE.md). Remove the file when you are done.

## Limits

- The export reads what the capture holds. Changes made after the capture are not in it.
- The plan trusts the observation as the host reported it. A changed observation can name another recorded snapshot of the same site, never another site's dump.
