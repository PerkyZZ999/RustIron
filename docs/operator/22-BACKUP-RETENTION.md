# Backup retention authority

This procedure is the retention runbook for one product backup destination ([D-079](../decisions/D-079-backup-retention-authority.md)). The retention authority forgets old snapshots, detects a hidden recorded snapshot, and puts it back. [W503](../validation/S10-W503/README.md) rehearsed it on the lab store.

## Who holds what

| Key | Holder | Can |
| --- | --- | --- |
| Capture key (`aws`) | The host | Write snapshots, data, and indexes. Delete only its own lock files |
| Fetch key (`fetch-aws`) | The host and the operator PC | Read the site repository |
| Store root or retention key | The operator PC only | Forget and prune, read every version, and copy a version back. It cannot remove or shorten a COMPLIANCE lock |
| Repository password | The host, with a recovery copy on the operator PC | Open the repository |

Never send the retention key to a host, a log, or chat.

## Routine retention

1. On the host, export the observation: `systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor observe > observation.json`. Copy it to the PC. It holds no secret.
2. On the PC, list the site repository with the fetch key: `restic snapshots --json > snapshots.json`.
3. Run `rustiron --output json backup retention-plan --snapshots snapshots.json --observation observation.json --site SITE`.
4. If the exit status is 3, stop. A recorded capture is missing from the listing. Go to [a hidden snapshot](#a-hidden-snapshot).
5. Forget only the IDs in `forget`, with the retention key: `restic forget ID...`. Run `restic prune` with the same key when space matters.

The plan keeps the newest recorded capture, every recorded capture that finished within the window (at least 30 days), and every unrecorded snapshot within the window. It never counts snapshots, so new snapshots from a compromised host cannot push out a recorded capture. Forget and prune place delete markers. The locked versions stay until their lock ends, and the bucket lifecycle removes them later.

## A hidden snapshot

A host's capture key can overwrite an object. The overwrite hides the recorded version but cannot remove it.

1. Stop captures of the site, and treat its host as compromised.
2. With the retention key, list the versions of `sites/rs_SITE/snapshots/ID`. The oldest version is the recorded one.
3. Copy that version back as the current version (an S3 `CopyObject` with `versionId`). Do the same for any other overwritten object that `restic check` names.
4. With the fetch key, run `restic snapshots` and `restic check`. Run the plan again: the exit status is 0.
5. Restore the snapshot on a clean machine with the fetch key and the recovery copy of the password, and check the files and the dump.

## Limits

- One store is not an independent copy ([D-026](../decisions/D-026-defer-offsite-and-escrow.md)).
- The homelab RustFS checks of D-079 are deferred until before the pilot.
