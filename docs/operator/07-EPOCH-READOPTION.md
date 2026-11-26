# Epoch re-adoption

This page describes an epoch rotation and the re-adoption that follows it.
The W369 run rotated the epoch of an enrolled product host ([W369](../validation/S10-W369/README.md)).
The W372 run rotated a second product host ([W372](../validation/S10-W372/README.md)).
It then re-adopted the sites and the live OLS generation with the `site_readopt` verb.
The verb is [D-030](../decisions/D-030-re-adoption-verb.md), specified in [RE-ADOPTION](../technical/RE-ADOPTION.md).

## What rotation is

The journal metadata row stores one host id and one host epoch.
`open` and `migrate` compare the caller's epoch with that row and refuse a difference before any new record is written.
An intent whose epoch is not the open epoch is also refused.

The admission mark is stored outside the journal and is bound to the same host and epoch.
A new epoch therefore needs a new journal.
The old file stays as evidence.

Nobody edits the old file in place.

## Executor answers during a rotation

W369 recorded these answers on the product host. [W102](../validation/S10-W102/README.md) recorded the same `open` and `migrate` refusals on a journal copy.

| Command | Policy epoch | Journal folder | Answer |
| --- | --- | --- | --- |
| `initialize` | Old | Old journal | `JOURNAL_ROLLBACK` |
| `initialize` | Old | Empty | `JOURNAL_ROLLBACK`, from the source (not run in W369). `initialize` reads the mark before the folder. A mark with admitted work for the same epoch refuses a fresh journal |
| `ols-status`, `status`, `observe` | New | Old journal | `JOURNAL_IDENTITY_MISMATCH` |
| `migrate` | New | Old journal | `EXECUTOR_DEPENDENCY_UNAVAILABLE`. The journal is already the current schema |
| `initialize` | New | Old journal | `JOURNAL_STATE_EXISTS` |
| `initialize` | New | Empty | Exit 0. The mark is rewritten for the new epoch with count 0 |

None of the refusals changed the journal or the mark. Their SHA-256 values stayed the same.

## Procedure

Run each step as root on the host. Each step names the success signal.

WARNING: Do not delete or move the admission mark. If the mark is absent, `initialize` accepts the old epoch again. A fresh journal for the old epoch has no record of the old nonces. The executor then admits again an old grant that is still inside its time window.

1. Stop the executor. Save the ownership record of each site and the OLS status: `/usr/libexec/rustiron/rustiron-executor export SITE > export-SITE.json` in the root shell, and `systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor ols-status --admin-helper | cat > ols-status.json`. Record the SHA-256 of each file. Each re-adoption plan names one of these digests. After the rotation, `export` refuses the site.
2. Stop the management services: `systemctl stop rustiron-coordinator.service rustiron-executor.service`. Keep `rustiron-admin-helper.service` and `lshttpd.service` running. The sites keep serving.
3. Record the digests: `sha256sum /var/lib/rustiron/executor/* /var/lib/rustiron/admission/admission-mark`.
4. Write `policy.json` again with `packaging/enrollment-policy.py`. Change only `--host-epoch`. Measure the other values again, as in [09-PRODUCT-ENROLLMENT](09-PRODUCT-ENROLLMENT.md#values-to-measure-and-choose).
5. Compare the new file with the installed one. After you put the old epoch back into the new file, `cmp` must report no difference.
6. Install the file: `install -o root -g root -m 0600 DIR/policy.json /etc/rustiron/policy.json`, then `restorecon -R /etc/rustiron`.
7. Make a root-only archive folder, for example `install -d -m 0700 ARCHIVE/executor ARCHIVE/admission`.
8. Copy the mark: `cp -p /var/lib/rustiron/admission/admission-mark ARCHIVE/admission/`.
9. Move each file of `/var/lib/rustiron/executor` into `ARCHIVE/executor/` with `mv`. The folder must be empty after this step.
10. Compare the archive digests with step 3. Each digest must be equal.
11. Run `/usr/libexec/rustiron/rustiron-executor initialize`, then `restorecon -R /var/lib/rustiron`. The mark must show the new epoch and count 0.
12. Start the services: `systemctl start rustiron-executor.service rustiron-coordinator.service`. Wait until `/run/rustiron/executor.sock` and `/run/rustiron-coordinator/control.sock` exist.
13. Run `systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor observe`. The output must show the new epoch and no operation.
14. Copy the archive and the step 1 output off the host.

NOTE: W369 put the archive below `/var/lib/rustiron`. Then `restorecon` gives it the executor state type `rustiron_executor_var_lib_t`. Use a root-only folder outside `/var/lib/rustiron` for the archive. W372 used `/root/w372-archive/epoch_w372_1`.

NOTE: Do not redirect the output of `systemd-run --pipe` straight into a file below `/root`. In W372 the transient unit failed (`Remote peer disconnected`) and SELinux denied `init_t` the write to `admin_home_t`. Pipe the output through `cat`.

In W369, steps 2, 6, 9, 11, and 12 took 0.41 s in a script. The management services were stopped for 0.61 s. The site served during the whole rotation. In W372, steps 2 to 12 took 0.26 s.
The coordinator store does not change. The signer list and the revocation list do not change.

## What the new journal does not contain

Provision rows are the ownership records. They stay in the archived journal; the new journal has none.
The new journal also has no OLS operation. In the product profile, an empty history establishes the bootstrap generation ([W362](../validation/S10-W362/README.md)). The live `current` is then unexplained drift: `ols-status --admin-helper` reports `explained_by_journal` false and `clean` false.
Until the re-adoption below, every `config_activate` is refused, and `status`, `provision`, and `export` of an old site answer `NOT_ADMITTED_FOR_EFFECT`.

Do not provision an old site again. Since W372, `site_provision` refuses an existing account, group, or site root before intent (`PROVISION_COLLISION`, exit 4). It records nothing, so the site ID stays free for a re-adoption.
Do not stop OLS and remove `current`. In W369, that path dropped the old site from serving.

## Re-adoption procedure

`site_readopt` records ownership of what already exists. It creates, changes, and deletes nothing on the host, and it has no compensation.
Each request is a signed plan and grant, as for every verb. Send it through the coordinator with `plan apply-file`.

1. Read the allocation floor from the archive (optional). With the archive opened read-only and immutable, take the highest `uid=` and `level=s0:c` of the Account and Labels steps. W372 used `sqlite3` with `mode=ro&immutable=1` ([31-after-rotation.sh](../validation/S10-W372/31-after-rotation.sh)). The digest of the archive must not change.
2. For each old site, create a site-form plan: `rustiron plan create site-readopt --plan-id ID --host-id HOST --host-epoch NEW --profile-digest DIGEST --requester REQUESTER --previous-epoch OLD --evidence-sha256 SHA256-OF-EXPORT --site-id SITE --hostname HOSTNAME --quota-block-hard-kib K --quota-inode-hard I [--floor-uid U --floor-category C] --observed-at T --valid-from T --expires-at T`. The hostname and the quota limits come from the saved export.
3. Review the plan with `rustiron-plan inspect PLAN.json`. Compare the site, the hostname, the quota limits, the previous epoch, and the evidence digest with the saved export. Then sign the grant (`verbs: [site_readopt]`, `site_ids: [SITE]`, no `targets`).
4. Send the request. Success is `state: succeeded` (the row is `adopted`), exit 0. A fact that does not match is `untouched` with `READOPT_MISMATCH`, exit 5. The row is then `refused`, nothing else is recorded, and the site ID stays free.
5. Stop the executor and run `rustiron-executor readopt-status OP`. It prints the form, the state, the observed facts, and the first failed rule. `export SITE` shows `provenance: explicitly_adopted`.
6. When every site that the live generation serves is adopted, create the generation-form plan: `rustiron plan create site-readopt-generation ... --site-id SITE (once per served site) --expected-generation CURRENT --expected-digest DIGEST --evidence-sha256 SHA256-OF-OLS-STATUS`. `CURRENT` and `DIGEST` come from the saved `ols-status`. The grant has `site_ids` equal to the plan list and `targets: [ols_lab_listener]`.
7. Send it. On success, `ols-status --admin-helper` reports `explained_by_journal` true, `clean` true, and `established_by: adoption`.
8. Change the OLS configuration with a normal `config_activate` from the adopted generation. Provision new sites as usual. New UIDs and categories are above every adopted value and the floor.

The generation form refuses a site list that differs from the live generation (`READOPT_MISMATCH`, rule `render`). The live `current` must be byte-equal to the executor's render from owned sites.

## Refusals after a rotation

| Request | Answer | Records |
| --- | --- | --- |
| Any plan or grant that names the old epoch | `FIXTURE_BINDING_DENIED` | None |
| `site_provision` of an old site | `PROVISION_COLLISION`, exit 4 (W372) | None |
| `site_readopt` of a site that a provision already holds, or of an ejected site | `PRECONDITION_CHANGED` | None |
| `site_readopt` while another operation is unresolved | `UNRESOLVED_OPERATION` | None |
| `site_readopt` site form, a fact differs (for example a foreign grant on the site database) | `READOPT_MISMATCH`, state `untouched`, exit 5 | The row, `refused`, with the rule |
| `site_readopt` generation form, a failed server check | `OLS_DRIFT` | The row, `refused` |
| `config_activate` with the bootstrap predecessor after an adoption | `PRECONDITION_CHANGED`, exit 4 | None |

If the executor stops after the `verifying` intent, the row blocks every other admission. Run `rustiron-executor reconcile OP --admin-helper` with the service stopped. It repeats the read-only observation and records `adopted` or `refused`.

The epoch binding is the only replay defense across the rotation. The new journal has no record of the old grants and nonces.
A re-adoption is not a recovery receipt. The record does not claim that a backup, a restore, or an independent copy exists.

These sites are out of scope: a CyberPanel site, an ejected site, and a site with the page cache.
A site restored with the [manual recovery guide](../technical/MANUAL-RECOVERY.md) is also out of scope.
Do not provision such a site again.
