# Restore cleanup observations — W165

2026-11-03.
Implemented local executor behavior.
No live host validation.
[Evidence](../validation/S10-W165/README.md).

A cleanup tool exit code is not proof that sandbox resources are absent.
Missing observations are not a zero count.
The executor now uses the same structured cleanup outcome for normal restore completion and administrative cleanup of an interrupted probe.

## Execution order

[cleanup.rs](../../crates/executor/src/restore/cleanup.rs) retains the existing fixed deletion set and derives every target from the journaled `rp_<six hex>` probe account.
It first stops matching `rustiron-probe-<account>-*` units.
Successful stop must be followed by a successful, empty `systemctl list-units --all --no-legend --plain --no-pager --full -- <pattern>` observation before any deletion.

Any retained matching unit blocks deletion, even if inactive; unsupported query options, manager failure and nonempty output fail closed.
The same query is repeated after removal.
No arbitrary unit/property/command input or new privileged verb is exposed.

The unit-listing contract is documented upstream in [systemctl](https://raw.githubusercontent.com/systemd/systemd/main/man/systemctl.xml) (checked 2026-11-03).
Target-version compatibility, effective process/cgroup shutdown, descendant containment and race behavior still require the disposable Alma10 host tests.
These local tests do not prove that PID 1 or its observations are trustworthy, nor that an escaped/orphaned process is absent.

After the pre-deletion gate, attempt the existing cleanup set:

- Drop the throwaway DB/user.
- Remove the two exact file-context mappings.
- Remove the sandbox root, probe account, and its mail spool.

Observe passwd, file-context rules, root/spool metadata, exactly two DB count results and matching units.
Read failures are unknown.
Only `NotFound` metadata is absence.

Links, including dangling links, are present.
An invalid/empty passwd view without a valid root entry is unknown.
Counts must be unsigned decimal integers, exactly two, with checked sums.

No overflow or malformed output becomes an invented count.
A policy listing reaching the fixed launcher's 1 MiB capture cap is unknown.
An empty successful local-rule listing remains an accepted no-local-rule view.

Deletion failures are counted and exported rather than silently discarded.
Cleanup commands can fail on already absent resources.
Independently verified postconditions can still establish completion.
If stop or observation fails, cleanup remains unknown regardless of apparent tool success.
This does not expand the existing destructive effect set or make cleanup atomic.

## Receipt representation and journal outcome

The opaque `cleanup` object in the lab probe receipt now contains:

| Field | Meaning |
| --- | --- |
| `leftover_resources` | Nonnegative integer only when all checked observations completed; otherwise JSON null |
| `status` | `complete` for verified zero; `incomplete` for a known positive count; `unknown` for an unavailable observation or unverified shutdown |
| `unverified` | Fixed redacted check labels: stop, units, account, policy, root, spool, database or resource_count; never raw errors/paths/SQL/credentials |
| `removal_failures` | Number of failed fixed deletion commands in this attempt; zero if deletion was not attempted |

The count covers one local account, one sandbox root, one policy-mapping group, and one spool path.
The count also includes DB user/schema row counts.
Any remaining matching unit makes the overall count unverified.
This is a bounded snapshot of checked resources, not a count of all host objects or a claim of containment.
Queries are sequential, not an atomic host snapshot.

Unknown/incomplete cleanup always yields `cleanup_incomplete`, even if application health passed.
That state retains the journal's existing new-probe block.
Administrative cleanup can close it only after verified zero, as `failed`, never `passed`.

Repeated incomplete administrative attempts keep the recorded receipt and finish time.
They do not claim to refresh observations.
Real SQLite tests cover persistence, restart, block retention and release through the actual administrative completion helper.

Normal outcome selection shares the same cleanup decision, with matching success/failure controls.

No operation state/code or seven-field RecoveryReceipt schema is changed.
Raw lab probe JSON and portable recovery receipts treat `cleanup` as an opaque object.
Export preserves its exact JSON value and seals its body digest.

No current console/parser/Python receipt consumer assumes an integer cleanup count.
New consumers must handle null and status explicitly.
Older stored receipts are not rewritten or retroactively verified.

A historical numeric zero is historical evidence with its original limits.
Product packages and external integrations need their own compatibility review.

## Local proof and remaining boundary

The original aggregation semantics, extracted behind a private host seam, fail the new fault cases before repair.
The fixed path passes focused tests with fake host observations/effects, actual safe temporary filesystem metadata checks, real SQLite and receipt export.
No `SystemCleanup` is instantiated in tests.
No administrative tools, source site, VM, signing key or planted corpus are used.
Private source mutations verify the guards matter.

F-05/D-012's hostile corpus, D-016 confinement, root content/archive traversal, credential-minimal worker phases, live cleanup/fault/race proof and independent recovery/review remain open.
See the [confinement study](EXECUTOR-CONFINEMENT-STUDY.md).

## Product restore probe (D-031)

A product build runs the lab probe phases under [D-031](../decisions/D-031-product-restore-probe.md) option B.
Task [W373](../validation/S10-W373/README.md) builds it and proves it on a fresh product host.
The admin helper derives every value from the journal and the bound projection. No request carries a path, account, unit, or argument.

| Phase | Product mechanism | Credential and network |
| --- | --- | --- |
| Bind and repository check | Unchanged from W320. A failure is a refusal before any sandbox exists | Fetch key, store namespace |
| Sandbox | The lab sandbox: `rp_<6 hex>`, `/srv/restore-probes/<account>`, level `s0:c950` | None |
| Size check | Worker action `restore-size`. It prints `restore-size <bytes> <files>`. The helper applies the 2 GiB and 200,000-entry ceilings | Fetch key, store namespace |
| Fetch | Worker action `restore`: one fixed `restic restore` into `<sandbox>/tmp/restore`, with no `security.*` attributes | Fetch key, store namespace |
| Repository check | The capture's `check` action, as the site account at the site level | Fetch key, store namespace |
| Inventory | The lab code without change | None. `PrivateNetwork=yes` |
| Import | [D-034](../decisions/D-034-probe-health-and-limits.md): the worker action `import` opens the dump as the probe and becomes the fixed `mariadb --sandbox` client with the dump on stdin. The helper watches the probe database size and stops the import over the cap | None. `PrivateNetwork=yes` |
| Health check | D-034: a fixed database facts reader, then the page render. PID 1 writes each stdout to `/run/rustiron-admin`, and root decides the verdict | None. `PrivateNetwork=yes` |
| Cleanup | The lab cleanup without change | None |

The two restore actions run as the probe account in `rustiron_capture_t` at `s0:c950`. Their units are named `rustiron-probe-<account>-<step>-<suffix>`, so cleanup stops and lists them like every other probe unit.
`ReadWritePaths=` names only the sandbox `tmp` folder of the `restore` unit.
`worker_arguments` refuses a site level, a name that is not a journaled probe account, or a snapshot ID that is not 64 lowercase hex digits.

The worker checks the same values again before it reads a secret.
The calling account must own the sandbox `tmp` folder.
The restore target must not exist.
The worker then checks the projection digest and the repository ID before restic starts.

The receipt schema is `rustiron-restore-probe/2`. `independent_copy_confirmed` is `not_run` ([D-026](../decisions/D-026-defer-offsite-and-escrow.md)).
The executor journals the outcome and the receipt that the helper reports. A lost or unreadable reply keeps the probe `running`.
To recover, stop the admin helper, the executor, and the coordinator. Then run `rustiron-executor probe-cleanup <operation>` as root.
Cleanup stops the probe units, also an import that still runs. It records `failed` with no check claimed. A product build writes the admin cleanup receipt with schema `rustiron-restore-probe/2`.
The receipt export of a probe without stored fields states all seven fields ([W374](../validation/S10-W374/README.md)).
