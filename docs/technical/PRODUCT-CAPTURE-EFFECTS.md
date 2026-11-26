# Product capture effects

Scope B01, B09 and B10. [D-025](../decisions/D-025-product-capture-effects.md) governs the product capture path.
[D-029](../decisions/D-029-product-write-gate.md) option B opens the write gate: a product build writes capture snapshots to the enrolled HTTPS S3 store.
The lab build keeps the gate closed.

## Current state

The product path admits a v2 capture durably and binds the journaled projection digest (W319).
The product helper re-binds the projection, passes the write gate, and runs the phase sequence below (W356, D-029).
[W371](../validation/S10-W371/README.md) records a signed product capture on a fresh product host with the shipped product build.
Recovery of a capture left `running` lists snapshots by operation tag through the same path (W321).
A product restore probe runs after its repository check under [D-031](../decisions/D-031-product-restore-probe.md). See the [product restore probe](RESTORE-CLEANUP.md#product-restore-probe-d-031) and [W373](../validation/S10-W373/README.md).

## Scheduled capture (D-035)

A standing capture grant ([D-035](../decisions/D-035-scheduled-capture.md)) uses the same capture path.
The executor first finds the run that the grant derives for the requested operation ID, then checks the window with its own clock.
After those checks, the capture is a schema 2 capture: the same destination check, intent, helper phases, outcome, and receipt.
The journal row holds the derived run grant ID and nonce, and the SHA-256 of the standing grant as `grant_digest`.
The intent expires when the window closes. A run that fails uses its window. The next window gives the next attempt.
[13-SCHEDULED-CAPTURE](../operator/13-SCHEDULED-CAPTURE.md) gives the operator steps, and [W386](../validation/S10-W386/README.md) the lab proof.

## Write gate

`PRODUCT_WRITES_ENABLED` in [`write_gate.rs`](../../crates/executor/src/write_gate.rs) is true in each build with `--cfg rustiron_profile="product"`, and false in the lab build.
The helper checks the gate right after the bind, and the worker `backup` action checks it before it opens a session.
The lab build therefore cannot run the product write path.
W371 removed the lab write-proof flag (`rustiron_write_proof`). The product profile alone now opens the gate, so the flag had no remaining effect.

The gate does not replace any other check. A capture still needs the enrolled projection digest, the store namespace and relay, the lock precheck and postcheck, and the per-object retention.
The write-failure rules below stay. The operator still enrolls each store explicitly. A host without an enrolled product backup projection cannot capture.
The [D-029 residual risks](../decisions/D-029-product-write-gate.md#residual-risks) stay open.

The lab capture ([capture launch](CAPTURE-LAUNCH.md)) runs the dump, marker, snapshot, check, find, manifest, and lock phases.
The lab store is cleartext HTTP on the host network, and the lab lock check signs S3 requests in the worker over HTTP.
The product build refuses all lab backup paths (W303).

## Phase sequence

The admin helper runs the sequence for one admitted capture. Every store phase uses the store namespace, the relay, and one fixed worker action.

| Step | Phase | Program and action | Credential | Network |
| ---: | --- | --- | --- | --- |
| 1 | Bind | Helper reloads trusted policy and compares the journaled digest | None | None |
| 2 | Store check | Executor store checks, then worker `repo-id` | Fetch | Store namespace |
| 3 | Lock precheck | Worker `lock`: bucket versioning and default COMPLIANCE retention | Capture | Store namespace |
| 4 | Dump | Fixed `mariadb-dump` of the site database (unchanged) | Site database only | None |
| 5 | Marker and freeze | Lab D-021 marker and optional serving freeze (unchanged) | Site database only | None |
| 6 | Snapshot | Worker `backup`: `restic backup` with the operation tag | Capture | Store namespace |
| 7 | Check | Worker `check`: `restic check --no-lock` | Fetch | Store namespace |
| 8 | Find | Worker `snapshot-tag` (W321) | Fetch | Store namespace |
| 9 | Lock postcheck | Worker `lock`, plus retention of the new snapshot objects | Capture | Store namespace |
| 10 | Manifest | Worker `dump` manifest (W203) | Fetch | Store namespace |
| 11 | Record | Executor journals the snapshot and receipt | None | None |

Steps 2 and 3 refuse before any write. A refusal there records `failed` with no snapshot.
Step 6 starts the snapshot write. After its worker starts, a failure leaves the capture `running` for reconciliation.

## Worker actions

Every store action runs in the existing product worker, not as a bare `restic` command.
Before network use, each action repeats the W313 checks: projection digest, exact CA bytes, static credential shape, and sealed input snapshots.
Each action that reads or writes the repository first requires the enrolled repository ID.
This closes the gap where a bare `restic` unit would trust a CA file and repository URL without checking them.

- **`backup SITE DIGEST OPERATION`** runs `restic backup` of the site root and the dump. It uses `--tag rustiron-op-OPERATION`, a fixed host name, `--no-cache`, and `-o s3.connections=2` within the relay's eight-connection limit. The capture credential and repository password are its only secrets. The worker reads the bounded restic summary. Its success line names the snapshot, counts, and new index IDs.
- **`check SITE DIGEST`** runs `restic check --no-lock --json` with the fetch credential. It passes only on exit 0 with one summary line that reports no error, no broken pack, and no index repair hint.
  The check reads every index and tree, so its time grows with the repository. It gets the 90-second deadline and the 100-second unit of the snapshot write ([W378](../validation/S10-W378/README.md)). A 15-second check failed at 36 snapshots.

W323 adds the `check` action and the `backup` action with a product write gate ([evidence](../validation/S10-W323/README.md)).
W356 adds the fixed backup command. A lab build refuses it before any secret read, network use, or restic start. D-029 opens it in product builds.
- **`lock SITE DIGEST [OPERATION INDEXES]`** reads `GetBucketVersioning` and `GetObjectLockConfiguration` for the enrolled bucket with the OS `curl`. It passes only when versioning is `Enabled` and the default retention is COMPLIANCE for at least the enrolled `retention_days`. The postcheck takes the operation and the index list from the write result. It checks the tagged snapshot, the named indexes, and their packs. Each date must be COMPLIANCE and cover the enrolled retention from the snapshot start. See D-025 items 1 and 2.

[W414](../validation/S10-W414/README.md) compares complete index listings before and after the write.
The store must list writes as soon as it acknowledges them. Keep other writers out of the enrolled prefix during capture.
The worker refuses a missing old index or a difference that disagrees with whether Restic wrote pack data.
After an ambiguous write it reports the known snapshot ID for settlement, when available.

W391 ([D-041](../decisions/D-041-retention-evidence-record.md)) makes the per-object read version-exact. For each written object, a `HeadObject` read names the current version ID, its lock mode, and its retain-until date. Then `GetObjectRetention` with that `versionId` must return COMPLIANCE with the same date. A version ID is 1 to 128 characters of `A-Z`, `a-z`, `0-9`, `.`, `_`, and `-`, and never `null`.
A passing `lock` prints closed lines to its output file: `bucket Enabled COMPLIANCE DAYS`, then with an operation one `object KIND ID VERSION COMPLIANCE UNTIL` line for each object. The runner refuses any other output as it refuses a failed unit.

W334 adds the `lock` action ([evidence](../validation/S10-W334/README.md)). The evidence gives the object selection, its limits, and the SELinux additions that `curl` needs.
W342 fuzzes the action's S3 reader and `curl` builders ([evidence](../validation/S10-W342/README.md)). The reader also accepts the `&#34;` and `&#39;` quote references that MinIO writes in listing `ETag` values.
Packs that an earlier capture wrote and this snapshot reuses keep only the retention that their own capture checked. After that retention ends, the backend authority review alone protects them.

The executor builds every action from the closed `WorkerAction` type ([store network](../../crates/executor/src/store_network.rs)). No request text chooses an action, path, tag, or argument.

## Credentials and network

- The capture credential (`aws` slot) reaches only steps 3, 6, and 9. The fetch credential (`fetch-aws` slot) reaches steps 2, 7, 8, and 10.
- The dump and marker phases keep `PrivateNetwork=yes` and hide both credential directories (unchanged).
- Each store unit receives only its four `LoadCredential=` copies, and its source directory is inaccessible inside the unit (W315).
- All sites share one relay and one endpoint. Per-site isolation at the store depends on per-site backend principals and repository prefixes. Backend review must prove that one site's capture credential cannot list, read, or write another site's prefix.

## Failure and recovery semantics

| Point | Recorded outcome |
| --- | --- |
| Bind, store check, or lock precheck refused | `failed`, no snapshot, known refusal code. Journal v18 stores the code (W391) |
| Dump or marker failed | `failed`, no snapshot (lab rule) |
| Snapshot started, then any failure or lost reply | `running` until reconciliation |
| Check, find, or lock postcheck failed | `running` until reconciliation |
| All steps pass | `succeeded` with snapshot ID, consistency label, retention, and manifest. Journal v18 also stores the retention evidence: the bucket days at steps 3 and 9 and each object version that step 9 read (W391) |
| Step 9 reads versions that do not name the written snapshot once | `running` until reconciliation (W391) |
| Recovery finds no tagged snapshot | `failed`, no snapshot |
| Recovery finds one tagged snapshot | `running` until the operator settles it |
| Operator settlement finds one tagged snapshot | `failed`, with the snapshot kept as unclaimed evidence (W366) |
| A recovery check fails | `running`, nothing recorded |

Recovery after a product write extends W321.
Recovery first checks that no capture or store unit is active.
When the write gate is open, recovery removes any leftover dump.
It then queries the enrolled repository for the operation tag.
An empty result settles the capture as `failed`.
A tagged snapshot or a lookup failure leaves the capture `running` for investigation.

Restic can retain a partial snapshot with the operation tag when it exits 3.
Repository structure and retention checks cannot establish whether restic read every source file.
Recovery needs durable evidence of a complete write before it can record success.

### Operator settlement (W366)

A capture with a tagged snapshot stays `running`, and one `running` capture blocks every new capture admission.
The settlement is the exit from that state. It never records `succeeded`.
Stop the admin helper and the executor first. Then run the settlement as root:

```sh
rustiron-s02-executor capture-reconcile <operation> --settle-unclaimed
```

The settlement uses the same fresh checks as recovery:

1. The journaled projection digest matches the current enrollment.
2. No capture or store unit of the site is active.
3. The store checks pass: credentials, endpoint file, namespace, route, ruleset, and relay listener.
4. The worker `snapshot-tag` finds the enrolled repository ID and at most one snapshot with the operation tag.

When the gate is open, the settlement also removes a leftover dump, as recovery does.
No tagged snapshot records `failed`, as recovery does.
One tagged snapshot records `failed`, and journal v14 keeps the snapshot ID in `capture_unclaimed`.
A failed check, or two snapshots with one tag, records nothing, and the capture stays `running`.
A capture that is not `running` returns its stored status, with no binding read and no store use.
The lab build refuses the option with `INVALID_REQUEST`.

The settlement does not run `restic check` or the lock postcheck.
A capture whose retention drifted can therefore leave `running`. The settled row makes no claim that needs these checks.

A replay of a settled capture replies `failed` with `unclaimed_snapshot_id` ([D-032](../decisions/D-032-power-cut-serving-and-reply-states.md)). Each `failed` capture replies `failed`, not `untouched`, and exits 5.
The receipt of a settled capture has `state` `failed`, `snapshot_id` null, and an `unclaimed_snapshot` object with `claimed` false.
Its `artifacts_complete` field is `unknown`. No restore, retention, or manifest claim follows from the unclaimed snapshot.
`check_receipt.py` refuses an `unclaimed_snapshot` beside a success claim or a snapshot ID.

The settlement uses the authority of the other admin recovery commands: root, the executor stopped, and the journal writer lock.
The settlement is not a signed verb, because it records no effect and claims nothing.
A truthful success after a lost reply needs a durable completion record that the helper writes before it replies (W366 option a). No code writes that record yet.
[W366](../validation/S10-W366/README.md) gives the design choice and the lab proof steps.

## Proof before enabling

| Proof | Observation | Lab evidence |
| --- | --- | --- |
| Lab store over HTTPS | Capture succeeds through the relay against a versioned, COMPLIANCE-locked bucket with a pinned CA | [W356](../validation/S10-W356/README.md); W363 journaled the success |
| Phase credentials | Each unit receives only its credential; the dump unit has no network and no credential | [W356](../validation/S10-W356/README.md) |
| Write failures | A refusal before the write can settle as `failed`. An interrupted write or lost reply leaves `running`. Reconciliation preserves `running` when it finds a tagged snapshot. The operator settlement records `failed` with the snapshot unclaimed | [W356](../validation/S10-W356/README.md): refusals and a killed check. [W363](../validation/S10-W363/README.md#case-2-write-failures): relay stop during the write, lost helper reply. Settlement: [W366](../validation/S10-W366/README.md) local tests and the [W367](../validation/S10-W367/README.md) lab proof |
| Retention | A post-upload lock check fails closed when the bucket default changes during the capture window (W226) | [W363](../validation/S10-W363/README.md#case-1-retention-drift) |
| Backend authority | With the actual principals: cross-site denial, no history or version deletion, no retention change, fetch cannot write, capture cannot write or delete `config` or `keys/` | [W344](../validation/S10-W344/README.md), [W363](../validation/S10-W363/README.md#case-4-backend-authority-with-two-sites), [W365](../validation/S10-W365/README.md#item-1-repository-identity) |
| Retained versions | Restore an approved snapshot from protected versions after current objects are overwritten (transport candidate) | [W363](../validation/S10-W363/README.md#case-3-retained-versions); [procedure](PRODUCT-S3-TRANSPORT.md#recovery-from-retained-versions) |

Each row has lab evidence. [D-029](../decisions/D-029-product-write-gate.md) is the recorded decision that opens the write gate for product builds (D-025 item 4).
[W371](../validation/S10-W371/README.md) proves the open gate on a fresh product host.
The [W363 limits](../validation/S10-W363/README.md#limits-and-open-items) list what the lab evidence does not show.

Real provider accounts, keys, and spending remain [human checkpoints](../AUTONOMY.md#critical-checkpoints).
