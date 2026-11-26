# Coordinator inventory v1

2026-10-24.
S01/W004 implements unprivileged coordinator state for R01/R02/R15 and the relevant schema-refusal part of R16.
This is metadata observation, not site adoption, provisioning, an executor registry or a recovery journal.
The signed re-adoption of [W372](../validation/S10-W372/README.md) records ownership in the executor journal only. The coordinator store does not change across an epoch rotation or a re-adoption, and an import into this inventory is still not an adoption.

## State and explicit initialization

Supply an existing canonical directory owned by the ordinary development UID, mode exactly 0700.
Fixed files are `control.sqlite`, SQLite WAL/SHM sidecars and `writer.lock`.
Main DB/lock ownership, regular-file type, mode 0600 and single link are checked.

Links/unsafe directories are refused.
Initialization requires all DB/sidecar names to be absent and never replaces an existing resource.
The persistent advisory lock covers the store lifetime, including offline tools.

It prevents cooperating Rustiron processes from becoming concurrent writers; it does not constrain a malicious process running as the same trusted UID.

An explicit init operation creates version 1 in one transaction: application ID, schema/user versions, inventory identity and the three tables `schema_version`, `inventory_meta`, `sites`.
It does **not** declare the host empty.
Until a complete report is imported, list/inspect return `DEPENDENCY_UNAVAILABLE`, exit 7.

Opening a store never creates a missing DB.
A read-only probe checks application ID, exact known schema, version and SQLite quick_check before writable setup.
Typed rows/provenance and record count are also checked.

Foreign, corrupt, incomplete, unknown/newer schemas fail without an empty fallback or automatic repair.
Version 0 is accepted only as the newly created file in explicit init; there is no automatic downgrade or existing-file migration.
Private coordinator lock/WAL bookkeeping may occur.

Refusal is not a claim of zero filesystem writes.

## Durability and query bounds

The connection sets and reads back WAL, synchronous FULL (numeric 2), foreign keys ON, trusted_schema OFF and a 250 ms busy timeout.
One connection is held behind a coordinator mutex.
Concurrent requests that cannot acquire it fail dependency-unavailable rather than queue indefinitely.
No lock is held while waiting for an IPC frame.
Imports are offline while the daemon is stopped.

Replacement validates a full report, deletes/inserts rows and advances revision in a single SQLite transaction.
Errors cannot acknowledge a partial replacement.
Selected failure/lock/preservation tests pass.

Effective PRAGMAs are not proof of physical power-loss, storage flush honesty, reset recovery or backups.
Those campaigns remain later work.
State belongs on a local filesystem suitable for [SQLite WAL](https://sqlite.org/wal.html), not a network filesystem.

## Report format and provenance

The closed JSON file permits at most 1 MiB, nesting 32, and 1,000 unique site IDs.
IDs retain the 64-byte bound.
Display values retain the 512-byte bound.

Timestamps use exact integers.
The count is a metadata DoS bound, not supported hosting density.
Duplicate members, unknown fields, positional records, partial reports, duplicate IDs and unexportable metadata are refused.

No ownership flag, SQL, config text, root path or execution instruction is accepted.

Example **synthetic** report:

```json
{"schema_version":1,"report":{"reported_at":42,"source":"operator_report"},"complete":true,"sites":[{"site_id":"site-a","name":"Fixture A","configuration_generation":"gen-a"}]}
```

`complete` declares the supplied report scope complete.
It is not evidence that the actual host has been exhaustively inspected.
Source/time are retained in each response's additive `inventory` provenance object.

Reported sites always have `ownership: observed_only`.
A supplied generation is `inferred` from the inventory when `reported_at` is within 300 seconds of the read, the same bound plan admission uses.
An older or future report time is `stale` and keeps that original timestamp.

A missing generation is unknown.
No package, OLS/PHP/MariaDB configuration, service or filesystem resource is adopted or repaired.
Select/redact metadata before import.

Arbitrary display text is not a credential detector.
Human output labels provenance and escapes terminal/bidi controls.
JSON preserves display data as data.

## Pagination and export

Reads use a consistent SQLite transaction and binary ID ordering, 1–100 rows per page, explicit null `next_cursor` at end.
Opaque cursors bind the random store instance, report revision, next offset and page size.
They work across a daemon restart.

Replacement, a different DB, changed limit or invalid bounds return `CURSOR_EXPIRED`, exit 4.
They do not silently restart traversal.
Cursor encoding is an implementation detail, not a signature or authorization capability.

Offline export returns a sorted, consistent versioned report with original provenance.
It is not a byte-for-byte SQLite backup, root authority manifest, replay ledger or independent recovery receipt.
Restoring old coordinator state does not establish freshness or protect executor epochs.
`rustiron state compare` checks exported site ids and names against a lab observation's `site_id` and `hostname` ([W075](../validation/S10-W075/README.md)).
A match is not adoption.
Since journal v20 ([W396](../validation/S10-W396/README.md), [D-045](../decisions/D-045-signed-admission-bytes.md)) a lab observation also carries `admissions` and `signed_objects`, the signed plan and grant bytes for the console. The compare reads only `sites`. The host-status merge keeps both members unchanged. The inventory import takes a report, not this document.

## Actual local commands

After the root README build/setup steps, use an ordinary account:

```sh
state_dir=$(mktemp -d /tmp/rustiron-state.XXXXXX)
target/debug/rustiron-control --state-dir "$state_dir" --init-state
```

Save an approved report in your own regular JSON file.
Substitute that absolute pathname for `OBSERVATIONS_JSON`.
These are offline commands with the daemon stopped.
A running writer causes an explicit failure.

```sh
target/debug/rustiron-control --state-dir "$state_dir" --import-observations OBSERVATIONS_JSON
target/debug/rustiron-control --state-dir "$state_dir" --export-observations
target/debug/rustiron state export --state-dir "$state_dir" --output json
target/debug/rustiron state compare --state-dir "$state_dir" --observation OBSERVE_JSON --output json
```

Start the coordinator with both `--socket` and `--state-dir`.
The socket follows the [private-directory/lifecycle guide](LOCAL-DEVELOPMENT.md).
Use the existing CLI's `site list --limit 20`, `site list --cursor TOKEN --limit 20` and `site inspect SITE_ID`, with `--output json` or `human`.

Inventory does not grant mutation authority.
Separately configured executor submission is described in [W062](../validation/S10-W062/README.md).
Omitting --state-dir retains the doctor and optional executor paths without an inventory store.

## Native-library version review

W004 originally recorded a bundle lag: published rusqlite 0.41.0/native binding 0.39.0 still include SQLite 3.54.0.
W011 now selects the unmodified official 3.54.1 static build through supported binding hooks, with independently published archive/source hashes and runtime source identity checks.
See the [verified native input](NATIVE-SQLITE.md) and its evidence.

No crate fork or host library upgrade occurred.
Coordinator startup refuses a different runtime tuple.
This closes the local development version deadline, not root/AlmaLinux journal, confinement, physical durability or recovery acceptance.

See [W004 evidence](../validation/S01-W004/README.md), [Roadmap](../planning/ROADMAP.md#roadmap-to-v10) and the maintained root handoff.
Distinct-UID, tenant confinement, VM reset, storage faults and physical durability acceptance remain unrun.
W004 does not close those security/recovery gates.
