# Restored-content inventory worker

2026-11-03, W167 implementation.
W168 dated AlmaLinux lab integration.
[Evidence](../validation/S10-W167/README.md).

## Boundary and fixed operation

The executor no longer recursively counts restored content as root.
After fetching, it launches the native `rustiron-restore-inventory` binary as the throwaway probe account through its existing fixed systemd runner.
The installed lab path is `/usr/local/libexec/rustiron-s07-lab/restore-inventory`.

The site root is derived from the admitted probe/site records.
The worker accepts exactly two arguments: the absolute restore target (`<sandbox>/tmp/restore`) and the site path below it (`srv/sites/<account>`, plain names only).
[W378](../validation/S10-W378/README.md) added the restore target, so the worker can see snapshot paths outside the site.
This private helper is not a new privileged verb, public command endpoint, arbitrary root walker or signing authority.

The worker refuses real UID zero and mismatched real/effective UIDs before opening input.
It opens every path component and descended directory relative to a directory descriptor with no-follow flags.
It enumerates `html` metadata and observes the fixed `tmp/rustiron-capture.sql` name.
It also lists each directory from the restore target down to the dump. Each entry beside the captured paths counts as one extra path (W378).

It reads no file contents, executes no site code and accesses no repository.
Only single-link regular files count.
Other file types, other devices and ancestor cycles refuse.

Opening a child must preserve its observed inode/device identity.
This is a bounded metadata observation, not an atomic snapshot, authenticity check or proof that content is safe.
Concurrent replacement remains a host-test obligation.

## Limits and report

The fixed limits are 100,000 entries, 64 descended directory levels, a 30-second cooperative elapsed-time budget, and a 4,096-byte JSON report.
Prefix path depth is also bounded to 64.
I/O may block between time checks.

The existing systemd 300-second runtime budget remains the external ceiling.
Entries include files and directories, excluding `.` and `..`.
Exactly reaching a count/depth bound can complete if no further work exceeds it.

The closed version-3 object has required members `schema_version`, `status`, `reason`, `files`, `dump`, `entries`, `max_depth`, `world_writable` (W222), and `extra_paths` (W378). Versions 1 and 2 are refused.
The nullable members must be explicitly present.
Status is `complete`, `error` or `limit`:

- Complete requires null reason and known file/dump observations. Zero files or
  a missing dump are known incomplete artifacts, not traversal errors.
- Error reasons are `io`, `unsupported`, `changed`, `identity` or `privileged`. `privileged` is a setuid or setgid regular file in `html/` or as the dump (W222), or a setuid or setgid folder in `html/` ([D-034](../decisions/D-034-probe-health-and-limits.md), [W383](../validation/S10-W383/README.md)).
- `world_writable` counts regular files with the other-write bit. It is reported, not refused; it is present only for `complete` and never exceeds `files`.
- `extra_paths` counts the entries outside the captured paths. These are entries beside `srv/sites/<account>` on the way down, beside `html` and `tmp`, and beside the dump.
  The worker counts each entry once and does not open, follow, or descend into it. Extra paths are reported, not refused.
  They count in `entries`, and `files` plus `extra_paths` never exceeds `entries`. The receipt's `artifacts_complete` scope states the count.
- Every directory on the site path must be listable by the probe account. An unlistable or linked one is an `io` error, because the worker cannot then count extra paths.
- Limit reasons are `entries`, `depth` or `time`.
- Error/limit results discard partial file/dump observations to null. The
  bounded counters describe progress, never completeness.

No paths, filenames, file contents or raw error strings enter the report.
Wrong argument count returns exit 2 and a fixed `INVENTORY_ARGUMENTS` diagnostic.
Identity refusal emits an error report and exits 2.
Other error/limit reports exit zero: zero means report produced, not inventory complete.

Root validates byte size, closed shape, version, counters and status/reason/ nullable consistency.
It reads the root-owned single-link output from its private runtime directory and removes it.
Launch, read, unlink, malformed or nonzero worker outcomes become unavailable inventory.
Crash-orphaned runtime output cleanup is not independently journaled by this change.

## Isolation and recovery outcome

The launch retains probe User/Group, empty capabilities, NoNewPrivileges, and strict system mounts.
Writes remain tmp-only, with private home/tmp/devices and restricted proc.
Budgets remain 512 MiB memory, no swap, and 32 tasks.

Inventory adds the existing capture SELinux domain/level, private network, deny-all IP policy, masked credential roots and removal of twelve named AWS/restic/credential-directory variables.
No fetch credentials are loaded.
These are tested arguments.

Effective PID 1 settings, label transitions and adversarial isolation need live proof.

Only a complete report with positive file count, present dump, successful fetch and repository integrity can run database import.
Only successful import can run WordPress health.
Unknown/error/limit reports make `artifacts_complete` unknown; import/health are `not_run`.

The seven recovery fields and cleanup blocking rules remain.
Lab and portable receipts include additive `inventory` metadata.
Older receipts export null.

A successful inventory does not pass the independent-copy, application consistency, confinement or cleanup gates by itself.

A product build runs the same inventory worker from `/usr/libexec/rustiron/jobs/restore-inventory` after the product fetch ([D-031](../decisions/D-031-product-restore-probe.md), [W373](../validation/S10-W373/README.md)).

## Installation and remaining proof

The helper is built without a new dependency.
[W168](../validation/S10-W168/README.md) installs it with the executor using the isolated [lab deployment](../../lab/dev/README.md).
Search-only ancestors above the restore target use traversal-only O_PATH descriptors, preserving no-follow checks without requiring directory listing.

Benign complete/error/depth-limit cases run under SELinux Enforcing.
Signed WordPress restore imports and passes health.
Unavailable helper reports unknown inventory, skips import/health and cleans up.

Those are dated normal/failure-path observations, not hostile corpus or general isolation acceptance.
No broad SELinux allow rule was added.
Historical six-binary release bundles remain frozen.

A future bundle needs a reviewed seven-binary profile.

Root relabel/provision/archive walks remain outside this fix.
D-016's proposed administration-helper split, D-012's unverified hostile corpus under D-018 participation, new-decoder fuzz coverage, live races, resource enforcement and production gates stay open.
