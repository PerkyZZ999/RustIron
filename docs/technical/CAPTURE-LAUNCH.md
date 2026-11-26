# Capture phase credentials — W166

2026-11-03.
Local implementation.
Live target-profile validation remains open.
[Evidence](../validation/S10-W166/README.md).

The capture runner now uses a closed internal phase enum.
It cannot combine an arbitrary phase name with an unrelated network flag.
The actual [launch builder](../../crates/executor/src/capture.rs) constructs arguments used by the production path.
It is not an exported executor API or new verb.

| Phase | Program/action | Credential file selection | Network/command restrictions |
| --- | --- | --- | --- |
| Dump | Fixed `mariadb-dump`, this site's `--defaults-file` | No `LoadCredential`, repository environment or credential mount requested; only site DB config is needed | Private network, all IP denied; credential roots hidden; named repository/AWS environment variables explicitly unset |
| Snapshot | Fixed `restic backup` | Enrolled site `aws` upload identity plus `repo.password` | One enrolled store IP; existing scoped repository/account path and operation tag |
| Check | Fixed `restic check --no-lock --no-cache` | Enrolled site `fetch-aws` identity plus `repo.password` | One enrolled store IP; no repository lock write requested |
| Find | Fixed `restic snapshots --no-lock --no-cache` | Enrolled site `fetch-aws` identity plus `repo.password` | One enrolled store IP; operation-tag lookup, then the same read-only check |

`fetch-aws` is the existing restore-fetch credential name, not a new provider or credential format.
Its intended backend role is read-only.
Selecting that file locally does not prove the provider enforces its permissions.

Require actual backend denial/restore evidence before making a live least-privilege claim.
Snapshot keeps the existing source no-delete/prune design.
Repository phases also remove eight named ambient identity/password/config variables so the explicit credential-file and repository assignments are not overridden by those variables.

Read-only commands use `--no-lock` because creating/removing repository locks would require write authority.
They remain subject to repository mutation/outage races: failed checks remain uncertain and do not turn into a successful capture.
This work does not introduce repository pruning or concurrent capture admission.

Every phase retains site UID/GID, capture MCS domain, empty capabilities, and `NoNewPrivileges`.
Mounts remain strict, with site tmp writes, private tmp/devices, and protected home/proc.
Budgets remain **600 seconds**, 512 MiB memory, zero swap, and 32 tasks.

Stdout remains an executor-owned runtime file, read through the existing 4 MiB bounded reader.
The timeout/output mechanics are unchanged.
Phase/action/program mismatches and another site's DB-config prefix are refused before the output-directory/launch path.

For Dump, `InaccessiblePaths=-/etc/rustiron-s07-lab/sites -/run/credentials` requests masking credential directories if they exist.
Absent paths are allowed.
`UnsetEnvironment` removes the twelve named AWS/restic/credential-directory variables listed in the builder.

It is not a universal environment scrubber or proof that hostile same-UID processes cannot reach secrets through other paths.
The relevant upstream final environment-removal semantics and path masking are in [systemd.exec](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.exec.xml), checked 2026-11-03.
Actual target-version mounts, environment, namespaces, process identity and secret/network denials still need the disposable Alma10 campaign.

No system service was launched by this task.

## Enrollment before new capture intent

New capture now requires all three files (`aws`, `fetch-aws`, `repo.password`) under the enrolled root-owned per-site credential directory.
Metadata-only checks require regular single-link files, exact owner, private mode, owner read permission and size 0–4096 bytes, without following links or reading secret contents.
They establish safe file shape, not valid key/password contents or backend rights.

Empty synthetic input is not proof that a real credential works.
Missing/unsafe input refuses the existing dependency precondition before intent; this intentionally tightens the old two-file readiness check.
Existing lab hosts must be inspected before deployment.

No existing enrollment is assumed.

The production wrapper fixes owner UID to zero.
A private parameterized helper allows local tests against temporary files owned by the test process.
It does not allow a request to choose credential paths or owner UID.
PID 1 later loads the selected enrolled credentials for the matching worker.
Changes between preflight and use, or root/policy compromise, require separate host proof.

## Validation and remaining scope

Thirty-one focused tests inspect the actual argument builder, real capture and reconciliation phase sequences, command/phase refusals and synthetic file metadata cases.
Fifteen private guard mutations compile and fail their intended assertions.
Tests read only synthetic temporary files and never launch systemd, access live credentials or contact a repository.

No signing authority, five-verb catalogue, journal schema, request/response version, dependency or global host policy is changed.
This is a launch-profile change requiring live compatibility/denial proof before pilot promotion.
D-012/F-05 hostile restore, D-016 confinement, root content traversal and independent recovery/human review remain open.

## Backup policy binding in journal v13

New capture and restore probe intents store a digest of the validated root-owned backup policy in the admission transaction.
The digest covers the destination ID, repository base, store address, and retention days.
SHA-256 takes the `rustiron/backup-policy/v1` domain and one NUL byte, followed by the canonical JSON of those fields.

The helper requires the current policy to match the journaled digest before it starts a capture or probe.
Capture reconciliation requires the same match before it looks up a snapshot by operation tag.
Missing or different bindings fail the precondition. An unresolved capture from an earlier schema stays unresolved.
Historical operations remain readable, and exact signed replays return their recorded status.
The [W300 evidence](../validation/S10-W300/README.md) records the test and migration rehearsal.
