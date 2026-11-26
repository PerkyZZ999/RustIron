# Local coordinator and CLI development

2026-10-24.
S01/W003 implements an experimental Linux-only, same-user inspection path.
It is local development software.

It does not install services, bootstrap the VM or adopt resources.
An optionally configured executor can receive signed submissions through W062.
The coordinator does not perform privileged effects itself.

W004 adds an optional [coordinator inventory](COORDINATOR-INVENTORY.md).
Without an attached reported store, site list/inspect return `DEPENDENCY_UNAVAILABLE` (exit 7), not fabricated empty inventory.
A validated attached store serves real persisted metadata.

## Reproduce the complete local smoke check

Use the ordinary development user, not root or a setuid invocation.
From the repository root:

```sh
rust-tc check
rust-tc quick
rust-tc doctor
python3 scripts/check_local_cli.py
```

First setup also needs `cargo fetch --locked` to populate the dependency cache before the isolated feature gate runs offline.
Python 3.11 or later is required for the standard-library lockfile reader.

The smoke script builds locked workspace binaries and starts the coordinator in its own mode-0700 temporary directory.
The script checks JSON/human doctor, malformed/oversized frames, eight-handler limits, disconnect recovery, and stale-socket refusal.
It terminates only its own test process and removes its own temporary directory.

It also verifies explicit inventory init/ import/export, list/inspect provenance, daemon restart, cursor expiry, competing writer denial and corrupt-store refusal.
Inventory fixtures are synthetic and are never adopted host resources.
Its JSON includes selected host observations and four sampled configuration hashes.

Equal hashes are not exhaustive proof that every host/network/service property stayed unchanged.

Rust tests also exercise parser/codec goldens, exact kernel peer-UID policy checks, unsafe/symlink socket paths, absolute read/write deadlines, unresponsive coordinator, request correlation and fixed canary-safe errors.
Distinct-UID live integration remains **not run** here: this session did not create users, change identities, use sudo or mutate the VM.
A mismatch against kernel-derived credentials is tested, but is not a substitute for that scenario.

## Manual inspection

Build with `cargo build --locked --workspace --bins`.
In the first terminal:

```sh
runtime_dir=$(mktemp -d /tmp/rustiron-dev.XXXXXX)
printf '%s\n' "$runtime_dir/control.sock"
target/debug/rustiron-control --socket "$runtime_dir/control.sock"
```

In a second terminal, replace `SOCKET_PATH` with the absolute pathname printed above.
For coordinator commands, `--socket` is a required top-level option, before the subcommand; `--output` defaults to `human` and may appear after the subcommand.

```sh
target/debug/rustiron --socket SOCKET_PATH doctor --output json
target/debug/rustiron --socket SOCKET_PATH doctor --output human
target/debug/rustiron --socket SOCKET_PATH site list --limit 20 --output json
```

Stop the foreground coordinator with Ctrl-C.
It does not automatically unlink its socket on exit or at startup.
Use a fresh private directory for another run.

Before removing a stale socket, verify its coordinator stopped and the path is your own test artifact.
Existing files/sockets are never overwritten by startup.
No `/etc/rustiron`, `/run/rustiron` or service identity is created.

The optional coordinator startup argument `--executor-socket PATH` enables `rustiron --socket SOCKET_PATH operation status OPERATION_ID --output json` and `rustiron --socket SOCKET_PATH evidence export RECEIPT_ID --output json`.
Evidence JSON is the coordinator response.
The receipt document is `data.value.receipt`.

It is self-attested, not independent proof ([W071](../validation/S10-W071/README.md)).
The executor endpoint must satisfy the root-owned socket and root-peer checks in [W057](../validation/S10-W057/README.md).
It is not supplied by the request.

Without that setting the query returns dependency-unavailable.
A read-only status query from `rustiron-build` reached the live root executor ([W092](../validation/S10-W092/README.md)).
A binding-refused submission was forwarded and not recorded ([W093](../validation/S10-W093/README.md)).

[W095](../validation/S10-W095/README.md) admitted one signed `blog13` capture through this path.
Status then read `succeeded`.
The coordinator is not installed as a product service. A lab-only unit runs it as `rustiron-build` on the lab VM ([W191](../validation/S10-W191/README.md)).

## Implemented identity and frame rules

- Both executables require effective UID = real UID, nonzero. The coordinator
  authorizes exactly its own UID.
The CLI expects that UID from the server.
Both use Linux `SO_PEERCRED`, not a request-asserted identity.
- The explicit absolute socket path must have an existing canonical parent
  directory owned by that UID with mode exactly 0700.
The CLI also requires a socket inode with matching owner and mode 0600, rejects links and checks the connected peer.
Filesystem checks alone do not authenticate the endpoint.
- Framing is a four-byte unsigned network-order length followed by one UTF-8
  JSON object.
Each sender half-closes its write direction after that frame; the receiver requires EOF, rejects trailing bytes and checks length before allocation.
The W002 JSON limits remain 256 KiB request / 1 MiB response.
- The CLI has a five-second absolute transaction deadline from connect through
  response.
Each accepted handler has a five-second absolute deadline.
Remaining time is checked before and after each read/write, so trickled bytes do not reset the budget.

OS scheduling can overshoot a timeout.
This is not a hard-real-time guarantee.
Connect is nonblocking.

A full backlog is treated as dependency-unavailable.
Backlog-flood load behavior has not been accepted.
- Eight handlers may run concurrently. Excess accepted connections close without
  a response.
Each handler releases its slot on completion/disconnect.
Kernel backlog, host CPU behavior, and flood fairness require separate acceptance.

A configured external executor receives signed submissions through the bounded W062 worker.
A disconnected client does not cancel it; unknown outcomes require reconciliation.
W063 adds the file-based CLI bridge.
- The CLI matches returned IDs and successful data kinds. Null IDs remain
  permitted for errors before reliable request parsing.
Usage/transport/parser errors use fixed public messages.
Raw argv, paths and OS/parser errors are not emitted.
JSON mode produces one object on stdout.
Human text is escaped.

This same-UID policy is for one trusted development account.
It does not prove separation from malicious code running as that account, future dedicated service identities, tenant confinement, root catalogue safety or production IPC ancestry.
Those retain their separately reviewed bootstrap and host-test gates.

## Create a site plan

`target/debug/rustiron plan create site-provision` writes one canonical `site_provision` plan to stdout.
The operator supplies the host, recipe, window, and the time they assert the site was absent.
If no limitation is given, the plan records an unobserved host.
With `--quota-block-hard-kib` and `--quota-inode-hard`, the plan is schema 2 ([W341](../validation/S10-W341/README.md)).
It then carries those hard quota limits for signing.
Without them, the plan is schema 1 and the executor applies its enrolled limits.

The command does not sign, submit, or inspect a live host.
A stale observation or a bad hostname exits 2.
See [W068](../validation/S10-W068/README.md).

`plan create site-eject` writes one canonical `site_eject` plan the same way.
The operator supplies the generation and digest.
The command does not observe those values.

A stale observation or a compensation window longer than 300 seconds exits 2.
The command does not eject a site.
See [W088](../validation/S10-W088/README.md).

`plan create config-activate` writes one canonical `config_activate` plan.
Repeat `--site-id` in sorted order.
The generation and digest are operator-supplied.

An unsorted or empty site list, or a stale observation, exits 2.
The command does not reload OpenLiteSpeed.
See [W089](../validation/S10-W089/README.md).

`plan create backup-capture` writes one canonical `backup_capture` plan for the lab PC store and the `site_files_db_v1` recipe.
Those two values are the only ones the closed contract allows.
The command does not read or copy the site.
A window longer than 3600 seconds, or a bad site id, exits 2.
See [W090](../validation/S10-W090/README.md).

`plan create restore-probe` writes one canonical `restore_probe` plan.
The operator supplies the site and a 64-character snapshot id.
The profile is `local_no_egress_v1`.

The command does not restore the snapshot or change the source site.
A window longer than 3600 seconds, or a snapshot id that is not 64 lowercase hex characters, exits 2.
See [W091](../validation/S10-W091/README.md).

## Review a plan offline

`target/debug/rustiron plan review-file PLAN_PATH --output human` reads a bounded local plan without a socket.
`--output json` returns the complete validated semantic plan and digest as data.
This review is not signature verification, approval or execution.
See [W065](../validation/S10-W065/README.md).

## Store a reviewed plan

`target/debug/rustiron plan import-file --plan-dir DIR PLAN_PATH` stores the canonical bytes of one validated lab plan in a private directory.
Repeating the same bytes reports `existing`.
Different bytes for that plan id are refused.

`plan export --plan-dir DIR PLAN_ID` writes those canonical bytes to stdout.
`plan inspect --plan-dir DIR PLAN_ID --output human` shows the same complete plan as file review, including the verb, digest, and `authority: none`.
A missing id exits 4 and does not echo the id.

Neither command signs, approves, or submits.
See [W067](../validation/S10-W067/README.md) and [W072](../validation/S10-W072/README.md).

## Apply a stored plan

`target/debug/rustiron --socket SOCKET plan apply --plan-dir DIR PLAN_ID --grant-file GRANT --signature-file SIGNATURE --operation-id OP --idempotency-key KEY` loads the stored canonical plan.
The grant's `plan_id` and `plan_digest` must match that plan or the attempt is not sent.
The CLI does not sign.
See [W069](../validation/S10-W069/README.md).

## Submit prepared files

With a coordinator started using `--executor-socket`, the local build accepts:

```text
target/debug/rustiron --socket SOCKET_PATH plan apply-file --plan-file PLAN_PATH --grant-file GRANT_PATH --signature-file SIGNATURE_PATH --operation-id OPERATION_ID --idempotency-key KEY --output json
```

The files must already be prepared and signed.
The CLI reads them locally and does not sign or approve.
The peer, authorization, durable intent and effects are executor responsibilities.

This is a development bridge for files that are not in the plan store.
Stored apply is [W069](../validation/S10-W069/README.md).
It is not an installed service or a verified admitted effect.

[W093](../validation/S10-W093/README.md) forwarded one closed fixture plan to the live root executor.
Binding was refused and the journal did not gain a row.
[W094](../validation/S10-W094/README.md) killed a coordinator after a root stub had received the bytes.

The CLI reported `outcome_unknown` and kept the operation id.
On an unknown outcome retain the operation ID and reconcile; `NOT_FOUND` alone is not proof that a retry is safe.
See [W063](../validation/S10-W063/README.md).

## Doctor observations

Only NAME/VERSION_ID from the fixed `/etc/os-release` file and kernel release/architecture via uname are read.
The release file has a 16 KiB read bound; display text retains the contract's 512-byte bound.
A conservative quoted-value parser never evaluates shell expressions and marks duplicate/malformed/missing fields unknown.
Missing VERSION_ID on a rolling system is not invented.

All values have provenance and UTC Unix seconds.
Missing access/data/time stays unknown.
`hosting_profile` and `site_confinement` are explicitly unknown/not checked, because OS metadata does not establish either acceptance.
These are additive v1 doctor fields: newer readers default them to unknown when omitted by an older server.
Older readers may ignore them.
No package/service/firewall/OLS, database, SELinux-policy or confinement repair is performed by doctor.

See [read contract](READ-PROTOCOL.md), [W003 evidence](../validation/S01-W003/README.md) and [Roadmap](../planning/ROADMAP.md#roadmap-to-v10).
W004 inventory has separate evidence.
W005 records S01 local acceptance.
Later product and host gates remain separate.
