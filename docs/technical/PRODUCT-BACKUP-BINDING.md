# Product backup destination binding

Contract design, 2026-11-11. W304 implements the v2 Rust plan and grant decoders and their pure binding check.
W305 adds offline plan preparation and review. Trusted enrollment and execution remain pending. See the [W305 verification](../validation/S10-W305/README.md).

W306 checks v2 grants against separate offline review policy and exports the canonical grant bytes. See [grant review](OFFLINE-REVIEW.md#product-backup-v2).
W308 validates and hashes the HTTPS S3 candidate projection offline. See [W308 verification](../validation/S10-W308/README.md).

W309 checks that projection during grant review and reports the enrolled repository ID for the signed site.
W310 loads the pinned projection in the product executor. See [W310 verification](../validation/S10-W310/README.md).

This design applies D-005 and D-006 to product capture and restore probes. See the [decision register](../decisions/DECISIONS.md).

## Why bind the destination

Lab v1 uses the opaque `profile_digest` pin and a root-owned repository setting.
Changing that setting under the same pin can redirect the same signed request before admission. See the [W299 reproduction](../validation/S10-W299/README.md).
Journal v13 protects the interval after admission. See the [lab proof](../validation/S10-W301/README.md).
Product requests need both checks.

## Signed scope

Use closed schema v2 records for the two existing verbs. The other verbs keep their current schemas.
Both plans require `destination_id` and `destination_policy_digest`. Use a validated `Id` and a lowercase hexadecimal `Sha256Digest`.
Reserve `lab_pc_store` for lab v1. Use the `production` risk value in both product records.

| Verb | Plan target fields | Grant restrictions |
| --- | --- | --- |
| `backup_capture` | `site_id`, `destination_id`, `destination_policy_digest`, `recipe_id` | `verbs = [backup_capture]`, one matching site in `site_ids`, one matching ID in `destinations` |
| `restore_probe` | `site_id`, `destination_id`, `destination_policy_digest`, `snapshot_id`, `profile_id` | `verbs = [restore_probe]`, one matching site in `site_ids`, one matching ID in `destinations`, one full matching ID in `snapshot_ids` |

Keep the other fields, ID and time bounds, and scope checks from each verb's v1 record.
Each grant carries `max_operations = 1` and the digest of the entire v2 plan. That digest binds `destination_policy_digest` into the signed grant.

Keep the existing plan digest domain and SSHSIG namespace. The canonical `schema_version` inside each object distinguishes v1 and v2.
Reject mixed plan and grant versions, unknown fields, duplicate keys, and invalid scope. See the [canonical bytes contract](CANONICAL-BYTES.md).

The probe binds one explicit repository and full snapshot ID. The executor derives the repository for the signed site from enrollment.
The probe may fetch an explicitly approved snapshot from that repository without depending on local capture history. Manual recovery keeps its [independent path](MANUAL-RECOVERY.md).

## Offline preparation and review

Use `rustiron plan create product-backup-capture` or `rustiron plan create product-restore-probe` for v2.
Both commands require `--destination-id` and `--destination-policy-digest` from the operator-reviewed enrollment.
Capture requires `--recipe-id` with `site_files_db_v1` or `site_files_db_frozen_v1`.
Probe requires the full hexadecimal `--snapshot-id` and `--profile-id local_no_egress_v1`.
Use each command's `--help` for the required host, site, and time arguments.

Creation emits the complete canonical plan to stdout.
`rustiron plan review-file` displays the complete plan and digest in human or JSON form. `rustiron-plan inspect` displays a summary with the exact destination and target IDs.
The plan store also accepts v2 for local import, inspection, and canonical export.
The existing `backup-capture` and `restore-probe` creation commands emit lab v1 plans.

## Root enrollment and the digest

Start with one root-enrolled product destination per host. The requester supplies its ID and digest from an operator-reviewed enrollment export.
The offline review must show the actual signed site, destination ID, digest, and recipe or probe target.
The signer compares these values with an independently trusted copy of the enrollment. The export and offline review cannot grant authority.

Run `rustiron plan destination-digest PROJECTION --output json` to validate the HTTPS S3 projection and print `destination_id` and `destination_policy_digest`.
The command reads a bounded local file and checks the projection schema. Enrollment and live verification still require the host, route, repository, and credential facts.

### Product executor enrollment

The product profile reads `backup-destination.json` from the same trusted directory as `policy.json`.
The file must be an owner-only, single-link regular file within 16 KiB.
The executor opens the fixed leaf relative to the trusted directory descriptor.

To enroll the destination, set `schema_version` to `2` in `policy.json`. Keep the required host and signer fields.
Add a `product_backup` object with exactly `destination_id` and `destination_policy_digest`.
Use the ID and digest of the reviewed projection. The v2 policy requires both files and disallows a lab backup enrollment.
`packaging/enrollment-policy.py` writes this v2 policy from explicit values ([W374](../validation/S10-W374/README.md)). The [product store enrollment](../operator/10-PRODUCT-STORE-ENROLLMENT.md) gives the operator steps.

The executor validates the projection and compares its ID and computed digest with the pin.
A missing, unsafe, malformed, or mismatched file refuses policy loading.
The lab profile refuses host policy v2. Host policy v1 continues to load without product enrollment.

The existing read-only executor observation adds `host.product_backup_enrollment` for valid v2 enrollment.
It reports the destination ID and digest.
A product build writes capture snapshots to the enrolled destination ([D-029](../decisions/D-029-product-write-gate.md)). It also runs restore probes of them ([D-031](../decisions/D-031-product-restore-probe.md)).

### Destination projection and digest

Compute SHA-256 over `rustiron/backup-policy/v2`, one NUL byte, and the canonical JSON of the validated product policy projection.
The envelope uses the following fields.

| Field | Value |
| --- | --- |
| `schema_version` | `2` |
| `destination_id` | The enrolled ID |
| `transport_id` | A closed adapter and contract version selected by the host profile |
| `transport` | The adapter's validated, canonical effect parameters |
| `retention_days` | The enrolled day count |
| `capture_credential_profile` | Validated projection of the scoped upload credential profile |
| `fetch_credential_profile` | Validated projection of the scoped read-only credential profile |

The adapter defines the exact `transport` schema before it can ship.
W307 defines the [HTTPS S3 candidate projection](PRODUCT-S3-TRANSPORT.md#destination-policy-projection) for review.
Include repository identity and the rule for deriving the repository for each site.
Include the endpoint, transport trust, and enforced network allowlist.
The same validated adapter value supplies the projection and the fixed job arguments. Raw configuration or caller strings cannot choose those arguments.

The digest covers effective settings and excludes credential bytes and private keys.
Each adapter must define a closed credential profile projection. Include the profile ID, backend principal, approved scope, and root-owned credential selection rule.
Resolve and include those values even when enrollment refers to the profile by ID. Changes to that mapping produce a new digest.
Credential rotation under the same profile requires independent validation of the same principal, scope, and repository.
The existing `profile_digest` still binds the host profile separately.

## Standing capture grant (schema 3)

[D-035](../decisions/D-035-scheduled-capture.md) adds plan and grant schema 3 for `backup_capture` only.
The plan names 1 to 16 sites, the destination ID and digest, the recipe, and a window series (`first_window_start`, `period_seconds`, `window_seconds`, `max_runs`).
The grant repeats the sites, the destination, the window series, and the validity. The grant has no `max_operations` field.
[D-035](../decisions/D-035-scheduled-capture.md#bounds) gives the bounds, the run identity, and the admission order.

`rustiron plan create product-standing-capture` creates the plan. `rustiron plan review-file` lists every window.
The offline grant review accepts a schema 3 grant with the destination projection and reports the repository of each named site.
`rustiron schedule runs` lists the derived run identities offline.
A lab build refuses schema 3. A product build refuses a schema 3 plan with a schema 2 grant, and the reverse.

## Admission and recovery

W311 adds verification for both product v2 verbs at the executor socket.
The executor checks the kernel peer, open journal identity, closed scope, and validity window.
It verifies the SSHSIG over canonical grant bytes. It then checks the destination ID, digest, and signed site's repository against the loaded projection.

See [W311 verification](../validation/S10-W311/README.md).

W319 admits product v2 captures durably in steps 1 to 5 below. The admin helper re-binds the journaled digest and runs the store repository check.
Before D-029, snapshot effects were not enabled, and an admitted capture ended `failed` with `NOT_ADMITTED_FOR_EFFECT` and no snapshot.
See [W319 verification](../validation/S10-W319/README.md).
[D-029](../decisions/D-029-product-write-gate.md) opens the write gate in product builds. The helper then runs the [capture effects](PRODUCT-CAPTURE-EFFECTS.md#phase-sequence) ([W371](../validation/S10-W371/README.md)).
W320 admits restore probes v2 the same way. A failed bind or repository check stops the helper before it creates a sandbox. The probe then ends `failed` with a receipt that names the refusal.
See [W320 verification](../validation/S10-W320/README.md).
Under [D-031](../decisions/D-031-product-restore-probe.md), the helper then runs the [product restore probe](RESTORE-CLEANUP.md#product-restore-probe-d-031) ([W373](../validation/S10-W373/README.md)).

The following order describes the full product admission path.

1. Resolve the peer and load the trusted host policy. Decode the plan and grant, then verify exact binding, validity and SSHSIG against enrollment.
2. For an authenticated exact replay, return the stored status. Compare operation ID, idempotency key, plan digest and grant digest. A conflict remains a replay refusal.
3. For a new operation, resolve the signed destination ID under trusted policy. Compute the digest and compare it with the signed digest. A missing or changed destination fails before intent and leaves replay history untouched.
4. Check the operation's site and runner preconditions. Store the matched digest, intent and replay consumption in the admission transaction.
5. Before repository use, the helper or capture reconciliation must resolve policy under the same host and epoch. Use the journaled digest to verify the resolved policy.

A refused product submission carries stored status only for the enrolled requester peer, as a status query does.
See [W329 verification](../validation/S10-W329/README.md).

Use the v13 policy digest tables for step 4. A product digest includes its destination ID and a distinct hash domain.
If policy changes after admission, the helper refuses before launch. Capture reconciliation leaves any uncertain result unresolved until the admitted policy is available again.
Probe cleanup remains scoped to journaled sandbox resources and needs no repository access.

Lab builds continue to accept lab v1. Product builds must refuse lab backup v1 before intent.
Neither build may fall back to the other version. Historical status queries stay readable, and no migration fabricates a missing policy digest.

## Verification required before product effects

| Case | Required observation |
| --- | --- |
| Canonical identity | Independent v2 vectors match plan digests and signed grant bytes. Existing v1 vectors still match. |
| Scope and version | Refuse cross-version, cross-site, cross-destination, altered digest, mismatched snapshot, and lab scope on the product path. |
| Policy changes before intent | Under a fixed host profile pin, a changed endpoint, repository identity, network scope, retention, or credential profile refuses the original signed request. No row or admission mark changes. |
| Policy changes after intent | The same change after admission stops both helper jobs and prevents reconciliation from consulting another repository. Status-only replay starts no job. |
| Target-host operation | Show signed capture, read-only restore fetch, credential-free contained restore, backend source no-delete rights, and cleanup with the selected adapter. |

Provider, transport, retention authority, and production key custody remain under the [human checkpoints](../AUTONOMY.md#critical-checkpoints).
The design defines the signed boundary. Product authority requires the selected adapter and operational proof.
