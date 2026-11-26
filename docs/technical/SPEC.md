# Rustiron Core specification

Updated: 2026-11-13.
Owner-approved Core contract with D-018 scope and participation addendum.
Implementation and scoped proof are tracked in [STATE](../STATE.md) and [VALIDATION](../planning/VALIDATION.md).

Requirements below are not completion claims.
The [brief](../PROJECT_BRIEF.md) supplies product intent.
Accepted choices live in [DECISIONS.md](../decisions/DECISIONS.md).

[ARCHITECTURE.md](ARCHITECTURE.md) explains mechanisms.
Requirement IDs below are the MVP contract for review.
Future gates and features are in [Roadmap](../planning/ROADMAP.md#roadmap-to-v10).

## Product scope and participation

The [Project Brief](../PROJECT_BRIEF.md) requires CyberPanel workflow replacement and Node.js/Bun app deployment and management.
D-018 selects mature-service orchestration and reduces routine human participation.
The [autonomy policy](../AUTONOMY.md) governs those checkpoints.

The M1 Core baseline started with six verbs (with [D-030](../decisions/D-030-re-adoption-verb.md) adding read-only `site_readopt`), and subsequent accepted decisions (D-053 through D-100) expanded the closed v1.0 privileged catalogue to 23 typed verbs while keeping arbitrary commands, SQL, config text, and generic root runners forbidden.
New DNS, mail, firewall, app, and tenancy effects require their own reviewed contracts before implementation.
The roadmap retains all P01–P29 and CP01–CP08 acceptance work.

An agent can verify manual recovery without Rustiron.
Physical independence and recovered custody remain required.
Production signatures and critical human security acceptance remain separate.

## Delivery and claims

Proposed MVP exit: **verified experimental Core proof**, satisfying G1–G3 and S01–S10.
The operator inspects a fresh supported candidate and provisions one disposable WordPress fixture.
The operator reviews/applies bounded plans and receives truthful interrupted outcomes.

The operator captures encrypted off-host artifacts, tests contained restore, and demonstrates independent manual recovery.
Eject preserves serving data.
Use a second fixture to test compromise boundaries.

An unconfined host, synthetic-only signer, same-host backup, incomplete real key recovery or untested manual recovery cannot pass the MVP.
Live pilot requires G4 obligations after MVP.
No public management listener, console, MCP, automatic production migration, multiple runtimes/hosts, source-side prune, arbitrary SQL/shell or destructive site deletion is enabled by this scope.

## MVP requirements and traceability

`Txx` identifies a planned acceptance campaign in [VALIDATION.md](../planning/VALIDATION.md).
`Sxx` identifies a delivery slice in [ROADMAP.md](../planning/ROADMAP.md).
Campaign acceptance is partial.
See State and the S10 audit.

| ID | Required behavior / acceptance | Slice | Verification |
| --- | --- | --- | --- |
| R01 | Inspect host and resource ownership read-only; label observed, inferred, unknown and stale information; no automatic adoption or repair | S01 | T01: file/process/network snapshots show no managed-state effects; unavailable checks remain unknown |
| R02 | Local human/JSON CLI and versioned bounded IPC; fixed errors/exit codes; unauthorized peers cannot inspect secrets or mutate | S01, S02 | T01, T02: goldens, malformed/slow/oversize frames, peer denials |
| R03 | Immutable canonical plan binds exact semantic changes, target/profile, observations, blast radius, risk, artifact versions, expiry and compensation | S02 | T03: canonical vectors, parser ambiguity and single-field tampering denied |
| R04 | Executor independently verifies scoped human authority, epoch/time/replay/budgets; agent and coordinator cannot sign or expand grants | S02 | T03: replay, cross-host/site/verb, clock, custody and scope attacks |
| R05 | Six fixed privileged verbs only (D-030 added `site_readopt`, which records only); independent registry/path derivation; no root tenant-code execution or generic passthrough | S02–S08 | T04: operation abuse, command/config/env/SQL injection; audit effective UID at content execution |
| R06 | Durable admission and step intent precede effects; exact retry returns existing outcome; uncertain state blocks affected resources | S02, each mutation slice | T05: crash/reset/full-disk/read-only/corrupt-store at each boundary, concurrent duplicate submissions |
| R07 | Enforcing, measured per-site file/DB/process/socket/secret and resource boundaries; no site access to Rustiron IPC | S03, S04 | T06: adversarial fixture A versus B, descendant/resource exhaustion and MAC/domain tests |
| R08 | Fresh fixture provisioning has pinned verified artifacts, private credentials/temp/session, site-user install and repeatable results | S04 | T07: two independent clean provisions, injected tool/package failures, WP checksums and identity |
| R09 | Explicit trusted OLS adoption, disabled WebAdmin, deterministic minimal includes; drift refused; syntax + effective identity + all-site health gates; tested LKG compensation | S05 | T08: invalid/wrong-host configs, ancestry races, activation/probe/revert failures and `.htaccess` bounds |
| R10 | Established sites serve while management is stopped; eject/export preserves data, serving configuration and security prerequisites | S06 | T09: both services stopped/killed, eject and uninstall rehearsal; HTTP/content/private-cache probes |
| R11 | Encrypted off-host backup, scoped backend no-delete rights and separate retention authority; document file/DB capture consistency. Off-host means outside the managed VM, under a principal that the host cannot use; physical independence follows D-026 ([D-040](../decisions/D-040-m1-closure-scope.md) item 1) | S07, S09 | T10: restore/read/integrity checks, source delete/prune denials, repository outage, capture-skew/DB cases |
| R12 | Restore hostile artifacts only in a new unprivileged bounded sandbox without egress, production/repository secrets or host access | S08 | T11: traversal/links/special files/bombs/callbacks/credential probes and cleanup |
| R13 | Independent physical off-host copy and clean-host restore without Rustiron, using recovered credentials; manual runbook and measured RPO/duration | S09 | T12: source unavailable, independent recovery-runner replay, key loss/recovery and independent evidence |
| R14 | Export seven separate scoped recovery fields, artifact hashes, identities, limitations and truthful outcomes; local root logs are not immutable proof. Receipts carry a host-key signature that `check_receipt.py` verifies; each receipt states that it is self-attested ([D-042](../decisions/D-042-host-receipt-key.md)); independent anchoring follows D-026 | S07–S09 | T10–T12: fail/unknown cases remain distinct; receipt schema and provenance validation; signature verification and tamper refusal |
| R15 | Secrets excluded from plans/logs/argv/results; diagnostics bounded/redacted; site-origin content remains untrusted data | S01 onward | T13: canary credentials, malicious terminal/log/agent content, unauthorized diagnostic access |
| R16 | Store/schema migration, consistent state export and corrupt/newer-version refusal preserve replay/ownership; recovery rotates host epoch before mutations | S02, S06, S09 | T05, T09, T12: interrupted migration, stale DB/VM replay, export and recovery |
| R17 | Preserve failed benchmark; measure correctness, control-plane overhead and comparative operator value with preregistered fair trials | S10 | T14: eligible cohort results/raw samples and operator-task trials; no unsupported superiority claim |
| R18 | Document exact candidate matrix, evidence and limitations; no live pilot before independent human review and operational gates; human owner controls promotion | S10 | T15: requirements/evidence audit, explicit experimental status and G4 blocking checklist |

An unmet row blocks MVP acceptance.
An implementation defect cannot be resolved by changing a requirement or marking a test waived without explicit scope review.
First-slice work items are W001–W006 in [Roadmap](../planning/ROADMAP.md#roadmap-to-v10).
Later work items are created immediately before their slice, retaining these IDs.

## Domain records and ownership

Use opaque random IDs for host, site, plan, operation, step, artifact and grant.
Server IDs are never paths.
The trusted host identity includes a root-enrolled epoch.
Cloning/recovery must not silently duplicate authorization identity.

| Record | Minimum content / owner |
| --- | --- |
| HostProfile | Exact OS/architecture/kernel/filesystem/package/tool/policy versions, approved recipes, checker and launch behavior; root policy |
| Site / OwnershipManifest | Opaque ID, created/adopted provenance, UID/GID, scoped DB/socket, owned ancestry and generations, dependencies, resource budget, lifecycle; root registry authoritative |
| Observation | Resource identity, value/hash, timestamp, source and completeness; coordinator stores, executor re-observes |
| Plan / Step | Version, intent, canonical digest, observations/preconditions, fixed verbs and recipe versions, artifacts, expected writes/effects, verification and compensation; immutable after compilation |
| ApprovalGrant | Issuer/requester identities, host/epoch, exact plan digest, resource/verb set, nonce, validity and bounded effects/compensation; external signer |
| Operation | Idempotency key, plan/grant binding, status, durable step intents/outcomes, blocked resources, diagnostic references; executor authority for effects. Journal v20 ([D-045](../decisions/D-045-signed-admission-bytes.md)) also keeps the exact canonical plan and grant bytes with the verified issuer and signer-policy epoch, never the signature. Journal v21 ([D-053](../decisions/D-053-site-import.md)) keeps the signed dry-run facts of a site import and its six import steps, inside the provision's Recipe step |
| RecoveryReceipt | Snapshot/artifact IDs and hashes, capture/test times, source and restore identities, seven evidence fields, RPO/duration/limits and attester; exported portable record |

Ownership is `created`, `explicitly_adopted`, `observed_only` or `unknown`.
The last two cannot be mutated.
Read-only drift reporting offers an explanation; it does not reconcile.
Existing CyberPanel parent configurations are never automatically adopted.
Initial OLS parent adoption is a reviewed new-host bootstrap procedure with an export and exact ownership manifest.

## Privileged operation catalogue v1

The original M1 Core baseline below defined six semantic verbs: five mutation verbs and `site_readopt` (D-030).
Subsequent accepted decisions (D-053 through D-100) added 17 closed, individually reviewed verbs for site import/clone/update/delete/retire, certificates, aliases, DNS zones/changes, reverse proxies, Node.js/Bun apps, and credential rotation (23 fixed verbs total in `crates/contracts/src/approval/prepared.rs`), governed by their respective technical contracts.
`site_readopt` records ownership after a read-only verification and changes nothing on the host.
Inspection and receipt retrieval are bounded queries, not additional generic operations.
Every verb requires a signed plan and preconditions, including nonproduction applies.
Production/destructive applies are disabled in the experimental MVP host policy.

| Verb / typed input | Fixed effect and verification | Specific refusal / compensation |
| --- | --- | --- |
| `site_provision(site_id, approved_recipe_id, hostname)` | W372: an existing account or group of the derived name, or an existing site root, is refused before intent (`PROVISION_COLLISION`) and records nothing. Reserve root-derived site identity/paths, set and read back the per-site user quota on the site uid before any directory exists (D-028; W335), create scoped DB identity, install pinned fixture via site-user recipe, verify credentials/identity/checksums; no traffic activation. Plan schema 2 signs the hard limits (`quota_limits`); schema 1 uses the enrolled policy limits. The Directories intent records the limits and their source (W341). W399 ([D-047](../decisions/D-047-provisioned-site-install.md)): the product profile admits only `wordpress713_install_v1`; its Recipe step installs WordPress as the site account in its sandbox, and the generated `rustiron_admin` password goes only to `private/rustiron-admin.txt` (0600 `root:root`); Verify requires the `siteurl` option and the `rustiron_admin` login for the install recipe, and no tables for the unpack-only lab recipe ([W399](../validation/S10-W399/README.md)) | Unknown recipe, collision or foreign resource denied; schema 2 limits above the enrolled quota, or without an enrolled quota, are refused before intent; the product profile refuses schema 1 and the unpack-only recipe `wordpress713_v1` before intent (`FIXTURE_BINDING_DENIED`, W399); a failed install fails the Recipe step and quarantines the provision, so activation never serves it; a sites filesystem without enforced user quota is refused (`SITE_QUOTA_UNAVAILABLE`) when a quota is enrolled; partial allocations retained/quarantined with explicit status, never recursively removed |
| `config_activate(site_id, settings, expected_generation)` | Render approved semantic settings against root registry; stage/check/switch/recycle/probe all registered sites; record generation. Plan schema 2 adds one closed page-cache opt-in (`page_cache`: a served site, recipe `litespeed_cache_793_v1`, its archive digest); the intent records the opt-in (journal v15), the site gets its own cache storage in this and every later generation, and after the probes the admin helper installs the pinned plugin as the site with fixed scripts, fixed settings (page cache off) and no network ([PAGE-CACHE](PAGE-CACHE.md), [W368](../validation/S10-W368/README.md)). W370: the fixed settings add `cache-exc_qs` and are locked by a fixed must-use file; an opted-in vhost also renders a post-password `modcache:0` rule, and every other vhost renders the cache module off (`ls_enabled 0`). Plan schema 3 adds one closed page-cache opt-out (`page_cache_opt_out`: an opted-in site and its recipe); the intent records it (journal v16), the site's vhost renders the cache module off, and after the probes the admin helper deactivates the plugin as the site and empties the site's own cache storage with a closed job that runs as the OLS account. A later schema 2 plan re-enables the site and reuses the pinned tree after the same checks ([W370](../validation/S10-W370/README.md)). W395 ([D-044](../decisions/D-044-cache-on-recipe.md)): recipe `litespeed_cache_793_cache_on_v1` is the same plugin with the fixed settings and lock that turn the page cache on; its `recipe_digest` is the SHA-256 of a fixed manifest that names the archive, checksum list, settings and lock digests; the intent records the recipe (journal v19, `page_cache_recipes`); after activation an anonymous `GET /` must be stored and then served as a public `hit`; the helper replaces the lock file only when it holds the other recipe's exact lock; the opt-out must name the recipe of the site's opt-in, and the observation states `cache_on` ([W395](../validation/S10-W395/README.md)) | A page-cache opt-in for a site outside the predecessor generation or already opted in, and an opt-out for a site that is not opted in or that the lab policy lists for storage, are refused before intent (`PRECONDITION_CHANGED`); a recipe digest other than the executor pin is refused (`FIXTURE_BINDING_DENIED`); an opt-out that names another recipe than the site's opt-in is refused before intent (`PRECONDITION_CHANGED`, W395); a failed plugin step deactivates the plugin and takes the single signed restore; the single signed restore of any page-cache change, inline or through `compensate OP --admin-helper`, also deactivates the plugin and empties the site's storage, and a failed removal leaves the operation unverified (W370); No raw directives/paths/commands; drift denied; the generation checks refuse before intent in both modes and judge the `current` that matches the plan predecessor ([W359](../validation/S10-W359/README.md), [W360](../validation/S10-W360/README.md)); only a verified activation establishes a generation: an `untouched` or `failed_compensated` operation keeps the generation established before it, and from an empty history it re-establishes only the bootstrap generation (W360); in the product profile an empty history establishes the bootstrap generation, so a `current` present while the history is empty is unexplained drift: the activation refuses it before intent, `ols-status` reports `explained_by_journal: false`, and reconcile and compensate refuse it (`OLS_DRIFT`) with no record; a present `current` that names the bootstrap generation is never explained, in both profiles; the lab profile keeps the W021 rule, under which an empty history establishes nothing ([W362](../validation/S10-W362/README.md)); a drift refusal recorded after intent exits 4 (W360); a render equal to the current generation is refused before intent (`OLS_GENERATION_CURRENT`, exit 4; W289); only signed LKG switch and bounded recycle may compensate, and reconcile reloads and compensate restores only a predecessor that the history before the operation explains (W362). Bootstrap (W355): on a host with no `current`, the plan names the empty generation as predecessor; only when every bootstrap fact holds does the helper start OLS instead of reloading it, and the compensation stops OLS and removes `current` ([W355](../validation/S10-W355/README.md)). Bootstrap reconcile (W382, [D-033](../decisions/D-033-bootstrap-crash-settlement.md)): `reconcile` of a bootstrap operation asks the helper for the read-only `ols_bootstrap_confirm` step (no `current`, OLS stopped, both ports closed, the parent reviewed, the history before the operation) and records the empty generation only for a bare `ok`: `untouched` without the restore mark, `failed_compensated` with it; a refusal records `needs_attention`, and a binding refusal records nothing. OLS starts only when the `current` link exists (`ConditionPathIsSymbolicLink` in the shipped drop-in), so a host with no generation has no restart loop. Staging (W384): the target is written in a temporary sibling folder `generations/<id>.staging-<random>`; each file and the folder are synced and read back, and only then the folder is renamed to its id without replacing an entry and `generations` is synced, so a power cut leaves at most a temporary folder, which nothing reads or deletes. A folder under the id is reused only when its files equal the render; a root-owned folder with other files is never trusted: it is renamed to `<id>.quarantine-<operation>`, never deleted, and the target is staged again; any other entry under the id is refused (`PROVISION_COLLISION`) and the operation records `untouched`. The rename takes only the verified folder: a link or another folder under the temporary name, or under the id after the rename, is refused (`PROVISION_COLLISION`) before the effect mark ([W394](../validation/S10-W394/README.md)). The executor log has one `ols_stage` line for each staging. `reconcile` of a running activation without the effect mark asks the helper for no step, because the helper allows only the preflight in that state: when `current` is the journaled predecessor that the history before the operation explains, it records `untouched`; before W384 it asked for the reload, the helper refused it (`FIXTURE_BINDING_DENIED`), and the row stayed `intent` ([W384](../validation/S10-W384/README.md)) |
| `backup_capture(site_id, destination_id, capture_recipe_id)` | Verified quiescence/consistency window, scoped file/DB export, encryption/upload, integrity evidence and service restoration | Destinations/recipes are root-enrolled; no prune/delete; capture failure cannot claim consistency; resume only recorded site processes through fixed recipe. Product plan and grant schema 3 is a standing capture grant ([D-035](../decisions/D-035-scheduled-capture.md), [W386](../validation/S10-W386/README.md)): 1 to 16 named sites, the enrolled destination digest, and at most 35 signed windows; the executor derives each run identity from the grant digest, refuses an identity that is not a run of a named site (`STANDING_RUN_MISMATCH`) and a run whose window is not open at its clock (`STANDING_WINDOW_CLOSED`), both before intent and exit 3; the journal consumes each site's run in each window once; a lab build refuses schema 3. Journal v18 ([D-041](../decisions/D-041-retention-evidence-record.md), [W391](../validation/S10-W391/README.md)) stores, with a product success, the bucket default days at the lock precheck and postcheck and each written object's version ID, COMPLIANCE mode and retain-until time as the postcheck read them; and with a refused capture its refusal code. The receipt states `retention.status` `recorded` with each version, or `not_recorded` for a row without them, and `refusal` for a refused capture |
| `restore_probe(site_id, snapshot_id, sandbox_profile_id)` | Separate credentialed fetch, then credential-free hostile restore/application probes in a new local sandbox; export evidence and cleanup | No in-place site overwrite, host mounts or caller image/entrypoint; false/unknown independence stays explicit; cleanup only root-registered sandbox resources |
| `site_readopt(form, site_id or site_ids, previous_epoch, evidence_sha256)` | Records, in the current journal, ownership of a resource that already exists after an epoch rotation ([RE-ADOPTION](RE-ADOPTION.md), [W372](../validation/S10-W372/README.md)). Site form: the executor reads the account files and the local file-context rules, and the admin helper reads the site root, skeleton, labels, PHP units, database grants, credentials file and quota as root; every path comes from the site ID. When every rule holds, one transaction records the re-adoption `adopted` and a provision row in the state `adopted` (provenance `explicitly_adopted`); every verb that needs a succeeded provision accepts it. Generation form: the live `current` becomes the established generation only when its stored files are byte-equal to the executor's render from owned sites and the enrolled policy, the server checks pass, the unit is active with the shipped `KillMode` and drop-ins for the build profile, and every listed site answers. Plan schema 1 signs the form, the site or the site list, the signed quota limits (site form), the live generation (generation form), the previous epoch, the evidence digest and an optional `allocation_floor`. Journal v17 | Refused before intent and with no record: a binding, signature or time failure; an unresolved operation; a site or hostname that any provision holds, an ejection marker, an existing OLS operation or generation adoption, or a listed site that is not owned (`PRECONDITION_CHANGED`). After the `verifying` intent, a fact that does not match is `READOPT_MISMATCH` (failed server checks: `OLS_DRIFT`), and the row is recorded `refused` with the first failed rule; nothing else is recorded and the site ID stays free. A missing helper or a lost reply leaves the row `verifying`, which blocks every other admission until `reconcile` repeats the read-only observation. No effect, no compensation. A `current` that names the bootstrap generation is never adopted. The W359 to W362 rules keep applying, with the adopted generation as the baseline after an adoption |
| `site_eject(site_id, expected_generation)` | Export ownership/runbook and turn current verified config into independently usable serving configuration; stop future Rustiron writes/jobs for this site; prove serving survives. D-037 ([W387](../validation/S10-W387/README.md)): the executor writes the standalone vhost once to `/etc/rustiron-ejected/<account>/vhost.conf` (OLS starts the site PHP as the site account through its suEXEC daemon; no Rustiron path, unit or page) and the next generation points the site at it; after the switch and reload, the admin helper step `eject_php_stop` stops and disables the site's Rustiron PHP socket, service and sandbox timer, then requires the site's PHP login page through the listener; the one compensation and the reconcile of an attempted ejection run `eject_php_restore` on the restored predecessor. The shipped parent has a `CGIRLimit` block (`minUID`/`minGID` 1000). A `package` uninstallation copies the vhost to `/usr/local/lsws/conf/vhosts/<account>/vhconf.conf`, writes a standalone parent and starts OLS ([12-UNINSTALL](../operator/12-UNINSTALL.md)) | No deletion of files/DB/certs/accounts; keep the site account, its DAC modes and its own database user; state the isolation loss (no per-site SELinux category, PHP unit sandbox, network refusal or cgroup limit after eject, D-037); WebAdmin stays closed; refuse if ownership/serving continuity cannot be demonstrated; journal schema unchanged (the `ejections` row records removal from management) |

Settings are a versioned allowlisted struct: hostname, approved runtime profile, document-root reference derived from site ID, approved rewrite/cache recipe and bounded resource references.
No extension field carrying arbitrary text.
Hostnames are validated ASCII DNS names.

Internationalized input must be converted and reviewed before planning.
UID, GID, DB identifiers, ports and paths are allocated/derived by trusted policy, not free-form client arguments.
Root DB provisioning uses a reviewed scoped adapter with safe identifier construction; WordPress SQL imports run against a throwaway/site-only DB principal.

The root registry records inactive partial resources.
A failed provision does not imply they never existed or grant permission to delete them.
Deletion or production overwrite requires a future separately reviewed operation contract.

The lab fixture switch (W014a–W014e, [FIXTURE-APPROVAL](FIXTURE-APPROVAL.md)) is a lab/test-only executor path.
It is not a sixth verb and not part of this catalogue.
It must not ship in a product executor.
Adding any verb needs an explicit catalogue change recorded here and in the decision log.

## Plan and grant contract

W009 implements the closed, single-lab-fixture subset in [FIXTURE-APPROVAL.md](FIXTURE-APPROVAL.md), preserving all fields below and exact canonical original bytes.
Pure binding is not signature, replay or root admission proof.
Real OLS and other catalogue operations remain unimplemented.

Plan schema v1 includes these fields:

- `schema_version`, `plan_id`, `host_id`, `host_epoch`, `profile_digest`, `requester`.
- `resource_ids`, `observations`, `steps`, `artifact_digests`, `generator_version`, `expected_effects`.
- `dependencies`, `external_effects`, `blast_radius`, `risk_class`, `reversibility`.
- `downtime_estimate`, `data_loss_exposure`, `budgets`, `valid_from`, `expires_at`, `compensation`, `limitations`.

Unknown estimates are explicit values, never zero by default.
Each fixed step identifies its precheck, effect, observer, verification and permitted compensation recipe.
It cannot carry executable caller-authored instructions.

The digest excludes only its own digest/signature transport fields.
Required unknown facts prevent an actionable plan.
Diagnostic estimates are labeled and never replace preconditions.

Even a one-site config change declares its global OLS recycle and all-site probe scope.

The JSON decoder rejects duplicate/unknown members, invalid UTF-8, unsupported versions, trailing data and out-of-range integers before canonicalization.
Security-relevant numbers are nonnegative exact integers no greater than 2^53−1.
No floating-point budgets.

RFC 8785 conformance vectors and independent parser agreement are required.
Do not invent a JSON sorting approximation.
Hash canonical plan bytes with `rustiron/plan/v1` domain separation.

Sign a canonical grant envelope containing that digest and all grant restrictions, using SSHSIG namespace `rustiron-plan-v1`.
Verify exact signer/principal and revocation policy.
Signature validity alone is not authorization.

The review helper must render the actual signed bytes, including global effects, compensation limits and unknowns.
Signing is outside the coordinator/executor and outside requesting-agent control.
Real key enrollment/custody needs a human setup decision.

Tests with generated keys are labeled synthetic.
Never reuse an existing personal SSH key automatically.
A grant cannot modify signer policy, mint a broader grant, switch host epoch or grant itself more time.

Transport bounds are 256 KiB requests, 1 MiB responses, and a 5-second complete-frame deadline.
The proposed operation bound is 32 fixed steps and one active mutation.
Read bounds are 8 concurrent connections and 100 records per list page.

These are proposed DoS bounds, not measured capacity targets.
Require explicit bounded runtime, memory/PID/output/temporary-storage budgets per runner recipe before it can run; there is no unlimited fallback.
Global recycle count and affected-site count must be bounded in the plan and independently checked.

Initial core has one primary site and at most one adversarial fixture, not an implied density tier.

## Local API and CLI v1

S01/W002 now implements the [read contract subset](READ-PROTOCOL.md): doctor, site list/inspect models, strict bounded JSON, public read errors and human formatting.
Golden fixtures are synthetic.
W003 implements the [local same-user coordinator/CLI](LOCAL-DEVELOPMENT.md), kernel peer checks, length+EOF framing, absolute five-second deadlines and eight active handlers.

W004 adds the [coordinator inventory](COORDINATOR-INVENTORY.md), explicit metadata init/import/export, schema/durability checks and revision-bound pagination.
Dedicated enrolled service identities and the complete product apply workflow remain planned.
W062 adds local signed-submission dispatch with synthetic socket evidence.

The executor independently authorizes effects.
R01/R02/R15 have partial local evidence; no complete host/peer security campaign is accepted from it.

Implemented development Unix framing: unsigned 32-bit network-order byte length followed by one strict UTF-8 JSON object and a write half-close/EOF.
One request/response per connection.
Authenticate peer and enforce deadlines before decoding work.

No stream of unbounded events.
Coordinator methods: `doctor`, `site_list`, `site_inspect`, `plan_create`, `plan_inspect`, `plan_apply`, `operation_status`, `evidence_export`.
Executor methods: `apply_signed_plan`, `operation_status`, `receipt_read`.

Queries reveal only caller-authorized redacted state.
Paginated list input is `cursor, limit`; output includes opaque `next_cursor`, nullable at end.
Expired cursors return a structured error rather than quietly restarting a list.

Envelope: `schema_version`, `request_id`, `method`, `params`.
Responses contain `schema_version`, `request_id`, `status`, `data`, `error`.
Exactly one of data or error is non-null.

Errors contain stable `code`, safe `message`, `retryable`, `operation_id` if admitted, and bounded structured `details`.
Error messages are not machine contracts.
Codes and documented fields are.

Unsupported versions fail explicitly.
Later additive response fields are tolerated by clients; security-sensitive request schemas remain closed until versioned extension.

Doctor/site and operation-status command shapes are implemented as local build artifacts with the required top-level `--socket PATH`.
Site queries require an attached initialized/ reported state store.
Absent/unobserved stores remain dependency-unavailable.

Local commands include plan creation, canonical export, stored inspection/apply, and evidence export.
Creation limits: [W068](../validation/S10-W068/README.md), [W088](../validation/S10-W088/README.md), [W089](../validation/S10-W089/README.md), [W090](../validation/S10-W090/README.md), [W091](../validation/S10-W091/README.md).
Storage/apply/evidence limits: [W067](../validation/S10-W067/README.md), [W072](../validation/S10-W072/README.md), [W069](../validation/S10-W069/README.md), [W071](../validation/S10-W071/README.md).

`plan review-file` is an offline command for the five lab v1 plan kinds, `site_readopt` v1 (W372), `config_activate` v2 and v3, and both product backup v2 plans.
The [product backup contract](PRODUCT-BACKUP-BINDING.md#offline-preparation-and-review) describes explicit v2 creation and inspection.
It needs no socket and does not verify a signature or grant authority.
Operation status is implemented locally with the limits in [W058](../validation/S10-W058/README.md).

W063 adds `plan apply-file` as a development bridge for separately prepared signed files.
Stored `plan apply` is [W069](../validation/S10-W069/README.md).
Evidence export is [W071](../validation/S10-W071/README.md).

These binaries are not installed.

```text
rustiron doctor --output json
rustiron site list --limit 20 --output human
rustiron plan create site-provision --site-id <id> --recipe <approved-id> --hostname <test-name>
rustiron plan create site-eject --site-id <id> --expected-generation <id> --expected-digest <sha256>
rustiron plan create config-activate --site-id <id> --expected-generation <id> --expected-digest <sha256>
rustiron plan create backup-capture --site-id <id>
rustiron plan create restore-probe --site-id <id> --snapshot-id <sha256>
rustiron plan create site-readopt --site-id <id> --hostname <name> --previous-epoch <id> --evidence-sha256 <sha256> ...
rustiron plan create site-readopt-generation --site-id <id> --expected-generation <id> --expected-digest <sha256> ...
rustiron plan inspect <plan-id> --output human
rustiron plan export <plan-id> --output json
rustiron plan review-file <local-plan-file> --output human
rustiron plan apply <plan-id> --grant-file <local-signed-envelope> --idempotency-key <key>
rustiron operation status <operation-id> --output json
rustiron evidence export <receipt-id> --output json
```

Local file paths in CLI import/export are operator-side file I/O.
None are forwarded as privileged executor paths.
`plan_create` accepts only catalogue intents.

`plan_apply` returns an operation ID.
A disconnected CLI cannot cancel, retry blindly or turn an accepted operation into a failure/success inference.
No `--yes`, caller-asserted approval flag or agent-generated signature bypass.

| Exit | Meaning |
| --- | --- |
| 0 | Read command succeeded, or apply has durably reached `succeeded` with required verifications |
| 2 | Usage/schema/version/unsupported operation |
| 3 | Authentication/authorization/signature/expiry/replay denial before new effects |
| 4 | Precondition, ownership, drift, policy-budget or idempotency conflict |
| 5 | Verified operation failure (inspect structured outcome for effects/compensation) |
| 6 | `needs_attention`; state/effect is uncertain or compensation failed |
| 7 | Transport/dependency unavailable; if admission is unknown, query by idempotency key/operation ID before retry |
| 10 | Accepted/running; no completion claim |

Stable codes include `UNAUTHORIZED_PEER`, `INVALID_SIGNATURE`, `STALE_PLAN`, `GRANT_EXPIRED`, `GRANT_REPLAY`, `POLICY_DENIED`, `OWNERSHIP_CONFLICT`, `JOURNAL_UNAVAILABLE`, `IDEMPOTENCY_CONFLICT`, `VERIFICATION_FAILED`, `COMPENSATION_FAILED`, `STATE_UNCERTAIN`, `DEPENDENCY_UNAVAILABLE`.
Output is one JSON object on stdout in JSON mode.
Diagnostic noise goes to bounded stderr and never includes secrets.
Escape terminal control characters in human output.
Default logs and evidence omit raw tenant content.

## Workflow state and recovery semantics

Coordinator planning states: `draft -> planned -> awaiting_approval -> submitted`.
These do not prove executor admission.
Executor operation states:

```text
admitted -> running -> succeeded
                   -> failed
                   -> compensating -> failed_compensated
                                    -> needs_attention
                   -> needs_attention
```

`rejected` is a pre-admission result with no new effects.
Each step has `intent_recorded`, `effect_observed`, `verified` or `uncertain` evidence.
No side effect begins before durable intent.

`failed` means known failure with explicit partial effects.
It does not mean rollback.
`failed_compensated` means only the predefined compensation was verified.

A product build writes `backup_capture` snapshots to the enrolled store. [D-029](../decisions/D-029-product-write-gate.md) enabled these writes, and the lab build keeps them off ([W371](../validation/S10-W371/README.md)).
A product `restore_probe` runs the lab probe phases under [D-031](../decisions/D-031-product-restore-probe.md) ([W373](../validation/S10-W373/README.md)).
The size check and the fetch use two closed store worker actions in the store namespace with the fetch key. The receipt never claims an independent copy.
A probe whose helper reply is lost stays `running` until `probe-cleanup` records it `failed`.

A product `backup_capture` left `running` with a tagged snapshot has an operator exit (W366).
`capture-reconcile OP --settle-unclaimed` repeats the recovery checks now and records `failed`.
The capture keeps the one tagged snapshot ID only as unclaimed evidence, and its receipt states `claimed: false`.
A failed check records nothing. The settlement never records `succeeded`.
See [product capture effects](PRODUCT-CAPTURE-EFFECTS.md#operator-settlement-w366).
A `failed` capture replies `failed`, and a settled one also carries `unclaimed_snapshot_id`. The exit codes stay those of `untouched` ([D-032](../decisions/D-032-power-cut-serving-and-reply-states.md)).

A product `backup_capture` under a standing grant (D-035) runs on a schedule.
`rustiron schedule run` submits the open window's run of each named site through the coordinator. `rustiron schedule status` reports each window, missed runs, and the snapshot age, and exits 5 on an alert.
The units `rustiron-scheduled-capture.timer` and `rustiron-scheduled-capture-check.timer` run them. The installer does not enable them ([scheduled capture](../operator/13-SCHEDULED-CAPTURE.md)).

The product boot guard (D-032) runs before `lshttpd`, the admin helper, and the executor.
If an OLS activation has its effect mark recorded, is not settled, and `current` names its target, the guard restores the journaled predecessor link. For a bootstrap activation, it removes `current`.
The guard records nothing in the journal. `reconcile` and `compensate` settle the operation as before.

For a bootstrap operation, `reconcile` records the empty generation when the helper confirms the bootstrap state (D-033). After the guard removed `current`, it records `untouched`.

A `site_readopt` (W372) is recorded `verifying`, then `adopted` or `refused`. The executor reply uses the existing states: `intent`, `succeeded`, and `untouched`.
A `verifying` row blocks every admission until `reconcile OP` repeats the read-only observation. A re-adoption is not a recovery receipt.

New operations on blocked resources are denied.
Read-only diagnosis remains available.

Recovery observers can finalize an already completed effect without another effect.
Reissuing a step requires current preconditions and remaining grant authority.
An expired grant cannot initiate unfinished steps.

Ambiguity needs an explicit new reviewed recovery plan.
Production recovery retains human authorization under the autonomy policy.
Universal exactly-once effects and universal rollback are not promised.

Restoring an application DB can discard new orders/posts.
Production restoration is outside the MVP catalogue.

## Recovery receipt v1

Required fields: `artifacts_complete`, `repository_integrity_checked`, `decryption_tested`, `application_consistency_assessed`, `restored_in_isolation`, `health_checks_passed`, `independent_copy_confirmed`.
Each has `status: pass|fail|unknown|not_run`, `scope`, `observed_at`, `evidence_refs`, `limitations`.
Never aggregate them into a misleading single “backup healthy.”

Include the following receipt metadata:

- Receipt/schema version, site/host/epoch, capture start/end, snapshot, and artifact hashes.
- DB/files consistency description, tool/profile versions, and repository authority/location attestation.
- Restore environment/physical host, signer/attester, and validation steps.
- Callback/network/mail outcomes and key-recovery method reference without the key.
- Estimated RPO with assumptions, measured phase durations, and cleanup result.

### Receipt signature

[D-042](../decisions/D-042-host-receipt-key.md) and [W392](../validation/S10-W392/README.md).
The installer makes the host receipt key, an Ed25519 key in `/etc/rustiron/receipt-key`. Of the Rustiron domains, only the executor domain reads it.
At each export (`receipt-export` and the evidence query), the pinned `ssh-keygen -Y sign` signs the canonical body bytes, the bytes of `body_sha256`, in the SSHSIG namespace `rustiron-receipt-v1`.
The document then holds `attestation` `self-attested, signed` and `signature` with `format` `sshsig`, `namespace`, `key_fingerprint`, and `armored`.
A host without the key exports `attestation` `self-attested, unsigned`. A receipt from before W392 has neither member and stays valid as unsigned.
`check_receipt.py RECEIPT --public-key KEY.pub` requires a signature and verifies it with the public key that the operator recorded off the host.
A verified signature shows that the host receipt key signed the bytes. It is not independent evidence: root on the host can sign anything.

G0's same-host result remains independence=false in its historical schema.
Schema conversion must preserve that meaning.

MVP exit requires passing evidence at all seven levels with explicit scope, including a real independent key-recovery/manual drill.
A different human guide follower is optional under D-018.
Hash verification is not application health.

A clean SQL import is not file/DB atomicity.
A timed local restore is not an operational RTO promise.
D-010 defines the accepted RPO/RTO targets.

Set any additional environment-specific service budgets before the final drill or live claims.
Unmet budgets block the applicable claim.
