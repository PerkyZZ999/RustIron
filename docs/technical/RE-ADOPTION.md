# Site and generation re-adoption

Technical design, 2026-11-13. Status: accepted as [D-030](../decisions/D-030-re-adoption-verb.md) option C and implemented in [W372](../validation/S10-W372/README.md).
[As implemented](#as-implemented-w372) lists where the code is more exact than the first proposal.
The [W369 drill](../validation/S10-W369/README.md) gives the problem. [07-EPOCH-READOPTION](../operator/07-EPOCH-READOPTION.md) describes the rotation.

## Problem

An epoch rotation starts a new journal. The new journal has no provision row and no OLS operation.
W369 showed the result on a product host that served one site:

- The live `current` is unexplained drift ([W362](../validation/S10-W362/README.md) product rule). Every `config_activate` is refused. The OLS configuration is frozen.
- `status`, `provision`, and `export` of an old site answer `NOT_ADMITTED_FOR_EFFECT`. Capture, probe, and eject need a succeeded provision.
- A second `site_provision` of an old site records a quarantined row that holds the site ID and hostname for the journal's life.
- The only OLS path is a manual stop of OLS and removal of `current`. That path dropped the old site from serving.

Re-adoption gives the new journal an explicit, signed, verified record of what already exists. Re-adoption creates nothing and changes nothing on the host.

## Terms

| Term | Meaning |
| --- | --- |
| Re-adoption | A signed operation that records ownership of an existing resource in the current journal. It has no host effect |
| Site form | The form of `site_readopt` that re-adopts one site |
| Generation form | The form of `site_readopt` that adopts the live OLS generation |
| Owned site | A site with a `succeeded` provision (provenance `created`) or an `adopted` provision (provenance `explicitly_adopted`) in the current journal. SPEC ownership values apply |
| Previous epoch | The epoch of the archived journal. The plan names it as evidence. The executor does not read the archived journal |

## Design summary

1. Add one verb, `site_readopt`, with two closed plan forms: `site` and `generation`.
2. Each form records only. Neither form writes a file, an account, a label, a quota, a database row, or an OLS file. Neither form reloads a service.
3. The executor records the intent first, then the admin helper observes the facts as root, then the executor records `adopted` or `refused`.
4. A refused re-adoption leaves the host as it was. Re-adoption never deletes or repairs anything.
5. The site form makes the site an owned site. Every verb then treats it like a provisioned site.
6. The generation form makes the live `current` the established generation, but only when the executor renders the same bytes from owned sites.
7. Add a pre-intent collision refusal to `site_provision`, so that a mistaken re-provision records nothing.

## Precondition: pre-intent collision refusal

Today `site_provision` records intent, then the Account step finds the existing account and quarantines the provision (W369 request 46).
The quarantined row holds `site_id` and `hostname`, which are unique among provisions. A later re-adoption of that site then has no row to create.

Change (implemented in W372): before intent, the executor checks the derived account name, group name, and site root.
If one of them exists, the executor refuses with `PROVISION_COLLISION` and records nothing.
The executor already reads `/etc/passwd` and `/etc/group` in its own domain for the UID choice.
The executor domain may have no read access to the sites root. Then the root check uses a read-only admin helper request.
The database check stays in the Database step, after intent.

A journal that already holds such a quarantined row keeps it. The site form refuses that site ID with `PRECONDITION_CHANGED`. The operator rotates again or leaves the site unmanaged.

## Plan and grant shape

Both forms use plan schema 1 of the new verb and the common fields of the [plan contract](SPEC.md#plan-and-grant-contract).
The common fields are `schema_version`, `plan_id`, `host_id`, `host_epoch`, `profile_digest`, `requester`, `risk_class`, `valid_from`, `expires_at`, and `limitations`.
The decoder rejects unknown fields, duplicate keys, and a mixed form. The digest domain and the SSHSIG namespace do not change ([canonical bytes](CANONICAL-BYTES.md)).

### Site form

| Field | Type | Rule |
| --- | --- | --- |
| `verb` | `"site_readopt"` | Fixed |
| `form` | `"site"` | Fixed |
| `site_id` | `SiteId` | The site. Every name and path is derived from it |
| `hostname` | `Hostname` | Unique among owned sites of this journal |
| `quota_limits` | `{block_hard_kib, inode_hard}` | Must equal the live user quota of the site UID and be at most the enrolled cap |
| `previous_epoch` | `Id` | Must differ from `host_epoch`. Evidence only |
| `evidence_sha256` | `Sha256Digest` | SHA-256 of the pre-rotation `export` output. Evidence only |
| `allocation_floor` | `{uid, category}` or absent | Optional. See [Retired allocations](#retired-allocations) |
| `observations` | One entry, `state: "present_unowned"` | Reported, never trusted |
| `expected_effects` | `creates_account`, `creates_database`, `traffic_activation`, `network_access`, `sets_quota`: all `false`; `records_ownership`: `true` | Fixed |

Grant: `verbs = [site_readopt]`, `site_ids = [site_id]`, `max_operations = 1`, no compensation.

### Generation form

| Field | Type | Rule |
| --- | --- | --- |
| `verb` | `"site_readopt"` | Fixed |
| `form` | `"generation"` | Fixed |
| `expected_generation` | `Id` | The live `current` id |
| `expected_digest` | `Sha256Digest` | The live generation digest |
| `site_ids` | 1 to 32 `SiteId`, sorted, no repeats | The sites that the live generation serves |
| `previous_epoch`, `evidence_sha256`, `allocation_floor` | As the site form | `evidence_sha256` is the SHA-256 of the pre-rotation `ols-status` output |
| `expected_effects` | All effects `false`; `records_generation`: `true` | Fixed |

Grant: `verbs = [site_readopt]`, `site_ids` equal to the plan list, `resource_ids` the OLS resource, `max_operations = 1`, no compensation.

The offline review shows every field, the previous epoch, and both evidence digests. The signer compares them with the archived `export` and `ols-status` output.

## Admission order

1. The executor decodes the plan and the grant and runs the binding check. A wrong epoch is `FIXTURE_BINDING_DENIED`.
2. The executor verifies the signature and the time.
3. Before intent, under the writer lock, the executor checks the journal facts. See [Pre-intent checks](#pre-intent-checks).
4. The executor records the intent with state `verifying`. The intent consumes the grant, nonce, operation ID, and idempotency key.
5. The executor sends one `ReadoptObserve` request to the admin helper. The helper finds the operation in the journal, derives every path from the journaled site ID, and returns the facts.
6. The executor compares the facts with the plan and the enrolled policy.
7. In one transaction, the executor records `adopted` with the facts, or `refused` with the first failed rule.

If the executor stops after step 4, the row stays `verifying`. `reconcile OP` repeats steps 5 to 7. The observation is read-only, so a repeat is safe.
A `verifying` row never becomes `adopted` without a complete new observation. A `verifying` row blocks new admissions, as an unresolved operation does today.

### Pre-intent checks

| Check | Both forms | Refusal |
| --- | --- | --- |
| No unresolved operation, provision, capture, probe, or re-adoption | Yes | `UNRESOLVED_OPERATION` |
| Site form: `site_id` and `hostname` are not owned and not in any provision row | Site | `PRECONDITION_CHANGED` |
| Site form: `/etc/rustiron-ejected/rs_<site>` does not exist | Site | `PRECONDITION_CHANGED` |
| Generation form: the journal has no OLS operation and no generation adoption | Generation | `PRECONDITION_CHANGED` |
| Generation form: each listed site is owned and not ejected | Generation | `PRECONDITION_CHANGED` |
| `previous_epoch` differs from the enrolled epoch | Yes | `INVALID_REQUEST` |

## What the site form verifies

The admin helper reads each fact as root in `rustiron_admin_t`. The executor decides. Every path comes from the site ID and the compiled layout, never from the plan.

| Fact | Trusted source | Rule |
| --- | --- | --- |
| Account | `/etc/passwd`, `/etc/group` | Exactly one entry `rs_<site>`. UID equals GID. UID inside the enrolled UID range. Home `/srv/sites/rs_<site>`, shell `/sbin/nologin`. No other entry has that UID or GID. The group has no member list |
| UID reuse | The current journal | No provision step and no adoption of this journal records that UID |
| Site root | Descriptors from the trusted sites root | `rs_<site>` is a directory, not a link, `root:root`, mode 0751, on the sites file system (same device as `/srv/sites`) |
| Skeleton | Descriptors | Top-level entries `errors`, `html`, `tmp`, `logs`, `private` with the owners and modes of the Directories step. No walk below them. Site content is tenant data |
| File contexts | `file_contexts.local` | Exactly the two rules of the Labels step for this root, with one level `s0:cN` |
| Category | `file_contexts.local`, the current journal | N inside the enrolled category range. No other local rule and no other record of this journal uses N |
| Live labels | `getxattr` on the root, `html`, `tmp`, `logs` | The rule types at level `s0:cN` |
| PHP units | `/etc/systemd/system`, `systemctl` | `rustiron-site-php@rs_<site>.service.d/50-selinux.conf` has exactly the bytes of the PhpUnits step for `s0:cN` and no other file. Socket and sandbox timer enabled. Socket active |
| Database | MariaDB over the local socket | Schema `rs_<site>` exists. User `rs_<site>` exists only for `localhost`. `SHOW GRANTS` lists only `USAGE` and `ALL PRIVILEGES ON rs_<site>.*` |
| Credentials | Descriptors | `private/db.cnf` is a regular file, site-owned, mode 0600, one link. The helper does not read its content |
| Quota | `repquota` on the sites file system, as the Directories step reads back | User quota enforced. Hard limits of the UID equal `quota_limits` |
| Ejection | Descriptors | No `/etc/rustiron-ejected/rs_<site>` |

The executor does not check the WordPress files, the database content, or the admin hand-over file. Those files and rows are tenant data. Re-adoption claims ownership of the isolation boundary, not of the content.

On `adopted`, one transaction writes the re-adoption row and a provision row with state `adopted` for the site. The provision row carries the operation identity of the re-adoption.
Every check that requires a `succeeded` provision then accepts `adopted` too: `served`, capture, probe, eject, `export`, `retire-quota`.

## What the generation form verifies

The live `current` becomes established only through this form. The form never changes `current`, never reloads OLS, and has no compensation.

| Fact | Source | Rule |
| --- | --- | --- |
| `current` | The include directory, through descriptors | Present. Not the bootstrap id `re3b0c44298fc1c14` |
| Content address | `generation_digest` | The digest of the stored files matches the id. Equals `expected_generation` and `expected_digest` |
| Render | `ols::render` with the enrolled listener, address, `adopted`, and the listed owned sites in account order | Byte-equal to the live generation: same file names, same bytes, same digest |
| Server checks | Admin helper `ServerChecks` | Parent SHA-256 equals the enrolled value. WebAdmin port closed. Only the enrolled listener listens. Adopted vhosts pinned |
| Unit | `systemctl show lshttpd.service` | `active`, `KillMode=mixed`, and the drop-in paths for the build profile |
| Serving identity | `probe_with_retry` over the listed sites | Each hostname returns its `rustiron-site.txt` marker through the enrolled listener |

Both profiles require `/etc/systemd/system/lshttpd.service.d/50-rustiron-killmode.conf`.
The product profile also requires `/etc/systemd/system/lshttpd.service.d/51-rustiron-boot-guard.conf`.
Only generic vendor drop-ins under `/usr/lib/systemd/system/service.d/` are optional.

The render rule is the core of the form. When the render is byte-equal, every virtual host, map, and vhost file in the live generation comes from an owned site and the enrolled policy.
A planted or edited generation fails the content address or the render. A generation that serves a site this journal does not own fails the render.

On `adopted`, the executor writes one `ols_adoptions` row: operation, generation, digest. The journal allows at most one such row.

### How the established generation changes

| Journal state | Established generation (product) | Established generation (lab) |
| --- | --- | --- |
| No OLS operation, no adoption | Bootstrap (W362) | None (W021) |
| No OLS operation, one adoption | The adopted generation | The adopted generation |
| OLS operations after the adoption | The W360 rule, with the adopted generation as the baseline | The same |

`established_generation` reads the adoption before it falls back to the profile rule. The executor passes the adopted generation as the `baseline` of `resource_history`.
An `untouched` or `failed_compensated` activation after the adoption then keeps the adopted generation, as it keeps the bootstrap generation today.

### W359 to W362 stay intact

| Rule | Effect of the proposal |
| --- | --- |
| W359: the generation checks judge the `current` that matches the plan predecessor | No change. After an adoption, the predecessor of the next plan is the adopted generation |
| W360: only a verified activation establishes a generation | No change for activations. The adoption is a second, separately verified record. A `verifying` or `refused` adoption establishes nothing |
| W362: product empty history establishes the bootstrap generation; a `current` with an empty history is drift | No change while no adoption exists. The generation form is the only way out, and it needs a signature and a byte-equal render |
| W362: a `current` that names the bootstrap id is never explained | The form refuses that `current` |
| W355: the bootstrap plan needs no `current` | After an adoption, the history is not the bootstrap generation, so bootstrap plans refuse |
| Reconcile and compensate restore only an explained predecessor | The adopted generation is explained, so a later compensation may restore it. The adoption itself has no compensation |

## Retired allocations

Allocation is monotonic: a new UID or category is above every value in use and every value the journal recorded (`recorded_numbers`).
The new journal does not know the values that the old epoch recorded. A UID that the old epoch retired after a removal could be allocated again.

The optional `allocation_floor` closes that gap. The executor records the highest floor of all adoptions and treats it as a retired value in `next_above`.
A floor can only move the next allocation up. A wrong floor wastes range and ends in `JOURNAL_CAPACITY`, but it cannot weaken isolation.

The signer takes the floor from the archived journal, for example the highest `uid=` and `level=s0:c` of its provision steps.
`recorded_numbers` also reads the UID and category of each adopted provision.

## Journal records

Schema version 17, with a one-way migration from version 16. [W368](../validation/S10-W368/README.md) took version 15 and [W370](../validation/S10-W370/README.md) took version 16 for the page-cache tables. Every older supported version migrates in the same step. The migration rebuilds `provisions` with foreign keys off inside one transaction, copies every row back, and requires an empty foreign-key check before the commit.

| Change | Content |
| --- | --- |
| New table `readoptions` | `operation_id` (primary key), `idempotency_key`, `grant_id`, `nonce` (each unique), `plan_digest`, `grant_digest`, `host_id`, `host_epoch`, `form` (`site` or `generation`), `site_id` (null for the generation form), `previous_epoch`, `evidence_sha256`, `expires_at`, `state` (`verifying`, `adopted`, `refused`), `facts` (canonical JSON, at most 4096 bytes, no secret), `refusal` (code or null) |
| `provisions.state` | Adds `adopted`. A table rebuild in the migration, because SQLite cannot change a `CHECK` |
| New table `provision_adoptions` | `operation_id` (references `provisions`), `uid`, `category`, `quota_kib`, `quota_inodes` |
| New table `ols_adoptions` | `operation_id` (references `readoptions`), `generation`, `digest`. At most one row |
| New table `allocation_floors` | `operation_id`, `uid`, `category` |
| `consumed_ids` | Also checks `readoptions` |
| `admission_count` | Also counts `readoptions`, so the admission mark covers re-adoptions |

A refused re-adoption leaves only its `readoptions` row. The site ID stays free, so a corrected plan can re-adopt the site later in the same epoch.

## Refusals

| Code | When | Records |
| --- | --- | --- |
| `FIXTURE_BINDING_DENIED` | Plan or grant names another host, epoch, profile, requester, or signer | None |
| `INVALID_SIGNATURE`, `GRANT_TIME_DENIED` | As for every verb | None |
| `UNRESOLVED_OPERATION` | Another operation is not settled | None |
| `PRECONDITION_CHANGED` | A pre-intent check fails | None |
| `READOPT_MISMATCH` (new) | A verified fact does not match the plan or the policy | The row is `refused` with the code and the failed rule |
| `ADMIN_HELPER_UNREACHABLE` | The helper is absent for the bounded wait | The row stays `verifying`. `reconcile` settles it |
| `OLS_DRIFT` | Generation form: the server checks fail | The row is `refused` |

## Receipts and status

- The coordinator reply carries the state `succeeded` for `adopted`, `failed` for `refused`, and `running` for `verifying`.
- `readopt-status OP` (admin, service stopped) prints the row: form, state, facts, refusal, previous epoch, and evidence digest.
- `export SITE` adds `provenance` (`created` or `explicitly_adopted`) and, for an adopted site, the re-adoption operation, the previous epoch, and the SHA-256 of the facts.
- `observe` lists re-adoptions beside provisions.
- `ols-status` adds `established_by` with the value `operation`, `adoption`, or `bootstrap`.

A re-adoption is not a recovery receipt. The re-adoption record does not claim that a backup, a restore, or an independent copy exists.

## Threat cases

| Case | Defense |
| --- | --- |
| Old-epoch grant replayed after the rotation | Binding check refuses before any record (W369) |
| Root plants an account, a tree, and a database that look like a site | Re-adoption needs a signed grant. The review shows the previous epoch and the evidence digest. Root on the host remains inside the trust boundary, as for enrollment |
| A non-site account shares the site UID | Account rule: no other entry has that UID or GID |
| Two sites share one SELinux category | Category rule: no other local rule or record uses it |
| Site root is a link, a bind mount, or on another file system | Descriptor checks and the device rule |
| Database user with global grants or access to another schema | `SHOW GRANTS` rule |
| Quota removed or raised above the cap | Quota rule against the signed limits and the enrolled cap |
| `current` edited, planted, or extended with an extra vhost | Content address and byte-equal render |
| `current` names the bootstrap id | Refused, as in W362 |
| Generation adoption repeated, or after an activation | Pre-intent: no OLS operation and no adoption |
| Site re-adopted twice, or a hostname shared | Pre-intent uniqueness against owned sites and provisions |
| Crash between intent and outcome | Row stays `verifying`. `reconcile` repeats the read-only observation. No success without a complete observation |
| Facts change after the observation | The adoption records observed facts with time. Each later verb checks its own preconditions, as today |
| Retired UID or category of the old epoch reused | `allocation_floor` |
| Ejected site re-adopted | Refused in this version. The ejected vhost lives outside the generation. After D-037, eject also disables the site's PHP units, so the PHP unit rule fails too ([D-037](../decisions/D-037-independent-eject.md#reversibility)) |
| Admin helper output forged by another process | The helper accepts only an executor-domain peer (D-020). The executor accepts only the helper socket |

## Out of scope

- Ejected sites, lab `adopted` sites, and `lscache` sites.
- Sites without the Rustiron layout, for example a CyberPanel site. Those need a separate import design.
- Content checks of WordPress files or the database.
- Re-adoption on the lab VM. The lab profile keeps W021.
- Any change to an OLS file, an account, a label, a quota, or a database.

## Tests

Test-first, in the order of the implementation tasks.

| Test | Covers |
| --- | --- |
| Contract decoder vectors | Both forms, unknown fields, mixed forms, a missing `previous_epoch`, `site_ids` order and bounds, grant scope |
| Journal migration 16 to 17 | Rows keep their bytes. The `adopted` state, the new tables, `consumed_ids`, and `admission_count` |
| Pre-intent collision of `site_provision` | Existing account, group, or root: `PROVISION_COLLISION` and no record |
| Site form fact rules | One planted fixture for each rule in the site table: each must give `READOPT_MISMATCH` and a `refused` row |
| Site form success | Provision row `adopted`. `served`, capture, probe, eject, `export`, and `retire-quota` accept the site |
| Crash after intent | Fault point after the `verifying` row. `reconcile` settles. No `adopted` without a complete observation |
| Crash after the observation (W377) | Fault point `AfterReadoptObservation`, after the decision and before the outcome transaction. The row stays `verifying` with no facts. `reconcile` observes again and records once |
| Generation form | Byte-equal render accepted. One extra file, one edited byte, one missing site, the bootstrap id, an unowned site, and a prior OLS operation: each refused |
| Established generation | `ols-status` explained true after the adoption. An activation from the adopted predecessor succeeds. A compensated activation keeps the adopted generation. A bootstrap plan refuses |
| Allocation floor | The next UID and category are above the floor. A floor at the range end gives `JOURNAL_CAPACITY` |
| Product profile suite | The maintained `--test product_profile` run includes every case above |
| Lab drill | A fresh product host as in W369: rotate, re-adopt the site, adopt the generation, activate a new site, and confirm that the old site still serves |

## As implemented (W372)

| Item | Implementation |
| --- | --- |
| Grant scope of the generation form | `targets: ["ols_lab_listener"]`, the OLS resource name the other OLS grants use, instead of `resource_ids`. The site form has no `targets` |
| Generation form plan | Also `target: "ols_lab_listener"` and one observation `state: "observed"` with the live generation and digest, as in `config_activate` |
| `readoptions` row | Also `hostname` (site form), `rule` (the first failed rule of a refusal) and `plan` (the canonical plan, at most 64 KiB). The journal checks on write and on open that `plan` hashes to `plan_digest` and names the recorded form, site and epochs. A reconcile compares a new observation with exactly the signed plan |
| Refusal codes in the row | `READOPT_MISMATCH` or `OLS_DRIFT`. The rule names are `account`, `uid_range`, `uid_shared`, `group`, `uid_recorded`, `site_root`, `skeleton`, `file_contexts`, `category_range`, `category_shared`, `labels`, `php_units`, `database`, `credentials`, `quota`, `ejected`, `current_absent`, `bootstrap`, `content_address`, `expected`, `render`, `server_checks`, `unit`, `probes` and `observation` |
| `observation` rule | The helper refused the request or its reply was not the closed facts shape. The row is `refused`, because a `verifying` row that can never settle would block the host. Only an absent helper or a lost reply leaves the row `verifying` |
| Database rule | Also: no other account has a schema, table, column or routine privilege on the site schema (`mysql.db`, `tables_priv`, `columns_priv`, `procs_priv`). `SHOW GRANTS` lines lose the password hash before the comparison; no hash is stored |
| Unit rule | `DropInPaths` must match the [build profile](#what-the-generation-form-verifies). An extra local `lshttpd` drop-in refuses |
| Who reads what | The executor reads `/etc/passwd`, `/etc/group`, `file_contexts.local` and the OLS include (current, stored files, render) itself. The admin helper (`readopt_observe`) reads the site root, skeleton, labels, PHP units, database, credentials file, quota and ejection marker (site form), or the server checks, unit facts and identity probes (generation form) |
| Collision check of `site_provision` | The account and group come from the executor's own read. The site root comes from a second request without an operation, `v1 site_root <site_id>`, answered `ok present` or `ok absent`. A site ID has no `_`, so the line never decodes as a step |
| Reply states | `verifying`: `intent`; `adopted`: `succeeded`; `refused`: `untouched` (with the code). The coordinator and the CLI need no change |
| Admission count | `readoptions` rows count; an `adopted` provision row does not count again |
| Busy rule | A `verifying` row blocks operations, provisions, captures, probes and re-adoptions. A re-adoption needs all of them settled |
| `ols-status` | Adds `established_by`: `operation`, `adoption`, `bootstrap`, `none` (lab, empty history) or `unresolved` |
| Commands | `readopt-status OP`; `reconcile OP [--admin-helper]` settles a `verifying` re-adoption; `plan create site-readopt` and `site-readopt-generation`; `lab/s10/make_readopt_request.py` for the lab signer |

## Implementation tasks

1. Pre-intent collision refusal for `site_provision`.
2. Contract types, decoders, offline creation, and review for both forms.
3. Journal schema 17 and its migration from version 16.
4. Admin helper `ReadoptObserve` and the SELinux rules it needs: read `file_contexts.local`, run `repquota`, and read MariaDB grants.
5. Executor admission, verification, and `reconcile` for both forms.
6. The established-generation change and its W359 to W362 tests.
7. Status, export, and observe fields.
8. Operator guide and the lab drill.

The owner accepted D-030 on 2026-11-13. W372 implemented tasks 1 to 8.
