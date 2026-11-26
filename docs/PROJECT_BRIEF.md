# Rustiron project brief

Version: 0.3.
Updated: 2026-11-03, America/Toronto.
The owner identifies this brief as the product source of truth.
The [decision register](decisions/DECISIONS.md#d-018--product-goal-documentation-and-agent-autonomy) records the authorized scope revision.
The [roadmap](planning/ROADMAP.md) is the only delivery plan and task queue.

Rustiron is an open-source hosting panel built with Rust and TypeScript.
Rustiron replaces required CyberPanel hosting workflows and improves operational safety, recovery, usability, and agent automation.
Note: that improvement is a product target, not a measured result ([W400 claims audit](validation/S10-W400/README.md)).
The product includes deployment and management of modern apps, including Node.js and Bun apps.
Rustiron orchestrates mature infrastructure instead of recreating infrastructure services.

## 1. Executive overview

Rustiron serves developers and VPS operators who manage websites, apps, domains, databases, and recovery.
The product provides a CLI, an accessible console, and scoped automation through the same operation contracts.
The first milestone proves single-host WordPress hosting and recovery.
The panel and app-hosting milestones extend that foundation.
A narrow first milestone does not reduce the final product goal.

Website requests bypass Rustiron and use the serving stack directly.
Existing sites and apps continue serving when Rustiron management stops.
Rust does not by itself make WordPress requests faster.

The product hypothesis is measurable operational value: fewer unsafe manual steps, clearer outcomes, useful recovery proof, and lower operator effort.
Feature counts and visual polish do not establish that value.
[State](STATE.md) distinguishes implemented behavior from planned capabilities.

## 2. Product identity and four pillars

The four pillars remain Performance, Reliability, Security, and Agent/User Friendliness.
Security and reliability constrain performance and convenience.

| Pillar | Product requirement | Evidence |
| --- | --- | --- |
| Performance | Preserve OLS/LSCache behavior; bound management overhead; measure hosting costs | Cached, cold, uncached, authenticated, and private workloads; p50/p95/p99 latency; CPU, memory, I/O, and capacity |
| Reliability | Report interrupted changes truthfully; preserve serving; recover data | Durable intent, fault injection, configuration checks, independent copies, clean-host recovery |
| Security | Contain compromised sites, apps, agents, and coordinator requests | Independently enforced grants, scoped identities, denial tests, resource limits, critical security review |
| Agent/User Friendliness | Expose consistent operations through CLI, console, and automation | Readable plans, stable JSON and exit codes, accessible workflows, actionable errors, limited human checkpoints |

Publish the resource cost of isolation.
Reject optimizations that weaken ownership, authorization, recovery, or private-content correctness.
The historical tagline is not a speed guarantee or a release claim.

## 3. Target users, first use case, and product strategy

The first operator manages personally controlled hosts.
The initial operator is trusted.
Website code, app dependencies, imported content, and agent input are untrusted.
Delegated users and reseller workflows follow a separate tenancy contract.

The first working path covers these outcomes:

- Inspect prerequisites and resource ownership.
- Create and review a bounded plan.
- Provision an isolated WordPress fixture on a supported fresh host.
- Activate configuration with verified failure handling.
- Capture encrypted data and inspect separate consistency and integrity results.
- Restore in containment and recover independently without Rustiron.
- Export or eject a site without losing serving or data.

### Build-versus-compose gate

Compare Rustiron with competently operated CyberPanel and composed OLS/WP-CLI/restic/systemd tooling.
D-013 fixes the operator-task comparison baseline and thresholds.
Focused panels and app platforms remain integration alternatives, not automatic dependencies.
A read-only sidecar remains a fallback if privileged hosting cannot meet the safety requirements.
Equivalent request performance does not invalidate demonstrated recovery or operator value.

## 4. Fundamental product boundaries

- Rustiron manages infrastructure. Website traffic has no synchronous management dependency.
- The first supported profile is AlmaLinux 10 x86_64 with a verified package tuple.
- v1.0 supports AlmaLinux 10 only and is for the owner's own host; AlmaLinux 9, other operating systems, and a public release follow v1.0 ([D-058](decisions/D-058-v1-scope.md)).
- The first Core uses one trusted operator and a local Unix-socket API.
- The panel, DNS, mail, delegated access, apps, and multiple hosts have explicit delivery milestones.
- Resource ownership precedes mutation. Unknown ownership or unexplained drift causes refusal.
- No generic privileged shell, arbitrary SQL, caller-selected root path, or unrestricted agent capability is a product feature.
- Site and app code execute with scoped unprivileged identities.
- Recovery, portability, and management-independent serving remain acceptance requirements.
- Website migration does not implicitly authorize DNS or mail changes.
- Public exposure and production cutover require the critical checkpoints in the autonomy policy.
- Security updates, disclosure, release integrity, and incident response continue after release.

## 5. Proposed architecture — Rustiron Core

The accepted management path remains CLI → coordinator → executor → fixed operation.
The console and automation adapters use the same contracts.
The executor distrusts coordinator state and independently validates authority and current preconditions.
The [architecture](technical/ARCHITECTURE.md) describes components and trust boundaries.

```text
Human operator / bounded automation
          |
  rustiron CLI (human + JSON)
          |
   Local versioned Unix-socket API
          |
 [RUSTIRON CONTROL — unprivileged]
   - authenticate + authorize + scoped approval
   - inventory and explicit resource ownership
   - plan compiler and read-only drift inspection
   - durable workflow / operation journal
   - evidence ledger and constrained observers
   - SQLite (single coordinator/writer)
          |
  typed, bounded operation request
          |  [UNTRUSTED DAEMON -> PRIVILEGE BOUNDARY]
          v
 [RUSTIRON EXECUTOR — minimal privileged process]
   - reauthorize request and validate opaque resource IDs
   - fixed operation catalogue; derives its own paths
   - safely update managed configuration
   - launch site-scoped tasks with dropped privileges
   - verify results; report independent executor evidence
          |
          +--> OpenLiteSpeed + LSPHP + LSCache
          +--> WordPress/WP-CLI (run as site's Unix user)
          +--> MariaDB (per-site scoped credentials)
          +--> ACME and systemd (limited operations)
          +--> mature encrypted backup backend
                         |
                   Independent off-host repository

Internet clients ----------------> OLS ---> WordPress
         [NORMAL REQUEST PATH NEVER REQUIRES RUSTIRON]
```

### 5.1 Core technology preferences, not immutable commitments

| Component | Direction | Scope |
| --- | --- | --- |
| Engine, CLI, executor | Rust; separate synchronous privileged executor | Existing architecture |
| Console | React, strict TypeScript, Bun, Astryx | Selected; read-only implementation exists |
| Optional TypeScript adapter | Elysia on Bun | Unprivileged; no alternate signing authority |
| State | SQLite with separate coordinator and executor stores | Explicit locks, durability, migrations, and recovery |
| Web/PHP | OpenLiteSpeed, LSPHP, LSCache, WP-CLI | Existing lab integrations; WP-CLI runs as site identity |
| Database | MariaDB | Site-scoped credentials and reviewed administration |
| Backup | restic with tested backend permissions | Encryption, integrity, retention separation, portable recovery |
| Process and isolation | systemd, cgroups, SELinux | Verify effective restrictions on the supported profile |
| Authoritative DNS | PowerDNS | Owner-selected integration direction; implementation pending |
| Firewall | firewalld | Owner-selected integration direction; bounded rules and ownership pending |
| Modern app runtimes | Node.js and Bun | Required hosting capabilities; exact recipes and versions pending |
| Mail, certificates, transfer | Mature external services | Select maintained integrations at their roadmap milestone |

Do not write replacement DNS, SMTP, database, backup-encryption, or service-manager implementations.
Check compatibility, maintenance, licenses, and supported versions before adding an integration.
Reusing a service does not establish CyberPanel data or API compatibility.

### 5.2 Minimal domain model

Retain `Site`, `OwnershipManifest`, `Operation`, `Plan`, `Step`, `Artifact`, `Evidence`, `ApprovalGrant`, `Principal`, and `HostProfile`.
Credentials use opaque references.
Add app and deployment records when the app contract requires them.
Avoid speculative generic controllers or plugin frameworks.

### 5.3 Owned, observed and unknown resources

Record identity, provenance, owned paths, dependencies, version, and observation time.
Imported observations do not grant adoption or executor authority.
Drift inspection is read-only.
Adopt, restore-owned, ignore, and eject are explicit choices with reviewed operation contracts.
Manual emergency edits do not trigger a silent background reset.

## 6. Safe change semantics

The operation flow remains:

`request -> authenticate -> authorize -> generate immutable plan -> (approve if required) -> re-check preconditions -> journal intent -> apply typed step -> observe/verify -> journal outcome -> structured result`.

A plan binds its content hash, target, host profile, observations, expected writes, dependencies, privilege class, expiry, and blast radius.
The plan states external effects, compensation, and known downtime or data-loss exposure.
A plan cannot predict arbitrary plugin or app behavior.
Approval binds exact bytes and observed preconditions.
Altered, stale, or replayed authorization does not permit new effects.

### 6.1 Operation classes

| Class | Examples | Required semantics |
| --- | --- | --- |
| Managed configuration | Owned OLS include or unit drop-in | Planned writes, validation, tested idempotence |
| Durable workflow | Install, certificate, backup, restore, app deployment | Intent before effects; explicit external effects and interrupted outcomes |
| Inspection and evidence | Doctor, drift, benchmark, recovery report | Bounded read-only behavior; no hidden repair or tuning |

Each step defines `precheck`, `apply`, `verify`, and optional `compensate` behavior.
On restart, the executor re-observes interrupted effects.
Unknown outcomes block affected resources and require a documented recovery action.
Configuration reversal, compensation, and application restore are distinct operations.
A database restore cannot undo later orders safely by assumption.

### 6.2 Privileged boundary: the most important implementation contract

Use fixed versioned semantic operations and root-enrolled resource identities.
The executor derives paths and tool arguments from trusted records.
The executor verifies peers, scope, signatures, epochs, budgets, replay, and current preconditions.

External tools use pinned absolute executables, fixed arguments, scrubbed environments, and bounded resources.
No shell interprets request text.
Tenant PHP, WP-CLI, package scripts, SQL content, and archive handling run without root authority.

Filesystem operations need verified descriptor, ancestry, link, ownership, and atomic-replacement rules.
Restore tests cover traversal, links, special files, oversized content, callbacks, and resource exhaustion.
Typed parameters alone do not prove safety.

## 7. Initial host and OpenLiteSpeed strategy

AlmaLinux 10 x86_64 is the accepted first host direction.
Pin the tested OLS/LSPHP/MariaDB, kernel, systemd, SELinux, and native SQLite inputs.
A dated lab tuple is not a supported release matrix.
Retain LSCache behavior and compare with the existing hosting baseline.

### 7.1 Reconciliation of the reviewers' differing OLS proposals

D-003 selects minimal owned includes beneath a trusted parent.
The owner accepted an immutable root-owned parent.
Disable WebAdmin under the managed profile and document emergency ownership transfer.
The official `ols` CLI remains a reference, not an automatically trusted provisioning primitive.

Configuration acceptance requires candidate selection checks, effective vhost and PHP identity, all-site probes, and tested last-known-good compensation.
Syntax checks and HTTP 200 alone do not establish correct serving.
Bound `.htaccess` reload effects, global reload budgets, and process shutdown.
If the ownership model fails, reopen the affected decision instead of weakening checks.
Never adopt active CyberPanel configuration implicitly.

### 7.2 Initial site isolation contract

Assume a compromised plugin or app obtains code execution as its scoped identity.
Prevent cross-site access to files, databases, credentials, processes, sockets, sessions, temporary data, and management IPC.
Verify effective UID/GID, supplementary groups, enforcing MAC, cgroups, namespaces, and descendant limits.

Distinct UIDs alone do not establish containment.
Commercial hostile tenancy requires additional tests and review.
Per-site Valkey remains workload-dependent rather than mandatory for every site.

### 7.3 Operational dependencies not to forget

Account for firewalld, SSH policy, clocks, storage and inodes, logs, OS updates, runtime lifecycle, database health, jobs, mail relay, and TLS.
Test renewal failure, missed jobs, failed delivery, exhausted storage, upgrade interruption, and diagnostic uncertainty.
The supported host profile owns the exact ports and service boundaries.

## 8. Backup, restore, and recovery evidence

Use encrypted off-host artifacts and backend-enforced source no-delete rights.
Keep retention and recovery authority separate from the source worker.
Do not infer immutability from an append-only client flag.
Test deletion, prune, malicious snapshots, provider failure, lost keys, and repository outage within the declared scope.

Document file/database consistency, engine limits, quiescence, and capture timing.
Separate fetch authority from restored-code execution.
Restore into new identities and a disposable database without egress, production secrets, repository credentials, or host access.
Verify cleanup and preserve uncertainty when cleanup cannot be observed.

### Recovery evidence receipt

Report these seven fields separately:

| Field | Required distinction |
| --- | --- |
| `artifacts_complete` | Expected files, database export, metadata, and state references exist |
| `repository_integrity_checked` | Repository checks passed at the recorded scope |
| `decryption_tested` | Recovered credentials decrypted the artifacts |
| `application_consistency_assessed` | File/database skew and transaction limits are assessed |
| `restored_in_isolation` | Files and database were restored in a new contained environment |
| `health_checks_passed` | Runtime, database, content, and fatal-error checks passed |
| `independent_copy_confirmed` | Recovery used data outside the source host's control |

Use `pass`, `fail`, `unknown`, and `not_run` with scope, source, time, and evidence references.
A local receipt or hash chain is not tamper-proof against host root.
A same-machine restore cannot pass independent-copy requirements.
D-010 sets RPO 24 h, per-site RTO 4 h, host RTO 8 h, and 30-day retention.
Those targets still require measured independent evidence.

## 9. Performance and optimization

Measure cached, cold, uncached, authenticated, and private requests separately.
Retain failures and report correctness, errors, latency distributions, CPU, memory, I/O, and isolation costs.
Preregister workloads, repetitions, acceptance thresholds, and comparison conditions.
Historical G0 timeouts remain unresolved evidence, not discarded outliers.

Experiment Cards state a hypothesis, baseline, risk, workload, change, budget, measurement, and retain/revert outcome.
Test LSCache invalidation, OPcache, PHP workers, and uncached paths only through bounded hypotheses.
No automatic database tuning or private-content caching shortcut is implied.

### 9.2 Budgets and background work

Show site, privilege, reload, time, and resource budgets before execution.
Enforce consumed authority durably across interruption.
Traffic-aware scheduling remains conditional on evidence that simpler schedules fail.
Backlog, starvation, stale metrics, and missed RPO targets need observable failure behavior.

## 10. Human and agent experience

Humans, scripts, console sessions, and agents use the same safe operation contracts.
Expose readable plans, stable JSON, stable exit codes, redacted diagnostics, and exact operation identities.
Separate read, nonproduction apply, production apply, and destructive risk classes.
Agent identity does not become human signing authority.
Site text, logs, plugin names, and tool output remain untrusted data.

Development proceeds autonomously within approved scope.
Batch consequential decisions and ask only when dependent work requires an answer.
The [autonomy policy](AUTONOMY.md) defines critical human checkpoints.
MCP and remote gateways remain thin scoped adapters, not alternate executors.

The console uses the accepted React/TypeScript/Bun/Astryx stack and approved light/dark design.
Preserve keyboard access, screen-reader semantics, responsive layouts, visible uncertainty, and recovery evidence.
Console writes and remote sessions need their own authentication, authorization, and web-security acceptance.

## 11. MVP, phases, and evidence gates

The Core proof, production pilot, usable panel, and full replacement are separate milestones.
The [roadmap](planning/ROADMAP.md) contains their tasks and acceptance contracts.
Historical G0–G6 labels remain traceability identifiers, not competing plans.

### 11.1 Prototype scope guardrail

Start with one disposable WordPress fixture and one trusted operator.
Use a second fixture for cross-site tests.
Do not require every future panel feature before testing the engine.
Node.js/Bun hosting remains required product scope after the foundation.

### 11.2 Release readiness: mandatory tests

Retain fault, privilege, isolation, config, backup, agent, supply-chain, and operational campaigns T01–T15.
Test crashes, resets, disk exhaustion, read-only storage, corrupt state, failed tools, unavailable services, and interrupted upgrades.
Retain critical security review before a production pilot and before expanded privileged or public boundaries.
Automated testing and agent reviews prepare those checkpoints.
Neither is a security certification.

## 12. Migration, lifecycle, and operational safety

Prefer fresh-host migration with the incumbent retained through acceptance.
Inventory files, databases, encodings, runtimes, extensions, URLs, uploads, jobs, TLS, credentials, DNS, mail, accounts, and API consumers.
Test repeated and interrupted transfers with manifest comparison.
Preserve MX, SPF, DKIM, DMARC, and mailbox ownership until a separately authorized mail cutover.
An in-place converter remains a separate feasibility decision.

Support export, eject, break-glass, independent recovery, and management removal without implicit site-data deletion.
Define patch lag, EOL, compatibility, security updates, and failed-upgrade recovery.
A package downgrade is not a universal database rollback.

## 13. Project governance, licensing, and sustainability

The owner delegates routine development and authorized lab work to agents.
Human accountability remains for critical production, security, custody, spending, and release decisions.
The autonomy policy replaces repeated per-task human checkpoints.
Accepted technical decisions remain binding unless an explicit revision supersedes them.

Rustiron source is Apache-2.0 under D-014.
External programs retain their own licenses.
The selected name is Rustiron under D-015, with no Rust Project affiliation claim.
The registered domain [rustiron.app](https://rustiron.app) remains a product identifier, not deployment authorization.
Public branding retains its qualified-review checkpoint.

Before public production invitations, establish disclosure contact, supported branches, triage, patch response, and release ownership.
Record a maintainer-absence and recovery plan.
Agents can prepare and exercise those procedures.
They cannot create an unfunded human commitment.

## 14. Decisions captured in v0.2 and items still open

Accepted direction includes the four pillars, safe Core sequence, separate executor, SQLite, signed authority, owned OLS includes, and independent recovery.
D-009 selects the implemented frontend direction.
D-010 sets recovery targets.

D-011/D-012/D-016 retain explicit lab exceptions.
D-017 adds CyberPanel parity.
D-018 records this brief revision, app hosting, service orchestration, and reduced human checkpoints.

Still open: supported release tuple, full executor confinement, storage/custody arrangements, critical reviewer, app recipes, mail/transfer integrations, tenancy, and migration compatibility.
Exact integration versions require compatibility evidence when implemented.
Do not reopen settled choices merely because archived drafts describe them as proposals.

## 15. Stop / pivot criteria

Reconsider the affected implementation if OLS ownership, privilege isolation, independent recovery, or maintenance cannot meet its contract.
Compare the cost and outcomes of composed alternatives.
Retain the panel goal unless the owner explicitly changes it.
A failed speed hypothesis removes speed claims, not demonstrated safety or recovery value.
No unresolved Critical/High security defect enters production.

## 16. Review questions for the next architecture session

Architecture work answers the next concrete blocker in the roadmap.
Resolve the smallest ownership, isolation, recovery, integration, or authority question that prevents a milestone exit.
Existing review questions and original rationale remain in the preserved source.
Do not restart product discovery or create another roadmap.

## Source and provenance notes

The owner-supplied brief and independent reviews established the original fact set.
The [roadmap](planning/ROADMAP.md) retains all slice, feature-card, and parity identifiers.
Git preserves the original brief and retired planning detail at `49e0c7b`.

Historical research claims retain their dated scope.
New implementation claims need source and evidence.
External claims need primary references.
