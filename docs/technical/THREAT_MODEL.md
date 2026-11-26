# Rustiron Core threat model

Updated: 2026-11-03.
Core threat model.
Critical review and host proof remain open.
Scope: the proposed G1–G3 Core in [SPEC.md](SPEC.md), with gate changes for pilot/console/extensions in [Roadmap](../planning/ROADMAP.md#roadmap-to-v10).

## Assets and assumptions

Protect host root authority, each site's files/credentials/DB/processes, serving availability, signer authority, resource ownership, replay history, recovery credentials and independent artifacts.
Protect evidence integrity as far as its trust domain allows.
Root-owned local logs are not immutable against host root.

The technical operator and bootstrap administrator are trusted.
WordPress, plugins/themes/uploads, imported archives/SQL, website text, agent prompts and coordinator requests can be hostile.
An agent may be confused or deliberately malicious.

The coordinator may be fully compromised.
Backup uploader compromise is assumed possible.
The executor, approved package/kernel/SELinux/systemd implementation and out-of-band signer are part of the trusted computing base.

MVP is not hostile commercial shared hosting.
That narrower claim does not excuse cross-site data leaks or root escalation from a compromised plugin.
Root/kernel compromise, physical hypervisor compromise and malicious trusted administrators are not prevented.
Off-host copies, separated recovery authority, external signatures and independent receipts reduce resulting recovery/evidence risk.
No global root compromise containment or tamper-proof audit claim is made.

## Boundaries and authority

| Boundary | Untrusted input | Enforcing authority |
| --- | --- | --- |
| CLI → coordinator | Requests, local import files, agent text | Peer credentials, strict schema, read policy, redaction and quotas |
| Coordinator → executor | Entire request including IDs, purported observations and grants | Root registry/policy, independent signature/scope/precondition checks, durable replay ledger |
| Executor → host tools/files | Semantic inputs and potentially raced filesystem state | Fixed catalogue, protected descriptors, pinned executables/argv, bounded execution; no shell |
| Host → site runner | Packages/content, PHP/SQL behavior | Effective site UID/GID, enforcing MAC, cgroup/namespace/sockets and DB grants |
| Source worker → repository | Malicious uploads, snapshot names, credentials | Backend-enforced no-delete; per-site scope; independent retention policy |
| Repository → restore environment | Malicious files, SQL, metadata and application code | Separate fetch phase, unprivileged extraction/execution, no egress/secrets/host mounts, resource budgets |
| Human → grant | Possibly misleading proposed plan or compromised render path | Trusted offline rendering of signed bytes, separate key custody, bounded grant |
| Evidence → operator/agent/UI | Host/site-origin strings and self-reported claims | Escaping, provenance, completeness states, independent evidence verification |

## Abuse cases, controls and acceptance campaigns

W009 adds partial A03/A04 evidence through closed typed fixture contracts, full-byte digest binding, scoped plan/grant consistency and comparison with independently supplied policy facts.
It does not verify signatures, policy provenance, replay, live observations or a privileged enforcing boundary.
See [implemented limits](FIXTURE-APPROVAL.md).
No full campaign is accepted here.

Controls below retain their full host/privilege acceptance requirements.
W003's local development path supplies partial A01/A02/A20 evidence: same-UID kernel peer checks at both endpoints, a private socket, frame/deadline/worker bounds and fixed/escaped public diagnostics.
It does not establish distinct-UID integration, enrolled service identities, flood fairness, tenant containment or executor policy.
See [local development limits](LOCAL-DEVELOPMENT.md).
Full campaigns remain pending.

| ID | Attack / failure | Required control and proof | Test |
| --- | --- | --- | --- |
| A01 | Site or another local user connects to either socket or swaps a socket path | Root-owned ancestry, exact peer UID authorization, no tenant membership in privileged groups; exercise both live sockets | T02, T06 |
| A02 | Slow frames, many clients, huge nested JSON or floods starve root work | Pre-admission frame/depth/count/time quotas, bounded parsing/outputs, no mutation lock while waiting on input, bounded queues | T02, T04 |
| A03 | Coordinator replaces hostname/site/verb/artifact/profile or global effects after approval | Strict canonical plan and signed grant; executor independently renders/checks registry and verifies complete semantic digest | T03 |
| A04 | Duplicate members, Unicode/number ambiguity or version downgrade causes parser disagreement | Closed request schemas, duplicate rejection, RFC vectors, exact integers, independent round trips and no fallback protocol | T03, T04 |
| A05 | Agent signs its own plan, forwards a signing agent, impersonates a human or expands a capability | Separate issuer/requester, external key unavailable to services/agent, fixed signer allowlist and risk policy; inspect actual custody | T03, T13 |
| A06 | Replay/concurrent requests, two executor processes or stale restored journal repeats effects | Unique durable grant binding, process lock, single mutation admission, status-only repeat; restore forces new host epoch | T03, T05, T12 |
| A07 | Full disk, corrupt/absent ledger, failed fsync or backwards clock fails open | Deny new effects, preserve diagnostics and blocks; never create an empty replay DB; expiry/clock policy checked before steps | T03, T05 |
| A08 | Traversal, symlink/hardlink, mount/ancestor swap or TOCTOU redirects root config writes | Root-controlled ancestry, descriptor-relative no-follow/beneath operations, inode/type/owner/link checks, atomic replacement and parent sync; adversarial races | T04, T08 |
| A09 | Root WP-CLI, attacker PHAR, command/env/config/SQL injection gains host execution | No arbitrary tool/argv/env/config inputs; root never executes or traverses tenant content; fixed launcher drops privileges before parsing content | T04, T07, T11 |
| A10 | Site A reads B credentials/session/temp/socket, signals B or reads host/control secrets | Distinct identities, private paths/DB grants, effective enforcing policy, process restrictions and explicit shared-memory tests | T06 |
| A11 | Fork/memory/CPU/I/O/disk exhaustion or PHP descendants escape accounting | Tested per-site process membership and configured limits, private storage quotas/bounds where supported, failure/alert thresholds; reject unenforced limits. Site PHP (`rustiron_php_t`) has no exec right beyond its entry point, and the module hides no exec denial, so each exec attempt is refused with an AVC record that names the site category ([W398](../validation/S10-W398/README.md), [D-046](../decisions/D-046-php-exec-audit-scope.md)). The module hides only the denials of normal traffic: name-lookup file reads, the `statfs` of `/`, and `access(2)` checks on the site code folder. That access stays denied ([W401](../validation/S10-W401/README.md), [D-048](../decisions/D-048-php-denial-noise.md)) | T06, T15 |
| A12 | OLS syntax passes but vhost maps to another site/identity | Semantic config check plus vhost/UID/GID/content probes for all sites; false-positive HTTP 200 cannot pass | T08 |
| A13 | WebAdmin/package update/manual edit becomes another config writer | WebAdmin disabled, explicit ownership/adoption, read-only drift and signed activation; unknown parent changes refuse writes | T08, later P06 |
| A14 | Site `.htaccess` edits force endless global reloads; failed restart leaves old workers | No automatic unbounded reload; signed reload budget/coalescing and actual process-lifecycle verification | T08 |
| A15 | Crash between config switch, DB creation, upload or outcome commit causes false success/unsafe retry | Per-step durable intent, fixed recovery observers, explicit partial/uncertain outcomes and blocks; exercise every boundary | T05, T08, T10 |
| A16 | Backup source ransomware deletes/prunes history or floods malicious snapshots | Backend no-delete rights and negative tests, separate retention authority, storage monitoring and conservative retention; source never prunes | T10, later P03 |
| A17 | Provider/account failure, source-host loss or key loss makes good-looking backups useless | Independent physical off-host copy, recovered keys, clean-host manual restore, provider/credential failure drills; publish residual common dependencies | T12, later P03 |
| A18 | Archive traversal/device/hardlink/bomb, SQL extension abuse or plugin callbacks attack restore host | Unprivileged fixed sandbox, no production access or repository secrets, throwaway DB, no egress/mail, extraction/resource corpus tests | T11 |
| A19 | Restored malicious code steals fetch credentials before they are removed | Separate fetch/stage identity; no restored-code execution until credential FDs/mounts/env are absent; probe inheritance and cleanup | T11 |
| A20 | Logs/plugin names/website output inject terminal escapes or instructions; diagnostics leak keys | Bound/redact/escape by default; agent treats content as data; policy enforced in executor even if agent follows injected text | T13 |
| A21 | Local receipt/“backup succeeded” hides failed health, independence or incomplete capture | Seven independent fields, evidence hashes/provenance/scope, explicit unknowns; independent attester/host validation for independence. A host receipt key signs each receipt ([D-042](../decisions/D-042-host-receipt-key.md)): a change after export is detected with the recorded public key, but root on the host can sign any receipt, so the receipt stays self-attested | T10–T12 |
| A22 | Snapshot restore or failed upgrade rolls back ownership/authorization history | Schema gate, offline consistent backups, epoch/key rotation and re-observation before admitting new work; no blind DB downgrade | T05, T12, later P06 |
| A23 | Compromised dependency, package feed or self-update expands trusted code | Pinned reviewed sources/lockfile, minimum executor dependencies, checksum/signature/license/advisory checks; no unsigned self-update | T15, later P09 |
| A24 | Eject/uninstall deletes sites or removes security prerequisites | Ownership-aware export/transfer, no data deletion, retain required serving/isolation units and prove both services can stop | T09 |

## Recovery and availability failure limits

Systemd stop completion is not proof that OLS/PHP descendants exited.
Capture must verify its actual quiescence model and restore service state on known failure.
Shared OLS/MariaDB can remain common failure domains even with per-site resource limits.
Crash-recovery cannot make multi-system effects atomic.
Data capture consistency and manual recovery limits must be explicit.

A host with compromised root may falsify observations, read source credentials, delete local journals and tamper with application data before upload.
Backend no-delete protects historical retention only to the extent tested by that backend.
It does not prove all copies survive provider administration failure.
Independent copy/key recovery is mandatory for MVP.
Broader provider/immutability and ransomware scenarios are required before the corresponding pilot claim.

The signer can approve a dangerous but accurately described action.
Offline rendering, bounded effects, no destructive MVP verbs and recovery evidence reduce risk.
They do not replace human review.
Crypto protocol tests using synthetic keys cannot establish actual human separation/custody.

## Review and promotion rules

Each verb needs a focused threat review before activation, including arguments, root paths, tool inputs, secrets, limits, preconditions, interruption and compensation.
Fuzzing supplements scenario tests.
Maintain an abuse-case → test → immutable evidence index.
Preserve failures even when later fixed.

Before G1 acceptance, resolve A01–A11 for the enabled boundary and the exact host profile.
Before G2, prove A12–A15 and A24.
Before G3, prove A16–A22 within the core recovery scope.

Dependency and disclosure readiness grows with exposure; no Critical/High outstanding security defects or unreviewed trust boundary may enter a live pilot.
A qualified independent human reviews at least executor, authorization/host isolation and restore paths before G4, with fix/retest evidence.
A named critical reviewer and maintenance owner remain unassigned.

D-018 permits autonomous test preparation and isolated lab execution.
A different human recovery-guide follower is optional.

Remote gateway, MCP writes, console writes, public management access, extra PHP/runtime profiles and multi-host execution each reopen the affected threat boundaries.
None inherit security acceptance merely by reusing CLI schemas.

## Cleanup truthfulness update — W165, 2026-11-03

[W165](../validation/S10-W165/README.md) adds bounded local A15/A18/A21 evidence: stop/quiescence must precede deletion.
Unavailable or malformed postconditions cannot become zero/clean.
Unknown cleanup retains the journal block and exact receipt uncertainty across reopen.

Verified administrative cleanup ends failed, not passed.
See [cleanup contract](RESTORE-CLEANUP.md).
This does not accept live process shutdown, hostile cleanup races, root-content separation or T11.

The D-012/F-05 hostile corpus and D-016 confinement obligations stay open.

## Capture phase update — W166, 2026-11-03

[W166](../validation/S10-W166/README.md) adds local A09/A19 launch-argument evidence.
The tests cover closed phases, no dump repository credentials, masked roots, named environment scrubbing, fetch/no-lock reads, and metadata-only preflight.
The [contract](CAPTURE-LAUNCH.md) retains precise limitations.
Argument/metadata proof is not effective worker namespace, credential secrecy, backend-right or hostile-content proof.
T04/T10/T11 and the pre-pilot confinement/review gates remain open.

## Restored-content inventory update — W167, 2026-11-03

[W167](../validation/S10-W167/README.md) removes the root recursive count walk.
A fixed unprivileged native worker reports bounded metadata.
Unreadable or limited traversal cannot pass artifact completeness or run import/health.

[Contract](RESTORE-INVENTORY.md) records limits, no-content processing and tested launch/report boundaries.
Local tests do not prove effective namespaces/MAC, races, hostile corpus safety or the remaining root relabel/archive walks.
The owner authorizes lab VM tests.

T11, D-016 and production gates stay open.

## Scheduled capture update — W386, 2026-11-13

[D-035](../decisions/D-035-scheduled-capture.md) adds a standing capture grant for the daily capture.
A compromised coordinator holds that grant for up to 35 days. It can choose the second of each capture inside an open window and can withhold runs.
It cannot change the verb, the sites, the destination, or the recipe, run outside a window, run twice in one window, or exceed `max_runs` (A03, A06).
Missed-run detection on the coordinator is not independent of the coordinator. The root `capture-status` command and a store listing with the fetch key are the independent checks.
[W386](../validation/S10-W386/README.md) records the local tests and the lab proof.

## Service and app expansion

D-018 requires Node.js/Bun app hosting and mature-service orchestration, including PowerDNS and firewalld.
Treat package scripts, dependency artifacts, deployments, app logs, DNS record values, and imported mail/configuration as untrusted data.
Each adapter needs resource ownership, scoped credentials, authorization, replay, interruption, and recovery tests before effects.

Build identities cannot read management or production secrets.
DNS and firewall adapters cannot modify foreign zones, widen host exposure, or alter mail records through generic passthrough requests.
Public sessions, mail hosting, reseller delegation, and runtime changes need their affected critical review.

No expanded boundary inherits Core acceptance automatically.
