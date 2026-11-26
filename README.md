# Rustiron

Rustiron is an open-source hosting panel built with Rust and TypeScript.
The product replaces required CyberPanel workflows and includes Node.js, Bun, and EmDash CMS hosting.
Rustiron orchestrates mature infrastructure instead of reimplementing web, DNS, database, firewall, or backup services.
Its goal is to improve operational safety, recovery, usability, and agent automation.
That goal is a target, not a measured result ([W400 claims audit](docs/validation/S10-W400/README.md)).

## Current implementation

Status: experimental lab software, 2026-11-24.
Production readiness is not reached, and no production release exists.
Thirty-nine of fifty v1.0 roadmap items are done at lab scope, covering every lab-doable v1.0 capability.
The remaining v1.0 items await explicit owner checkpoints such as production key custody, real DNS/CA/mail choices, and independent human review.

| Surface | Implemented scope (lab verified unless noted) | Current limit |
| --- | --- | --- |
| CLI, coordinator & MCP | `rustiron`, `rustiron-control`, `rustiron-plan`, and read-only stdio `rustiron-mcp` (P17); bounded sockets, inventory, offline plan review, D-098 blast-radius envelopes, and evidence export | Local Unix-socket and workstation-local stdio only; production signer custody stays external |
| Executor & journal v44 | Independent SSHSIG admission, durable intent, and 23 closed verbs across WordPress, static/alias, proxy, Node.js/Bun, EmDash, DNS, TLS, maintenance, and recovery | Lab signer `lab_agent` / `policy_3` only; production release trust and human custody remain open |
| Workloads & confinement | Per-site UIDs, SELinux MCS (`rustiron_php_t`, `rustiron_mail_relay_t`), cgroup/IO limits, WordPress + D-044 LSCache, static/alias, proxy sites, P27 `node_22_v1`/`bun_1_v1`, P30 EmDash 1.6.0, and D-071 mail relay | AlmaLinux 10 x86_64 only ([D-058](docs/decisions/D-058-v1-scope.md)); live container cutover and external mail host wait for M6 |
| DNS & firewall | CP05 PowerDNS 5.1 (`dns_zone_import`, `dns_change`, TSIG AXFR) and CP08 enrolled `rustiron` firewalld zone with loopback-only MariaDB | Production registrar, secondary transfer, and DNS cutover remain owner actions |
| Recovery, diagnoses & alerts | P03 restic + COMPLIANCE Object Lock, retention drills, `site_restore`, `site_credential_rotate`, P04 diagnoses, P05 Uptime Kuma check-in, and P12 capacity envelope | Independent off-site copy follows v1.0 ([D-026](docs/decisions/D-026-defer-offsite-and-escrow.md)); homelab RustFS checks precede P11 |
| Console (`console/`) | React, strict TypeScript, Bun, Astryx; 42 Built routes on charcoal theme; Better Auth accounts, live D-090 loopback coordinator backend, opt-in P15 separate-custody apply and mail catalog (disabled by default) | Owner design review, human screen-reader session, and focused P15 UI review remain open |
| Post-v1.0 (M7) modules | P17 MCP, P24 drift explanation, P25 traffic budget, and P22 Experiment Cards lab verified; Slice 1 contracts/verifiers verified locally for P16, P18, P19, P20, P21, P28, and CP07 | Live remote exposure, multi-host transport, second PHP RPM, Valkey, and multi-tenancy require separate owner decisions |

Read [State](docs/STATE.md) for verified checkpoints and open gates.
Read [M6 replacement migration acceptance](docs/operator/37-M6-REPLACEMENT-MIGRATION.md) for the integrated lab rehearsal and cutover rules.

## Install

No supported public installer or production release exists.
Use the [local development guide](docs/technical/LOCAL-DEVELOPMENT.md) for source builds.
Do not use lab scripts as production installation procedures.

## Quick start

Read the [Project Brief](docs/PROJECT_BRIEF.md), [roadmap](docs/planning/ROADMAP.md), and [handoff](HANDOFF.md).
Use the [documentation index](docs/README.md) to locate technical contracts and operator runbooks.
For the local Console preview, follow the [console guide](console/README.md).
The preview requires no production credentials and opens no public listener.

## Requirements

Local development uses Linux with the pinned Rust and Bun toolchains.
The first supported host profile targets AlmaLinux 10 x86_64, OpenLiteSpeed 1.9, LSPHP 8.4, MariaDB 10.11, systemd, and enforcing SELinux.
Optional v1.0 host components include PowerDNS 5.1, Node.js 22 LTS, Bun 1.4, and Postfix (loopback-only relay).
Exact version floors and end-of-life dates live in `crates/control/support-matrix.json` ([support matrix](docs/technical/SUPPORT-MATRIX.md)).

## Local verification

Follow the [Rust-Toolchain guide](docs/technical/RUST-TOOLCHAIN-INTEGRATION.md) for build prerequisites.
The Python suite requires the isolated [SBOM schema environment](scripts/release/README.md#offline-sbom-schema-validation).
Run every command from the repository root with `TMPDIR=/tmp`.
Each gate returns exit code 0 on success.
If a gate fails, preserve its output and fix the failure before committing a completed task.

```sh
sed -n '1,180p' docs/STATE.md
rg --files docs
sha256sum docs/feasibility/g0/G0_OPUS_SYSTEMS_REPORT.md
python3 scripts/prepare_sqlite.py --fetch
rust-tc check
rust-tc quick
rust-tc doctor
rust-tc fuzz-check
python3 scripts/check_local_cli.py
python3 scripts/check_readonly_acceptance.py
python3 scripts/check_canonical_vectors.py
python3 scripts/check_fixture_review.py
python3 scripts/check_fixture_journal.py
python3 scripts/check_docs.py
python3 scripts/check_receipt.py docs/validation/S10-W041/receipt-op_pr13.json
python3 -m py_compile scripts/check_docs.py scripts/check_local_cli.py scripts/check_features.py scripts/check_readonly_acceptance.py scripts/check_canonical_vectors.py scripts/check_fixture_review.py scripts/prepare_sqlite.py scripts/tests/test_sqlite_build.py scripts/check_fixture_journal.py scripts/check_receipt.py
target/release-schema-env/bin/python -I scripts/release/sbom_schema.py docs/validation/S10-W142/sbom.cdx.json
python3 -m unittest discover -s scripts/tests -v
bunx --bun @google/design.md@0.4.0 lint docs/DESIGN.md
bun run --cwd console verify
bun run --cwd console check:browser
git diff --check
git diff --cached --check
```

Also run `console check:browser` against `console/.live/observation.json` and the product-profile executor tests.
Use the [agent workflow](docs/AGENT-WORKFLOW.md) for full gate details and evidence rules.

## Documentation map

- [Documentation index](docs/README.md): categorized map of every contract, guide, decision, and archive.
- [Project Brief](docs/PROJECT_BRIEF.md): product source of truth.
- [Roadmap](docs/planning/ROADMAP.md): the only milestone timeline and task queue.
- [State](docs/STATE.md) and [Handoff](HANDOFF.md): dated implementation state and short resume checkpoint.
- [Decision register](docs/decisions/DECISIONS.md): all accepted architectural and scope choices (`D-000` to `D-101`).
- [Operator kit](docs/operator/README.md): critical owner checkpoints and all 38 operator runbooks.
- [Autonomy policy](docs/AUTONOMY.md): routine agent boundaries and human authority gates.

## Scope and source license

Rustiron source is Apache-2.0 under [D-014](docs/decisions/ACCEPTED-RECORDS.md#d-014--source-license).
See [LICENSE](LICENSE).
Workspace packages remain unpublished.

External services retain their own licenses.
The name claims no Rust Project affiliation under [D-015](docs/decisions/ACCEPTED-RECORDS.md#d-015--name-and-trademark).
The registered domain [rustiron.app](https://rustiron.app) does not authorize deployment or public exposure.
