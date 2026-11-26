# Rust-Toolchain integration contract

2026-10-24.
**Integrated and verified on S01's real contracts workspace.** Source of instructions: [owner's local integration guide](/mnt/data-z/MyProjects/Rust-Toolchain/RUST-TOOLCHAIN.md).
Read it at execution time.
This page records the project-specific sequence and status, not a fork of its entire procedure.

## Current inspection

Rustiron now has a real `rustiron-contracts` Cargo member, pinned Rust 1.99.1, justfile, reviewed deny policy and Nextest profiles with fail-fast disabled.
`rust-tc`/just and all required tools were already installed.
No global tool replacement was needed.
Historical research manifests remain separate PoCs.

W001/W006 `rust-tc check`, `quick` and `doctor` passed on Rust 1.98.1, including three integration tests and one doctest, Clippy, cargo-deny, cargo-shear and bounded feature checks.
See [evidence](../validation/S01-W001-W006/rust-gates.json) and [validation log](../planning/VALIDATION.md).
Formatting and missing integration-test crate documentation initially failed.
The sources were fixed and logs retained.

W002 adds Serde/serde_json and their eleven-package external dependency graph.
The owner requires latest compatible stable versions.
Registry checks confirm Serde 1.0.229/serde_json 1.0.154, with no compatible lockfile updates.

Rustup identified stable 1.99.1, installed as a separate exact project toolchain with rustfmt/Clippy/LLVM tools.
The global default was not changed.
W002 evidence records reverified gates and 22 tests plus one doctest on that pin.

All workspace members are unpublished.
The source license is Apache-2.0 (D-014). deny.toml classifies the workspace crates under that license.
Dependency, advisory, and source checks stay active.

MIT and Apache-2.0 remain the general dependency permissions.
The bundled Unicode-3.0 notice was reviewed for unicode-ident 1.0.27 and is permitted only for that exact package version.
The initial denied-license run is retained.

See [W002 evidence](../validation/S01-W002/README.md).
No dependency was added solely for a gate.
Deeper Miri/mutants/fuzz/public SemVer recipes are not wired without relevant code/targets/baselines.

No dummy acceptance or Sonar setup.

## Maintaining the integration

1. Inspect the actual Cargo members, toolchain, lint/test/deny/Nextest config,
   justfile and ignored outputs.
Preserve useful existing values.
2. Check installed prerequisites from the guide. Install only missing tools,
   avoiding any global replacement of an already available wrapper/toolchain.
3. Merge the reference `justfile`, `deny.toml`, `.config/nextest.toml` and
   `rust-toolchain.toml` components.
Use the real workspace/package scope.
Review dependency licenses, source/advisory policy and features against the actual lockfile.
Nextest must have `fail-fast = false`.
4. Keep `/target/` ignored and AGENTS as the single instruction source. The
   project's per-task rule requires quick feedback and a full doctor before each completed Rust task/commit.
Do not replace AGENTS with the template.
5. Actually execute `rust-tc check`, `rust-tc quick`, and `rust-tc doctor`. Fix
   every failure and record commands, environment/results and justified limits.
Only then mark W006 integrated.
Default tools are local only.
No CI-provider YAML or Sonar configuration is implied.

## Check ownership

| Responsibility | Owner |
| --- | --- |
| Formatting / compile / Rust lint | rustfmt, cargo check, Clippy through rust-tc |
| Unit/integration / doctests | Nextest; separate cargo test --doc |
| Advisories/licenses/bans/sources | cargo-deny |
| Dependency placement / unused dependencies | cargo-shear |
| Feature combinations | cargo-hack through the bounded guide recipes |
| Public library compatibility | cargo-semver-checks when an actual public API baseline exists |
| Deeper testing | Miri/mutants/fuzz/deeper features only for applicable risk and real targets |

W003 introduced a genuine cross-crate dev dependency.
`cargo-hack` removes those manifests temporarily, so its no-dev graph cannot use the unchanged full-workspace lockfile with --locked.
`scripts/check_features.py` derives the graph offline in a disposable source copy.

The script verifies each package/version/source/checksum against the original lock.
The script then runs the required locked no-dev feature checks.
Original manifests/Cargo.lock stay untouched.

No warning/check was disabled.
The initial locked-graph failure is preserved in W003 evidence.
On first setup, populate the cache with `cargo fetch --locked`.

The isolation script uses Python 3.11+ and intentionally refuses an uncached offline graph.

`rust-tc quick` provides fmt/check/Clippy/Nextest/doctests.
`rust-tc doctor` is the full local gate and also covers dependency/feature checks.
Use `rust-tc` as the public command.

Do not add cargo-audit, rust-doctor, Sonar, or blanket warning suppressions.
Run deeper feature powersets only for a stated risk.
The exact integration acceptance contract is the linked owner guide, not the existence of these planning instructions.

Passing doctor never replaces Rustiron's actual privilege, isolation, journal, OLS, recovery or independent human-review campaigns.

## W157 maintained parser fuzzing

[W157](../validation/S10-W157/README.md) adds real canonical-object and five-kind PreparedPlan targets in a separate unpublished [workspace](../../fuzz/README.md).
`rust-tc fuzz-check` checks formatting/Clippy, its independent lock/dependency policy, deterministic seed paths and instrumented seed replay.
`rust-tc fuzz` adds bounded coverage-guided campaigns.

Both use the documented pinned local cargo-fuzz and separately named nightly.
Product Rust remains 1.99.1.
ASan and standard-library instrumentation are enabled.

Doctor remains the ordinary product gate.
It does not cover this independent graph or timed campaigns.

The composed fuzz policy inherits root checks and permits only the reviewed libfuzzer-sys 0.4.13 NCSA conjunct.
No root exception/advisory suppression or new product dependency is added.
Generated corpora/artifacts stay under ignored target paths with manifests.

Intended private decoder regressions must fail oracle assertions and replay.
Initial compile failures and measured campaign limits are retained in W157.
This covers parser invariants only, not whole T04, executor effects, the hostile restore corpus or security acceptance.
