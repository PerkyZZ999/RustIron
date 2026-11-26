# Local release integrity tools

These are unprivileged P09 development tools.
There is no supported release, release key, publication channel or installer.
The remaining owner choices are in [SECURITY.md](../../SECURITY.md) and [Roadmap](../../docs/planning/ROADMAP.md#p09--release-integrity).

The [P09 readiness map](../../docs/planning/P09-READINESS.md) separates current local proof from remaining human/product obligations.
The [emergency-patch/absence protocol](../../docs/planning/P09-DRILL-PROTOCOL.md) has a **PASS_LOCAL_TECHNICAL** result under [W155](../../docs/validation/S10-W155/README.md).
W153's failing preflight and W154's repair are retained.
The patched-tool candidate and backup-process handoff/refusals are now exercised.
Real human emergency-response/custody and product-release acceptance remain open.

## Manifest, sign and verify

Run from the repository root with Python 3.11+ and OpenSSH available:

```sh
scripts/release/release_sig.sh manifest RELEASE_DIR
scripts/release/release_sig.sh sign RELEASE_DIR KEY
scripts/release/release_sig.sh verify RELEASE_DIR ALLOWED_SIGNERS SIGNER_ID
scripts/release/release_sig_test.sh
python3 -m unittest discover -s scripts/tests -p test_release_sig.py -v
scripts/release/release_sig_test.sh target/candidate-w151-lab-unsigned-final-20261102
python3 -m unittest discover -s scripts/tests -p test_release_sig_runner.py -v
```

The caller controls the staging directory and its ancestry.
Keep that directory private and free of concurrent writers until verification finishes.
Artifacts are never run.

`KEY` is an external private key.
Nothing creates a real release key.
The test command creates and removes temporary synthetic keys.

These keys cannot authorize executor operations.

The optional test-runner argument is a real artifact directory.
Its Python helper copies the complete nested tree, including hidden files and names with spaces, into a private temporary tree.
It compares all copied payload hashes with the source before testing the same seven signature cases.

Read-only source modes and bytes are preserved.
Only copied directories/payloads are made writable where needed.
Source executables are never run.

Root manifest/signature metadata is type-checked, then replaced only in private copies with fresh synthetic metadata.
Nested files with those names remain payloads.
This does not verify the original signature or authenticate the source.

Raw regular source hardlinks are allowed here because copying produces separate single-link staged files.
Source symlinks (including the root and metadata), special files, unsupported names and empty payload trees are refused.
Unsupported input is never silently omitted.

The underlying manifest/sign/verify commands still require single-link files.
Temporary test keys and allowlists stay outside every copied artifact tree and are removed with the private workspace on normal completion or handled failure.
Keep source/ancestry private without concurrent writers.

This test runner is not a privileged or concurrent-writer boundary.

`release_manifest.py` walks the actual directory through no-follow directory and file descriptors and builds sorted UTF-8 SHA-256 lines.
Both signing and verification require the stored manifest to match those exact bytes.
Manifest paths are never interpreted as input paths, so absolute, traversal, duplicate or noncanonical entries cannot redirect reads.
OpenSSH still verifies the signature in namespace `rustiron-release-v1` against the supplied allowlist and identity.
Matching hashes alone do not authenticate a release.

Only root `SHA256SUMS` and `SHA256SUMS.sig` are metadata.
Files with those names in subdirectories are artifacts and are hashed.
All files, including metadata, must be single-link regular files.

Symlinks, hard links, FIFOs, sockets and devices are refused.
Names must be UTF-8 without backslashes or ASCII control characters.
Nested paths and spaces are supported.

At least one artifact is required.
Manifest replacement is atomic and does not truncate an existing link target.

The existing manifest/sign/verify command interface and SSHSIG namespace are unchanged.
A normal W142 manifest remains compatible.
Exit 0 means success, 1 means refusal or verification failure, and 2 means an unknown command.

Diagnostics omit untrusted file names.
This format signs file names and bytes, not permissions, empty directories or a future archive format.
It is not proof against a concurrent staging-directory writer and does not install anything.

W143 regression and mutation evidence is in [S10-W143](../../docs/validation/S10-W143/README.md).

## Private integrated lab bundle (W151)

W151 exercised the existing tools together on a new private staging tree: `target/candidate-w151-lab-unsigned-final-20261102`.
It contains the six W150 binaries under `lab-bin/`, generated SBOM, raw reproduction/native/Cargo records, input pins, the source license, draft security policy and a lab-only marker.
There are 18 payload files plus canonical `SHA256SUMS`, with no signature.

The parent is mode 0700.
All artifact files are independent single-link copies.
This is a local lab verification bundle, not a product package or installer.

The executor contains the fixture switch that SPEC forbids shipping in a product executor.
Third-party redistribution notices are not claimed complete.

Verified read-only commands for this exact local bundle are:

```sh
python3 scripts/release/release_manifest.py check target/candidate-w151-lab-unsigned-final-20261102
python3 scripts/release/sbom.py check target/candidate-w151-lab-unsigned-final-20261102/metadata/sbom.cdx.json
target/release-schema-env/bin/python -I scripts/release/sbom_schema.py target/candidate-w151-lab-unsigned-final-20261102/metadata/sbom.cdx.json
```

The [one-off W151 campaign](../../docs/validation/S10-W151/stage_campaign.py) also verifies exact payload inventory, binary hashes against the independently checked W150 pair and exact copied provenance/pins/documents.
Tamper, missing, extra, symlink and FIFO probes are refused.
With a regenerated unsigned manifest, the profile still refuses changed binaries, added files and an inconsistent SBOM.

An unsigned manifest alone authenticates nothing.
Those profile checks rely on the trusted local builder's independently checked records.
W151 makes no release signature or independent-attestation claim.

Evidence and residual gates: [W151](../../docs/validation/S10-W151/README.md).

## Integrated synthetic signature exercise (W152)

W152 signed only disposable copies of the W151 lab bundle with temporary synthetic Ed25519 keys.
The test copy's lab marker explicitly described that synthetic signature.
The original W151 tree stayed unchanged and unsigned.
Keys and allowlists stayed outside bundle trees, and temporary private-key files and copied bundles were removed.
Only public verification evidence is retained in [W152](../../docs/validation/S10-W152/README.md).

The real release wrapper accepted the intact copy and refused 20 altered or unauthorized cases, including wrong identity/key/namespace and regenerated manifests after payload changes.
Forged in-bundle trust files could not replace the explicitly supplied external allowlist.
Four deliberately weakened wrapper copies failed the campaign's assertions.
No project signing code changed.

A deliberately re-signed inconsistent SBOM passed signature and schema checks but failed `sbom.py check`.
Signature verification authenticates signed bytes under the supplied trust policy.
It does not replace source/profile, SBOM consistency, schema or release-governance gates.

The temporary test identity `release-w152@synthetic` is not a real release identity or executor authority.
Public replay verifies the retained manifest signature only.
Full bundle checks ran live before temporary copies were removed.

Exact commands and the initial raw-OpenSSH exit-code expectation correction are preserved in the evidence.

## Packaged product candidate (W584)

[W584](../../docs/validation/S10-W584/README.md) applies the same signature runner to a product-profile management archive built on AlmaLinux 10.3. The intact package verified and tampered copies failed. The candidate uses synthetic release trust and stays private.

## Synthetic patch and backup-process rehearsal (W155)

W155 binds the exact reviewed W154 three-file patch, four release tools and regression test to a new private 26-payload lab candidate.
A frozen public packet and external synthetic policy precede the absence branch.
The primary temporary private key is removed before the backup process starts.

The backup process applies/checks the patch, assembles/verifies the candidate, and exercises its copied helper.
The backup process signs only with its own enrolled test key.
No candidate ELF is run.

Disable Python bytecode for that explicit copied-helper invocation so the closed candidate stays exact; never exclude generated bytecode from its inventory to force acceptance.

Unknown/no-authorized backup, stale/mismatched packet, changed policy, wrong namespace/key/identity and altered/regenerated/re-signed candidates are refused at their respective signature/profile boundaries.
Three removed guards trigger acceptance assertions.
All temporary keys/candidates are removed.
Public material can reconstruct and verify the full candidate without any private key:

```sh
python3 docs/validation/S10-W155/replay.py docs/validation/S10-W155/run-5 target/w155-new-public-replay
```

Use a fresh output path.
Dated campaigns must never overwrite old evidence.
The [evidence](../../docs/validation/S10-W155/README.md) records all failures, commands, cleanup, full project gates and the synthetic scope.
Same agent, UID and host operate both roles.
Real custody, human availability and P09 stay open.

## Other tools

The complete same-host Rust/native reproducibility check is:

```sh
systemd-run --user --wait --pipe -p MemoryMax=8G -p MemorySwapMax=0 --working-directory=$PWD $PWD/scripts/release/repro_build.sh target/repro-full-new
python3 scripts/release/repro_build.py check target/repro-full-new
python3 -m unittest discover -s scripts/tests -p test_repro_build.py -v
```

The shell command keeps its `OUTDIR` argument.
That path must now be new, with an existing parent.
The tool never deletes previous builds.

It creates a private directory, builds native SQLite independently, and runs two clean `--release --locked --offline --workspace --bins` Cargo builds.
Each uses the exact toolchain pin and its host target, its own target directory and explicit private SQLite library/header overrides.
Incremental compilation and compiler wrappers are disabled.

Encoded path-remapping flags avoid shell word splitting.
The ordinary SQLite cache and `.cargo/config.toml` are unchanged.
Both metadata and compilation select the pinned Cargo/rustc executables through `rustup which` and execute their recorded resolved paths directly.

`CARGO`, `RUSTC` and `RUSTUP_TOOLCHAIN` are set explicitly.
Empty wrapper overrides reset global Cargo wrapper configuration as documented in the [Cargo environment reference](https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-reads).

Cargo metadata defines the exact binary inventory.
Missing, extra or duplicate binary names fail.
Feature-conditional binary targets require an explicit future profile change.

Cargo JSON records must show one static SQLite binding and its own native search path for each build.
The checker then compares all binary and native hashes.
The public `check` command also verifies the recorded Cargo.lock hash, exact toolchain, host and local project input fingerprint against current inputs.

`result.json` records the result, inputs and commands.
`sha256-a.txt` and `sha256-b.txt` retain the binary digest lists.
Cargo events are in `cargo-a.jsonl` and `cargo-b.jsonl`.

Binaries are under `target-{a,b}/HOST/release`, and native builds are under `native/{a,b}`.
The former `build-info.txt` is replaced by the structured result.
Exit 0 means complete inventories match, 1 means valid outputs differ, and 2 means build/input/verification failure.

Nothing executes or installs these binaries.

W149 adds `source_inputs` with profile `rustiron-worktree-v1` and a sorted relative-path → SHA-256 map.
It fingerprints all files under `crates/`, including embedded assets and untracked additions, plus these fixed inputs:

- `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`;
- `.cargo/config.toml` and legacy `.cargo/config` when present;
- `native/sqlite.toml`;
- `scripts/prepare_sqlite.py`, `scripts/release/sqlite_repro.py`,
  `scripts/release/repro_build.py`, `scripts/release/repro_build.sh`.

Inputs and their ancestry must be regular files/directories without symlinks; special files are refused before opening.
Every local Cargo package must be inside the fingerprinted `crates/` tree.
An external local dependency requires an explicit future profile change.

Dirty starting trees are allowed: the record describes their actual file bytes, not an authenticated Git revision.
Changes to docs, console files or other paths outside this profile do not invalidate the record.
File permissions and empty directories are not hashed.

The command captures inputs before Cargo metadata and rechecks after metadata, before building, after the native pair, after each Rust build and after output comparison.
A persistent change stops the build without publishing `result.json`.
The public `check` compares the complete current profile with the stored map and rechecks after output verification.

Old records without this map are refused; keep them as historical evidence and create a fresh build rather than adding unobserved provenance retroactively.
W149's actual pair records 140 inputs; all six binaries and three native artifacts match.
See [W149](../../docs/validation/S10-W149/README.md).

W150 adds `build_tools` with profile `rustiron-build-tools-v1`.
It records requested/resolved paths, SHA-256 of the selected regular executable and version output for pinned Cargo/rustc and SQLite's fixed `/usr/bin/cc`/`/usr/bin/ar` drivers.
Tool symlinks are supported and their resolved target is recorded; nonexecutables and special files are refused.
Version probes run the selected invocation path in the C locale, fail on missing/empty/nonzero results and have a ten-second deadline.
The invocation name matters for aliases such as `cc`.

These identities join the existing source/input comparisons at every boundary; `check` rejects missing or changed tool records.
Paths are derived from current local selection.
Paths read from `result.json` are never executed.

A tool update requires a new build.
Do not fill in historical provenance retroactively.
Metadata/builds use the recorded Cargo binary directly, with the recorded `RUSTC` and `CARGO` and explicit `RUSTUP_TOOLCHAIN`.

The `+toolchain` syntax belongs to rustup proxies, as described in [rustup's override reference](https://rust-lang.github.io/rustup/overrides.html).
The standalone native helper keeps its fixed driver commands and normal cache contract.
See [W150 evidence](../../docs/validation/S10-W150/README.md).

These are unsigned records from a trusted local builder.
Comparison does not authenticate source revision, a clean tree or a compiler.
The fingerprint proves local consistency, not a hermetic build closure.

Excluded inputs include registry source/cache contents, compiler/helper libraries, subprocess tools including the Rust linker, external/global Cargo configuration, and arbitrary build-script inputs.
Only the four selected executable drivers are fingerprinted, not complete compiler installations.
The source is not frozen.

Changes restored between checks can evade them.
The caller must control source/output ancestry and prevent concurrent writes.
Cross-builder, AlmaLinux runtime compatibility, packaging and supported-release proof remain separate.

See [W146](../../docs/validation/S10-W146/README.md).

The optional native SQLite two-build check is:

```sh
systemd-run --user --wait --pipe -p MemoryMax=8G -p MemorySwapMax=0 --working-directory=$PWD /usr/bin/python3 scripts/release/sqlite_repro.py build target/repro-native-new
python3 scripts/release/sqlite_repro.py check target/repro-native-new
python3 -m unittest discover -s scripts/tests -p 'test_sqlite*.py' -v
```

`build` requires a new output path with an existing parent.
It compiles the same verified archive independently for `a` and `b` with a commit-derived `SOURCE_DATE_EPOCH`.
No download or default compiled-cache reuse occurs.

`check` revalidates each pin/receipt/artifact set before comparing the static archive, header and pkg-config file.
Both commands return 0 when they match, 1 when independently valid outputs differ, and 2 on build, input or cache errors.
Existing output is preserved and refused by `build`.

Detailed result and build receipts are stored in `result.json` inside a completed build output.
The directory and its ancestry are caller-controlled and must have no concurrent writers.
These checks do not authenticate a compromised compiler or prove another machine/architecture.

See [W145](../../docs/validation/S10-W145/README.md).

The SBOM input-consistency check is:

```sh
python3 scripts/release/sbom.py generate OUT.json
python3 scripts/release/sbom.py check OUT.json
python3 scripts/release/sbom.py selftest
python3 -m unittest discover -s scripts/tests -p test_sbom.py -v
```

`check` requires unique Cargo name/version identities, canonical Cargo references, and exact archive checksums from `Cargo.lock`.
The check requires one matching lockfile provenance property and exactly one native component matching SQLite's pin.
The native comparison includes its version, reference, archive SHA3-256, download URL, license label and provenance.

Extra native components, missing SQLite, duplicate identities or conflicting hashes fail.
Malformed JSON is refused without reflecting its content.
Checking uses the local lock and pin.

Only generation needs offline `cargo metadata`.
Generation remains byte-compatible with W142.
Evidence: [W144](../../docs/validation/S10-W144/README.md).

This is a consistency check for Rustiron's generated profile.
It is not full CycloneDX schema validation, a binary linkage inventory, an SBOM signature or verification of Cargo component license expressions.
Cargo-deny remains the dependency/license/advisory gate.
The output includes target-specific locked packages that may not be linked into a Linux binary.

[W142](../../docs/validation/S10-W142/README.md) remains historical evidence for the earlier shared-native Rust builds.
W145 and W146 add independent native and combined Rust/native evidence without rewriting it.
W147 adds the offline schema check below.
An independent builder and owner governance remain open.

## Offline SBOM schema validation

`sbom_schema.py` checks the full official CycloneDX 1.6 JSON Schema, including its SPDX/JSF references and all four declared format kinds.
It complements `sbom.py check`: schema validity alone does not prove Cargo/SQLite consistency.
The existing generator and historical SBOM bytes are unchanged.

First prepare an isolated environment with Python 3.11+ and an installed `uv`.
Create the environment only if the path is absent.
Reuse the existing project environment by running just the sync command.
No system Python packages change.
Setup may download hash-locked wheels from the official Python package index:

```sh
python3 -m venv --without-pip target/release-schema-env
uv --no-config pip sync --default-index https://pypi.org/simple --python target/release-schema-env/bin/python --require-hashes --only-binary :all: --link-mode=copy scripts/release/schema-requirements.txt
```

Normal validation is offline.
Run from the repository root:

```sh
target/release-schema-env/bin/python -I scripts/release/sbom_schema.py docs/validation/S10-W142/sbom.cdx.json
python3 -m unittest discover -s scripts/tests -p test_sbom_schema.py -v
```

The full Python suite also requires this environment.
`-I` ignores global Python environment/site overrides.
The checked-in requirements pin all transitive versions and hashes.

See the [dependency review](../../docs/validation/S10-W147/dependency-review.json).
The validator uses `jsonschema` 4.26.0 with explicit format checking.
Required format implementations must be present.

An incomplete installation fails setup.
It registers the three [pinned schemas](schemas/cyclonedx-1.6/README.md) in memory and refuses retrieval of every other URI, including local files.
The document cannot select another schema.

No validation-time download occurs.

Input must be a regular file without a final symlink, at most 4 MiB, containing UTF-8 JSON with unique members and no NaN/Infinity constants.
Special files are refused before opening.
Errors identify trusted schema rules without echoing input values or property names.
Exit 0 means schema/format validation passed, 1 means invalid input/profile/schema shape, and 2 means validator setup failed.

This checks JSON structure and the library's declared format implementations.
It does not verify signatures, actual linked binaries, license-expression semantics, source authenticity or release authority.
A JSF signature-shaped object can pass without a real signature.
It does not close P09.
Evidence, mutation checks and the network-isolated run: [W147](../../docs/validation/S10-W147/README.md).

## Unified signed release bundles

`scripts/release/bundle_release.py` packages a staged `stage-product.sh` management root (with signed `SHA256SUMS.sig`), an optional `console/` source archive (excluding `node_modules`, `dist`, `.env*`, and SQLite/secret files), an optional CycloneDX SBOM, and a canonical `release.json` manifest into a deterministic `rustiron-<version>-almalinux10-x86_64.tar.gz` bundle, signs bundles or `releases.json` channel indexes off-host in `rustiron-release-v1`, and verifies both signature layers and archive safety (`W647`).
Hosts consume signed bundles or indexes through `packaging/rustiron-updater.py` ([product update runbook](../../docs/operator/16-PRODUCT-UPDATE.md#unified-release-bundles-and-one-command-updater-w647)).
This tooling does not publish packages or establish a supported production release.

## Clean public repository export

`scripts/release/export_public_repo.py` produces a self-contained public repository snapshot ready for GitHub publication (`W652`), stripping internal engineering docs (`docs/validation/`, `docs/feasibility/`, `docs/reviews/`, `docs/planning/`, `docs/decisions/`, `docs/STATE.md`, `HANDOFF.md`, `AGENTS.md`, `CLAUDE.md`, `lab/`, and owner-specific runbooks) and running a fail-closed hygiene audit asserting zero leaked secrets, personal IPs/domains/emails, or broken curated Markdown links.
The script never runs `git push` or contacts any remote host.

```sh
python3 scripts/release/export_public_repo.py --out /tmp/rustiron-public --clean --init-git
python3 -m unittest scripts/tests/test_public_export.py -v
```
