# Project-local SQLite patch and build gate

2026-10-24.
W011 closes the documented native packaging gap without a crate fork or system package change. rusqlite 0.41.0/libsqlite3-sys 0.39.0 were the compatible published crates selected at W011.
Their bundled 3.54.0 is overridden by their supported linked-library hook and an unmodified official SQLite 3.54.1 static build inside target/native.
The host library remains unchanged.

```sh
python3 scripts/prepare_sqlite.py --fetch
rust-tc check
rust-tc quick
rust-tc doctor
```

Only --fetch permits downloading a missing archive.
Normal gates verify the existing cache and fail with setup instructions if input is absent.
There is no network download during ordinary Cargo compilation or feature checks.

W145 adds an optional local native reproducibility check:

```sh
systemd-run --user --wait --pipe -p MemoryMax=8G -p MemorySwapMax=0 --working-directory=$PWD /usr/bin/python3 scripts/release/sqlite_repro.py build target/repro-native-new
python3 scripts/release/sqlite_repro.py check target/repro-native-new
```

The `build` output path must not exist.
The command compiles the cached, hash-verified archive twice into independent `a` and `b` directories.
It does not fetch or reuse the normal compiled cache.

`prepare(fetch, dest)` supports these explicit destinations while its CLI/default path stays the same.
Each output receives the existing pin and artifact checks.
Comparison rechecks both outputs, then compares all three artifact hashes.

Existing output is refused without deleting or replacing it.
The build records its commit-derived `SOURCE_DATE_EPOCH`, compiler, flags and source provenance.
This is same-host native artifact proof, not another compiler/host or a Rust binary rebuilt against each native output.

See [W145 evidence](../validation/S10-W145/README.md) for actual outcomes.
[native/sqlite.toml](../../native/sqlite.toml) pins the official release URL, archive SHA3-256, independent sqlite3.c SHA3-256, source identity and compiler flags.
The [official download page](https://sqlite.org/download.html) and [release page](https://sqlite.org/releaselog/3_54_1.html) supply those hashes.

Both were actually checked before compilation.
SQLite identifies a 32-bit heap-buffer fix and other corrections in this patch.
This project remains a 64-bit Linux candidate and does not infer native-code security from a version.

The helper reads only the two fixed sqlite3.c/sqlite3.h members after archive validation.
No archive paths or scripts are executed.
The helper runs fixed /usr/bin/cc and /usr/bin/ar with the published binding's Linux bundled flags.

The helper publishes a static archive, header, and pkg-config file.
The helper records checksums, compiler version, and pin hash.
Changed pins or cache artifacts fail rather than being silently rebuilt or interpreted as a reviewed tuple.

Compiler/host trust and local same-account cache integrity remain development assumptions.
This receipt is not root-resistant supply-chain attestation.
A fresh explicit build is needed when pins change.

Do not edit cached source to patch a dependency.

.cargo/config.toml forces the binding's documented library-directory/static link hooks to this project-local path.
All supported Rust-Toolchain compile/test recipes verify native input first.
Disposable feature workspaces retain their own source/lock and only reference the verified native cache.

They do not fall back to the older bundled or system library.
No crate/registry source was edited.
The application checks the exact runtime version/source ID before opening or creating coordinator state.

A different tuple is dependency-unavailable.

The actual runtime reports 3.54.1 and source ID matching the release.
Ldd shows no libsqlite3.so dependency.
Hash and runtime/feature tests are in [W011 evidence](../validation/S02-W011/README.md).
This resolves the package version deadline for **local journal development**.
It is not AlmaLinux package/ SELinux/profile, filesystem crash/sync or root journal acceptance.

SQLite's deliverable code is [public domain](https://sqlite.org/copyright.html).
Only its unmodified deliverable amalgamation/header are compiled.
Cargo-deny continues reviewing Rust packages, while this explicitly pinned native source has its separate provenance/hash/build review.
Keep the native source provenance and release hashes with distribution records.
