# Maintained parser fuzzing

This unpublished workspace tests the real `rustiron-contracts` byte/plan APIs and the executor's restore inventory report decoder, which it includes by path (`crates/executor/src/restore/inventory_report.rs`) so the fuzz graph adds only `serde`, the W203 capture-manifest tar reader, worker walk and canonical builder (`crates/executor/src/manifest/{format,tar,worker}.rs`, also by path; `serde` and `sha2` only), and the W272 executor/admin-helper line wire (`crates/executor/src/admin_helper/wire.rs`, by path; `rustiron-contracts` only).
The W324 payload targets link the `rustiron-executor` and `rustiron-journal` libraries by path, because the capture and probe payload readers return executor and journal types.
That link adds `rusqlite` and its SQLite build dependencies to the fuzz lock, at the root lock's versions; the targets open no journal. W435: the executor link also adds `quick-xml` 0.42.0, at the root lock's version; no fuzz target uses it.
The W342 S3 targets include the capture worker's `crates/executor/src/manifest/{s3,lock}.rs` by path; they add no package.
It has its own lockfile and leaves product dependencies and Rust 1.99.1 intact.
These targets do no signing, signature verification, storage, executor effects, HTTP or VM operations.
Signature fields contain untrusted test text.

| Target | Invariants on accepted input |
| --- | --- |
| `canonical_object` | Size ceiling, JSON value preservation, canonical idempotence, independent domain framing, rejection of generated duplicate/escaped-alias keys |
| `prepared_plan` | Typed verb and version dispatch across all 23 catalogue verbs (including W386 standing capture schema 3, W551–W608 DNS, proxy, modern app, and credential-rotation schemas), D-098 envelope determinism, input-derived identity, exact canonical bytes/digest, roundtrip, unknown-member refusal and changed-id/digest binding |
| `grant` | All 23 catalogue raw grant decoders, canonical/id/nonce/expiry preservation, verb uniqueness, operation/time bounds and unknown-member/self-issued/expanded-budget refusal |
| `plan_grant_binding` | Lab v1, site v2 and product backup v2 pairs against fixed synthetic facts; independently checked tuple/digest/window/site/snapshot/destination/compensation, clock edges and changed context/scope; site v2 limits bind only under an equal or larger enrolled cap, never without one, and v1 ignores the cap; nonce changes preserve pure consistency only. W386: standing capture schema 3 pairs; each derived run belongs to one named site and window, a run past the last window does not exist, and each window opens and closes at its signed seconds |
| `submission` | Exact raw plan/grant bytes and metadata, encode/decode stability, closed envelopes, duplicate/escaped-alias rejection, object shape, version and bounded ASCII signature text |
| `apply_request` | The same raw-byte properties through operator encode/decode and pure executor forwarding; closed outer/parameter objects and request identity |
| `submission_reply` | Fixed operation context, complete known reply and additive extensions, recorded/refused/replay relations, bounded code text, roundtrip and truthful exit classes |
| `apply_response` | Fixed request/operation context, tagged and unambiguous outcomes, nested reply properties, roundtrip and additive envelope/outcome fields |
| `read_response` | Required slots/error fields, bounded errors, preserved known values, typed roundtrip and additive fields; correlation stays with callers |
| `status_response` | Independent query/operation facts, changed-context denial, recorded state versus refusal and additive envelope compatibility |
| `evidence_response` | Independent query/operation facts, receipt object/digest shape, changed-context/digest denial and additive envelope compatibility. W392: the attestation label agrees with the signature, which has the receipt namespace and a bounded armored block; a signed receipt without its signature, or in the plan namespace, is refused. The signature itself is not verified here |
| `read_request` | Five closed read methods, input method/ID, page bounds, intentional omitted/null cursor rules, roundtrip and executor-query agreement |
| `status_query` | Closed status query, identity/method/roundtrip agreement; separately checked partial correlation header with JSON size/depth/duplicate bounds |
| `inventory_report` | 4096-byte ceiling (over-size refused), exact nine members, version 3, entry/depth ceilings, only `complete` claims files/dump/world_writable/extra_paths and has no reason, world_writable ≤ files and files + extra_paths ≤ entries (W378); `privileged` is an error reason, stable re-encoding; version/unknown/missing/ceiling/claim changes refused |
| `capture_manifest` | 64 KiB archive cap; tar/PAX/GNU reader and walk never panic and never write past the stream bound; a finished walk always builds, counts agree with the `end` line, the canonical bytes verify to the recorded digest and counts, and any byte change changes the digest; raw input as worker output never panics |
| `evidence_query` | Closed evidence query, identity/method/roundtrip agreement and invalid/unknown/positional refusal |
| `admin_request` | 128-byte ceiling (129 refused); only the exact `v1 <id> <step>\n` encoding decodes and re-encodes byte-identically; the `ols_status` line never decodes as a step; dropped newline, CRLF, extra field, leading space, other version and doubled input refused; every step re-encodes under the ceiling with the same id |
| `admin_reply` | Non-UTF-8 refused as the client's string read is; a decoded reply re-encodes to the exact input; `ok` and `ok <payload>` never read as a code and a code is never `ok…`; no decoded line holds a newline; a refused input is oversized or not one newline-terminated line. Campaign cap 64 KiB; the 8 MiB ceiling is unit-tested |
| `admin_capture_payload` | The real `decode_capture_for` and `encode_capture`, for a plain and a frozen capture: non-UTF-8 refused as the client's string read is; an unreadable or unknown reply is the uncertain fallback; a decoded success has the input's 64-hex id and counts; a missing or unknown consistency label is never `matched`, and `freeze_not_held` comes only for a frozen capture; a kept manifest is the input's and never changes the outcome; a decoded outcome survives its own encoding and a respelled reply. Campaign cap 64 KiB |
| `admin_probe_payload` | The real `decode_probe` and `encode_probe`: non-UTF-8 refused; a decoded state is `passed`, `failed` or `cleanup_incomplete` and names the input's state, never `running`; the receipt is the input's object; a final state with an object receipt always decodes; a decoded reply re-encodes to the same state and, without floats, the same receipt; an encoded `running` never decodes. Campaign cap 64 KiB |
| `s3_versioning` | Read as `curl` prints it, with the HTTP 200 marker: a declaration or white space before the marker changes nothing; the document twice reads twice; another count or status refuses; the accepted text holds no comment, CDATA, DTD, control character or unknown reference, at most 7 levels and 16,384 elements; no body passes two response shapes; a pass is exactly the bucket check's versioning half. Campaign cap 256 KiB |
| `s3_object_lock` | The shared reader properties; the days are 1 to 999,999 × 365 and survive the canonical `Days` or `Years` shape; the bucket check passes exactly at the enrolled days and never under the 30-day floor |
| `s3_retention` | The shared reader properties; the retain-until time is in the RFC 3339 range and survives the canonical shape; it covers the enrolled days exactly at the start time plus the days less 15 minutes |
| `s3_list` | The shared reader properties against a fixed bucket and prefix, from the start and after a fixed key: keys are the prefix and a full ID in strictly rising order after `start-after`; at most 1,000 keys; a truncated page is not empty; the page survives its canonical shape; another bucket or prefix refuses; the written-object keys give one-query retention URLs that pass the config check |
| `s3_batch` | One count byte (0 to 3), then `curl` stdout: an accepted batch has exactly that many documents, no other count reads it, the 1 MiB ceiling holds (over-size refused) and the batch twice over reads twice. Campaign cap 1 MiB + 2 |
| `s3_curl` | Fields split at 0xFF: argv, config and URL builders. A key, secret, region or URL outside its allowlist never reaches the config or argv; an accepted config has no byte that could leave its quotes and reads back to the exact inputs; argv has the config first and no URL, user, header or second config flag; URLs keep the endpoint, bucket and query, and the listing query decodes back to the prefix and `start-after` |
| `s3_timestamp` | The RFC 3339 reader agrees with an independent reference; an accepted time is 20 to 35 bytes, in range, and its canonical `Z`, millisecond and `+00:00` spellings read the same |
| `dns_zone` | D-091 canonical DNS zone parser (`parse_zone`): 1 MiB ceiling (`MAX_ZONE_BYTES + 1` refused), UTF-8 + trailing newline, bytewise sorted unique lines, exact canonical reassembly & digest, apex-only single SOA and NS sets, CNAME exclusivity, TTL bounds, and refusal of missing newline or duplicate lines |

Errors are ordinary inputs, not crashes.
Oversized inputs are actually tested, not truncated/skipped.
The ID metamorphism accounts for the byte ceiling.

A successful decode or invariant check grants no authority.
These targets do not establish enrollment, signatures, journals, effects or the whole T04 campaign.
Wire targets independently compare returned objects with raw JSON map members; roundtrips preserve lexical whitespace, escape/number spellings and member order.

Their normal JSON numeric profile is broader than canonical signed contracts.
Passing raw objects and ASCII signature text remain unvalidated proposals.

The binding target uses a bounded JSON test wrapper with plan/grant values and asserted `now`.
A canonical shape check precedes semantic re-encoding.
It is not the signed transport.

Context facts are fixed fixture values, never derived from the proposed plan/grant.
A changed nonce passing pure consistency does not pass signature or replay checks.
Raw duplicate/lexical grant inputs have their own grant target.

The wrapper's whole-input cap does not test two maximum-sized messages simultaneously.

## Verified setup and commands

Run from the repository root.
The selected runtime is `libfuzzer-sys =0.4.13`.
The registry/source review and actual compatibility proof are in [W157](../docs/validation/S10-W157/README.md).

```sh
cargo install --locked --version 0.13.2 --root target/fuzz-tools cargo-fuzz
rustup toolchain install nightly-2026-11-03 --profile minimal --component rustfmt --component clippy
rustup component add rust-src --toolchain nightly-2026-11-03
cargo fetch --locked --manifest-path fuzz/Cargo.toml
rust-tc fuzz-check
rust-tc fuzz
```

The checker requires the exact `cargo-fuzz` version in `config.json`, uses the local installed binary first and keeps generated artifacts under ignored `target/`.
Existing global toolchains/defaults remain unchanged.
`fuzz-check` runs format/Clippy, the separate dependency gate, deterministic seed-oracle smoke, an instrumented build and seed-only libFuzzer replay.

`fuzz` adds 60 seconds per target with one engine process at a time.
The fixed seed is 20261103.
Input timeout is 5 seconds; engine RSS is 2,048 MiB.

Input caps equal each target's byte ceiling plus one: 262145 for requests and 1048577 for responses.
Checked seed metadata supplies response caps.
A cap that would skip a checked seed fails.

Build jobs are capped at four.
The backend explicitly enables AddressSanitizer and instrumented standard-library builds.
This is on demand.

Ordinary doctor continues using the product toolchain and does not run timed fuzz campaigns.

The initial online build populated the nightly standard-library dependency cache.
It was verified with the same `--build-std` backend used by the checker.
For a new cache, after installing the pinned prerequisites, bootstrap that exact build:

```sh
PATH="$PWD/target/fuzz-tools/bin:$PATH" CARGO_BUILD_JOBS=4 cargo +nightly-2026-11-03 fuzz build --build-std --fuzz-dir fuzz --target-dir target/fuzz-instrumented
```

Subsequent checks/builds/runs use `CARGO_NET_OFFLINE=true`. cargo-fuzz 0.13.2 has no `--locked` option.
The checker uses locked Cargo/deny checks and refuses any change to either lock across offline backend work.
This is a post-command guard, not isolation from concurrent source/cache writers.

Use a caller-controlled workspace.
The root lock is unchanged.
Shared Rust runtime package versions match the root lock.

The fuzz-native runtime's build helper `cc` is 1.11.0 while the product lock retains 1.10.0.
Existing product pins constrain the matching parser dependencies.
Review/regenerate the fuzz lock with the next product dependency update.

Do not silently fuzz a different parser dependency profile.

The dependency gate composes root `deny.toml` with one exact-version license exception for libfuzzer-sys 0.4.13's declared NCSA conjunct.
Root policy and all advisory/bans/source checks remain unchanged.
Declared license checks are not a complete source/redistribution-notice audit.
Vendored LLVM headers also reference Apache-2.0 WITH LLVM-exception.
This test workspace is not a distribution profile.

## Evidence and corpus lifecycle

Each invocation prints a fresh evidence directory and retains command stdout/ stderr/status, tool versions, configuration, initial seed manifest and final corpus hashes.
The Rust seed generator uses existing golden vectors and all five plan fixtures, plus malformed, forbidden, exact/over-size and exact/over-depth cases.
It checks all 536 expected acceptance/rejection paths before writing them.

The checker discovers every declared Cargo binary and requires both positive and refusal controls for each, so adding a target cannot silently omit its run.
One fixture table supplies plans, paired cases and raw wire envelopes.
Generated corpora and crash artifacts remain under a separate ignored runtime directory recorded in `result.json`.

Never stage an entire generated corpus.
Promote a real minimal reproducer with its regression test after reviewing it.
Fresh `--output` paths and bounded `--seconds` are available through the Python checker.

Existing evidence is refused/preserved.
Timeout handling kills the checker-owned process group.
Retained logs describe a timeout as failure.

W157's two 60-second campaigns found no crash.
W158 extends this to four targets, 160 seed paths and six additional detected/replayed grant/binding regressions ([evidence](../docs/validation/S10-W158/README.md)).
W157's three private source regressions compiled, failed their intended oracle assertions and replayed from retained inputs.
Main product sources stayed unchanged.
Finite campaigns and seed smoke are scoped evidence, not exhaustive validation or security acceptance.

W159 adds raw submission/apply targets, bringing the declared total to six ([evidence](../docs/validation/S10-W159/README.md)).

W160 adds five response targets, fixes omitted required read-error `operation_id` handling and restores additive executor replies ([evidence](../docs/validation/S10-W160/README.md)).
Response known values/defaults survive typed roundtrips.
Ignored extensions need not survive.
Valid arbitrary receipt numbers may expand beyond the output cap; only ResponseTooLarge is accepted for that encoding refusal.
Raw wire, strict canonical contracts and receipt authenticity retain their distinct boundaries.

W161 adds read/status/evidence query targets ([evidence](../docs/validation/S10-W161/README.md)).
The status header helper intentionally accepts invalid full-query witnesses for correlated errors.
Its supplemental witnesses and shape controls do not authorize work.
Site-list cursor omission/null are intentional defaults, not missing-field failures.
All fifteen targets remain pure parser/contract tests.

W324 adds the admin-helper capture and probe payload targets, bringing the declared total to 20 ([evidence](../docs/validation/S10-W324/README.md)).
The two targets call the executor's own functions, not copies.
The executor and journal libraries link SQLite, but the targets call only pure payload functions.

W342 adds seven S3 reader and `curl` builder targets, bringing the declared total to 27 ([evidence](../docs/validation/S10-W342/README.md)).
A MinIO-shaped listing seed found that the reader refused Go's `&#34;` quote reference; the reader now reads `&#34;` and `&#39;` only.
The targets call the worker's own functions; `Element` fields stay private, so the oracles compare whole elements and decisions.

Primary references: [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz/guide.html), [LLVM libFuzzer options](https://llvm.org/docs/LibFuzzer.html), [published libfuzzer-sys manifest](https://docs.rs/crate/libfuzzer-sys/0.4.13/source/Cargo.toml), [cargo-fuzz source](https://github.com/rust-fuzz/cargo-fuzz).
