# Implemented canonical-object boundary

2026-10-24.
S02/W008 implements `rustiron_contracts::CanonicalObject`.
It is shared byte plumbing, **not a plan/grant schema, approval or admission policy**.
No executor, signing key, apply command or host mutation is introduced.

`CanonicalObject::decode` takes an object of at most 262,144 bytes and 32 nested containers.
Before constructing a value tree, the decoder rejects duplicate decoded keys, including escaped aliases and nested array members.
The decoder also rejects invalid UTF-8, lone surrogates, non-object roots, and trailing input.

Numeric tokens must be unsigned integers 0..9007199254740991.
Fractions, exponent notation, negative integers and negative zero fail rather than being rounded/normalized into security budgets.
This deliberately restricts the accepted numeric subset of RFC 8785.

The maintained RFC 8785 library supplies canonical escaping, recursive UTF-16 property order and preserved array order.
Unicode is not normalized.
Immutable `as_bytes()` returns the complete canonical object without a newline.

No members are dropped, inserted or defaulted.
S01 request/response numeric validation keeps its existing behavior.
The stricter profile is separate.

`plan_domain_digest()` computes SHA-256 over these exact bytes:

```text
ASCII("rustiron/plan/v1") || 00 || canonical_object_utf8
```

It returns 32 bytes.
This method works even for `{}`.
It does not establish that the object is a plan.

W009 must validate every closed typed plan/grant record and semantic restriction from [SPEC](SPEC.md) before using it for signing/admission.
Keep digest/signature transport outside the semantic object.
Never hash a lossy reconstruction that silently discards fields.

Authorization, expiry, replay, custody, resource ownership and independent preconditions remain later work.

## Dependencies and verification

Registry checks selected latest stable serde_json_canonicalizer 0.4.1 (MIT) and sha2 0.11.1 (MIT OR Apache-2.0.
MSRV 1.88, default features disabled).
The former has no declared MSRV.

Actual project compile/tests establish compatibility with pinned Rust 1.99.1.
Published source was inspected for UTF-16 key ordering and existing upstream vectors.
Its ryu-js dependency supplies ECMAScript-compatible number formatting.

No custom JSON sorting or hash algorithm was written.
Cargo.lock pins all transitive versions.
Cargo-deny license/advisory/source/bans checks pass without new exceptions and dry-run update finds no newer compatible packages.

See [dependency inventory](../validation/S02-W008/dependency-inventory.json).

Primary references: [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html), [canonicalizer published source](https://crates.io/crates/serde_json_canonicalizer/0.4.1), [RustCrypto SHA-2](https://docs.rs/sha2/0.11.1/sha2/).
Search indexes lagged the canonicalizer registry release.
The registry and downloaded published package were used.
W011 now verifies [native SQLite](NATIVE-SQLITE.md) for local journal work; target-host/root acceptance remains separate.

Twenty-one public contract tests cover RFC property/string examples within the restricted numeric profile, nested values, exact byte/depth boundaries, malformed input, digest framing/tampering and canonical idempotence.
Five golden vectors are also parsed independently with Python stdlib json, and their digest is independently computed with hashlib.
Rust results match those same golden bytes/digests.
Python does not implement a second JCS serializer.
This is parser/ value/hash agreement, not exhaustive JCS numeric or cryptographic verification.

Six mutations in disposable source copies trigger failing assertions.
The mutations remove duplicate checks, integer range, floating-token rejection, domain separator, UTF-16 ordering, or depth bounds.
A separate unchanged-copy baseline passes.

The workspace sources are unchanged by the campaign.
W008 recorded 88 Rust tests, one doctest, and ordinary/read-only namespace CLI checks.
Dependency/features and documentation/Python checks passed.

Design lint reported zero errors and 23 reviewed warnings.
See [W008 evidence](../validation/S02-W008/README.md).

W009 now adds [closed typed fixture plan/grant records](FIXTURE-APPROVAL.md) before canonical digest use, with intrinsic semantics and pure binding checks.

[W341](../validation/S10-W341/README.md) adds two site plan schema 2 vectors with the nested `quota_limits` object.
Python encodes them independently, and the [vector check](../../scripts/check_canonical_vectors.py) requires printable ASCII member names at every depth.
The byte rules and the digest framing do not change.
Generic CanonicalObject remains a byte helper, never a validated plan or authority.

[W372](../validation/S10-W372/README.md) adds two `site_readopt` plan schema 1 vectors, one for each form, and their grants (`readopt-plan-vectors.json`).
The site form has the nested `quota_limits` and `allocation_floor` objects. The generation form has a sorted `site_ids` list and a grant with `targets`.
Python encodes both independently, and the [vector check](../../scripts/check_canonical_vectors.py) also checks the fixed effects, the epoch rule and the grant scope.
The byte rules and the digest framing do not change.

[W386](../validation/S10-W386/README.md) adds two standing capture schema 3 vectors (`standing-capture-vectors.json`, [D-035](../decisions/D-035-scheduled-capture.md)): a daily series for two sites and a compressed series for one site.
Python writes them with the standard library only ([generator](../validation/S10-W386/make_standing_vectors.py)).
The [vector check](../../scripts/check_canonical_vectors.py) recomputes the canonical bytes, the plan digest, the grant SHA-256, the schedule bounds, and each derived run identity.
The run identity uses its own hash domain, `rustiron/standing-capture-run/v1`. The plan digest framing does not change.

[W392](../validation/S10-W392/README.md) ([D-042](../decisions/D-042-host-receipt-key.md)) signs receipts. The signed bytes are the canonical receipt body, the same bytes as `body_sha256`, with no added framing. The SSHSIG namespace `rustiron-receipt-v1` separates the domain from plan signatures (`rustiron-plan-v1`).
Three vectors (`receipt-signature-vectors.json`: a capture body, a probe body, and a body with one added member) come from a [generator](../validation/S10-W392/make_receipt_vectors.py) with its own Ed25519 code and no OpenSSH or Rust code.
The executor test signs each body with OpenSSH and gets the same signature byte for byte. The [vector check](../../scripts/check_canonical_vectors.py) recomputes the bytes and the digest and verifies each signature with `ssh-keygen -Y verify`. It also refuses a tampered body, the wrong key, and the plan namespace.
The plan digest framing does not change.

[W396](../validation/S10-W396/README.md) ([D-045](../decisions/D-045-signed-admission-bytes.md)) keeps the admitted bytes. Journal v19 stores the canonical plan and grant of each admission once by plain SHA-256, up to 8,192 bytes for each object, with the issuer and the signer-policy epoch.
The journal refuses bytes that are not one canonical object, a plan that does not hash to the intent's plan digest with the framing above, and a grant that does not hash to the grant digest. It checks the stored rows again when it opens.
`observe` shows the bytes with both recorded digests. The console hashes the shown bytes again in the browser and states a mismatch as an error.
The plan digest framing does not change.
