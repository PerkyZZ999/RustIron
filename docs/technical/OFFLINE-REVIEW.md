# Offline grant review and SSHSIG verification

2026-10-24.
W010 adds the ordinary-user `rustiron-review` binary.
It reads local files and optionally verifies a signature over the exact canonical grant bytes.
W306 adds product v2 backup grants and independent destination policy checks.
W309 checks the full destination projection and resolves the repository for the signed site.

It never signs, enrolls keys, contacts either daemon, consumes a nonce, admits work or executes a hosting change.
Real human custody/enrollment, root authorization and replay/durability proof remain separate gates.

```sh
cargo run --locked -p rustiron-cli --bin rustiron-review -- --help
python3 scripts/check_fixture_review.py
```

The campaign creates disposable **synthetic** Ed25519 keys, exercises the actual binary and OpenSSH verifier, then removes its temporary directory.
Private keys are never written into the repository, receipts or services.
Its optional `--evidence-dir` records public sample reviews only.
See [human sample](../validation/S02-W010/sample-review.txt), [JSON sample](../validation/S02-W010/sample-review.json) and [campaign receipt](../validation/S02-W010/final-review.json).

## Inputs, outputs and trust

The binary requires --plan, --grant and --policy.
The v1 mode accepts the [closed fixture plan and grant](FIXTURE-APPROVAL.md).
Its policy is a bounded closed object with schema_version=1, host_id, host_epoch, profile_digest, requester, issuer, signer_policy_epoch and verifier_sha256.

It must be independently reviewed.
Copying submitted claims into it defeats its purpose.
This operator file is not root enrollment or proof of policy provenance.

Without signature inputs, signature_status is not_checked.
Verification requires all three of --signature, --allowed-signers and --revocations, including an explicit empty revocations file if no keys are revoked.
Missing/unreadable policy fails.

The initial allowlist is deliberately narrow: exactly one line, exact issuer, namespaces="rustiron-plan-v1", ssh-ed25519 and the base64 public key.
No wildcard principals, CA flags, extra keys/options or alternate namespace are accepted.
OpenSSH validates the actual key/signature and revocation file.

--output human (default) shows every field in the validated original plan/grant, including observations, global effect counts, budgets, compensation, estimates and limitations.
Terminal controls/bidi are escaped. --output json emits one complete structured review. --output grant-bytes emits exactly the canonical grant, with no newline, for a separately controlled signer.
Never sign pretty transport JSON: it differs from the verifier's canonical semantic bytes.

Receipts include the plan digest, canonical grant SHA-256, policy digest, namespace, verifier hash and allowlist/revocation file hashes.
They always say execution_authority=false.
Signature success alone is not admission, actual human approval or a trustworthy host state observation.
Errors are fixed JSON codes without parser text, file paths or external-tool output.
Exits are 2 for input, 3 for signature/time denial, 4 for binding and 7 for dependencies.

System time is the default. --synthetic-time permits old fixture timestamps and is explicitly labeled in review output.
It is a test aid in this offline tool, not a clock override for any future executor.
Real clock rollback/uncertainty needs the independent journal/policy boundary, not this receipt.

## Product backup v2

Use an independent offline policy with `schema_version` 2 and the same host, signer, and verifier fields.
Add a `backup_destination` object with exactly `destination_id` and `destination_policy_digest`.
Use the reviewed enrollment values for both fields. See the [product backup binding](PRODUCT-BACKUP-BINDING.md).

Supply the independently reviewed HTTPS S3 projection with `--destination-policy`.
Use the [closed projection](PRODUCT-S3-TRANSPORT.md#destination-policy-projection) that produced the pinned digest.
Fixture review accepts no destination projection.

The policy version selects the decoder. V2 accepts both product backup verbs and checks the exact plan and grant scope.
The reviewer compares the plan and projection with the independent destination ID and digest in the host policy.
The projection must include a repository for the signed site.
These checks precede export and signature verification.

Mixed versions, a missing projection, and malformed policy fields return exit 2 and `INVALID_REVIEW_INPUT`.
Destination mismatch returns exit 4 and `DESTINATION_POLICY_MISMATCH`.
A signed site without a repository returns exit 4 and `DESTINATION_SITE_NOT_ENROLLED`.

```sh
rustiron-review --plan plan.json --grant grant.json --policy review-policy.json \
  --destination-policy projection.json --output human
rustiron-review --plan plan.json --grant grant.json --policy review-policy.json \
  --destination-policy projection.json --output grant-bytes > grant.canonical
```

Check the export command's exit status before passing the file to the signer.
Successful product receipts report `destination_policy_binding: matched` and `execution_authority: false`.
They include the expected `repository_id` for the signed site.

The `repository` object shows the resolved URL, endpoint, region, CA digest, and retention.
It shows the relative password and phase credential paths, plus the enrolled profile, principal, and authorization digest for each phase.
The paths are relative to the product site credential root. Review reads the projection only.

Supply the signature, allowlist, and revocations to verify the result with the same policy and namespace.
The [W309 verification](../validation/S10-W309/README.md) covers both product verbs and uses disposable synthetic keys.

## Verifier and resource boundaries

The fixed executable is /usr/bin/ssh-keygen.
It must be a regular root-owned file, not writable by group/other, and match the independently supplied binary SHA-256.
The tested tuple is OpenSSH 10.6p1/OpenSSL 3.6.5.

Its exact hash/package is in [verifier evidence](../validation/S02-W010/verifier-version.log).
Updates require review/retest and an explicit policy hash change.
PATH cannot substitute a tool.

Root/kernel/package-manager compromise is outside this check's protection.

The invocation is fixed SSHSIG verify, namespace rustiron-plan-v1, exact policy issuer, explicit allowlist/revocations and signature.
No shell or SSH agent is used.
The environment is cleared and tool stdout/stderr discarded.

Signature, allowlist and revocations are copied into a mode-0700 random private scratch directory, alongside the exact canonical grant.
The child reads that snapshot through a file stdin, not an unbounded blocking pipe or mutable original path.
Normal success/denial paths remove these public scratch files.

Process kill or system failure can leave public scratch data.
There is no crash-cleanup claim.

Input leaves reject symlinks and special files with O_NOFOLLOW/O_NONBLOCK.
Plan/grant limits are 256 KiB each. The host policy, destination projection, and signature each have a 16 KiB limit.
Key policy and revocations have a 64 KiB limit each. The verifier binary has a 16 MiB limit.
A five-second monotonic child deadline kills and reaps this process on failure.

Output is not collected without bounds.
Same-UID adversaries and trusted-root updates racing verification are not contained by the ordinary-user helper.
Future root execution must independently verify policy, signature, peer, live registry and durable admission.

Primary mechanism: [OpenSSH ssh-keygen manual](https://man.openbsd.org/ssh-keygen).
The implemented fixed verification uses its SSHSIG namespace, principal, allowed-signers and revocation support.
No custom signature algorithm was added.
Existing locked Rust dependencies were reused.
Package versions did not change.
