#!/usr/bin/env python3
"""Offline validator for a Rustiron RecoveryReceipt v1 export (W041).

A finished backup capture uses the same document. Fields the capture row
does not observe stay not_run or unknown. See S10-W050.

  check_receipt.py RECEIPT.json [--public-key KEY.pub]

Checks that the body hash matches its canonical bytes (sorted compact JSON;
keys are ASCII), that all seven SPEC fields are present and distinct with an
allowed status, that nothing aggregates them into a single verdict, and that
the attester is labelled self-attested. A settled capture's
`unclaimed_snapshot` (W366) needs a `failed` capture with no snapshot ID, a
64 lowercase hex ID, `claimed` false and a scope. A present `observed_at`,
`evidence_refs`, or per-field `limitations` is checked. A field that omits
them still passes, so the sealed W041 receipt stays valid. W391: a capture's
`retention` is `not_recorded` (rows before journal v18) or `recorded` with
passed lock checks and one COMPLIANCE object version per written object that
covers the days and names the snapshot once; a `refusal` code needs a failed
capture without a snapshot. Passing proves
internal consistency only: the receipt is a root-written local record, not
independent evidence.

W392 (D-040 item 6): a receipt states `attestation` "self-attested, signed"
with a `signature` from the host receipt key, or "self-attested, unsigned".
A receipt without either is an older unsigned receipt. With --public-key
(the key the operator recorded off the host at installation), a signature
is required, and `ssh-keygen -Y verify` checks it over the canonical body in
the namespace rustiron-receipt-v1. A verified signature shows that the host
receipt key signed these bytes. It is still self-attested: root on that
host could sign anything with that key.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

FIELDS = (
    "artifacts_complete", "repository_integrity_checked", "decryption_tested",
    "application_consistency_assessed", "restored_in_isolation",
    "health_checks_passed", "independent_copy_confirmed",
)
STATUSES = {"pass", "fail", "unknown", "not_run"}
AGGREGATES = {"healthy", "backup_healthy", "overall", "verdict", "ok"}
NAMESPACE = "rustiron-receipt-v1"
SIGNED = "self-attested, signed"
UNSIGNED = "self-attested, unsigned"
SIGNATURE_MEMBERS = {"format", "namespace", "key_fingerprint", "armored"}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def problems(document: dict) -> list[str]:
    found = []
    body = document.get("body")
    if not isinstance(body, dict):
        return ["missing body"]
    if hashlib.sha256(canonical(body)).hexdigest() != document.get("body_sha256"):
        found.append("body_sha256 does not match the canonical body")
    if body.get("receipt_schema") != "rustiron-recovery-receipt/1":
        found.append("unknown receipt_schema")
    fields = body.get("fields")
    if not isinstance(fields, dict) or set(fields) != set(FIELDS):
        found.append("the seven fields are not exactly present")
    else:
        for name in FIELDS:
            entry = fields[name]
            if not isinstance(entry, dict) or entry.get("status") not in STATUSES or not entry.get("scope"):
                found.append(f"{name}: needs an allowed status and a scope")
                continue
            observed = entry.get("observed_at", None)
            if "observed_at" in entry and not (
                type(observed) is int and observed >= 0
            ):
                found.append(f"{name}: observed_at must be a non-negative integer")
            refs = entry.get("evidence_refs")
            if "evidence_refs" in entry and not (
                isinstance(refs, list) and all(isinstance(item, str) and item for item in refs)
            ):
                found.append(f"{name}: evidence_refs must be an array of non-empty strings")
            limits = entry.get("limitations")
            if "limitations" in entry and not (
                isinstance(limits, list)
                and limits
                and all(isinstance(item, str) and item for item in limits)
            ):
                found.append(f"{name}: limitations must be non-empty strings")
    for key in AGGREGATES & set(body):
        found.append(f"aggregate verdict '{key}' is not allowed")
    if body.get("attester", {}).get("kind") != "local_executor_self_attested":
        found.append("attester must be labelled local_executor_self_attested")
    if not body.get("limitations"):
        found.append("limitations must be stated")
    if "unclaimed_snapshot" in body and not unclaimed_ok(body):
        found.append("unclaimed_snapshot needs a failed capture without a snapshot, a 64 lowercase hex id, claimed false and a scope")
    if isinstance(body.get("retention"), dict) and not retention_ok(body):
        found.append("retention evidence needs a succeeded capture, passed before and after checks, and one COMPLIANCE version per object that names the snapshot once and covers the days")
    if "refusal" in body and not refusal_ok(body):
        found.append("refusal needs a failed capture without a snapshot and a code of 1 to 64 characters A-Z, 0-9 and _")
    found.extend(label_problems(document))
    return found


def label_problems(document: dict) -> list[str]:
    """W392: the attestation label agrees with the signature, which has the fixed shape."""
    found = []
    label = document.get("attestation")
    signature = document.get("signature")
    if label is not None and label not in (SIGNED, UNSIGNED):
        found.append(f"unknown attestation {label!r}")
    if signature is None:
        if label == SIGNED:
            found.append(f"attestation {SIGNED!r} needs a signature")
        return found
    if label != SIGNED:
        found.append(f"a signature needs the attestation {SIGNED!r}")
    if not isinstance(signature, dict):
        return [*found, "signature must be an object"]
    extra = sorted(set(signature) - SIGNATURE_MEMBERS)
    if extra:
        found.append("signature has unknown members: " + ", ".join(extra))
    if signature.get("format") != "sshsig":
        found.append("signature format must be sshsig")
    if signature.get("namespace") != NAMESPACE:
        found.append(f"signature namespace must be {NAMESPACE}")
    armored = signature.get("armored")
    if not (isinstance(armored, str) and armored.startswith("-----BEGIN SSH SIGNATURE-----\n")
            and armored.endswith("-----END SSH SIGNATURE-----\n")):
        found.append("signature armored must be one armored SSH signature")
    return found


def attestation(document: dict) -> str:
    """The label a receipt states; an older receipt without one is unsigned."""
    return SIGNED if document.get("signature") is not None else UNSIGNED


def fingerprint(public_key: str) -> str:
    """OpenSSH SHA256 fingerprint of an `ssh-ed25519 BASE64 [comment]` line."""
    words = public_key.split()
    if len(words) < 2 or words[0] != "ssh-ed25519":
        raise ValueError("the public key must be one ssh-ed25519 line")
    digest = hashlib.sha256(base64.b64decode(words[1], validate=True)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def signature_problems(document: dict, public_key: str) -> list[str]:
    """Verify the signature over the canonical body with the given public key."""
    signature = document.get("signature")
    if not isinstance(signature, dict) or not isinstance(document.get("body"), dict):
        return ["a signature is required with --public-key, and the receipt has none"]
    found = []
    words = public_key.split()
    if signature.get("key_fingerprint") != fingerprint(public_key):
        found.append("key_fingerprint does not match the given public key")
    keygen = shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen"
    with tempfile.TemporaryDirectory(prefix="check-receipt-") as folder:
        allowed = os.path.join(folder, "allowed_signers")
        signed = os.path.join(folder, "receipt.sig")
        with open(allowed, "w", encoding="ascii") as handle:
            handle.write(f'receipt namespaces="{NAMESPACE}" {words[0]} {words[1]}\n')
        with open(signed, "w", encoding="ascii") as handle:
            handle.write(str(signature.get("armored")))
        try:
            result = subprocess.run(
                [keygen, "-Y", "verify", "-f", allowed, "-I", "receipt", "-n", NAMESPACE, "-s", signed],
                input=canonical(document["body"]), capture_output=True, timeout=30,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        except (OSError, subprocess.SubprocessError):
            return [*found, "ssh-keygen (OpenSSH) is needed to verify a signature"]
    if result.returncode != 0:
        found.append(f"signature does not verify with the given public key in namespace {NAMESPACE}")
    return found


def hex64(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def whole(value: object) -> bool:
    return type(value) is int and value >= 0


VERSION_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
CODE_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
# SigV4 bounds the store clock to 15 minutes; the lock reader allows it.
SKEW_SECS = 15 * 60


def retention_ok(body: dict) -> bool:
    """W391: `not_recorded` (W371 rows), or recorded per-version evidence."""
    retention = body["retention"]
    status = retention.get("status")
    if status == "not_recorded":
        return not {"checks", "objects"} & set(retention)
    operation = body.get("operation")
    if status != "recorded" or not isinstance(operation, dict):
        return False
    days, checks, objects = retention.get("days"), retention.get("checks"), retention.get("objects")
    snapshot, started = body.get("snapshot_id"), operation.get("started_at")
    if not (operation.get("state") == "succeeded" and hex64(snapshot) and whole(started)
            and whole(days) and 1 <= days <= 3650 and isinstance(checks, dict)
            and set(checks) == {"before", "after"} and isinstance(objects, list)
            and 1 <= len(objects) <= 1024 and retention.get("scope")):
        return False
    for check in checks.values():
        if not (isinstance(check, dict) and check.get("result") == "passed"
                and check.get("versioning") == "Enabled" and check.get("default_mode") == "COMPLIANCE"
                and whole(check.get("default_days")) and check["default_days"] >= days):
            return False
    seen, snapshots = set(), 0
    for item in objects:
        if not isinstance(item, dict) or set(item) != {"kind", "object_id", "version_id", "mode", "retain_until"}:
            return False
        version = item["version_id"]
        if not (item["kind"] in {"snapshot", "index", "pack"} and hex64(item["object_id"])
                and isinstance(version, str) and 1 <= len(version) <= 128 and version != "null"
                and set(version) <= VERSION_CHARS and item["mode"] == "COMPLIANCE"
                and whole(item["retain_until"])
                and item["retain_until"] >= started + days * 86400 - SKEW_SECS
                and (item["kind"], item["object_id"]) not in seen):
            return False
        seen.add((item["kind"], item["object_id"]))
        if item["kind"] == "snapshot":
            snapshots += 1
            if item["object_id"] != snapshot:
                return False
    return snapshots == 1


def refusal_ok(body: dict) -> bool:
    """W391: a refused capture names its stored code and claims nothing."""
    code = body["refusal"]
    operation = body.get("operation")
    return (
        isinstance(operation, dict)
        and operation.get("state") == "failed"
        and body.get("snapshot_id") is None
        and "unclaimed_snapshot" not in body
        and isinstance(code, str)
        and 1 <= len(code) <= 64
        and set(code) <= CODE_CHARS
    )


def unclaimed_ok(body: dict) -> bool:
    """W366: a settled capture keeps its tagged snapshot as evidence only."""
    unclaimed = body["unclaimed_snapshot"]
    operation = body.get("operation")
    if not isinstance(unclaimed, dict) or not isinstance(operation, dict):
        return False
    snapshot = unclaimed.get("snapshot_id")
    return (
        operation.get("state") == "failed"
        and body.get("snapshot_id") is None
        and isinstance(snapshot, str)
        and len(snapshot) == 64
        and all(c in "0123456789abcdef" for c in snapshot)
        and unclaimed.get("claimed") is False
        and bool(unclaimed.get("scope"))
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("receipt")
    parser.add_argument("--public-key", help="the receipt public key recorded off the host; requires a signature")
    args = parser.parse_args()
    with open(args.receipt, encoding="utf-8") as handle:
        document = json.load(handle)
    found = problems(document)
    note = "signature present, not verified: no --public-key given"
    if args.public_key:
        with open(args.public_key, encoding="ascii") as handle:
            key = handle.read()
        try:
            found.extend(signature_problems(document, key))
            note = f"signature verified with {fingerprint(key)}"
        except ValueError as error:
            found.append(str(error))
    elif document.get("signature") is None:
        note = "no signature"
    for item in found:
        print(f"FAIL: {item}")
    if not found:
        statuses = {name: document["body"]["fields"][name]["status"] for name in FIELDS}
        print(f"PASS: consistent {attestation(document)} receipt; {note}; "
              + ", ".join(f"{k}={v}" for k, v in statuses.items()))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
