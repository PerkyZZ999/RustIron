#!/usr/bin/env python3
"""Independent Python checks for canonical bytes and SHA-256 vectors."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def unsigned(value: str) -> int:
    number = int(value)
    assert not value.startswith("-") and number <= 9_007_199_254_740_991
    return number


def reject_float(value: str) -> None:
    raise ValueError("non-integer token")


def unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        assert key not in result, "duplicate member"
        result[key] = value
    return result


def parse(value: str) -> dict:
    result = json.loads(value, parse_int=unsigned, parse_float=reject_float,
                        parse_constant=reject_float, object_pairs_hook=unique_object)
    assert isinstance(result, dict)
    return result


def product_vectors(fixtures: Path) -> int:
    vectors = json.loads((fixtures / "product-backup-vectors.json").read_text())
    assert {vector["name"] for vector in vectors} == {"capture", "probe"}
    assert len(vectors) == 2
    for vector in vectors:
        for kind in ("plan", "grant"):
            parsed = parse(vector[f"{kind}_input"])
            # These records have printable ASCII member names and flat values
            # or arrays of scalars, so Python sorting matches UTF-16 ordering.
            assert all(key.isascii() and key.isprintable() for key in parsed)
            assert all(isinstance(value, (int, str)) or (
                isinstance(value, list) and all(isinstance(item, str) for item in value)
            ) for value in parsed.values())
            encoded = json.dumps(parsed, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            assert encoded == vector[f"{kind}_canonical"], (vector["name"], kind)
        digest = hashlib.sha256(b"rustiron/plan/v1\0" + vector["plan_canonical"].encode()).hexdigest()
        assert digest == vector["plan_digest"] == parse(vector["grant_canonical"])["plan_digest"]
    return len(vectors)


def ascii_members(value: object) -> bool:
    """Every member name at every depth is printable ASCII, so Python's
    recursive key sort matches UTF-16 ordering; values are JSON scalars,
    arrays or objects without floats (the parser already refuses floats)."""
    if isinstance(value, dict):
        return all(key.isascii() and key.isprintable() and ascii_members(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return all(ascii_members(item) for item in value)
    return isinstance(value, (bool, int, str))


def site_vectors(fixtures: Path) -> int:
    """W341: site plan schema v2 with nested quota limits and its v1 grant."""
    vectors = json.loads((fixtures / "site-plan-v2-vectors.json").read_text())
    assert [vector["name"] for vector in vectors] == ["default", "minimum"]
    for vector in vectors:
        for kind in ("plan", "grant"):
            parsed = parse(vector[f"{kind}_input"])
            assert ascii_members(parsed), (vector["name"], kind)
            encoded = json.dumps(parsed, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            assert encoded == vector[f"{kind}_canonical"], (vector["name"], kind)
        plan = parse(vector["plan_canonical"])
        assert plan["schema_version"] == 2 and plan["expected_effects"]["sets_quota"] is True
        assert set(plan["quota_limits"]) == {"block_hard_kib", "inode_hard"}
        digest = hashlib.sha256(b"rustiron/plan/v1\0" + vector["plan_canonical"].encode()).hexdigest()
        assert digest == vector["plan_digest"] == parse(vector["grant_canonical"])["plan_digest"]
    return len(vectors)


def ols_vectors(fixtures: Path) -> int:
    """W368: config_activate plan schema v2 with the page-cache opt-in and its v1 grant."""
    vectors = json.loads((fixtures / "ols-plan-v2-vectors.json").read_text())
    assert [vector["name"] for vector in vectors] == ["page_cache", "single_site"]
    for vector in vectors:
        for kind in ("plan", "grant"):
            parsed = parse(vector[f"{kind}_input"])
            assert ascii_members(parsed), (vector["name"], kind)
            encoded = json.dumps(parsed, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            assert encoded == vector[f"{kind}_canonical"], (vector["name"], kind)
        plan = parse(vector["plan_canonical"])
        assert plan["schema_version"] == 2 and plan["verb"] == "config_activate"
        assert set(plan["page_cache"]) == {"site_id", "recipe_id", "recipe_digest"}
        assert plan["page_cache"]["site_id"] in plan["site_ids"]
        digest = hashlib.sha256(b"rustiron/plan/v1\0" + vector["plan_canonical"].encode()).hexdigest()
        assert digest == vector["plan_digest"] == parse(vector["grant_canonical"])["plan_digest"]
    return len(vectors)


def ols_v3_vectors(fixtures: Path) -> int:
    """W370: config_activate plan schema v3 with the page-cache opt-out and its v1 grant."""
    vectors = json.loads((fixtures / "ols-plan-v3-vectors.json").read_text())
    assert [vector["name"] for vector in vectors] == ["page_cache_opt_out", "single_site_opt_out"]
    for vector in vectors:
        for kind in ("plan", "grant"):
            parsed = parse(vector[f"{kind}_input"])
            assert ascii_members(parsed), (vector["name"], kind)
            encoded = json.dumps(parsed, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            assert encoded == vector[f"{kind}_canonical"], (vector["name"], kind)
        plan = parse(vector["plan_canonical"])
        assert plan["schema_version"] == 3 and plan["verb"] == "config_activate"
        assert "page_cache" not in plan
        assert set(plan["page_cache_opt_out"]) == {"site_id", "recipe_id"}
        assert plan["page_cache_opt_out"]["site_id"] in plan["site_ids"]
        digest = hashlib.sha256(b"rustiron/plan/v1\0" + vector["plan_canonical"].encode()).hexdigest()
        assert digest == vector["plan_digest"] == parse(vector["grant_canonical"])["plan_digest"]
    return len(vectors)


CACHE_ON = "litespeed_cache_793_cache_on_v1"
CACHE_ON_RECIPE_DIGEST = "3665c57f288174dddba0be23a5b43a554c11a226ec681171f79334e5c1dad767"


def ols_cache_on_vectors(fixtures: Path) -> int:
    """W395: the cache-on recipe in a schema 2 opt-in and a schema 3 opt-out, with v1 grants."""
    vectors = json.loads((fixtures / "ols-plan-cache-on-vectors.json").read_text())
    assert [vector["name"] for vector in vectors] == ["cache_on_opt_in", "cache_on_opt_out"]
    for vector in vectors:
        for kind in ("plan", "grant"):
            parsed = parse(vector[f"{kind}_input"])
            assert ascii_members(parsed), (vector["name"], kind)
            encoded = json.dumps(parsed, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            assert encoded == vector[f"{kind}_canonical"], (vector["name"], kind)
        plan = parse(vector["plan_canonical"])
        assert plan["verb"] == "config_activate"
        digest = hashlib.sha256(b"rustiron/plan/v1\0" + vector["plan_canonical"].encode()).hexdigest()
        assert digest == vector["plan_digest"] == parse(vector["grant_canonical"])["plan_digest"]
    opt_in = parse(vectors[0]["plan_canonical"])
    assert opt_in["schema_version"] == 2 and "page_cache_opt_out" not in opt_in
    assert opt_in["page_cache"] == {"site_id": "blog5", "recipe_id": CACHE_ON,
                                    "recipe_digest": CACHE_ON_RECIPE_DIGEST}
    opt_out = parse(vectors[1]["plan_canonical"])
    assert opt_out["schema_version"] == 3 and "page_cache" not in opt_out
    assert opt_out["page_cache_opt_out"] == {"site_id": "blog5", "recipe_id": CACHE_ON}
    return len(vectors)


def readopt_vectors(fixtures: Path) -> int:
    """W372: site_readopt plan schema 1 in its site and generation forms, and their grants."""
    vectors = json.loads((fixtures / "readopt-plan-vectors.json").read_text())
    assert [vector["name"] for vector in vectors] == ["site", "generation"]
    for vector in vectors:
        for kind in ("plan", "grant"):
            parsed = parse(vector[f"{kind}_input"])
            assert ascii_members(parsed), (vector["name"], kind)
            encoded = json.dumps(parsed, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            assert encoded == vector[f"{kind}_canonical"], (vector["name"], kind)
        plan = parse(vector["plan_canonical"])
        grant = parse(vector["grant_canonical"])
        assert plan["verb"] == "site_readopt" and plan["form"] == vector["name"]
        assert plan["previous_epoch"] != plan["host_epoch"]
        effects = plan["expected_effects"]
        assert not any(effects[key] for key in ("creates_account", "creates_database",
                                                "traffic_activation", "network_access", "sets_quota"))
        if plan["form"] == "site":
            assert effects["records_ownership"] is True and "records_generation" not in effects
            assert grant["site_ids"] == [plan["site_id"]] and "targets" not in grant
        else:
            assert effects["records_generation"] is True and "records_ownership" not in effects
            assert plan["site_ids"] == sorted(set(plan["site_ids"]))
            assert grant["site_ids"] == plan["site_ids"] and grant["targets"] == ["ols_lab_listener"]
        assert grant["verbs"] == ["site_readopt"] and "compensation" not in grant
        digest = hashlib.sha256(b"rustiron/plan/v1\0" + vector["plan_canonical"].encode()).hexdigest()
        assert digest == vector["plan_digest"] == grant["plan_digest"]
    return len(vectors)


def standing_vectors(fixtures: Path) -> int:
    """W386 (D-035): standing capture plan and grant schema 3 and their derived run identities."""
    vectors = json.loads((fixtures / "standing-capture-vectors.json").read_text())
    assert [vector["name"] for vector in vectors] == ["daily", "compressed"]
    for vector in vectors:
        for kind in ("plan", "grant"):
            parsed = parse(vector[f"{kind}_input"])
            assert ascii_members(parsed), (vector["name"], kind)
            encoded = json.dumps(parsed, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            assert encoded == vector[f"{kind}_canonical"], (vector["name"], kind)
        plan = parse(vector["plan_canonical"])
        grant = parse(vector["grant_canonical"])
        assert plan["schema_version"] == grant["schema_version"] == 3
        assert plan["verb"] == "backup_capture" and grant["verbs"] == ["backup_capture"]
        assert plan["site_ids"] == sorted(set(plan["site_ids"])) == grant["site_ids"]
        assert 1 <= len(plan["site_ids"]) <= 16
        assert grant["destinations"] == [plan["destination_id"]] != ["lab_pc_store"]
        schedule = ("first_window_start", "period_seconds", "window_seconds", "max_runs")
        assert all(plan[key] == grant[key] for key in schedule)
        period, window, runs = plan["period_seconds"], plan["window_seconds"], plan["max_runs"]
        assert 300 <= period <= 86_400 and 60 <= window <= min(14_400, period // 2) and 1 <= runs <= 35
        last_end = plan["first_window_start"] + (runs - 1) * period + window
        assert plan["valid_from"] <= plan["first_window_start"] and last_end <= plan["expires_at"]
        assert 0 < plan["expires_at"] - plan["valid_from"] <= 35 * 86_400
        assert "max_operations" not in grant
        digest = hashlib.sha256(b"rustiron/plan/v1\0" + vector["plan_canonical"].encode()).hexdigest()
        assert digest == vector["plan_digest"] == grant["plan_digest"]
        grant_sha = hashlib.sha256(vector["grant_canonical"].encode()).hexdigest()
        assert grant_sha == vector["grant_sha256"]
        for run in vector["runs"]:
            material = b"\0".join([b"rustiron/standing-capture-run/v1", grant_sha.encode(),
                                    run["site_id"].encode(), str(run["window"]).encode()])
            h = hashlib.sha256(material).hexdigest()
            assert run["site_id"] in plan["site_ids"] and 0 <= run["window"] < runs
            assert (run["operation_id"], run["idempotency_key"], run["grant_id"], run["nonce"]) == (
                "sc_" + h[:32], "sk_" + h[32:], "sg_" + h[:32], "sn_" + h[32:]), run
    return len(vectors)


def json_keys_ascii(value: object) -> bool:
    """Like ascii_members, and also allows null leaves (receipt bodies have them)."""
    if isinstance(value, dict):
        return all(key.isascii() and key.isprintable() and json_keys_ascii(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return all(json_keys_ascii(item) for item in value)
    return value is None or isinstance(value, (bool, int, str))


def sshsig_verifies(armored: str, message: str, public_key: str, namespace: str) -> bool:
    """`ssh-keygen -Y verify` (OpenSSH), independent of the Rust code and the generator."""
    keygen = shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen"
    with tempfile.TemporaryDirectory(prefix="w392-vectors-") as folder:
        allowed, signature = os.path.join(folder, "allowed"), os.path.join(folder, "sig")
        Path(allowed).write_text(f'receipt namespaces="{namespace}" {public_key}\n')
        Path(signature).write_text(armored)
        result = subprocess.run([keygen, "-Y", "verify", "-f", allowed, "-I", "receipt", "-n", namespace,
                                 "-s", signature], input=message.encode(), capture_output=True, timeout=30)
    return result.returncode == 0


def receipt_signature_vectors(fixtures: Path) -> int:
    """W392 (D-040 item 6): receipt bodies, their canonical bytes and digest, and SSHSIG signatures.

    The generator signs with its own Ed25519 code; OpenSSH verifies here."""
    vectors = json.loads((fixtures / "receipt-signature-vectors.json").read_text())
    assert vectors["scheme"] == "sshsig" and vectors["hash_algorithm"] == "sha512"
    namespace = vectors["namespace"]
    assert namespace == "rustiron-receipt-v1"
    key, other = vectors["test_key"], vectors["other_key"]
    # The test key file holds the stated public key, and the fingerprint is its SHA-256.
    private = base64.b64decode(key["openssh_private_body_b64"])
    assert private.startswith(b"openssh-key-v1\0")
    blob = base64.b64decode(key["public_key"].split()[1])
    assert blob in private and blob.endswith(bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
    for item in (key, other):
        digest = hashlib.sha256(base64.b64decode(item["public_key"].split()[1])).digest()
        assert item["fingerprint"] == "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    assert [vector["name"] for vector in vectors["vectors"]] == ["capture", "probe", "extended"]
    bodies = {}
    for vector in vectors["vectors"]:
        parsed = parse(vector["body_input"])
        assert json_keys_ascii(parsed), vector["name"]
        encoded = json.dumps(parsed, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        assert encoded == vector["body_canonical"], vector["name"]
        assert hashlib.sha256(encoded.encode()).hexdigest() == vector["body_sha256"], vector["name"]
        assert parsed["receipt_schema"] == "rustiron-recovery-receipt/1"
        assert sshsig_verifies(vector["armored"], encoded, key["public_key"], namespace), vector["name"]
        assert not sshsig_verifies(vector["armored"], encoded, other["public_key"], namespace)
        tampered = encoded.replace('"status":"not_run"', '"status":"pass"', 1)
        assert tampered != encoded and not sshsig_verifies(vector["armored"], tampered, key["public_key"],
                                                           namespace), vector["name"]
        bodies[vector["name"]] = parsed
    # Generic coverage: the extended body is the capture body plus one member.
    extended = dict(bodies["extended"])
    assert set(extended) - set(bodies["capture"]) == {"unlisted_future_member"}
    del extended["unlisted_future_member"]
    assert extended == bodies["capture"]
    wrong = vectors["wrong_namespace"]
    capture = vectors["vectors"][0]["body_canonical"]
    assert wrong["namespace"] == "rustiron-plan-v1"
    assert sshsig_verifies(wrong["armored"], capture, key["public_key"], wrong["namespace"])
    assert not sshsig_verifies(wrong["armored"], capture, key["public_key"], namespace)
    return len(vectors["vectors"])


DESTINATION_VECTORS = (
    # (projection, digest file, port, egress profile)
    ("docs/validation/S10-W307/projection.json", "docs/validation/S10-W307/projection-digest.txt",
     443, "ipv4_tcp_443_v1"),
    ("docs/validation/S10-W352/projection-port.json",
     "docs/validation/S10-W352/projection-port-digest.txt", 9443, "ipv4_tcp_port_v1"),
)


def destination_vectors() -> int:
    """W307/W352: product destination projections and their v2 policy digests.

    The 443 vector keeps its W307 bytes; the enrolled-port vector uses 9443."""
    for projection, digest_file, port, profile in DESTINATION_VECTORS:
        parsed = parse((ROOT / projection).read_text())
        assert ascii_members(parsed), projection
        transport = parsed["transport"]
        assert transport["port"] == port and transport["egress_profile"] == profile, projection
        canonical = json.dumps(parsed, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(b"rustiron/backup-policy/v2\0" + canonical.encode()).hexdigest()
        assert digest == (ROOT / digest_file).read_text().strip(), projection
    return len(DESTINATION_VECTORS)


def main() -> None:
    fixtures = ROOT / "crates/contracts/tests/fixtures"
    vectors = json.loads((fixtures / "canonical-vectors.json").read_text())
    for vector in vectors:
        assert parse(vector["input"]) == parse(vector["canonical"]), vector["name"]
        actual = hashlib.sha256(b"rustiron/plan/v1\0" + vector["canonical"].encode()).hexdigest()
        assert actual == vector["plan_digest"], vector["name"]
    print(json.dumps({"status": "passed", "vectors": len(vectors), "product_pairs": product_vectors(fixtures),
                      "site_v2_pairs": site_vectors(fixtures),
                      "ols_v2_pairs": ols_vectors(fixtures),
                      "ols_v3_pairs": ols_v3_vectors(fixtures),
                      "ols_cache_on_pairs": ols_cache_on_vectors(fixtures),
                      "readopt_pairs": readopt_vectors(fixtures),
                      "standing_capture_pairs": standing_vectors(fixtures),
                      "receipt_signature_vectors": receipt_signature_vectors(fixtures),
                      "destination_projections": destination_vectors(),
                      "parser": "Python stdlib json independent of serde_json",
                      "hash": "Python hashlib SHA-256 independent of RustCrypto",
                      "signature": "OpenSSH ssh-keygen -Y verify of vectors that a standard-library Python generator signed",
                      "limits": "golden value/digest agreement and ASCII-key product, site v2, OLS v2 and v3, re-adoption, standing capture, receipt body and "
                                "destination projection canonicalization only"}))


if __name__ == "__main__":
    main()
