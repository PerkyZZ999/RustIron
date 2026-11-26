#!/usr/bin/env python3
"""Prepare D-096 EmDash 1.6.0 Node.js Starter releases and upgrades off-host (W602).

    emdash-recipe.py package-release --src DIR --out DIR --release-id ID \\
        --entrypoint dist/server/entry.mjs [--migration-entrypoint dist/migrate.mjs] \\
        [--emdash-version 1.6.0] [--require-upstream-license]

    emdash-recipe.py prepare-upgrade --baseline-meta JSON --src DIR --out DIR \\
        --release-id ID --entrypoint dist/server/entry.mjs \\
        --migration-entrypoint dist/migrate.mjs --to-version VERSION

Needs no network. Validates pinned EmDash release metadata, MIT license notice,
lockfile presence, strict P27 relative path grammar, and absence of symlinks,
special files, or setuid/setgid bits. Writes byte-reproducible bundle.tar.gz,
manifest.sha256, and release-meta.json (or upgrade-meta.json) for staging into
/var/lib/rustiron/app-intake/<site>/<release_id>/.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

SCHEMA = "rustiron-emdash-recipe/1"
DEFAULT_EMDASH_VERSION = "1.6.0"
PINNED_COMMIT = "bbe73edfcf5f8045dd6362568ff9840acebf7e82"
PINNED_STARTER = "templates/starter"
PINNED_MIT_LICENSE_SHA256 = "d5ab82c0225b0def1fa140af22ff2f3bed9791a527545be1b04ab4337dc88675"
PINNED_INTEGRITY = {
    "emdash@1.6.0": "sha512-AbHLzp8gbH9H7oJAjeDB3ULth3/BjC04tFuB70EjuF7KXgFI7IF93UeyCvkojlHO/0I8tqgbjH+35Fg/9zYNeQ==",
    "create-emdash@1.6.0": "sha512-LQmn+Fs4T7UeFu2CwdUGVmAMVicBdUog3EnKngFdj4mDv2HzQQ1RE83bLycGCClVLuSoTTMPz7663N2MVgf6Gg==",
    "upgrade-emdash@0.1.0": "sha512-pABX/EOVtp6q6uqrCkhKIZ0I0yw2uPGm0WcTe5u53BAbC2va7xNSdT41t2dyD+gGjiC64Q/p66ArteuV81UGcg==",
}

# Mirrors crates/contracts/src/approval/app.rs bounds.
MAX_FILES = 50_000
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_PATH_BYTES = 128
MAX_MANIFEST_PATH_BYTES = 256
RELEASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
MANIFEST_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._@\[\]-]+$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
LOCKFILES = ("package-lock.json", "bun.lock", "pnpm-lock.yaml")


class Refused(Exception):
    """Fixed refusal; never echoes untrusted file contents."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def valid_release_id(value: str) -> bool:
    return bool(RELEASE_ID_RE.fullmatch(value)) and ".." not in value


def valid_rel_path(rel: str) -> bool:
    if not rel or len(rel) > MAX_PATH_BYTES or rel.startswith("/") or rel.endswith("/"):
        return False
    parts = rel.split("/")
    return all(part not in ("", ".", "..") and bool(SEGMENT_RE.fullmatch(part)) for part in parts)


def valid_manifest_path(rel: str) -> bool:
    """W641 (H-13): mirrors Rust valid_manifest_path for passive release files
    (supports scoped npm packages `@org/pkg` and Astro `[slug]` route files)."""
    if not rel or len(rel) > MAX_MANIFEST_PATH_BYTES or rel.startswith("/") or rel.endswith("/"):
        return False
    parts = rel.split("/")
    return all(
        part not in ("", ".", "..") and bool(MANIFEST_SEGMENT_RE.fullmatch(part)) for part in parts
    )


def is_forbidden_env_file(rel: str) -> bool:
    """W641-F3: never bundle `.env` / `.env.*` secret files into release archives."""
    name = rel.rsplit("/", 1)[-1]
    return name == ".env" or (name.startswith(".env.") and name != ".env.example")


def collect_release_tree(src: Path) -> dict[str, bytes]:
    """Walks `src` refusing symlinks, special files, setuid/setgid, `.env` secrets, and unsafe paths."""
    if not src.is_dir() or src.is_symlink():
        raise Refused("source directory missing or symlink")
    files: dict[str, bytes] = {}
    total_bytes = 0
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        cur = Path(dirpath)
        dirnames.sort()
        for dname in list(dirnames):
            dp = cur / dname
            st = dp.lstat()
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise Refused("symlink or non-directory inside release tree")
            if st.st_mode & 0o6000:
                raise Refused("setuid/setgid directory refused")
            rel_d = dp.relative_to(src).as_posix()
            if not valid_manifest_path(rel_d):
                raise Refused(f"unsafe directory path: {rel_d}")
        for fname in sorted(filenames):
            fp = cur / fname
            st = fp.lstat()
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                raise Refused("symlink or special file inside release tree")
            if st.st_mode & 0o6000:
                raise Refused("setuid/setgid file refused")
            rel = fp.relative_to(src).as_posix()
            if is_forbidden_env_file(rel):
                raise Refused(f"secret environment file refused in release tree: {rel}")
            if not valid_manifest_path(rel):
                raise Refused(f"unsafe file path: {rel}")
            raw = fp.read_bytes()
            total_bytes += len(raw)
            if total_bytes > MAX_TOTAL_BYTES:
                raise Refused("release exceeds maximum unpacked bytes")
            files[rel] = raw
            if len(files) > MAX_FILES:
                raise Refused("release exceeds maximum file count")
    if not files:
        raise Refused("release tree is empty")
    return files


def check_emdash_metadata(
    files: dict[str, bytes],
    expected_version: str,
    entrypoint: str,
    migration_entrypoint: str | None,
    require_upstream_license: bool,
) -> tuple[str, str, str]:
    """Verifies package.json, lockfile, MIT LICENSE, and declared entrypoints.
    Returns (lockfile_name, lockfile_sha256, license_sha256).
    """
    if not SEMVER_RE.fullmatch(expected_version):
        raise Refused("invalid emdash version")
    if not valid_rel_path(entrypoint) or entrypoint not in files:
        raise Refused("entrypoint missing from release tree")
    if migration_entrypoint is not None and (
        not valid_rel_path(migration_entrypoint) or migration_entrypoint not in files
    ):
        raise Refused("migration entrypoint missing from release tree")
    if "package.json" not in files:
        raise Refused("package.json missing")
    try:
        pkg = json.loads(files["package.json"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refused("package.json unreadable") from exc
    if not isinstance(pkg, dict):
        raise Refused("package.json must be a JSON object")
    deps = pkg.get("dependencies") if isinstance(pkg.get("dependencies"), dict) else {}
    declared = deps.get("emdash")
    if declared != expected_version:
        raise Refused(f"package.json dependencies.emdash must be exact {expected_version!r}")

    lock_name = next((name for name in LOCKFILES if name in files), None)
    if lock_name is None:
        raise Refused("no lockfile found (expected package-lock.json, bun.lock, or pnpm-lock.yaml)")
    lock_sha = sha256_bytes(files[lock_name])

    # When package-lock.json is used for pinned 1.6.0, verify npm integrity if present.
    if lock_name == "package-lock.json" and f"emdash@{expected_version}" in PINNED_INTEGRITY:
        try:
            lock_doc = json.loads(files[lock_name].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Refused("package-lock.json unreadable") from exc
        packages = lock_doc.get("packages") if isinstance(lock_doc, dict) else None
        if isinstance(packages, dict) and "node_modules/emdash" in packages:
            entry = packages["node_modules/emdash"]
            if not isinstance(entry, dict) or entry.get("version") != expected_version:
                raise Refused("lockfile emdash version mismatch")
            integrity = entry.get("integrity")
            if integrity is not None and integrity != PINNED_INTEGRITY[f"emdash@{expected_version}"]:
                raise Refused("lockfile emdash integrity hash mismatch against D-096 pin")

    if "LICENSE" not in files:
        raise Refused("MIT LICENSE notice missing")
    lic_bytes = files["LICENSE"]
    lic_sha = sha256_bytes(lic_bytes)
    if require_upstream_license and lic_sha != PINNED_MIT_LICENSE_SHA256:
        raise Refused("LICENSE SHA-256 does not match D-096 pinned MIT notice")
    try:
        lic_text = lic_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Refused("LICENSE not UTF-8") from exc
    if "MIT License" not in lic_text and "Permission is hereby granted, free of charge" not in lic_text:
        raise Refused("LICENSE does not contain MIT permission notice")

    return lock_name, lock_sha, lic_sha


def write_deterministic_bundle(files: dict[str, bytes], out_dir: Path) -> dict:
    """Writes byte-reproducible bundle.tar.gz and manifest.sha256 into out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_lines: list[str] = []
    total_bytes = 0
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for rel in sorted(files):
            raw = files[rel]
            total_bytes += len(raw)
            manifest_lines.append(f"{sha256_bytes(raw)}  {rel}\n")
            info = tarfile.TarInfo(name=rel)
            info.size = len(raw)
            info.mode = 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tf.addfile(info, io.BytesIO(raw))

    gz_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz_buf, mtime=0, compresslevel=6) as gz:
        gz.write(tar_buf.getvalue())
    bundle_bytes = gz_buf.getvalue()
    manifest_bytes = "".join(manifest_lines).encode("utf-8")

    (out_dir / "bundle.tar.gz").write_bytes(bundle_bytes)
    (out_dir / "manifest.sha256").write_bytes(manifest_bytes)
    return {
        "artifact_sha256": sha256_bytes(bundle_bytes),
        "manifest_sha256": sha256_bytes(manifest_bytes),
        "file_count": len(files),
        "total_bytes": total_bytes,
    }


def package_release(
    src: Path,
    out_dir: Path,
    release_id: str,
    entrypoint: str,
    migration_entrypoint: str | None = None,
    emdash_version: str = DEFAULT_EMDASH_VERSION,
    require_upstream_license: bool = False,
) -> dict:
    if not valid_release_id(release_id):
        raise Refused("invalid release_id")
    files = collect_release_tree(src)
    lock_name, lock_sha, lic_sha = check_emdash_metadata(
        files, emdash_version, entrypoint, migration_entrypoint, require_upstream_license
    )
    bundle_info = write_deterministic_bundle(files, out_dir)
    meta = {
        "schema": SCHEMA,
        "kind": "release",
        "release_id": release_id,
        "runtime": "node_22_v1",
        "emdash_version": emdash_version,
        "starter": PINNED_STARTER,
        "pinned_commit": PINNED_COMMIT if emdash_version == DEFAULT_EMDASH_VERSION else None,
        "lockfile": lock_name,
        "lockfile_sha256": lock_sha,
        "license_sha256": lic_sha,
        "entrypoint": entrypoint,
        "migration_entrypoint": migration_entrypoint,
        "recommended_env_keys": ["EMDASH_ENCRYPTION_KEY", "EMDASH_SITE_URL"],
        "recommended_websocket": "/_emdash/api/content/",
        **bundle_info,
    }
    (out_dir / "release-meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    return meta


def prepare_upgrade(
    baseline_meta_path: Path,
    src: Path,
    out_dir: Path,
    release_id: str,
    entrypoint: str,
    migration_entrypoint: str,
    to_version: str,
    allow_same_version: bool = False,
) -> dict:
    if not valid_release_id(release_id):
        raise Refused("invalid release_id")
    try:
        baseline = json.loads(baseline_meta_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refused("baseline release-meta.json unreadable") from exc
    if not isinstance(baseline, dict) or baseline.get("schema") != SCHEMA:
        raise Refused("baseline metadata schema mismatch")
    from_version = baseline.get("emdash_version")
    if not isinstance(from_version, str) or not SEMVER_RE.fullmatch(from_version):
        raise Refused("baseline emdash_version invalid")
    if not allow_same_version and to_version == from_version:
        raise Refused("upgrade target version equals baseline version")

    files = collect_release_tree(src)
    lock_name, lock_sha, lic_sha = check_emdash_metadata(
        files, to_version, entrypoint, migration_entrypoint, False
    )
    bundle_info = write_deterministic_bundle(files, out_dir)
    target_fingerprint = sha256_bytes(
        f"{to_version}\0{lock_sha}\0{bundle_info['manifest_sha256']}\0{migration_entrypoint}".encode()
    )
    meta = {
        "schema": SCHEMA,
        "kind": "upgrade",
        "upgrader": "upgrade-emdash@0.1.0",
        "upgrader_integrity": PINNED_INTEGRITY["upgrade-emdash@0.1.0"],
        "release_id": release_id,
        "runtime": "node_22_v1",
        "from_emdash_version": from_version,
        "to_emdash_version": to_version,
        "from_lockfile_sha256": baseline.get("lockfile_sha256"),
        "to_lockfile_sha256": lock_sha,
        "lockfile": lock_name,
        "license_sha256": lic_sha,
        "entrypoint": entrypoint,
        "migration_entrypoint": migration_entrypoint,
        "requires_capture": True,
        "target_fingerprint": target_fingerprint,
        **bundle_info,
    }
    (out_dir / "upgrade-meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rel = sub.add_parser("package-release")
    p_rel.add_argument("--src", type=Path, required=True)
    p_rel.add_argument("--out", type=Path, required=True)
    p_rel.add_argument("--release-id", required=True)
    p_rel.add_argument("--entrypoint", required=True)
    p_rel.add_argument("--migration-entrypoint", default=None)
    p_rel.add_argument("--emdash-version", default=DEFAULT_EMDASH_VERSION)
    p_rel.add_argument("--require-upstream-license", action="store_true")

    p_up = sub.add_parser("prepare-upgrade")
    p_up.add_argument("--baseline-meta", type=Path, required=True)
    p_up.add_argument("--src", type=Path, required=True)
    p_up.add_argument("--out", type=Path, required=True)
    p_up.add_argument("--release-id", required=True)
    p_up.add_argument("--entrypoint", required=True)
    p_up.add_argument("--migration-entrypoint", required=True)
    p_up.add_argument("--to-version", required=True)
    p_up.add_argument("--allow-same-version", action="store_true")

    args = parser.parse_args()
    try:
        if args.cmd == "package-release":
            meta = package_release(
                args.src,
                args.out,
                args.release_id,
                args.entrypoint,
                args.migration_entrypoint,
                args.emdash_version,
                args.require_upstream_license,
            )
        else:
            meta = prepare_upgrade(
                args.baseline_meta,
                args.src,
                args.out,
                args.release_id,
                args.entrypoint,
                args.migration_entrypoint,
                args.to_version,
                args.allow_same_version,
            )
        print(json.dumps(meta, indent=2, sort_keys=True))
        return 0
    except Refused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
