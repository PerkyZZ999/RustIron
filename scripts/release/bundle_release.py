#!/usr/bin/env python3
"""Package, index, sign, and verify unified RustIron release bundles (W647).

Combines a staged AlmaLinux 10 management root (`packaging/stage-product.sh`),
optional Console Admin Panel source archive (`console/`), optional CycloneDX
SBOM, and a canonical `release.json` manifest into one reproducible tarball
signed off-host in the dedicated `rustiron-release-v1` OpenSSH SSHSIG
namespace.

Subcommands:
  pack    Build `rustiron-<version>-almalinux10-x86_64.tar.gz` + `.sha256`
  sign    Sign a release bundle or `releases.json` off-host (`rustiron-release-v1`)
  verify  Verify outer `.sig`, safe archive layout, `release.json`, inner
          `management/SHA256SUMS.sig`, and optional `console.tar.gz` digest
  index   Create or update a canonical `releases.json` channel index

Private release signing keys MUST remain off-host. Experimental pre-release
release tooling — no supported public release exists yet.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]

RELEASE_NAMESPACE = "rustiron-release-v1"
BUNDLE_SCHEMA = "rustiron-release-bundle/1"
INDEX_SCHEMA = "rustiron-release-index/1"
VALID_CHANNELS = ("stable", "beta", "nightly")
SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_MEMBER_COUNT = 20_000
MAX_JSON_BYTES = 1024 * 1024

CONSOLE_EXCLUDED_DIRS = frozenset({
    "node_modules", "dist", ".live", ".fallow", ".ds-receipts", ".git", "__pycache__",
})
CONSOLE_EXCLUDED_SUFFIXES = (".sqlite", ".sqlite-wal", ".sqlite-shm", ".secret", ".log")


class BundleError(ValueError):
    """Fail-closed error for invalid release bundles, manifests, or signatures."""


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


release_manifest = _load_module("release_manifest_bundler", HERE / "release_manifest.py")


def parse_semver(version: str) -> tuple[int, int, int, int, tuple]:
    """Parse SemVer `MAJOR.MINOR.PATCH[-prerelease]` into a strictly sortable key.

    A final release (`1.2.0`) sorts strictly higher than any prerelease (`1.2.0-rc.1`).
    """
    match = SEMVER_RE.fullmatch(version)
    if not match:
        raise BundleError(f"invalid version {version!r}; expected SemVer MAJOR.MINOR.PATCH[-prerelease]")
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    prerelease = match.group(4)
    if prerelease is None:
        return (major, minor, patch, 1, ())
    parts = tuple(
        (0, int(tok)) if tok.isdigit() else (1, tok)
        for tok in prerelease.split(".")
    )
    return (major, minor, patch, 0, parts)


def sha256_file(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise BundleError(f"not a regular file: {path}")
        return hashlib.file_digest(handle, "sha256").hexdigest()


def canonical_json(obj: dict) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def write_atomic(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise BundleError(f"refusing symlink destination {path}")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _norm_tarinfo(name: str, data: bytes, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = mode & 0o755
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    return info


def build_console_archive_bytes(console_dir: Path) -> bytes:
    """Create a deterministic gzip-compressed tarball of `console/` source files only."""
    if not console_dir.is_dir() or console_dir.is_symlink():
        raise BundleError(f"invalid console directory: {console_dir}")
    if not (console_dir / "package.json").is_file() or not (console_dir / "src/server.ts").is_file():
        raise BundleError(f"{console_dir} does not look like a RustIron console directory")

    entries: list[tuple[str, Path, int]] = []
    for root, dirs, files in os.walk(console_dir, followlinks=False):
        root_path = Path(root)
        dirs[:] = sorted(d for d in dirs if d not in CONSOLE_EXCLUDED_DIRS and not (root_path / d).is_symlink())
        for fname in sorted(files):
            if fname.endswith(CONSOLE_EXCLUDED_SUFFIXES) or fname == ".env" or fname.startswith(".env."):
                continue
            full = root_path / fname
            info = full.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise BundleError(f"refusing non-regular file in console tree: {full}")
            rel = full.relative_to(console_dir).as_posix()
            mode = 0o755 if (info.st_mode & 0o111) else 0o644
            entries.append((rel, full, mode))

    if not entries:
        raise BundleError("console directory contains no packable files")

    raw_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw_buf, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for rel, full, mode in entries:
                data = full.read_bytes()
                tar.addfile(_norm_tarinfo(rel, data, mode), io.BytesIO(data))
    return raw_buf.getvalue()


def verify_ssh_signature(payload_path: Path, sig_path: Path, allowed_signers: Path, signer_id: str) -> None:
    """Verify an OpenSSH SSHSIG signature in namespace `rustiron-release-v1`."""
    for p in (payload_path, sig_path, allowed_signers):
        info = p.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise BundleError(f"expected regular file: {p}")
    signers_info = allowed_signers.lstat()
    if signers_info.st_mode & 0o022:
        raise BundleError(f"allowed-signers file {allowed_signers} must not be group/world-writable")

    with payload_path.open("rb") as payload_fh:
        proc = subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y", "verify",
                "-n", RELEASE_NAMESPACE,
                "-f", str(allowed_signers),
                "-I", signer_id,
                "-s", str(sig_path),
            ],
            stdin=payload_fh,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin"},
            timeout=30,
            check=False,
        )
    if proc.returncode != 0:
        raise BundleError(
            f"release signature verification failed for {payload_path.name} "
            f"(namespace={RELEASE_NAMESPACE}, signer={signer_id})"
        )


def sign_file(payload_path: Path, key_path: Path, sig_out: Path | None = None) -> Path:
    """Sign a regular file off-host with OpenSSH SSHSIG in namespace `rustiron-release-v1`."""
    if not payload_path.is_file() or payload_path.is_symlink():
        raise BundleError(f"cannot sign non-regular file: {payload_path}")
    if not key_path.is_file() or key_path.is_symlink():
        raise BundleError(f"signing key not found: {key_path}")
    target_sig = sig_out or payload_path.with_name(payload_path.name + ".sig")
    if target_sig.is_symlink():
        raise BundleError(f"refusing symlink signature target: {target_sig}")
    with payload_path.open("rb") as payload_fh:
        proc = subprocess.run(
            ["/usr/bin/ssh-keygen", "-q", "-Y", "sign", "-n", RELEASE_NAMESPACE, "-f", str(key_path)],
            stdin=payload_fh,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin"},
            timeout=30,
            check=False,
        )
    if proc.returncode != 0 or not proc.stdout:
        raise BundleError(f"ssh-keygen sign failed: {proc.stderr.decode('utf-8', errors='replace').strip()}")
    write_atomic(target_sig, proc.stdout, 0o644)
    return target_sig


def _ensure_no_symlink_ancestors(dest_resolved: Path, target: Path) -> None:
    cur = dest_resolved
    for part in target.relative_to(dest_resolved).parts[:-1]:
        cur = cur / part
        if cur.is_symlink():
            raise BundleError(f"symlink ancestor refused during extraction: {cur}")


def safe_extract_tarball(archive_path: Path, dest_dir: Path) -> list[str]:
    """Safely extract a gzip tarball refusing symlinks, hardlinks, traversal, devices, and setuid."""
    info = archive_path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise BundleError(f"archive is not a regular file: {archive_path}")
    if info.st_size > MAX_BUNDLE_BYTES:
        raise BundleError(f"archive exceeds {MAX_BUNDLE_BYTES} byte limit")

    dest_resolved = dest_dir.resolve()
    extracted: list[str] = []
    total_bytes = 0
    with tarfile.open(archive_path, mode="r:gz") as tar:
        members = tar.getmembers()
        if len(members) > MAX_MEMBER_COUNT:
            raise BundleError(f"archive exceeds {MAX_MEMBER_COUNT} member limit")
        for member in members:
            name = member.name
            if not name or name.startswith("/") or "\\" in name:
                raise BundleError(f"unsafe archive member path: {name!r}")
            parts = Path(name).parts
            if any(p in ("", ".", "..") for p in parts):
                raise BundleError(f"path traversal member refused: {name!r}")
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise BundleError(f"non-regular/link member refused: {name!r}")
            if member.mode & 0o6000:
                raise BundleError(f"setuid/setgid member refused: {name!r}")
            target = (dest_resolved / name).resolve()
            if not target.is_relative_to(dest_resolved) or target == dest_resolved:
                raise BundleError(f"member escapes extraction root: {name!r}")
            _ensure_no_symlink_ancestors(dest_resolved, target)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise BundleError(f"unsupported archive member type: {name!r}")
            if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                raise BundleError(f"member exceeds size limit: {name!r}")
            if total_bytes + member.size > MAX_BUNDLE_BYTES:
                raise BundleError("unpacked archive exceeds size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(member)
            if src is None:
                raise BundleError(f"unreadable member: {name!r}")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(target, flags, 0o600)
            written = 0
            try:
                with os.fdopen(fd, "wb") as out:
                    while chunk := src.read(1 << 16):
                        written += len(chunk)
                        total_bytes += len(chunk)
                        if written > MAX_MEMBER_BYTES or total_bytes > MAX_BUNDLE_BYTES:
                            raise BundleError("unpacked archive stream exceeded size limit")
                        out.write(chunk)
                    os.fchmod(out.fileno(), member.mode & 0o755)
            except BaseException:
                target.unlink(missing_ok=True)
                raise
            extracted.append(name)
    return extracted


def pack_release(
    *,
    version: str,
    git_commit: str,
    management_root: Path,
    out_dir: Path,
    channel: str = "stable",
    journal_schema_version: int = 44,
    console_dir: Path | None = None,
    sbom_path: Path | None = None,
    release_notes_url: str | None = None,
    built_at: str | None = None,
) -> dict:
    """Package a unified signed-ready release bundle tarball + .sha256 checksum file."""
    parse_semver(version)
    if channel not in VALID_CHANNELS:
        raise BundleError(f"channel must be one of {VALID_CHANNELS}")
    if not COMMIT_RE.fullmatch(git_commit):
        raise BundleError("git_commit must be 7-40 lowercase hex chars")
    if not 1 <= journal_schema_version <= 1000:
        raise BundleError("journal_schema_version must be 1..1000")
    if release_notes_url is not None and not release_notes_url.startswith("https://"):
        raise BundleError("--release-notes-url must use https://")

    # Verify management_root manifest matches its exact files (no links or tampering).
    dir_fd = os.open(management_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        expected_sums = release_manifest.canonical_manifest(dir_fd)
        with release_manifest.regular_file(dir_fd, "SHA256SUMS") as src:
            actual_sums = src.read(len(expected_sums) + 1)
        if actual_sums != expected_sums:
            raise BundleError("management_root/SHA256SUMS does not match staged files")
    finally:
        os.close(dir_fd)

    if not (management_root / "SHA256SUMS.sig").is_file() or (management_root / "SHA256SUMS.sig").is_symlink():
        raise BundleError(
            "management_root/SHA256SUMS.sig is required; sign management_root with "
            "scripts/release/release_sig.sh sign first"
        )

    console_bytes: bytes | None = None
    if console_dir is not None:
        console_bytes = build_console_archive_bytes(console_dir)

    sbom_bytes: bytes | None = None
    if sbom_path is not None:
        if not sbom_path.is_file() or sbom_path.is_symlink():
            raise BundleError(f"SBOM file not found: {sbom_path}")
        sbom_bytes = sbom_path.read_bytes()

    timestamp = built_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata: dict = {
        "schema": BUNDLE_SCHEMA,
        "version": version,
        "channel": channel,
        "git_commit": git_commit,
        "built_at": timestamp,
        "arch": "x86_64",
        "os": "almalinux-10",
        "journal_schema_version": journal_schema_version,
        "management_sha256sums_sha256": hashlib.sha256(expected_sums).hexdigest(),
        "includes_console": console_bytes is not None,
    }
    if console_bytes is not None:
        metadata["console_archive_sha256"] = hashlib.sha256(console_bytes).hexdigest()
    if sbom_bytes is not None:
        metadata["sbom_sha256"] = hashlib.sha256(sbom_bytes).hexdigest()
    if release_notes_url is not None:
        metadata["release_notes_url"] = release_notes_url

    bundle_name = f"rustiron-{version}-almalinux10-x86_64.tar.gz"
    bundle_path = out_dir / bundle_name
    out_dir.mkdir(parents=True, exist_ok=True)

    # Collect management tree in sorted deterministic order (including SHA256SUMS + .sig).
    mgmt_files: list[tuple[str, Path, int]] = []
    for root, dirs, files in os.walk(management_root, followlinks=False):
        root_path = Path(root)
        dirs[:] = sorted(dirs)
        for fname in sorted(files):
            full = root_path / fname
            st = full.lstat()
            if not stat.S_ISREG(st.st_mode):
                raise BundleError(f"non-regular file in management_root: {full}")
            rel = full.relative_to(management_root).as_posix()
            mgmt_files.append((f"management/{rel}", full, st.st_mode & 0o755))

    raw_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw_buf, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            meta_bytes = canonical_json(metadata)
            tar.addfile(_norm_tarinfo("release.json", meta_bytes, 0o644), io.BytesIO(meta_bytes))
            for arcname, full, mode in mgmt_files:
                data = full.read_bytes()
                tar.addfile(_norm_tarinfo(arcname, data, mode), io.BytesIO(data))
            if console_bytes is not None:
                tar.addfile(_norm_tarinfo("console.tar.gz", console_bytes, 0o644), io.BytesIO(console_bytes))
            if sbom_bytes is not None:
                tar.addfile(_norm_tarinfo("sbom.cdx.json", sbom_bytes, 0o644), io.BytesIO(sbom_bytes))

    bundle_data = raw_buf.getvalue()
    write_atomic(bundle_path, bundle_data, 0o644)
    bundle_sha = hashlib.sha256(bundle_data).hexdigest()
    sha_path = out_dir / f"{bundle_name}.sha256"
    write_atomic(sha_path, f"{bundle_sha}  {bundle_name}\n".encode("ascii"), 0o644)
    return {
        "bundle_path": str(bundle_path),
        "sha256_path": str(sha_path),
        "bundle_sha256": bundle_sha,
        "metadata": metadata,
    }


@contextmanager
def verified_bundle_dir(
    bundle_path: Path,
    allowed_signers: Path,
    signer_id: str,
    sig_path: Path | None = None,
    expected_sha256: str | None = None,
):
    """Verify outer bundle signature, extract safely, verify inner management & console digests."""
    actual_sig = sig_path or bundle_path.with_name(bundle_path.name + ".sig")
    if not actual_sig.is_file() or actual_sig.is_symlink():
        raise BundleError(f"missing bundle signature: {actual_sig}")
    bundle_sha = sha256_file(bundle_path)
    if expected_sha256 is not None and bundle_sha != expected_sha256:
        raise BundleError(f"bundle SHA-256 mismatch: expected {expected_sha256}, got {bundle_sha}")
    verify_ssh_signature(bundle_path, actual_sig, allowed_signers, signer_id)

    tmp_dir = Path(tempfile.mkdtemp(prefix="rustiron-bundle-verify-"))
    os.chmod(tmp_dir, 0o700)
    try:
        safe_extract_tarball(bundle_path, tmp_dir)
        meta_path = tmp_dir / "release.json"
        if not meta_path.is_file():
            raise BundleError("bundle missing release.json")
        meta = json.loads(meta_path.read_bytes())
        if not isinstance(meta, dict) or meta.get("schema") != BUNDLE_SCHEMA:
            raise BundleError("unrecognized release.json schema")
        parse_semver(str(meta.get("version", "")))
        if meta.get("channel") not in VALID_CHANNELS:
            raise BundleError("invalid channel in release.json")

        mgmt_dir = tmp_dir / "management"
        if not mgmt_dir.is_dir():
            raise BundleError("bundle missing management/ directory")
        # Verify inner management/SHA256SUMS + management/SHA256SUMS.sig!
        sums_path = mgmt_dir / "SHA256SUMS"
        sums_sig = mgmt_dir / "SHA256SUMS.sig"
        if not sums_path.is_file() or not sums_sig.is_file():
            raise BundleError("management/ missing SHA256SUMS or SHA256SUMS.sig")
        dir_fd = os.open(mgmt_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            expected_sums = release_manifest.canonical_manifest(dir_fd)
            actual_sums = sums_path.read_bytes()
            if actual_sums != expected_sums:
                raise BundleError("inner management/SHA256SUMS does not match files")
        finally:
            os.close(dir_fd)
        if hashlib.sha256(actual_sums).hexdigest() != meta.get("management_sha256sums_sha256"):
            raise BundleError("release.json management_sha256sums_sha256 mismatch")
        verify_ssh_signature(sums_path, sums_sig, allowed_signers, signer_id)

        console_archive: Path | None = None
        if meta.get("includes_console"):
            cpath = tmp_dir / "console.tar.gz"
            if not cpath.is_file():
                raise BundleError("release.json declares includes_console=true but console.tar.gz is missing")
            if sha256_file(cpath) != meta.get("console_archive_sha256"):
                raise BundleError("console.tar.gz SHA-256 mismatch against release.json")
            console_archive = cpath

        if "sbom_sha256" in meta:
            spath = tmp_dir / "sbom.cdx.json"
            if not spath.is_file() or sha256_file(spath) != meta["sbom_sha256"]:
                raise BundleError("sbom.cdx.json missing or digest mismatch")

        yield {
            "extract_dir": tmp_dir,
            "management_root": mgmt_dir,
            "console_archive": console_archive,
            "bundle_sha256": bundle_sha,
            "metadata": meta,
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def update_release_index(
    *,
    index_path: Path,
    bundle_path: Path,
    bundle_url: str,
    sig_url: str | None = None,
    min_upgrade_from: str | None = None,
) -> dict:
    """Create or update a canonical `releases.json` channel index from a packed bundle."""
    if not bundle_url.startswith("https://"):
        raise BundleError("--bundle-url must use https://")
    actual_sig_url = sig_url or f"{bundle_url}.sig"
    if not actual_sig_url.startswith("https://"):
        raise BundleError("--sig-url must use https://")
    if min_upgrade_from is not None:
        parse_semver(min_upgrade_from)

    bundle_sha = sha256_file(bundle_path)
    tmp_dir = Path(tempfile.mkdtemp(prefix="rustiron-idx-"))
    os.chmod(tmp_dir, 0o700)
    try:
        safe_extract_tarball(bundle_path, tmp_dir)
        meta = json.loads((tmp_dir / "release.json").read_bytes())
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    if meta.get("schema") != BUNDLE_SCHEMA:
        raise BundleError("bundle release.json schema mismatch")

    if index_path.exists():
        doc = json.loads(index_path.read_bytes())
        if doc.get("schema") != INDEX_SCHEMA or not isinstance(doc.get("releases"), list):
            raise BundleError(f"existing {index_path} is not a valid {INDEX_SCHEMA}")
    else:
        doc = {"schema": INDEX_SCHEMA, "channels": {}, "releases": []}

    entry = {
        "version": meta["version"],
        "channel": meta["channel"],
        "git_commit": meta["git_commit"],
        "released_at": meta["built_at"],
        "arch": meta["arch"],
        "os": meta["os"],
        "journal_schema_version": meta["journal_schema_version"],
        "includes_console": bool(meta.get("includes_console", False)),
        "bundle_url": bundle_url,
        "sig_url": actual_sig_url,
        "bundle_sha256": bundle_sha,
    }
    if min_upgrade_from is not None:
        entry["min_upgrade_from"] = min_upgrade_from
    if "release_notes_url" in meta:
        entry["release_notes_url"] = meta["release_notes_url"]

    releases = [r for r in doc["releases"] if r.get("version") != entry["version"]]
    releases.append(entry)
    releases.sort(key=lambda r: parse_semver(r["version"]), reverse=True)
    doc["releases"] = releases

    channels: dict[str, str] = {}
    for ch in VALID_CHANNELS:
        matching = [r for r in releases if r.get("channel") == ch]
        if matching:
            channels[ch] = matching[0]["version"]
    doc["channels"] = channels

    write_atomic(index_path, canonical_json(doc), 0o644)
    return doc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_pack = sub.add_parser("pack", help="Pack staged management root + optional Console into a release tarball")
    p_pack.add_argument("--version", required=True, help="SemVer version (e.g. 0.2.0 or 0.2.0-rc.1)")
    p_pack.add_argument("--git-commit", required=True, help="7-40 char lowercase git SHA")
    p_pack.add_argument("--management-root", type=Path, required=True)
    p_pack.add_argument("--out-dir", type=Path, required=True)
    p_pack.add_argument("--channel", choices=VALID_CHANNELS, default="stable")
    p_pack.add_argument("--journal-schema-version", type=int, default=44)
    p_pack.add_argument("--console-dir", type=Path, default=None)
    p_pack.add_argument("--sbom", type=Path, default=None)
    p_pack.add_argument("--release-notes-url", default=None)

    p_sign = sub.add_parser("sign", help="Sign a bundle tarball or releases.json off-host (rustiron-release-v1)")
    p_sign.add_argument("file", type=Path)
    p_sign.add_argument("--key", type=Path, required=True)
    p_sign.add_argument("--sig-out", type=Path, default=None)

    p_verify = sub.add_parser("verify", help="Verify outer .sig, archive safety, release.json, and inner SHA256SUMS.sig")
    p_verify.add_argument("bundle", type=Path)
    p_verify.add_argument("--release-signers", type=Path, required=True)
    p_verify.add_argument("--release-signer-id", required=True)
    p_verify.add_argument("--sig", type=Path, default=None)
    p_verify.add_argument("--expected-sha256", default=None)

    p_idx = sub.add_parser("index", help="Create or update canonical releases.json index from a packed bundle")
    p_idx.add_argument("--index", type=Path, required=True)
    p_idx.add_argument("--bundle", type=Path, required=True)
    p_idx.add_argument("--bundle-url", required=True)
    p_idx.add_argument("--sig-url", default=None)
    p_idx.add_argument("--min-upgrade-from", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "pack":
            res = pack_release(
                version=args.version,
                git_commit=args.git_commit,
                management_root=args.management_root,
                out_dir=args.out_dir,
                channel=args.channel,
                journal_schema_version=args.journal_schema_version,
                console_dir=args.console_dir,
                sbom_path=args.sbom,
                release_notes_url=args.release_notes_url,
            )
            print(json.dumps(res, indent=2, sort_keys=True))
        elif args.command == "sign":
            sig = sign_file(args.file, args.key, args.sig_out)
            print(f"SIGNED {args.file} -> {sig} (namespace={RELEASE_NAMESPACE})")
        elif args.command == "verify":
            with verified_bundle_dir(
                args.bundle, args.release_signers, args.release_signer_id,
                sig_path=args.sig, expected_sha256=args.expected_sha256,
            ) as info:
                print(json.dumps({
                    "verified": True,
                    "namespace": RELEASE_NAMESPACE,
                    "signer_id": args.release_signer_id,
                    "bundle_sha256": info["bundle_sha256"],
                    "metadata": info["metadata"],
                }, indent=2, sort_keys=True))
        elif args.command == "index":
            doc = update_release_index(
                index_path=args.index,
                bundle_path=args.bundle,
                bundle_url=args.bundle_url,
                sig_url=args.sig_url,
                min_upgrade_from=args.min_upgrade_from,
            )
            print(json.dumps(doc, indent=2, sort_keys=True))
    except (BundleError, OSError, ValueError, release_manifest.InvalidPackage) as error:
        print(f"REFUSED {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
