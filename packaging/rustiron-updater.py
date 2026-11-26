#!/usr/bin/env python3
"""One-command verified RustIron release updater and rollback orchestrator (W647).

Wraps `packaging/stage-job-tools.py`, `packaging/assemble-install-root.py`,
`packaging/update-product.py` (D-049/D-062/D-063/H-09), optional Console Admin
Panel atomic swap + rollback, and signed `releases.json` channel checks in one
fail-closed CLI:

  rustiron-updater.py status [--json]
  rustiron-updater.py check (--manifest-file FILE | --manifest-url HTTPS_URL) \\
      --release-signers FILE --release-signer-id ID [--channel stable|beta] [--json]
  rustiron-updater.py verify --bundle FILE --release-signers FILE --release-signer-id ID
  rustiron-updater.py plan --bundle FILE --release-signers FILE --release-signer-id ID \\
      [--job-profile PATH] [--console-dir PATH]
  rustiron-updater.py apply (--bundle FILE | --manifest-url HTTPS_URL | --manifest-file FILE) \\
      --release-signers FILE --release-signer-id ID [--job-profile PATH] \\
      [--console-dir PATH] [--skip-console] [--migrate-journal] [--allow-downgrade]
  rustiron-updater.py rollback --update-dir DIR [--console-dir PATH] [--apply]

Security invariants:
- Never trusts an unsigned release index or bundle (`rustiron-release-v1` SSHSIG required).
- Remote downloads enforce HTTPS-only with no HTTP downgrades and strict size caps.
- Websites (OLS, PHP pools, EmDash/Node apps) stay online throughout management updates.
- Never modifies `/etc/rustiron-console/env` or Console SQLite auth/mail databases.
- Preserves `/var/lib/rustiron/install-record.json` untouched after `update-product.py`
  so native `update-product.py --rollback` remains 100% compatible.
"""
from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent

VERSION_RECORD = "var/lib/rustiron/release-version.json"
VERSION_SCHEMA = "rustiron-installed-version/1"
CONSOLE_BACKUP_NAME = "console.before.tar.gz"
CONSOLE_META_NAME = "console-update.json"
DEFAULT_JOB_PROFILE = HERE / "profiles/alma10-epel-el10_3-job-tools.toml"
DEFAULT_CONSOLE_DIR = Path("/opt/rustiron/console")
MAX_INDEX_BYTES = 1024 * 1024
MAX_BUNDLE_BYTES = 512 * 1024 * 1024


class UpdaterError(ValueError):
    """Fail-closed updater refusal."""


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


bundler = _load_module("bundle_release_upd", REPO_ROOT / "scripts/release/bundle_release.py")
product_updater = _load_module("update_product_upd", HERE / "update-product.py")


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https":
            raise UpdaterError(f"refused non-HTTPS redirect to {newurl!r}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_https_bounded(url: str, max_bytes: int, timeout: int = 60) -> bytes:
    """Download a resource strictly over HTTPS within a hard byte ceiling."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise UpdaterError(f"remote URL must use https://: {url!r}")
    opener = urllib.request.build_opener(_HttpsOnlyRedirect())
    req = urllib.request.Request(url, headers={"User-Agent": "rustiron-updater/1"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            chunks: list[bytes] = []
            total = 0
            while chunk := resp.read(1 << 16):
                total += len(chunk)
                if total > max_bytes:
                    raise UpdaterError(f"download from {url} exceeded {max_bytes} byte limit")
                chunks.append(chunk)
            return b"".join(chunks)
    except urllib.error.URLError as error:
        raise UpdaterError(f"failed to fetch {url}: {error}") from None


def read_installed_status(target: Path = Path("/")) -> dict:
    """Read-only summary of installed RustIron payload, version record, and rollback points."""
    record_path = target / product_updater.RECORD
    install_record = None
    if record_path.is_file() and not record_path.is_symlink():
        try:
            install_record = json.loads(record_path.read_bytes())
        except (OSError, ValueError):
            install_record = None

    version_path = target / VERSION_RECORD
    version_doc = None
    if version_path.is_file() and not version_path.is_symlink():
        try:
            parsed = json.loads(version_path.read_bytes())
            if isinstance(parsed, dict) and parsed.get("schema") == VERSION_SCHEMA:
                version_doc = parsed
        except (OSError, ValueError):
            version_doc = None

    updates_dir = target / product_updater.UPDATES
    rollbacks: list[str] = []
    if updates_dir.is_dir() and not updates_dir.is_symlink():
        for entry in sorted(updates_dir.iterdir(), reverse=True):
            manifest = entry / product_updater.UPDATE_MANIFEST
            if entry.is_dir() and manifest.is_file():
                try:
                    m = json.loads(manifest.read_bytes())
                    if m.get("state") == "complete":
                        rollbacks.append(str(entry))
                except (OSError, ValueError):
                    continue

    mark_path = target / "var/lib/rustiron/admission/admission-mark"
    admission_mark = mark_path.read_text(encoding="utf-8", errors="replace").strip() if mark_path.is_file() else None

    return {
        "schema": "rustiron-updater-status/1",
        "installed": install_record is not None,
        "version": version_doc.get("version") if version_doc else None,
        "git_commit": version_doc.get("git_commit") if version_doc else None,
        "channel": version_doc.get("channel") if version_doc else None,
        "journal_schema_version": version_doc.get("journal_schema_version") if version_doc else None,
        "updated_at": version_doc.get("updated_at") if version_doc else None,
        "payload_files": len(install_record.get("payload", {})) if install_record else 0,
        "release_signature": install_record.get("release_signature") if install_record else None,
        "update_history": install_record.get("updates", []) if install_record else [],
        "available_rollbacks": rollbacks,
        "admission_mark": admission_mark,
    }


def load_verified_index(
    *,
    release_signers: Path,
    release_signer_id: str,
    manifest_file: Path | None = None,
    manifest_url: str | None = None,
    sig_file: Path | None = None,
    fetcher=fetch_https_bounded,
) -> dict:
    """Load and SSHSIG-verify a `releases.json` channel index (local file or HTTPS URL)."""
    if bool(manifest_file) == bool(manifest_url):
        raise UpdaterError("provide exactly one of --manifest-file or --manifest-url")

    tmp_dir = Path(tempfile.mkdtemp(prefix="rustiron-index-"))
    os.chmod(tmp_dir, 0o700)
    try:
        if manifest_file is not None:
            actual_sig = sig_file or manifest_file.with_name(manifest_file.name + ".sig")
            if not actual_sig.is_file() or actual_sig.is_symlink():
                raise UpdaterError(f"missing index signature: {actual_sig}")
            bundler.verify_ssh_signature(manifest_file, actual_sig, release_signers, release_signer_id)
            raw = manifest_file.read_bytes()
        else:
            assert manifest_url is not None
            raw = fetcher(manifest_url, MAX_INDEX_BYTES)
            sig_raw = fetcher(f"{manifest_url}.sig", 64 * 1024)
            idx_path = tmp_dir / "releases.json"
            idx_sig = tmp_dir / "releases.json.sig"
            bundler.write_atomic(idx_path, raw, 0o600)
            bundler.write_atomic(idx_sig, sig_raw, 0o600)
            bundler.verify_ssh_signature(idx_path, idx_sig, release_signers, release_signer_id)
        doc = json.loads(raw)
        if not isinstance(doc, dict) or doc.get("schema") != bundler.INDEX_SCHEMA:
            raise UpdaterError("invalid releases.json schema")
        return doc
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def check_for_update(
    index_doc: dict,
    status_doc: dict,
    channel: str = "stable",
) -> dict:
    """Compare installed version against verified channel index."""
    if channel not in bundler.VALID_CHANNELS:
        raise UpdaterError(f"unknown channel: {channel}")
    latest_version = index_doc.get("channels", {}).get(channel)
    if not latest_version:
        return {
            "schema": "rustiron-update-check/1",
            "channel": channel,
            "current_version": status_doc.get("version"),
            "latest_version": None,
            "update_available": False,
            "release": None,
        }
    release = next((r for r in index_doc.get("releases", []) if r.get("version") == latest_version), None)
    if release is None:
        raise UpdaterError(f"channel {channel} points to missing release {latest_version}")
    current = status_doc.get("version")
    if current is None:
        available = True
    else:
        available = bundler.parse_semver(latest_version) > bundler.parse_semver(current)
    cur_schema = status_doc.get("journal_schema_version")
    new_schema = release.get("journal_schema_version")
    migration_needed = (
        cur_schema is not None and new_schema is not None and int(new_schema) > int(cur_schema)
    )
    return {
        "schema": "rustiron-update-check/1",
        "channel": channel,
        "current_version": current,
        "latest_version": latest_version,
        "update_available": available,
        "journal_migration_required": migration_needed,
        "release": release,
    }


def backup_console_dir(console_dir: Path, archive_out: Path) -> str:
    """Archive existing Console source tree (excluding node_modules/DBs/secrets) for rollback."""
    data = bundler.build_console_archive_bytes(console_dir)
    bundler.write_atomic(archive_out, data, 0o400)
    return hashlib.sha256(data).hexdigest()


def swap_console_dir(console_archive: Path, console_dir: Path, backup_out: Path | None = None) -> dict:
    """Atomically replace Console source tree while preserving node_modules, env, and SQLite DBs."""
    if not console_dir.is_dir() or console_dir.is_symlink():
        raise UpdaterError(f"console directory does not exist or is a symlink: {console_dir}")
    backup_sha = None
    if backup_out is not None:
        backup_sha = backup_console_dir(console_dir, backup_out)

    staged = Path(tempfile.mkdtemp(prefix=f".{console_dir.name}.new-", dir=console_dir.parent))
    os.chmod(staged, 0o755)
    old_swap = console_dir.with_name(f".{console_dir.name}.old-{secrets.token_hex(6)}")
    moved_nm = False
    moved_live = False
    swapped = False
    try:
        bundler.safe_extract_tarball(console_archive, staged)
        # Preserve existing node_modules so offline/air-gapped hosts need no network install
        # when bun.lock is unchanged, and preserve any local `.live` observation dir.
        old_lock = (console_dir / "bun.lock").read_bytes() if (console_dir / "bun.lock").is_file() else b""
        new_lock = (staged / "bun.lock").read_bytes() if (staged / "bun.lock").is_file() else b""
        lock_changed = old_lock != new_lock
        existing_nm = console_dir / "node_modules"
        if existing_nm.is_dir() and not existing_nm.is_symlink():
            shutil.move(str(existing_nm), str(staged / "node_modules"))
            moved_nm = True
        existing_live = console_dir / ".live"
        if existing_live.is_dir() and not existing_live.is_symlink():
            shutil.move(str(existing_live), str(staged / ".live"))
            moved_live = True
        st = console_dir.lstat()
        os.rename(console_dir, old_swap)
        try:
            os.rename(staged, console_dir)
            swapped = True
        except BaseException:
            os.rename(old_swap, console_dir)
            raise
        if os.geteuid() == 0:
            os.chown(console_dir, st.st_uid, st.st_gid)
            for root, dirs, files in os.walk(console_dir, followlinks=False):
                rp = Path(root)
                for name in (*dirs, *files):
                    if name == "node_modules":
                        continue
                    os.chown(rp / name, st.st_uid, st.st_gid, follow_symlinks=False)
                if "node_modules" in dirs:
                    dirs.remove("node_modules")
        shutil.rmtree(old_swap, ignore_errors=True)
        return {
            "console_dir": str(console_dir),
            "backup_archive": str(backup_out) if backup_out else None,
            "backup_sha256": backup_sha,
            "lockfile_changed": lock_changed,
        }
    except BaseException:
        # W651: restore moved node_modules/.live back before deleting staged so a failed swap never loses them.
        if not swapped and console_dir.is_dir():
            if moved_nm and (staged / "node_modules").is_dir() and not (console_dir / "node_modules").exists():
                shutil.move(str(staged / "node_modules"), str(console_dir / "node_modules"))
            if moved_live and (staged / ".live").is_dir() and not (console_dir / ".live").exists():
                shutil.move(str(staged / ".live"), str(console_dir / ".live"))
        shutil.rmtree(staged, ignore_errors=True)
        raise


def record_installed_version(target: Path, metadata: dict, bundle_sha256: str, update_folder: str | None) -> Path:
    """Persist installed version metadata separately from install-record.json (preserving rollback hash)."""
    doc = {
        "schema": VERSION_SCHEMA,
        "version": metadata["version"],
        "channel": metadata["channel"],
        "git_commit": metadata["git_commit"],
        "journal_schema_version": metadata["journal_schema_version"],
        "bundle_sha256": bundle_sha256,
        "update_folder": update_folder,
        "updated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    dest = target / VERSION_RECORD
    bundler.write_atomic(dest, bundler.canonical_json(doc), 0o600)
    return dest


def run_cmd(cmd: list[str], capture: bool = False) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
        timeout=600,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip() if capture else f"exit={proc.returncode}"
        raise UpdaterError(f"command failed ({' '.join(cmd[:3])}): {detail}")
    return proc


def _resolve_bundle_path(
    args,
    work_dir: Path,
    fetcher=fetch_https_bounded,
) -> tuple[Path, Path | None, str | None]:
    """Return `(bundle_path, sig_path, expected_sha256)` from local bundle or verified index."""
    if args.bundle is not None:
        return args.bundle, args.sig, args.expected_sha256
    index_doc = load_verified_index(
        release_signers=args.release_signers,
        release_signer_id=args.release_signer_id,
        manifest_file=args.manifest_file,
        manifest_url=args.manifest_url,
        fetcher=fetcher,
    )
    status_doc = read_installed_status(args.root)
    check = check_for_update(index_doc, status_doc, channel=args.channel)
    release = check.get("release")
    if release is None:
        raise UpdaterError(f"no release found for channel {args.channel}")
    bundle_bytes = fetcher(release["bundle_url"], MAX_BUNDLE_BYTES)
    sig_bytes = fetcher(release["sig_url"], 64 * 1024)
    bpath = work_dir / f"rustiron-{release['version']}-almalinux10-x86_64.tar.gz"
    spath = work_dir / f"{bpath.name}.sig"
    bundler.write_atomic(bpath, bundle_bytes, 0o600)
    bundler.write_atomic(spath, sig_bytes, 0o600)
    return bpath, spath, release["bundle_sha256"]


def _execute_plan_or_apply(args, do_apply: bool) -> dict:
    if args.root == Path("/") and os.geteuid() != 0:
        raise UpdaterError(f"{'apply' if do_apply else 'plan'} on / requires root")

    work_dir = Path(tempfile.mkdtemp(prefix="rustiron-updater-work-"))
    os.chmod(work_dir, 0o700)
    try:
        bundle_path, sig_path, expected_sha = _resolve_bundle_path(args, work_dir)
        status_doc = read_installed_status(args.root)

        with bundler.verified_bundle_dir(
            bundle_path,
            args.release_signers,
            args.release_signer_id,
            sig_path=sig_path,
            expected_sha256=expected_sha,
        ) as info:
            meta = info["metadata"]
            current_ver = status_doc.get("version")
            if current_ver is not None and not args.allow_downgrade:
                if bundler.parse_semver(meta["version"]) < bundler.parse_semver(current_ver):
                    raise UpdaterError(
                        f"refusing downgrade from {current_ver} to {meta['version']} "
                        "(pass --allow-downgrade or use rollback)"
                    )

            cur_schema = status_doc.get("journal_schema_version")
            new_schema = meta["journal_schema_version"]
            migration_needed = cur_schema is not None and int(new_schema) > int(cur_schema)
            if migration_needed and do_apply and not args.migrate_journal:
                raise UpdaterError(
                    f"release raises journal schema {cur_schema} -> {new_schema}; "
                    "re-run with --migrate-journal after reviewing Runbook 16"
                )

            mgmt_root = info["management_root"]
            job_parent = work_dir / "jobs"
            root_parent = work_dir / "assembled"
            job_parent.mkdir(mode=0o700)
            root_parent.mkdir(mode=0o700)

            # Stage host job tools as an unprivileged user if running as root on a real host.
            job_cmd = ["python3", str(HERE / "stage-job-tools.py"), str(args.job_profile), str(job_parent)]
            if args.root == Path("/") and os.geteuid() == 0:
                os.chown(job_parent, 65534, 65534)
                job_cmd = ["/usr/sbin/runuser", "-u", "nobody", "--", *job_cmd]
            job_proc = run_cmd(job_cmd, capture=True)
            host_job_root = Path(job_proc.stdout.strip().splitlines()[-1])

            asm_proc = run_cmd([
                "python3", str(HERE / "assemble-install-root.py"),
                str(mgmt_root), str(host_job_root), str(args.job_profile), str(root_parent),
            ], capture=True)
            install_root = Path(asm_proc.stdout.strip().splitlines()[-1])

            upd_cmd = [
                "python3", str(HERE / "update-product.py"),
                str(install_root), str(mgmt_root), str(host_job_root), str(args.job_profile),
                "--release-signers", str(args.release_signers),
                "--release-signer-id", args.release_signer_id,
            ]
            if do_apply:
                upd_cmd.append("--apply")
            upd_proc = run_cmd(upd_cmd, capture=True)
            print(upd_proc.stdout, end="")

            update_folder = None
            for line in upd_proc.stdout.splitlines():
                if line.startswith("UPDATE FOLDER "):
                    update_folder = line.removeprefix("UPDATE FOLDER ").strip()

            console_result = None
            will_update_console = (
                info["console_archive"] is not None
                and not args.skip_console
                and args.console_dir is not None
                and args.console_dir.is_dir()
            )
            if will_update_console:
                if do_apply:
                    backup_out = (
                        Path(update_folder) / CONSOLE_BACKUP_NAME
                        if update_folder
                        else args.root / product_updater.UPDATES / f"console-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.tar.gz"
                    )
                    console_result = swap_console_dir(info["console_archive"], args.console_dir, backup_out)
                    if update_folder:
                        bundler.write_atomic(
                            Path(update_folder) / CONSOLE_META_NAME,
                            bundler.canonical_json(console_result),
                            0o400,
                        )
                    if console_result["lockfile_changed"] and shutil.which("/usr/local/bin/bun"):
                        run_cmd(["/usr/local/bin/bun", "install", "--frozen-lockfile", "--cwd", str(args.console_dir)])
                    if shutil.which("/usr/local/bin/bun") and (args.console_dir / "scripts/build.ts").is_file():
                        run_cmd(["/usr/local/bin/bun", "run", "--cwd", str(args.console_dir), "build"])
                    if args.root == Path("/"):
                        run_cmd(["/usr/bin/systemctl", "restart", "rustiron-console.service"])
                else:
                    console_result = {
                        "planned": True,
                        "console_dir": str(args.console_dir),
                        "console_archive_sha256": meta["console_archive_sha256"],
                    }

            if do_apply and migration_needed and args.migrate_journal and args.root == Path("/"):
                run_cmd(["/usr/bin/systemctl", "stop", "rustiron-coordinator", "rustiron-executor", "rustiron-admin-helper"])
                jpath = Path("/var/lib/rustiron/executor/fixture-journal.sqlite")
                if update_folder and jpath.is_file() and not jpath.is_symlink():
                    fd = os.open(jpath, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    with os.fdopen(fd, "rb") as src_fh:
                        bundler.write_atomic(
                            Path(update_folder) / "fixture-journal.before-migrate.sqlite",
                            src_fh.read(),
                            0o400,
                        )
                run_cmd(["/usr/libexec/rustiron/rustiron-executor", "migrate"])
                run_cmd(["/usr/sbin/restorecon", "-R", "/var/lib/rustiron"])
                run_cmd(["/usr/bin/systemctl", "start", "rustiron-admin-helper", "rustiron-executor", "rustiron-coordinator"])

            if do_apply:
                record_installed_version(args.root, meta, info["bundle_sha256"], update_folder)

            return {
                "mode": "apply" if do_apply else "plan",
                "version": meta["version"],
                "git_commit": meta["git_commit"],
                "update_folder": update_folder,
                "journal_migration_required": migration_needed,
                "console": console_result,
            }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def run_rollback(args) -> dict:
    """Roll back both core RustIron payload and any Console backup captured in the update folder."""
    update_dir: Path = args.update_dir
    cmd = ["python3", str(HERE / "update-product.py"), "--rollback", str(update_dir)]
    if args.apply:
        cmd.append("--apply")
    proc = run_cmd(cmd, capture=True)
    print(proc.stdout, end="")

    console_restored = False
    backup_archive = update_dir / CONSOLE_BACKUP_NAME
    if backup_archive.is_file() and args.console_dir and args.console_dir.is_dir():
        if args.apply:
            swap_console_dir(backup_archive, args.console_dir, backup_out=None)
            if args.root == Path("/"):
                run_cmd(["/usr/bin/systemctl", "restart", "rustiron-console.service"])
            console_restored = True
    return {
        "mode": "rollback",
        "applied": bool(args.apply),
        "update_dir": str(update_dir),
        "console_backup_present": backup_archive.is_file(),
        "console_restored": console_restored,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_status = sub.add_parser("status", help="Show installed RustIron version, signature, and rollback folders")
    p_status.add_argument("--root", type=Path, default=Path("/"))
    p_status.add_argument("--json", action="store_true")

    p_check = sub.add_parser("check", help="Check a signed releases.json index for newer versions")
    p_check.add_argument("--manifest-file", type=Path, default=None)
    p_check.add_argument("--manifest-url", default=None)
    p_check.add_argument("--sig-file", type=Path, default=None)
    p_check.add_argument("--release-signers", type=Path, required=True)
    p_check.add_argument("--release-signer-id", required=True)
    p_check.add_argument("--channel", choices=bundler.VALID_CHANNELS, default="stable")
    p_check.add_argument("--root", type=Path, default=Path("/"))
    p_check.add_argument("--json", action="store_true")

    p_verify = sub.add_parser("verify", help="Verify a signed release bundle offline without installing")
    p_verify.add_argument("--bundle", type=Path, required=True)
    p_verify.add_argument("--sig", type=Path, default=None)
    p_verify.add_argument("--expected-sha256", default=None)
    p_verify.add_argument("--release-signers", type=Path, required=True)
    p_verify.add_argument("--release-signer-id", required=True)

    for cmd_name, help_text in (
        ("plan", "Dry-run a signed update bundle and print exact file/console changes"),
        ("apply", "Verify and atomically apply a signed release bundle (with zero site downtime)"),
    ):
        p = sub.add_parser(cmd_name, help=help_text)
        p.add_argument("--bundle", type=Path, default=None)
        p.add_argument("--sig", type=Path, default=None)
        p.add_argument("--expected-sha256", default=None)
        p.add_argument("--manifest-file", type=Path, default=None)
        p.add_argument("--manifest-url", default=None)
        p.add_argument("--channel", choices=bundler.VALID_CHANNELS, default="stable")
        p.add_argument("--release-signers", type=Path, required=True)
        p.add_argument("--release-signer-id", required=True)
        p.add_argument("--job-profile", type=Path, default=DEFAULT_JOB_PROFILE)
        p.add_argument("--console-dir", type=Path, default=DEFAULT_CONSOLE_DIR)
        p.add_argument("--skip-console", action="store_true")
        p.add_argument("--migrate-journal", action="store_true")
        p.add_argument("--allow-downgrade", action="store_true")
        p.add_argument("--root", type=Path, default=Path("/"))
        p.add_argument("--json", action="store_true")

    p_rb = sub.add_parser("rollback", help="Roll back a previous RustIron + Console update folder")
    p_rb.add_argument("--update-dir", type=Path, required=True)
    p_rb.add_argument("--console-dir", type=Path, default=DEFAULT_CONSOLE_DIR)
    p_rb.add_argument("--apply", action="store_true")
    p_rb.add_argument("--root", type=Path, default=Path("/"))
    p_rb.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "status":
            st = read_installed_status(args.root)
            if args.json:
                print(json.dumps(st, indent=2, sort_keys=True))
            else:
                print(f"Installed: {st['installed']} | Version: {st['version'] or 'untracked'} | Commit: {st['git_commit'] or 'unknown'}")
                print(f"Payload files: {st['payload_files']} | Rollback points: {len(st['available_rollbacks'])}")
                if st["release_signature"]:
                    sig = st["release_signature"]
                    print(f"Release trust: verified={sig.get('verified')} signer={sig.get('signer_id')} ns={sig.get('namespace')}")
        elif args.command == "check":
            idx = load_verified_index(
                release_signers=args.release_signers,
                release_signer_id=args.release_signer_id,
                manifest_file=args.manifest_file,
                manifest_url=args.manifest_url,
                sig_file=args.sig_file,
            )
            st = read_installed_status(args.root)
            res = check_for_update(idx, st, channel=args.channel)
            if args.json:
                print(json.dumps(res, indent=2, sort_keys=True))
            else:
                state = "UPDATE AVAILABLE" if res["update_available"] else "UP TO DATE"
                print(f"{state} (channel={res['channel']}): installed={res['current_version'] or 'none'} latest={res['latest_version']}")
                if res.get("journal_migration_required"):
                    print("NOTICE: journal schema migration required (--migrate-journal after Runbook 16 review)")
        elif args.command == "verify":
            with bundler.verified_bundle_dir(
                args.bundle, args.release_signers, args.release_signer_id,
                sig_path=args.sig, expected_sha256=args.expected_sha256,
            ) as info:
                print(json.dumps({
                    "verified": True,
                    "bundle_sha256": info["bundle_sha256"],
                    "metadata": info["metadata"],
                }, indent=2, sort_keys=True))
        elif args.command in ("plan", "apply"):
            if args.bundle is None and args.manifest_file is None and args.manifest_url is None:
                raise UpdaterError("provide --bundle, --manifest-file, or --manifest-url")
            res = _execute_plan_or_apply(args, do_apply=(args.command == "apply"))
            if args.json:
                print(json.dumps(res, indent=2, sort_keys=True))
        elif args.command == "rollback":
            res = run_rollback(args)
            if args.json:
                print(json.dumps(res, indent=2, sort_keys=True))
    except (UpdaterError, bundler.BundleError, OSError, ValueError) as error:
        print(f"REFUSED {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
