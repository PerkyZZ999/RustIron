#!/usr/bin/env python3
"""Deterministic off-host release packager for RustIron v0.1.1 modern full-stack apps (W660, D-102).

Packages pre-built frontend and/or backend release artifacts into a byte-reproducible
`bundle.tar.gz`, sorted `manifest.sha256`, and `release-meta.json` matching RustIron's
strict schema v2 `app_deploy` contracts across all four D-102 topologies:

  - static_spa          (Vite / React / Astro static / SvelteKit static -> Caddy static)
  - backend_api         (Bun / Node.js HTTP / SSR / WebSocket / SSE app)
  - fullstack_split     (Static SPA in frontend/ + Bun/Node API in backend/ -> Caddy split)
  - fullstack_dual_ssr  (SSR frontend in frontend/ + API backend in backend/ -> dual units)

Security invariants:
  - Runs 100% offline with Python stdlib only; NEVER runs package managers or user scripts.
  - Refuses symlinks, special files (FIFOs/sockets/devices), setuid/setgid bits, path
    traversal, unsafe manifest characters, and `.env` / `.env.*` secret files (`.env.example` allowed).
  - Enforces exact Rust contract ceilings (50,000 files, 512 MiB unpacked, 256-byte paths).
  - Emits exact, shell-quoted `scp` staging and `rustiron plan create app-deploy` commands.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import tarfile

sys.dont_write_bytecode = True

SCHEMA = "rustiron-app-pack/1"

# Mirrors crates/contracts/src/approval/app.rs bounds.
MAX_FILES = 50_000
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_PATH_BYTES = 128
MAX_MANIFEST_PATH_BYTES = 256

RELEASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SITE_ID_RE = re.compile(r"^[a-z][a-z0-9]{0,19}$")
SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
MANIFEST_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._@\[\]-]+$")

VALID_TOPOLOGIES = ("static_spa", "backend_api", "fullstack_split", "fullstack_dual_ssr")
VALID_RUNTIMES = ("bun_1_v1", "node_22_v1", "static_v1")
VALID_DATABASES = ("none", "sqlite", "mariadb", "postgresql_18")


class Refused(Exception):
    """Fail-closed pack refusal; never prints untrusted secret bytes."""


@dataclass(frozen=True)
class Preset:
    name: str
    description: str
    topology: str
    runtime: str
    database: str
    blue_green: bool
    spa_fallback: bool
    frontend_dir: str | None
    entrypoint: str
    frontend_runtime: str | None
    frontend_entrypoint: str | None
    health_path: str
    route_prefixes: tuple[str, ...]
    sse_prefixes: tuple[str, ...]


PRESETS: dict[str, Preset] = {
    "vite-elysia": Preset(
        name="vite-elysia",
        description="Vite/React SPA frontend + Bun/Elysia backend API (Caddy split, PostgreSQL 18, blue/green)",
        topology="fullstack_split",
        runtime="bun_1_v1",
        database="postgresql_18",
        blue_green=True,
        spa_fallback=True,
        frontend_dir="frontend",
        entrypoint="backend/server.ts",
        frontend_runtime=None,
        frontend_entrypoint=None,
        health_path="/api/health",
        route_prefixes=("/api/",),
        sse_prefixes=("/api/events/",),
    ),
    "react-hono": Preset(
        name="react-hono",
        description="React/Vite SPA frontend + Node.js/Hono backend API (Caddy split, PostgreSQL 18, blue/green)",
        topology="fullstack_split",
        runtime="node_22_v1",
        database="postgresql_18",
        blue_green=True,
        spa_fallback=True,
        frontend_dir="frontend",
        entrypoint="backend/dist/index.mjs",
        frontend_runtime=None,
        frontend_entrypoint=None,
        health_path="/api/health",
        route_prefixes=("/api/",),
        sse_prefixes=(),
    ),
    "nextjs-standalone": Preset(
        name="nextjs-standalone",
        description="Next.js standalone SSR frontend + Node.js/Bun API (dual SSR, PostgreSQL 18, blue/green)",
        topology="fullstack_dual_ssr",
        runtime="node_22_v1",
        database="postgresql_18",
        blue_green=True,
        spa_fallback=False,
        frontend_dir=None,
        entrypoint="backend/server.mjs",
        frontend_runtime="node_22_v1",
        frontend_entrypoint="frontend/server.js",
        health_path="/api/health",
        route_prefixes=("/api/",),
        sse_prefixes=(),
    ),
    "astro-ssr": Preset(
        name="astro-ssr",
        description="Astro SSR Node.js app (single runtime, SQLite or PostgreSQL 18)",
        topology="backend_api",
        runtime="node_22_v1",
        database="sqlite",
        blue_green=True,
        spa_fallback=False,
        frontend_dir=None,
        entrypoint="dist/server/entry.mjs",
        frontend_runtime=None,
        frontend_entrypoint=None,
        health_path="/health",
        route_prefixes=("/",),
        sse_prefixes=(),
    ),
    "tanstack-start": Preset(
        name="tanstack-start",
        description="TanStack Start SSR frontend + Bun API backend (dual SSR, PostgreSQL 18, blue/green)",
        topology="fullstack_dual_ssr",
        runtime="bun_1_v1",
        database="postgresql_18",
        blue_green=True,
        spa_fallback=False,
        frontend_dir=None,
        entrypoint="backend/index.ts",
        frontend_runtime="bun_1_v1",
        frontend_entrypoint="frontend/server/index.mjs",
        health_path="/api/health",
        route_prefixes=("/api/",),
        sse_prefixes=("/api/events/",),
    ),
    "static-spa": Preset(
        name="static-spa",
        description="Pure static SPA (Vite/React/Astro static, zero daemon, Caddy HTTP/3 + SPA fallback)",
        topology="static_spa",
        runtime="static_v1",
        database="none",
        blue_green=False,
        spa_fallback=True,
        frontend_dir="frontend",
        entrypoint="",
        frontend_runtime=None,
        frontend_entrypoint=None,
        health_path="/",
        route_prefixes=(),
        sse_prefixes=(),
    ),
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def valid_release_id(value: str) -> bool:
    return bool(RELEASE_ID_RE.fullmatch(value)) and ".." not in value


def valid_site_id(value: str) -> bool:
    return bool(SITE_ID_RE.fullmatch(value))


def valid_rel_path(rel: str) -> bool:
    if not rel or len(rel) > MAX_PATH_BYTES or rel.startswith("/") or rel.endswith("/"):
        return False
    parts = rel.split("/")
    return all(part not in ("", ".", "..") and bool(SEGMENT_RE.fullmatch(part)) for part in parts)


def valid_manifest_path(rel: str) -> bool:
    if not rel or len(rel) > MAX_MANIFEST_PATH_BYTES or rel.startswith("/") or rel.endswith("/"):
        return False
    parts = rel.split("/")
    return all(
        part not in ("", ".", "..") and bool(MANIFEST_SEGMENT_RE.fullmatch(part)) for part in parts
    )


def valid_health_path(path: str) -> bool:
    return (
        bool(path)
        and len(path) <= 128
        and path.startswith("/")
        and ".." not in path
        and all(33 <= ord(ch) <= 126 for ch in path)
    )


def is_forbidden_env_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name == ".env" or (name.startswith(".env.") and name != ".env.example")


def collect_tree(src: Path, prefix: str, dest: dict[str, bytes], running_bytes: int) -> int:
    """Collect regular files from `src` under `prefix`, refusing unsafe entries."""
    if not src.is_dir() or src.is_symlink():
        raise Refused(f"source directory missing or symlink: {src}")
    if prefix and not valid_rel_path(prefix):
        raise Refused(f"unsafe bundle prefix: {prefix}")
    added = 0
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
            full_d = f"{prefix}/{rel_d}" if prefix else rel_d
            if not valid_manifest_path(full_d):
                raise Refused(f"unsafe directory path: {full_d}")
        for fname in sorted(filenames):
            fp = cur / fname
            st = fp.lstat()
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                raise Refused("symlink or special file inside release tree")
            if st.st_mode & 0o6000:
                raise Refused("setuid/setgid file refused")
            rel = fp.relative_to(src).as_posix()
            full = f"{prefix}/{rel}" if prefix else rel
            if is_forbidden_env_file(full):
                raise Refused(f"secret environment file refused in release tree: {full}")
            if not valid_manifest_path(full):
                raise Refused(f"unsafe file path: {full}")
            if full in dest:
                raise Refused(f"duplicate file path in bundle: {full}")
            raw = fp.read_bytes()
            running_bytes += len(raw)
            if running_bytes > MAX_TOTAL_BYTES:
                raise Refused("release exceeds maximum unpacked bytes (512 MiB)")
            dest[full] = raw
            added += 1
            if len(dest) > MAX_FILES:
                raise Refused("release exceeds maximum file count (50000)")
    if added == 0:
        raise Refused(f"source directory contains no files: {src}")
    return running_bytes


def write_deterministic_bundle(files: dict[str, bytes], out_dir: Path) -> dict:
    """Write byte-reproducible bundle.tar.gz and sorted manifest.sha256."""
    out_dir.mkdir(parents=True, exist_ok=True)
    if out_dir.is_symlink():
        raise Refused("output directory must not be a symlink")
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


def build_deploy_plan_argv(
    *,
    site_id: str,
    release_id: str,
    runtime: str,
    artifact_sha256: str,
    manifest_sha256: str,
    file_count: int,
    total_bytes: int,
    health_path: str,
    blue_green_cutover: bool,
    migration_entrypoint: str | None = None,
    capture_operation_id: str | None = None,
    host_id: str = "<HOST_ID>",
    host_epoch: str = "<HOST_EPOCH>",
    profile_digest: str = "<PROFILE_DIGEST_SHA256>",
    requester: str = "rustiron_coordinator",
    plan_id: str | None = None,
    valid_from: int = 1_700_000_000,
    expires_at: int = 1_700_003_600,
) -> list[str]:
    """Return exact `rustiron plan create app-deploy` argument vector."""
    pid = plan_id or f"plan_deploy_{site_id}_{release_id.replace('.', '_').replace('-', '_')}"
    argv = [
        "rustiron",
        "plan",
        "create",
        "app-deploy",
        "--plan-id",
        pid,
        "--host-id",
        host_id,
        "--host-epoch",
        host_epoch,
        "--profile-digest",
        profile_digest,
        "--requester",
        requester,
        "--site-id",
        site_id,
        "--release-id",
        release_id,
        "--runtime",
        runtime,
        "--artifact-sha256",
        artifact_sha256,
        "--manifest-sha256",
        manifest_sha256,
        "--file-count",
        str(file_count),
        "--total-bytes",
        str(total_bytes),
        "--health-path",
        health_path,
        "--valid-from",
        str(valid_from),
        "--expires-at",
        str(expires_at),
    ]
    if blue_green_cutover:
        argv.append("--blue-green-cutover")
    if migration_entrypoint:
        argv.extend(["--migration-entrypoint", migration_entrypoint])
    if capture_operation_id:
        argv.extend(["--capture-operation-id", capture_operation_id])
    return argv


def pack_release(
    *,
    site_id: str,
    release_id: str,
    out_dir: Path,
    topology: str,
    runtime: str,
    frontend_dist: Path | None = None,
    backend_dist: Path | None = None,
    frontend_dir: str | None = None,
    backend_prefix: str | None = None,
    entrypoint: str = "",
    frontend_runtime: str | None = None,
    frontend_entrypoint: str | None = None,
    worker_entrypoint: str | None = None,
    migration_entrypoint: str | None = None,
    capture_operation_id: str | None = None,
    health_path: str = "/",
    blue_green_cutover: bool = False,
    database: str = "none",
    preset_name: str | None = None,
) -> dict:
    """Validate inputs, collect trees, write deterministic artifacts, and emit deploy commands."""
    if not valid_site_id(site_id):
        raise Refused("invalid --site-id (expected lowercase ASCII letter + up to 19 alphanumerics)")
    if not valid_release_id(release_id):
        raise Refused("invalid --release-id (expected [a-z0-9][a-z0-9._-]{0,63}, no '..')")
    if topology not in VALID_TOPOLOGIES:
        raise Refused(f"unsupported --topology: {topology}")
    if runtime not in VALID_RUNTIMES:
        raise Refused(f"unsupported --runtime: {runtime}")
    if database not in VALID_DATABASES:
        raise Refused(f"unsupported --database: {database}")
    if not valid_health_path(health_path):
        raise Refused("invalid --health-path")
    if migration_entrypoint and not capture_operation_id:
        raise Refused("--migration-entrypoint requires --capture-operation-id for rollback safety")

    files: dict[str, bytes] = {}
    running_bytes = 0

    if topology == "static_spa":
        if runtime != "static_v1":
            raise Refused("static_spa requires --runtime static_v1")
        if blue_green_cutover:
            raise Refused("static_spa does not use --blue-green-cutover")
        if migration_entrypoint:
            raise Refused("static_spa does not run migrations")
        if frontend_dist is None:
            raise Refused("static_spa requires --frontend-dist")
        fdir = frontend_dir or "frontend"
        if not valid_rel_path(fdir):
            raise Refused(f"invalid --frontend-dir: {fdir}")
        running_bytes = collect_tree(frontend_dist, fdir, files, running_bytes)
        index_key = f"{fdir}/index.html"
        if index_key not in files:
            raise Refused(f"static_spa requires {index_key} inside --frontend-dist")
    elif topology == "backend_api":
        if runtime == "static_v1":
            raise Refused("backend_api requires --runtime bun_1_v1 or node_22_v1")
        if backend_dist is None:
            raise Refused("backend_api requires --backend-dist")
        bpref = backend_prefix or ""
        running_bytes = collect_tree(backend_dist, bpref, files, running_bytes)
        if not valid_rel_path(entrypoint) or entrypoint not in files:
            raise Refused(f"backend entrypoint missing from bundle: {entrypoint!r}")
    elif topology == "fullstack_split":
        if runtime == "static_v1":
            raise Refused("fullstack_split requires --runtime bun_1_v1 or node_22_v1")
        if frontend_dist is None or backend_dist is None:
            raise Refused("fullstack_split requires both --frontend-dist and --backend-dist")
        fdir = frontend_dir or "frontend"
        bpref = "backend" if backend_prefix is None else backend_prefix
        if not valid_rel_path(fdir):
            raise Refused(f"invalid --frontend-dir: {fdir}")
        if bpref == fdir:
            raise Refused("frontend and backend bundle prefixes must differ")
        running_bytes = collect_tree(frontend_dist, fdir, files, running_bytes)
        running_bytes = collect_tree(backend_dist, bpref, files, running_bytes)
        index_key = f"{fdir}/index.html"
        if index_key not in files:
            raise Refused(f"fullstack_split requires {index_key} inside --frontend-dist")
        if not valid_rel_path(entrypoint) or entrypoint not in files:
            raise Refused(f"backend entrypoint missing from bundle: {entrypoint!r}")
    elif topology == "fullstack_dual_ssr":
        if runtime == "static_v1":
            raise Refused("fullstack_dual_ssr requires --runtime bun_1_v1 or node_22_v1")
        if frontend_runtime not in ("bun_1_v1", "node_22_v1"):
            raise Refused("fullstack_dual_ssr requires --frontend-runtime bun_1_v1 or node_22_v1")
        if frontend_dist is None or backend_dist is None:
            raise Refused("fullstack_dual_ssr requires both --frontend-dist and --backend-dist")
        fdir = frontend_dir or "frontend"
        bpref = "backend" if backend_prefix is None else backend_prefix
        if bpref == fdir:
            raise Refused("frontend and backend bundle prefixes must differ")
        running_bytes = collect_tree(frontend_dist, fdir, files, running_bytes)
        running_bytes = collect_tree(backend_dist, bpref, files, running_bytes)
        if not valid_rel_path(entrypoint) or entrypoint not in files:
            raise Refused(f"backend entrypoint missing from bundle: {entrypoint!r}")
        if not frontend_entrypoint or not valid_rel_path(frontend_entrypoint) or frontend_entrypoint not in files:
            raise Refused(f"frontend SSR entrypoint missing from bundle: {frontend_entrypoint!r}")

    if worker_entrypoint is not None:
        if not valid_rel_path(worker_entrypoint) or worker_entrypoint not in files:
            raise Refused(f"worker entrypoint missing from bundle: {worker_entrypoint!r}")
    if migration_entrypoint is not None:
        if not valid_rel_path(migration_entrypoint) or migration_entrypoint not in files:
            raise Refused(f"migration entrypoint missing from bundle: {migration_entrypoint!r}")

    bundle_info = write_deterministic_bundle(files, out_dir)
    deploy_argv = build_deploy_plan_argv(
        site_id=site_id,
        release_id=release_id,
        runtime=runtime,
        artifact_sha256=bundle_info["artifact_sha256"],
        manifest_sha256=bundle_info["manifest_sha256"],
        file_count=bundle_info["file_count"],
        total_bytes=bundle_info["total_bytes"],
        health_path=health_path,
        blue_green_cutover=blue_green_cutover,
        migration_entrypoint=migration_entrypoint,
        capture_operation_id=capture_operation_id,
    )
    intake_dest = f"/var/lib/rustiron/app-intake/{site_id}/{release_id}"
    scp_command = (
        f"ssh root@<HOST> {shlex.quote(f'install -d -m 0700 {intake_dest}')} && "
        f"scp {shlex.quote(str(out_dir / 'bundle.tar.gz'))} "
        f"{shlex.quote(str(out_dir / 'manifest.sha256'))} "
        f"root@<HOST>:{shlex.quote(intake_dest + '/')}"
    )

    meta = {
        "schema": SCHEMA,
        "preset": preset_name,
        "site_id": site_id,
        "release_id": release_id,
        "topology": topology,
        "runtime": runtime,
        "database": database,
        "frontend_dir": frontend_dir if topology in ("static_spa", "fullstack_split") else None,
        "entrypoint": entrypoint,
        "frontend_runtime": frontend_runtime if topology == "fullstack_dual_ssr" else None,
        "frontend_entrypoint": frontend_entrypoint if topology == "fullstack_dual_ssr" else None,
        "worker_entrypoint": worker_entrypoint,
        "migration_entrypoint": migration_entrypoint,
        "capture_operation_id": capture_operation_id,
        "health_path": health_path,
        "blue_green_cutover": blue_green_cutover,
        **bundle_info,
        "intake_dir": intake_dest,
        "scp_command": scp_command,
        "deploy_plan_argv": deploy_argv,
        "deploy_plan_command": " ".join(shlex.quote(part) for part in deploy_argv),
    }
    (out_dir / "release-meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return meta


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_presets = sub.add_parser("presets", help="List built-in full-stack framework presets")
    p_presets.add_argument("--json", action="store_true", help="Print presets as JSON")

    p_pack = sub.add_parser("pack", help="Pack pre-built artifacts into a deterministic release")
    p_pack.add_argument("--preset", choices=sorted(PRESETS), default=None)
    p_pack.add_argument("--site-id", required=True)
    p_pack.add_argument("--release-id", required=True)
    p_pack.add_argument("--out", type=Path, required=True)
    p_pack.add_argument("--topology", choices=VALID_TOPOLOGIES, default=None)
    p_pack.add_argument("--runtime", choices=VALID_RUNTIMES, default=None)
    p_pack.add_argument("--database", choices=VALID_DATABASES, default=None)
    p_pack.add_argument("--frontend-dist", type=Path, default=None)
    p_pack.add_argument("--backend-dist", type=Path, default=None)
    p_pack.add_argument("--frontend-dir", default=None)
    p_pack.add_argument("--backend-prefix", default=None)
    p_pack.add_argument("--entrypoint", default=None)
    p_pack.add_argument("--frontend-runtime", choices=("bun_1_v1", "node_22_v1"), default=None)
    p_pack.add_argument("--frontend-entrypoint", default=None)
    p_pack.add_argument("--worker-entrypoint", default=None)
    p_pack.add_argument("--migration-entrypoint", default=None)
    p_pack.add_argument("--capture-operation-id", default=None)
    p_pack.add_argument("--health-path", default=None)
    p_pack.add_argument("--blue-green-cutover", action="store_true", default=None)
    p_pack.add_argument("--no-blue-green-cutover", action="store_true")
    p_pack.add_argument("--json", action="store_true", help="Print release-meta.json to stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "presets":
        if args.json:
            print(json.dumps({k: asdict(v) for k, v in PRESETS.items()}, indent=2, sort_keys=True))
        else:
            for preset in PRESETS.values():
                print(
                    f"{preset.name:18s}  topology={preset.topology:18s}  "
                    f"runtime={preset.runtime:10s}  db={preset.database:13s}  "
                    f"bg={preset.blue_green}"
                )
                print(f"                    {preset.description}")
        return 0

    preset = PRESETS[args.preset] if args.preset else None
    topology = args.topology or (preset.topology if preset else None)
    runtime = args.runtime or (preset.runtime if preset else None)
    if not topology or not runtime:
        print("REFUSED: pass --preset NAME or both --topology and --runtime", file=sys.stderr)
        return 1
    database = args.database or (preset.database if preset else "none")
    frontend_dir = args.frontend_dir or (preset.frontend_dir if preset else None)
    entrypoint = args.entrypoint if args.entrypoint is not None else (preset.entrypoint if preset else "")
    frontend_runtime = args.frontend_runtime or (preset.frontend_runtime if preset else None)
    frontend_entrypoint = args.frontend_entrypoint or (preset.frontend_entrypoint if preset else None)
    health_path = args.health_path or (preset.health_path if preset else "/")
    if args.no_blue_green_cutover:
        blue_green_cutover = False
    elif args.blue_green_cutover:
        blue_green_cutover = True
    else:
        blue_green_cutover = bool(preset.blue_green) if preset else False

    try:
        meta = pack_release(
            site_id=args.site_id,
            release_id=args.release_id,
            out_dir=args.out,
            topology=topology,
            runtime=runtime,
            frontend_dist=args.frontend_dist,
            backend_dist=args.backend_dist,
            frontend_dir=frontend_dir,
            backend_prefix=args.backend_prefix,
            entrypoint=entrypoint,
            frontend_runtime=frontend_runtime,
            frontend_entrypoint=frontend_entrypoint,
            worker_entrypoint=args.worker_entrypoint,
            migration_entrypoint=args.migration_entrypoint,
            capture_operation_id=args.capture_operation_id,
            health_path=health_path,
            blue_green_cutover=blue_green_cutover,
            database=database,
            preset_name=args.preset,
        )
    except Refused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(meta, indent=2, sort_keys=True))
    else:
        print(f"Packed {meta['site_id']} release {meta['release_id']} ({meta['topology']}, {meta['runtime']})")
        print(f"  artifact_sha256 : {meta['artifact_sha256']}")
        print(f"  manifest_sha256 : {meta['manifest_sha256']}")
        print(f"  files / bytes   : {meta['file_count']} files / {meta['total_bytes']} bytes")
        print(f"  stage command   : {meta['scp_command']}")
        print(f"  plan command    : {meta['deploy_plan_command']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
