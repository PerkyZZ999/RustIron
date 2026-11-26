#!/usr/bin/env python3
"""Prepare the LiteSpeed Cache page-cache recipe for the recipe store (W368).

    page-cache-recipe.py litespeed-cache.7.9.3.zip litespeed-cache.7.9.3.checksums.json OUTDIR

The operator fetches the plugin archive and the WordPress.org per-file
checksum list (docs/operator/09-PRODUCT-ENROLLMENT.md). This tool runs as
root with `python3 -I`, needs no network, and writes two files into OUTDIR:

- `litespeed-cache-7.9.3.tar`: an uncompressed ustar archive of exactly the
  listed files under `litespeed-cache/`, sorted, with fixed metadata (mode
  0644, mtime 0, owner 0:0, no names). The same input always gives the same
  bytes, so the executor can pin the archive SHA-256.
- `litespeed-cache-7.9.3.checksums.json`: the unchanged checksum list.

It refuses (exit 1) on any digest other than the reviewed pins, any member
outside `litespeed-cache/`, a link or other special member, a path outside
the closed name rule, and any file that is missing from, extra to, or
different from the list. The executor checks every unpacked file against the
list again. The plugin is GPL-2.0; Rustiron keeps only these digests.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import zipfile

PLUGIN = "litespeed-cache"
VERSION = "7.9.3"
# Measured on the W368 throwaway VM from downloads.wordpress.org, 2026-11-13 UTC.
ZIP_SHA256 = "8ab0373e41a3e9d4329d8fa6f99f3afd096cc21ac2befb0a84dc005d8afb36d7"
LIST_SHA256 = "41dc8e796d55435e69abefd7274c075c694c2a7f451084095be9bfd38112d982"
TAR_NAME = f"{PLUGIN}-{VERSION}.tar"
LIST_NAME = f"{PLUGIN}-{VERSION}.checksums.json"

MAX_FILES = 2000
MAX_PATH = 255
MAX_DEPTH = 16
MAX_FILE_BYTES = 8 * 1024 * 1024
COMPONENT = re.compile(r"[A-Za-z0-9._-]+")
HEX64 = re.compile(r"[0-9a-f]{64}")


class Refused(Exception):
    """A fixed refusal; the message never echoes archive content."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_path(path: str) -> bool:
    parts = path.split("/")
    return (0 < len(path) <= MAX_PATH and len(parts) <= MAX_DEPTH
            and all(COMPONENT.fullmatch(part) and part not in (".", "..") for part in parts))


def parse_list(list_bytes: bytes, plugin: str, version: str) -> dict[str, str]:
    try:
        listed = json.loads(list_bytes)
    except (ValueError, UnicodeDecodeError):
        raise Refused("checksum list is not JSON") from None
    if (not isinstance(listed, dict) or listed.get("plugin") != plugin
            or listed.get("version") != version or not isinstance(listed.get("files"), dict)):
        raise Refused("checksum list names another plugin or version")
    files = listed["files"]
    if not 0 < len(files) <= MAX_FILES:
        raise Refused("checksum list size")
    result = {}
    for path, sums in files.items():
        digest = sums.get("sha256") if isinstance(sums, dict) else None
        if not safe_path(path) or not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise Refused("checksum list entry")
        result[path] = digest
    return result


def convert(zip_bytes: bytes, list_bytes: bytes, *, zip_sha256: str, list_sha256: str,
            plugin: str = PLUGIN, version: str = VERSION) -> bytes:
    if sha256(zip_bytes) != zip_sha256:
        raise Refused("plugin archive digest differs from the pin")
    if sha256(list_bytes) != list_sha256:
        raise Refused("checksum list digest differs from the pin")
    listed = parse_list(list_bytes, plugin, version)
    prefix = plugin + "/"
    found: dict[str, bytes] = {}
    try:
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
        for info in archive.infolist():
            name = info.filename
            kind = stat.S_IFMT(info.external_attr >> 16)
            if not name.startswith(prefix):
                raise Refused("member outside the plugin folder")
            if info.is_dir():
                if kind not in (0, stat.S_IFDIR) or not safe_path(name[:-1]):
                    raise Refused("directory member")
                continue
            relative = name[len(prefix):]
            if kind not in (0, stat.S_IFREG) or not safe_path(relative) or relative in found:
                raise Refused("special, unsafe or repeated member")
            if info.file_size > MAX_FILE_BYTES:
                raise Refused("member too large")
            found[relative] = archive.read(info)
    except (zipfile.BadZipFile, OSError, RuntimeError):
        raise Refused("plugin archive unreadable") from None
    if set(found) != set(listed):
        raise Refused("archive files differ from the checksum list")
    if any(sha256(data) != listed[path] for path, data in found.items()):
        raise Refused("archive file differs from its listed SHA-256")
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:", format=tarfile.USTAR_FORMAT) as tar:
        for relative in sorted(found):
            data = found[relative]
            info = tarfile.TarInfo(prefix + relative)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.type = tarfile.REGTYPE
            tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o644)


def prepare(zip_path: Path, list_path: Path, out: Path, *, zip_sha256: str = ZIP_SHA256,
            list_sha256: str = LIST_SHA256) -> str:
    zip_bytes, list_bytes = zip_path.read_bytes(), list_path.read_bytes()
    tar_bytes = convert(zip_bytes, list_bytes, zip_sha256=zip_sha256, list_sha256=list_sha256)
    try:
        write_new(out / TAR_NAME, tar_bytes)
        write_new(out / LIST_NAME, list_bytes)
    except FileExistsError:
        raise Refused("output file exists") from None
    return sha256(tar_bytes)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("zip", type=Path)
    parser.add_argument("checksums", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    try:
        digest = prepare(args.zip, args.checksums, args.out)
    except (Refused, OSError) as error:
        print(f"REFUSED {error.__class__.__name__}: {error}", file=sys.stderr)
        return 1
    print(f"{digest}  {TAR_NAME}")
    print(f"{LIST_SHA256}  {LIST_NAME}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
