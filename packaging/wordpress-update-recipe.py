#!/usr/bin/env python3
"""Prepare a D-084 WordPress update recipe on the operator PC (W513).

    wordpress-update-recipe.py OUTDIR \\
        --plugin SLUG VERSION SLUG.VERSION.zip SLUG.VERSION.checksums.json \\
        --theme SLUG VERSION SLUG.VERSION.zip
    wordpress-update-recipe.py OUTDIR \\
        --core VERSION wordpress-VERSION.zip wordpress-VERSION.zip.sha1 core-VERSION.json

The operator fetches each release archive from downloads.wordpress.org and,
for a plugin, its per-file checksum list from
downloads.wordpress.org/plugin-checksums/SLUG/VERSION.json. This tool needs
no network. It writes OUTDIR/recipe.tar, an uncompressed ustar archive with
fixed metadata (mode 0644, mtime 0, owner 0:0, no names), so the same input
always gives the same bytes:

- `manifest`: `rustiron-wordpress-update/1`, then one line per component in
  the given order: `<kind> <slug> <version> <archive sha256> <files sha256>`.
  The plan's `recipe_digest` is the SHA-256 of these bytes.
- `<kind>-<slug>.files`: one `<sha256>  <path>` line per file, sorted.
- `<kind>/<slug>/<path>`: each file of the release.

A plugin's files must equal its WordPress.org checksum list, which must name
the same plugin and version. A theme's `style.css` must state the version.

W525 (D-086): a core update is one `core wordpress VERSION` component and
nothing else. The operator also fetches the archive's published SHA-1
(wordpress.org/wordpress-VERSION.zip.sha1; W528-F1: WordPress.org publishes
no SHA-256 for core, and the `.sha256` address serves the archive itself)
and the per-file MD5 list
(api.wordpress.org/core/checksums/1.0/?version=VERSION&locale=en_US). The
archive must match the SHA-1. Both are weak digests that only check the
archive is WordPress.org's release as fetched over HTTPS; the recipe then
pins every file's SHA-256, which the signed plan binds. Every file under `wordpress/` except
`wp-content/` is taken; those files must equal the list's entries outside
`wp-content/`, and `wp-includes/version.php` must state the version.
It refuses (exit 1) on a link or special member, a member outside the
release folder, a path outside the closed name rule, and size limits. The
releases are GPL; Rustiron keeps no release file (D-014).
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

SCHEMA = "rustiron-wordpress-update/1"
RECIPE_NAME = "recipe.tar"
MAX_COMPONENTS = 8
MAX_FILES = 5000
MAX_PATH = 255
MAX_DEPTH = 16
# The executor reads at most this per file. W528-F2: WordPress 7.1.4 core
# ships a 13.4 MB file (wp-includes/js/dist/script-modules/vips/worker.min.js).
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_RECIPE_BYTES = 256 * 1024 * 1024
SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
VERSION = re.compile(r"[0-9][0-9A-Za-z.-]{0,31}")
# W518-F1: release files use `@` (`logo@2x.png`) and `,` (variable-font
# names). Spaces stay refused: the per-file list separates with two spaces.
COMPONENT = re.compile(r"[A-Za-z0-9._@,+~-]+")
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX40 = re.compile(r"[0-9a-f]{40}")
CORE_SLUG = "wordpress"
CORE_SKIPPED = "wp-content/"
CORE_VERSION = re.compile(rb"^\$wp_version\s*=\s*'([^'\r\n]*)';", re.MULTILINE)
THEME_VERSION = re.compile(rb"^[ \t/*#@]*Version:[ \t]*([^\r\n]*?)[ \t]*\r?$", re.MULTILINE | re.IGNORECASE)


class Refused(Exception):
    """A fixed refusal; the message never echoes archive content."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_path(path: str) -> bool:
    parts = path.split("/")
    return (0 < len(path) <= MAX_PATH and len(parts) <= MAX_DEPTH
            and all(COMPONENT.fullmatch(part) and part not in (".", "..") for part in parts))


def release_files(zip_bytes: bytes, slug: str, skipped: str | None = None) -> dict[str, bytes]:
    """Every regular file below `<slug>/`, by its path inside the folder,
    except those below `<slug>/<skipped>` (core's `wp-content/`)."""
    prefix = slug + "/"
    found: dict[str, bytes] = {}
    try:
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
        for info in archive.infolist():
            name = info.filename
            kind = stat.S_IFMT(info.external_attr >> 16)
            if not name.startswith(prefix):
                raise Refused("member outside the release folder")
            if skipped is not None and (name[len(prefix):] + "/").startswith(skipped):
                continue
            if info.is_dir():
                if kind not in (0, stat.S_IFDIR) or (name != prefix and not safe_path(name[len(prefix):-1])):
                    raise Refused("directory member")
                continue
            relative = name[len(prefix):]
            if kind not in (0, stat.S_IFREG) or not safe_path(relative) or relative in found:
                raise Refused("special, unsafe or repeated member")
            if info.file_size > MAX_FILE_BYTES:
                raise Refused("member too large")
            found[relative] = archive.read(info)
            if len(found) > MAX_FILES:
                raise Refused("too many files")
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
        raise Refused("release archive unreadable") from None
    if not found:
        raise Refused("release archive is empty")
    return found


def plugin_list(list_bytes: bytes, slug: str, version: str) -> dict[str, str]:
    try:
        listed = json.loads(list_bytes)
    except (ValueError, UnicodeDecodeError):
        raise Refused("checksum list is not JSON") from None
    if (not isinstance(listed, dict) or listed.get("plugin") != slug
            or listed.get("version") != version or not isinstance(listed.get("files"), dict)):
        raise Refused("checksum list names another plugin or version")
    result = {}
    for path, sums in listed["files"].items():
        digest = sums.get("sha256") if isinstance(sums, dict) else None
        if not safe_path(path) or not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise Refused("checksum list entry")
        result[path] = digest
    return result


def core_list(list_bytes: bytes, version: str) -> dict[str, str]:
    """W525: the per-file MD5 list of a core release, outside `wp-content/`."""
    try:
        listed = json.loads(list_bytes)
    except (ValueError, UnicodeDecodeError):
        raise Refused("checksum list is not JSON") from None
    files = listed.get("checksums") if isinstance(listed, dict) else None
    # The API nests the list under the version when asked without a locale.
    if isinstance(files, dict) and set(files) == {version} and isinstance(files[version], dict):
        files = files[version]
    if not isinstance(files, dict) or not files:
        raise Refused("checksum list has no files")
    result = {}
    for path, digest in files.items():
        if not isinstance(path, str) or not isinstance(digest, str) or not HEX32.fullmatch(digest):
            raise Refused("checksum list entry")
        if path.startswith(CORE_SKIPPED):
            continue
        if not safe_path(path):
            raise Refused("checksum list entry")
        result[path] = digest
    return result


def core_version(files: dict[str, bytes]) -> str | None:
    version = files.get("wp-includes/version.php")
    if version is None:
        return None
    match = CORE_VERSION.search(version[:65536])
    return match.group(1).decode("ascii", "replace") if match else None


def theme_version(files: dict[str, bytes]) -> str | None:
    style = files.get("style.css")
    if style is None:
        return None
    match = THEME_VERSION.search(style[:8192])
    return match.group(1).decode("ascii", "replace") if match else None


def component(kind: str, slug: str, version: str, zip_bytes: bytes,
              list_bytes: bytes | None,
              published: bytes | None = None) -> tuple[str, dict[str, bytes], bytes]:
    """The manifest line, the files, and the `.files` list of one component."""
    if kind not in ("plugin", "theme", "core"):
        raise Refused("component kind")
    if not SLUG.fullmatch(slug) or not VERSION.fullmatch(version) or ".." in version:
        raise Refused("slug or version outside the closed rule")
    if (kind == "core") != (published is not None):
        raise Refused("only core has a published archive digest")
    if kind == "core":
        files = core_component(slug, version, zip_bytes, list_bytes, published)
    elif kind == "plugin":
        files = release_files(zip_bytes, slug)
        if list_bytes is None:
            raise Refused("a plugin needs its checksum list")
        listed = plugin_list(list_bytes, slug, version)
        if set(files) != set(listed):
            raise Refused("archive files differ from the checksum list")
        if any(sha256(data) != listed[path] for path, data in files.items()):
            raise Refused("archive file differs from its listed SHA-256")
    else:
        files = release_files(zip_bytes, slug)
        if list_bytes is not None:
            raise Refused("a theme has no checksum list")
        if theme_version(files) != version:
            raise Refused("style.css states another version")
    listing = "".join(f"{sha256(files[path])}  {path}\n" for path in sorted(files)).encode()
    line = f"{kind} {slug} {version} {sha256(zip_bytes)} {sha256(listing)}"
    return line, files, listing


def core_component(slug: str, version: str, zip_bytes: bytes, list_bytes: bytes | None,
                   published: bytes) -> dict[str, bytes]:
    """W525 (D-086): a core release, checked against its published archive
    SHA-1 (W528-F1) and its per-file MD5 list; `wp-content/` is left out."""
    if slug != CORE_SLUG:
        raise Refused("core slug")
    words = published.decode("ascii", "replace").split()
    published_sha1 = words[0].lower() if words else ""
    if (not HEX40.fullmatch(published_sha1)
            or published_sha1 != hashlib.sha1(zip_bytes, usedforsecurity=False).hexdigest()):
        raise Refused("archive differs from its published SHA-1")
    if list_bytes is None:
        raise Refused("core needs its checksum list")
    listed = core_list(list_bytes, version)
    files = release_files(zip_bytes, slug, CORE_SKIPPED)
    if set(files) != set(listed):
        raise Refused("archive files differ from the checksum list")
    if any(hashlib.md5(data, usedforsecurity=False).hexdigest() != listed[path]
           for path, data in files.items()):
        raise Refused("archive file differs from its listed MD5")
    if core_version(files) != version:
        raise Refused("version.php states another version")
    return files


def regular(name: str, data: bytes) -> tuple[tarfile.TarInfo, io.BytesIO]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.type = tarfile.REGTYPE
    return info, io.BytesIO(data)


def build(components: list[tuple]) -> tuple[bytes, bytes]:
    """The recipe archive bytes and its manifest bytes."""
    if not 0 < len(components) <= MAX_COMPONENTS:
        raise Refused("component count")
    names = [(kind, slug) for kind, slug, *_ in components]
    if len(set(names)) != len(names):
        raise Refused("a component is named twice")
    if any(kind == "core" for kind, _ in names) and len(names) != 1:
        raise Refused("a core update names core only")
    built = [component(*entry) for entry in components]
    manifest = (SCHEMA + "\n" + "".join(line + "\n" for line, _, _ in built)).encode()
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:", format=tarfile.USTAR_FORMAT) as tar:
        tar.addfile(*regular("manifest", manifest))
        for (kind, slug, *_), (_, files, listing) in zip(components, built):
            tar.addfile(*regular(f"{kind}-{slug}.files", listing))
            for path in sorted(files):
                tar.addfile(*regular(f"{kind}/{slug}/{path}", files[path]))
    recipe = out.getvalue()
    if len(recipe) > MAX_RECIPE_BYTES:
        raise Refused("recipe too large")
    return recipe, manifest


def write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out", type=Path)
    parser.add_argument("--plugin", nargs=4, action="append", default=[],
                        metavar=("SLUG", "VERSION", "ZIP", "CHECKSUMS"))
    parser.add_argument("--theme", nargs=3, action="append", default=[],
                        metavar=("SLUG", "VERSION", "ZIP"))
    parser.add_argument("--core", nargs=4, action="append", default=[],
                        metavar=("VERSION", "ZIP", "ZIP_SHA1", "CHECKSUMS"))
    args = parser.parse_args()
    try:
        entries = [("plugin", slug, version, Path(archive).read_bytes(), Path(listing).read_bytes())
                   for slug, version, archive, listing in args.plugin]
        entries += [("theme", slug, version, Path(archive).read_bytes(), None)
                    for slug, version, archive in args.theme]
        entries += [("core", CORE_SLUG, version, Path(archive).read_bytes(), Path(listing).read_bytes(),
                     Path(published).read_bytes())
                    for version, archive, published, listing in args.core]
        recipe, manifest = build(entries)
        write_new(args.out / RECIPE_NAME, recipe)
    except FileExistsError:
        print("REFUSED: the recipe file exists", file=sys.stderr)
        return 1
    except (Refused, OSError) as error:
        print(f"REFUSED {error.__class__.__name__}: {error}", file=sys.stderr)
        return 1
    print(f"recipe_digest {sha256(manifest)}")
    print(f"recipe_sha256 {sha256(recipe)}  {RECIPE_NAME}")
    sys.stdout.write(manifest.decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
