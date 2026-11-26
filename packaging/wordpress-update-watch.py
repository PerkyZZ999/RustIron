#!/usr/bin/env python3
"""Find and prepare WordPress updates on the operator PC (W531, D-087).

    wordpress-update-watch.py INVENTORY.json
    wordpress-update-watch.py INVENTORY.json --fetch OUTDIR

INVENTORY.json is the output of `rustiron-executor update-inventory SITE
--admin-helper` for one site. The tool asks WordPress.org's public APIs for
the newest release of the installed core (in the installed branch, for
example 7.1.x) and of each plugin and theme folder, and prints one JSON line
per component with a newer release. A folder that WordPress.org does not
serve is printed as `unknown`; a single-file plugin is skipped.

With --fetch, the tool downloads each newer release and its checksum list
into a new OUTDIR, then builds the recipes with wordpress-update-recipe.py:
OUTDIR/core/recipe.tar for core and OUTDIR/extensions/recipe.tar for the
plugins and themes (D-086: a core update names core only). For each recipe
it writes `components.txt`, the plan's `KIND SLUG FROM TO` lines in recipe
order. The owner reviews and signs each plan; nothing here has authority.

Every answer comes from WordPress.org over HTTPS, as for the recipe tool. A
newer core branch (for example 7.2 when 7.1 is installed) is reported as
`newer_branch` and not fetched: a branch change is the owner's decision.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import urllib.parse
import urllib.request

API = "https://api.wordpress.org"
DOWNLOADS = "https://downloads.wordpress.org"
CORE_DOWNLOADS = "https://wordpress.org"
AGENT = "rustiron-update-watch"
TIMEOUT = 60
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
VERSION = re.compile(r"[0-9][0-9A-Za-z.-]{0,31}")

RECIPE_TOOL = Path(__file__).resolve().parent / "wordpress-update-recipe.py"


class Refused(Exception):
    """A fixed refusal; the message never echoes remote content."""


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).scheme != "https":
            raise Refused("only HTTPS")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str, limit: int) -> bytes:
    """GET over HTTPS with a size limit and no HTTP/file redirects; anything else is a refusal."""
    if not url.startswith("https://"):
        raise Refused("only HTTPS")
    opener = urllib.request.build_opener(_HttpsOnlyRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": AGENT})
    try:
        with opener.open(request, timeout=TIMEOUT) as answer:
            data = answer.read(limit + 1)
    except OSError:
        raise Refused("fetch failed") from None
    if len(data) > limit:
        raise Refused("answer too large")
    return data


def fetch_json(url: str) -> object:
    try:
        return json.loads(fetch(url, MAX_JSON_BYTES))
    except (ValueError, UnicodeDecodeError):
        raise Refused("answer is not JSON") from None


def version_key(text: str) -> tuple | None:
    """Numeric dotted versions compare as numbers; others are not compared."""
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)*", text or ""):
        return None
    return tuple(int(part) for part in text.split("."))


def newer(installed: str, latest: str) -> bool | None:
    a, b = version_key(installed), version_key(latest)
    if a is None or b is None:
        return None
    width = max(len(a), len(b))
    return b + (0,) * (width - len(b)) > a + (0,) * (width - len(a))


def branch(version: str) -> str:
    return ".".join(version.split(".")[:2])


def core_status(installed: str, get=fetch_json) -> dict:
    """The newest release in the installed branch, and whether a newer
    branch exists."""
    offers = get(f"{API}/core/version-check/1.7/")
    versions = [offer.get("version") for offer in (offers or {}).get("offers", [])
                if isinstance(offer, dict) and isinstance(offer.get("version"), str)]
    same = [v for v in versions if branch(v) == branch(installed) and version_key(v)]
    best = max(same, key=version_key, default=None)
    status = {"kind": "core", "slug": "wordpress", "from": installed}
    if best and newer(installed, best):
        status.update(state="update", to=best)
    else:
        status.update(state="current")
    top = max((v for v in versions if version_key(v)), key=version_key, default=None)
    if top and branch(top) != branch(installed) and newer(installed, top):
        status["newer_branch"] = top
    return status


def extension_status(kind: str, slug: str, installed: str, get=fetch_json) -> dict:
    status = {"kind": kind, "slug": slug, "from": installed}
    if not SLUG.fullmatch(slug):
        status["state"] = "unknown"
        return status
    query = urllib.parse.urlencode({"action": f"{kind}_information", "request[slug]": slug})
    try:
        info = get(f"{API}/{kind}s/info/1.2/?{query}")
    except Refused:
        info = None
    latest = info.get("version") if isinstance(info, dict) else None
    if not isinstance(latest, str) or not VERSION.fullmatch(latest):
        status["state"] = "unknown"
    elif newer(installed, latest):
        status.update(state="update", to=latest)
    elif newer(installed, latest) is None and latest != installed:
        status.update(state="unknown", latest=latest)
    else:
        status["state"] = "current"
    return status


def statuses(inventory: dict, get=fetch_json) -> list[dict]:
    result = [core_status(inventory["core"]["version"], get)]
    for plugin in inventory.get("plugins", []):
        if plugin.get("folder"):
            result.append(extension_status("plugin", plugin["folder"], plugin["version"], get))
    for theme in inventory.get("themes", []):
        result.append(extension_status("theme", theme["folder"], theme["version"], get))
    return result


def recipe_tool():
    spec = importlib.util.spec_from_file_location("wordpress_update_recipe", RECIPE_TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def prepare(updates: list[dict], out: Path, get_bytes=fetch) -> list[Path]:
    """Downloads the releases into `out` and builds the recipes."""
    tool = recipe_tool()
    out.mkdir(mode=0o700)
    built = []
    core = [u for u in updates if u["kind"] == "core"]
    extensions = [u for u in updates if u["kind"] != "core"]
    groups = [("core", core), ("extensions", sorted(extensions, key=lambda u: u["kind"] != "plugin"))]
    for name, group in groups:
        if not group:
            continue
        folder = out / name
        folder.mkdir(mode=0o700)
        entries = []
        for update in group:
            kind, slug, version = update["kind"], update["slug"], update["to"]
            if kind == "core":
                archive = get_bytes(f"{CORE_DOWNLOADS}/wordpress-{version}.zip", MAX_ARCHIVE_BYTES)
                sha1 = get_bytes(f"{CORE_DOWNLOADS}/wordpress-{version}.zip.sha1", 1024)
                listing = get_bytes(f"{API}/core/checksums/1.0/?"
                                    + urllib.parse.urlencode({"version": version, "locale": "en_US"}),
                                    MAX_JSON_BYTES)
                entries.append(("core", "wordpress", version, archive, listing, sha1))
            elif kind == "plugin":
                archive = get_bytes(f"{DOWNLOADS}/plugin/{slug}.{version}.zip", MAX_ARCHIVE_BYTES)
                listing = get_bytes(f"{DOWNLOADS}/plugin-checksums/{slug}/{version}.json", MAX_JSON_BYTES)
                entries.append(("plugin", slug, version, archive, listing))
            else:
                archive = get_bytes(f"{DOWNLOADS}/theme/{slug}.{version}.zip", MAX_ARCHIVE_BYTES)
                entries.append(("theme", slug, version, archive, None))
        recipe, manifest = tool.build(entries)
        write_new(folder / tool.RECIPE_NAME, recipe)
        lines = "".join(f"{u['kind']} {u['slug']} {u['from']} {u['to']}\n" for u in group)
        write_new(folder / "components.txt", lines.encode())
        write_new(folder / "recipe_digest", (tool.sha256(manifest) + "\n").encode())
        built.append(folder)
    return built


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--fetch", type=Path, metavar="OUTDIR")
    args = parser.parse_args()
    try:
        inventory = json.loads(args.inventory.read_bytes())
        if not isinstance(inventory, dict) or not isinstance(inventory.get("core"), dict):
            raise Refused("not an update inventory")
        found = statuses(inventory)
        for status in found:
            print(json.dumps(status, sort_keys=True))
        updates = [s for s in found if s["state"] == "update"]
        if args.fetch is not None:
            for folder in prepare(updates, args.fetch):
                print(f"prepared {folder}")
    except (Refused, OSError, ValueError, KeyError) as error:
        print(f"REFUSED {error.__class__.__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
