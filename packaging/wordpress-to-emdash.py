#!/usr/bin/env python3
"""Offline WordPress WXR + captured media migration planner and verifier for EmDash (P30, D-096).

    wordpress-to-emdash.py plan --wxr EXPORT.xml --media-dir UPLOADS_DIR \\
        --source-origin https://old.example --target-origin https://new.example \\
        --out OUT_DIR [--capture-op OP_ID]

    wordpress-to-emdash.py verify --bundle OUT_DIR --base-url http://127.0.0.1:8090 \\
        [--host new.example] [--sqlite DB.sqlite]

Follows D-096:
- Uses only local WXR XML and captured media bytes (never fetches live URLs).
- Refuses (exit 1) if any referenced WXR attachment is missing from the captured
  media directory so silent content loss is impossible.
- Preserves exact publication states (publish, draft, private), authors,
  categories, and tags.
- Rewrites internal media and permalink URLs to EmDash routes and generates a
  deterministic 301 redirect map for every changed legacy URL.
- `verify` confirms content parity, draft non-leakage, media SHA-256 parity,
  zero unrewritten source links, and live 301 redirects against a target EmDash
  lab site.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

SCHEMA = "rustiron-wp-to-emdash/1"
NS = {
    "wp": "http://wordpress.org/export/1.2/",
    "content": "http://purl.org/rss/1.0/modules/content/",
    "excerpt": "http://wordpress.org/export/1.2/excerpt/",
    "dc": "http://purl.org/dc/elements/1.1/",
}


class MigrationError(Exception):
    """Explicit refusal or verification mismatch."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_origin(origin: str) -> str:
    parsed = urllib.parse.urlparse(origin.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise MigrationError(f"invalid origin URL: {origin!r}")
    return f"{parsed.scheme}://{parsed.netloc}"


def scan_media_dir(media_dir: Path) -> dict[str, dict]:
    """Hashes every regular file in media_dir; refuses symlinks and traversal."""
    if not media_dir.is_dir() or media_dir.is_symlink():
        raise MigrationError("media directory missing or symlink")
    found: dict[str, dict] = {}
    for dirpath, dirnames, filenames in os.walk(media_dir, followlinks=False):
        dirnames.sort()
        cur = Path(dirpath)
        for d in dirnames:
            if stat.S_ISLNK((cur / d).lstat().st_mode):
                raise MigrationError("symlink directory inside media capture")
        for f in sorted(filenames):
            p = cur / f
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                raise MigrationError("symlink or non-regular file inside media capture")
            rel = p.relative_to(media_dir).as_posix()
            raw = p.read_bytes()
            found[rel] = {"path": rel, "sha256": sha256_bytes(raw), "bytes": len(raw)}
    return found


def uploads_relative_path(url: str) -> str | None:
    parsed = urllib.parse.urlparse(url.strip())
    marker = "/wp-content/uploads/"
    if marker not in parsed.path:
        return None
    rel = parsed.path.split(marker, 1)[1].lstrip("/")
    parts = rel.split("/")
    if not rel or any(part in ("", ".", "..") for part in parts):
        return None
    return rel


def text_of(elem: ET.Element, tag: str) -> str:
    child = elem.find(tag, NS)
    return (child.text or "").strip() if child is not None else ""


def raw_text_of(elem: ET.Element, tag: str) -> str:
    child = elem.find(tag, NS)
    return (child.text or "") if child is not None else ""


def emdash_path(post_type: str, slug: str) -> str:
    clean = slug.strip("/") or "untitled"
    if post_type == "page":
        return f"/{clean}"
    return f"/posts/{clean}"


def plan_migration(
    wxr_path: Path,
    media_dir: Path,
    source_origin: str,
    target_origin: str,
    out_dir: Path,
    capture_op: str | None = None,
) -> dict:
    src_origin = normalize_origin(source_origin)
    dst_origin = normalize_origin(target_origin)
    if not wxr_path.is_file() or wxr_path.is_symlink():
        raise MigrationError("WXR file missing or symlink")
    wxr_bytes = wxr_path.read_bytes()
    wxr_sha = sha256_bytes(wxr_bytes)
    media_files = scan_media_dir(media_dir)

    try:
        root = ET.fromstring(wxr_bytes)
    except ET.ParseError as exc:
        raise MigrationError(f"invalid WXR XML: {exc}") from exc

    channel = root.find("channel")
    if channel is None:
        raise MigrationError("WXR missing <channel>")

    authors = []
    for author in channel.findall("wp:author", NS):
        login = text_of(author, "wp:author_login")
        if login:
            authors.append(
                {
                    "login": login,
                    "display_name": text_of(author, "wp:author_display_name") or login,
                }
            )
    authors.sort(key=lambda a: a["login"])

    items = channel.findall("item")
    attachments = []
    missing_media = []
    raw_content = []
    permalink_map: dict[str, str] = {}

    for item in items:
        post_type = text_of(item, "wp:post_type")
        status = text_of(item, "wp:status") or "draft"
        title = text_of(item, "title")
        slug = text_of(item, "wp:post_name")
        link = text_of(item, "link")
        if post_type == "attachment":
            att_url = text_of(item, "wp:attachment_url") or link
            rel = uploads_relative_path(att_url)
            if rel is None or rel not in media_files:
                missing_media.append({"title": title, "url": att_url, "expected_rel": rel})
            else:
                entry = media_files[rel]
                attachments.append(
                    {
                        "title": title,
                        "source_url": att_url,
                        "rel_path": rel,
                        "target_path": f"/media/{rel}",
                        "sha256": entry["sha256"],
                        "bytes": entry["bytes"],
                    }
                )
        elif post_type in ("post", "page"):
            categories = []
            tags = []
            for cat in item.findall("category"):
                domain = cat.attrib.get("domain", "")
                nicename = cat.attrib.get("nicename", "").strip()
                label = (cat.text or "").strip()
                if domain == "category" and nicename:
                    categories.append({"slug": nicename, "name": label or nicename})
                elif domain == "post_tag" and nicename:
                    tags.append({"slug": nicename, "name": label or nicename})
            new_path = emdash_path(post_type, slug or title.lower().replace(" ", "-"))
            old_parsed = urllib.parse.urlparse(link)
            old_path = old_parsed.path or "/"
            if status == "publish" and old_path != new_path:
                permalink_map[old_path] = new_path
                if old_path.endswith("/") and len(old_path) > 1:
                    trimmed = old_path.rstrip("/")
                    if trimmed != new_path:
                        permalink_map[trimmed] = new_path
            raw_content.append(
                {
                    "type": post_type,
                    "status": status,
                    "title": title,
                    "slug": slug,
                    "author": text_of(item, "dc:creator"),
                    "published_at": text_of(item, "wp:post_date_gmt"),
                    "source_path": old_path,
                    "target_path": new_path,
                    "categories": sorted(categories, key=lambda c: c["slug"]),
                    "tags": sorted(tags, key=lambda t: t["slug"]),
                    "body": raw_text_of(item, "content:encoded"),
                    "excerpt": raw_text_of(item, "excerpt:encoded"),
                }
            )

    if missing_media:
        raise MigrationError(
            f"{len(missing_media)} WXR attachment(s) missing from captured media: "
            + ", ".join(m["url"] for m in missing_media)
        )

    # Rewrite media URLs and internal links deterministically.
    rewritten_links = 0
    src_uploads = f"{src_origin}/wp-content/uploads/"
    dst_media = f"{dst_origin}/media/"

    def rewrite_text(text: str) -> str:
        nonlocal rewritten_links
        if src_uploads in text:
            count = text.count(src_uploads)
            text = text.replace(src_uploads, dst_media)
            rewritten_links += count
        # Rewrite internal links matching known source permalinks (longest first).
        for old_p in sorted(permalink_map, key=len, reverse=True):
            old_full = f"{src_origin}{old_p}"
            new_full = f"{dst_origin}{permalink_map[old_p]}"
            if old_full in text:
                rewritten_links += text.count(old_full)
                text = text.replace(old_full, new_full)
        return text

    for doc in raw_content:
        doc["body"] = rewrite_text(doc["body"])
        doc["excerpt"] = rewrite_text(doc["excerpt"])

    redirects = [
        {"from": src_p, "to": dst_p, "status": 301}
        for src_p, dst_p in sorted(permalink_map.items())
    ]
    attachments.sort(key=lambda a: a["rel_path"])

    out_dir.mkdir(parents=True, exist_ok=True)
    content_bytes = (json.dumps({"authors": authors, "items": raw_content}, indent=2, sort_keys=True) + "\n").encode()
    media_bytes = (json.dumps({"attachments": attachments}, indent=2, sort_keys=True) + "\n").encode()
    redirects_bytes = (json.dumps({"redirects": redirects}, indent=2, sort_keys=True) + "\n").encode()

    (out_dir / "content.json").write_bytes(content_bytes)
    (out_dir / "media-index.json").write_bytes(media_bytes)
    (out_dir / "redirects.json").write_bytes(redirects_bytes)

    counts = {
        "posts": sum(1 for d in raw_content if d["type"] == "post"),
        "pages": sum(1 for d in raw_content if d["type"] == "page"),
        "published": sum(1 for d in raw_content if d["status"] == "publish"),
        "drafts": sum(1 for d in raw_content if d["status"] != "publish"),
        "authors": len(authors),
        "attachments": len(attachments),
        "rewritten_links": rewritten_links,
        "redirects": len(redirects),
    }
    manifest = {
        "schema": SCHEMA,
        "source_origin": src_origin,
        "target_origin": dst_origin,
        "capture_operation_id": capture_op,
        "wxr_sha256": wxr_sha,
        "content_sha256": sha256_bytes(content_bytes),
        "media_index_sha256": sha256_bytes(media_bytes),
        "redirects_sha256": sha256_bytes(redirects_bytes),
        "counts": counts,
    }
    (out_dir / "migration-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_get(base_url: str, path: str, host_header: str | None) -> tuple[int, dict[str, str], bytes]:
    url = base_url.rstrip("/") + path
    req = urllib.request.Request(url, method="GET")
    if host_header:
        req.add_header("Host", host_header)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=5) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, resp.read()
    except urllib.error.HTTPError as err:
        try:
            headers = {k.lower(): v for k, v in err.headers.items()}
            return err.code, headers, err.read()
        finally:
            err.close()


def verify_migration(
    bundle_dir: Path,
    base_url: str,
    host_header: str | None = None,
    sqlite_path: Path | None = None,
) -> dict:
    manifest = json.loads((bundle_dir / "migration-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != SCHEMA:
        raise MigrationError("bundle schema mismatch")
    content = json.loads((bundle_dir / "content.json").read_text(encoding="utf-8"))
    media = json.loads((bundle_dir / "media-index.json").read_text(encoding="utf-8"))
    redirects = json.loads((bundle_dir / "redirects.json").read_text(encoding="utf-8"))
    src_origin = manifest["source_origin"]

    failures: list[str] = []
    checked = {"published": 0, "drafts": 0, "media": 0, "redirects": 0, "sqlite_rows": 0}

    for doc in content["items"]:
        code, _hdrs, body = http_get(base_url, doc["target_path"], host_header)
        text = body.decode("utf-8", errors="replace")
        if doc["status"] == "publish":
            if code != 200 or doc["title"] not in text:
                failures.append(f"published {doc['target_path']} expected 200 with title, got {code}")
            elif src_origin in text:
                failures.append(f"unrewritten source origin found in {doc['target_path']}")
            else:
                checked["published"] += 1
        else:
            if code == 200:
                failures.append(f"unpublished {doc['target_path']} ({doc['status']}) leaked HTTP 200")
            else:
                checked["drafts"] += 1

    for att in media["attachments"]:
        code, _hdrs, body = http_get(base_url, att["target_path"], host_header)
        if code != 200 or sha256_bytes(body) != att["sha256"]:
            failures.append(f"media {att['target_path']} mismatch (status={code})")
        else:
            checked["media"] += 1

    for redir in redirects["redirects"]:
        code, hdrs, _body = http_get(base_url, redir["from"], host_header)
        loc = hdrs.get("location", "")
        if code != redir["status"] or not (loc == redir["to"] or loc.endswith(redir["to"])):
            failures.append(f"redirect {redir['from']} expected {redir['status']} -> {redir['to']}, got {code} -> {loc}")
        else:
            checked["redirects"] += 1

    if sqlite_path is not None:
        con = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
        try:
            rows = con.execute("SELECT slug, status FROM content ORDER BY slug").fetchall()
            expected = sorted((d["slug"], d["status"]) for d in content["items"])
            if rows != expected:
                failures.append(f"sqlite content mismatch: got {rows!r}, expected {expected!r}")
            else:
                checked["sqlite_rows"] = len(rows)
        finally:
            con.close()

    result = {"ok": not failures, "checked": checked, "failures": failures}
    if failures:
        raise MigrationError(json.dumps(result, sort_keys=True))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_plan = sub.add_parser("plan")
    p_plan.add_argument("--wxr", type=Path, required=True)
    p_plan.add_argument("--media-dir", type=Path, required=True)
    p_plan.add_argument("--source-origin", required=True)
    p_plan.add_argument("--target-origin", required=True)
    p_plan.add_argument("--out", type=Path, required=True)
    p_plan.add_argument("--capture-op", default=None)

    p_ver = sub.add_parser("verify")
    p_ver.add_argument("--bundle", type=Path, required=True)
    p_ver.add_argument("--base-url", required=True)
    p_ver.add_argument("--host", default=None)
    p_ver.add_argument("--sqlite", type=Path, default=None)

    args = parser.parse_args()
    try:
        if args.cmd == "plan":
            res = plan_migration(
                args.wxr,
                args.media_dir,
                args.source_origin,
                args.target_origin,
                args.out,
                args.capture_op,
            )
        else:
            res = verify_migration(args.bundle, args.base_url, args.host, args.sqlite)
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0
    except MigrationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
