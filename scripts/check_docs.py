#!/usr/bin/env python3
"""Check documentation links, instruction imports and preserved report hashes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parent.parent
OPUS_SHA256 = "aac7823697c171e6887e02b0d328af8dc17576b84129c1af27bb6f5904db364e"


def slugify_heading(raw: str) -> str:
    """Compute a GitHub-style Markdown heading anchor slug."""
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", raw)
    text = text.replace("`", "")
    text = re.sub(r"(\*\*|__|~~)", "", text)
    text = re.sub(r"(?<!\w)\*|\*(?!\w)", "", text)
    text = text.strip().lower()
    kept = [ch for ch in text if ch.isalnum() or ch in (" ", "-", "_")]
    return "".join(kept).replace(" ", "-")


def collect_heading_anchors(path: Path) -> set[str]:
    """Collect deduplicated GitHub-style heading anchors from a Markdown file."""
    counts: dict[str, int] = {}
    anchors: set[str] = set()
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if not match:
            continue
        base = slugify_heading(match.group(1))
        if not base:
            continue
        seen = counts.get(base, 0)
        counts[base] = seen + 1
        anchors.add(base if seen == 0 else f"{base}-{seen}")
    return anchors


def check_document(
    path: Path,
    errors: list[str],
    anchor_cache: dict[Path, set[str]] | None = None,
) -> int:
    content = path.read_text(encoding="utf-8")
    if content.count("```") % 2:
        errors.append(f"{path.relative_to(ROOT)}: unbalanced code fences")
    for number, line in enumerate(content.splitlines(), start=1):
        trailing = line[len(line.rstrip(" \t")) :]
        if trailing and trailing != "  ":
            errors.append(f"{path.relative_to(ROOT)}:{number}: accidental trailing whitespace")
    cache = anchor_cache if anchor_cache is not None else {}
    count = 0
    for match in re.finditer(r"\]\(([^)]+)\)", content):
        target = match.group(1).strip().strip("<>")
        if re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", target):
            continue
        raw_path, has_frag, raw_frag = target.partition("#")
        fragment = unquote(raw_frag).strip().lower() if has_frag else ""
        if target.startswith("#"):
            if not fragment:
                continue
            count += 1
            resolved = path.resolve()
            if resolved not in cache:
                cache[resolved] = collect_heading_anchors(resolved)
            if fragment not in cache[resolved]:
                line = content.count("\n", 0, match.start()) + 1
                errors.append(f"{path.relative_to(ROOT)}:{line}: missing anchor #{raw_frag}")
            continue
        relative = re.sub(r":\d+(?:-\d+)?$", "", unquote(raw_path))
        if not relative:
            continue
        count += 1
        candidate = Path(relative) if relative.startswith("/") else (path.parent / relative)
        if not candidate.exists():
            line = content.count("\n", 0, match.start()) + 1
            errors.append(f"{path.relative_to(ROOT)}:{line}: missing {target}")
            continue
        if fragment and candidate.is_file() and candidate.suffix.lower() == ".md":
            resolved = candidate.resolve()
            if resolved not in cache:
                cache[resolved] = collect_heading_anchors(resolved)
            if fragment not in cache[resolved]:
                line = content.count("\n", 0, match.start()) + 1
                errors.append(f"{path.relative_to(ROOT)}:{line}: missing anchor {target}")
    return count


def check_preserved_documents(errors: list[str]) -> int:
    manifest = json.loads(
        (ROOT / "docs/maintenance/DOCUMENT-MOVES.json").read_text(encoding="utf-8")
    )
    origins: set[str] = set()
    destinations: set[str] = set()
    preserved = 0
    for entry in manifest["moves"]:
        old, new = entry["from"], entry["to"]
        if old in origins or new in destinations:
            errors.append(f"duplicate relocation: {old} -> {new}")
        origins.add(old)
        destinations.add(new)
        path = ROOT / new
        if not path.is_file():
            errors.append(f"missing relocation target: {new}")
            continue
        expected = entry.get("preserved_sha256")
        if expected:
            preserved += 1
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                errors.append(f"preserved document changed: {new}")
    opus = ROOT / "docs/feasibility/g0/G0_OPUS_SYSTEMS_REPORT.md"
    if hashlib.sha256(opus.read_bytes()).hexdigest() != OPUS_SHA256:
        errors.append("original Opus report hash mismatch")
    return preserved


def luminance(color: str) -> float:
    channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [
        value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
        for value in channels
    ]
    return sum(value * weight for value, weight in zip(linear, (0.2126, 0.7152, 0.0722)))


def check_design_contrast(errors: list[str]) -> int:
    """Check this candidate's solid hex roles; official lint owns YAML/schema validation."""
    path = ROOT / "docs/DESIGN.md"
    if not path.exists():
        return 0
    block = re.search(
        r"^colors:\n((?:  .*\n)+)", path.read_text(encoding="utf-8"), re.MULTILINE
    )
    if block is None:
        errors.append("DESIGN.md: missing flat color roles for contrast checks")
        return 0
    colors = dict(
        re.findall(r'^  ([a-z0-9-]+): "(#[0-9A-Fa-f]{6})"$', block.group(1), re.MULTILINE)
    )
    pairs: list[tuple[str, str, float]] = []
    for theme in ("light", "dark"):
        for surface in ("canvas", "surface", "subtle"):
            for text in ("text", "muted"):
                pairs.append((f"{theme}-{text}", f"{theme}-{surface}", 4.5))
            for control in ("focus", "border-strong"):
                pairs.append((f"{theme}-{control}", f"{theme}-{surface}", 3.0))
        for action in ("action", "action-hover"):
            pairs.append((f"{theme}-on-action", f"{theme}-{action}", 4.5))
        pairs.append((f"{theme}-warning", f"{theme}-warning-surface", 4.5))
        for state in ("success", "warning", "error"):
            pairs.append((f"{theme}-{state}", f"{theme}-surface", 4.5))
        for series in ("cpu", "memory", "disk"):
            pairs.append((f"{theme}-{series}", f"{theme}-surface", 3.0))
    pairs.extend(
        [("light-focus", "light-selection", 4.5), ("dark-text", "dark-selection", 4.5)]
    )
    for foreground, background, minimum in pairs:
        if foreground not in colors or background not in colors:
            errors.append(f"DESIGN.md: missing solid role {foreground} or {background}")
            continue
        values = sorted((luminance(colors[foreground]), luminance(colors[background])))
        ratio = (values[1] + 0.05) / (values[0] + 0.05)
        if ratio < minimum:
            errors.append(f"DESIGN.md: {foreground} on {background}: {ratio:.2f}:1 < {minimum}:1")
    return len(pairs)


def main() -> int:
    errors: list[str] = []
    files = sorted(
        p for p in (ROOT / "docs").rglob("*.md") if "node_modules" not in p.parts
    ) + [
        ROOT / "README.md",
        ROOT / "HANDOFF.md",
        ROOT / "AGENTS.md",
        ROOT / "CLAUDE.md",
        ROOT / "research/g0/README.md",
        ROOT / "research/g1/README.md",
    ]
    anchor_cache: dict[Path, set[str]] = {}
    links = sum(check_document(path, errors, anchor_cache) for path in files)
    preserved = check_preserved_documents(errors)
    contrast_pairs = check_design_contrast(errors)
    lint_path = ROOT / "docs/maintenance/DESIGN-LINT.json"
    if lint_path.exists():
        report = json.loads(lint_path.read_text(encoding="utf-8"))
        candidate = hashlib.sha256((ROOT / report["document"]).read_bytes()).hexdigest()
        if report["document_sha256"] != candidate or report["summary"]["errors"]:
            errors.append("DESIGN.md: official lint receipt is stale or contains errors")
    if (ROOT / "CLAUDE.md").read_text(encoding="utf-8") != "@AGENTS.md\n":
        errors.append("CLAUDE.md must import the shared AGENTS.md without copied rules")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"PASS: {len(files)} documents, {links} local links, {preserved} preserved hashes, "
        f"{contrast_pairs} solid contrast pairs, Claude import"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
