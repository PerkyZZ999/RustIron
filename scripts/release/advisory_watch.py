#!/usr/bin/env python3
"""Watch security advisories and support-matrix status for Rustiron (P09, D-065, D-082).

    advisory_watch.py [--repo ROOT] [--observation OBS.json] [--offline-bundle BUNDLE.json]

Read-only PC/agent tool. Holds zero host authority and never modifies code,
packages, or host configuration. Under D-065 and D-082, findings map to
patch-response targets (48h critical/high, 7d moderate/low) and the project
owner reviews and signs every production change.

Exit codes:
    0  All feeds and support-matrix checks succeeded with zero findings.
    1  All feeds and support-matrix checks succeeded with >= 1 finding.
    2  Input, schema, or feed error (watch incomplete; never claims clean).
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = "rustiron-advisory-watch/1"
AGENT = "rustiron-advisory-watch/1"
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
ALMA10_ERRATA_URL = "https://errata.almalinux.org/10/errata.json"

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_FEED_BYTES = 16 * 1024 * 1024
MAX_OSV_BATCH = 500
MAX_SUMMARY_CHARS = 240

# Host RPM packages monitored against AlmaLinux 10 security errata.
WATCHED_ALMA_RPMS = frozenset({
    "almalinux-release",
    "dovecot",
    "firewalld",
    "glibc",
    "kernel",
    "mariadb",
    "mariadb-server",
    "nodejs",
    "openssh",
    "openssh-clients",
    "openssh-server",
    "openssl",
    "openssl-libs",
    "postfix",
    "restic",
    "selinux-policy",
    "selinux-policy-targeted",
    "systemd",
})

CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
VERSION_PARTS = re.compile(r"[0-9]+(\.[0-9]+)*")


class WatchError(Exception):
    """Fixed refusal without echoing untrusted remote payloads."""


def sanitize_text(value: object, limit: int = MAX_SUMMARY_CHARS) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = CONTROL_CHARS.sub(" ", value).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    if len(cleaned) > limit:
        return cleaned[: limit - 1] + "…"
    return cleaned


def read_regular_bounded(path: Path, limit: int = MAX_INPUT_BYTES) -> bytes:
    """Open a regular file with O_NOFOLLOW and enforce a byte cap."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise WatchError(f"cannot open input: {path.name}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise WatchError(f"not a regular file: {path.name}")
        if info.st_size > limit:
            raise WatchError(f"input exceeds size limit: {path.name}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise WatchError(f"input exceeds size limit: {path.name}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def parse_cargo_lock(path: Path) -> list[tuple[str, str]]:
    """Return sorted distinct (name, version) for crates.io packages in Cargo.lock."""
    raw = read_regular_bounded(path)
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise WatchError("invalid Cargo.lock") from exc
    packages = data.get("package")
    if not isinstance(packages, list):
        raise WatchError("Cargo.lock missing package list")
    found: set[tuple[str, str]] = set()
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        source = pkg.get("source")
        name = pkg.get("name")
        version = pkg.get("version")
        if (
            isinstance(source, str)
            and source.startswith("registry+")
            and isinstance(name, str)
            and isinstance(version, str)
            and name
            and version
        ):
            found.add((name, version))
    return sorted(found)


def strip_jsonc_trailing_commas(text: str) -> str:
    """Remove trailing commas before '}' or ']' outside JSON strings."""
    out: list[str] = []
    in_string = False
    escaped = False
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def split_npm_spec(spec: str) -> tuple[str, str] | None:
    """Split 'pkg@1.2.3' or '@scope/pkg@1.2.3' into (name, version)."""
    if not spec or "@" not in spec:
        return None
    at = spec.rfind("@")
    if at <= 0 or at == len(spec) - 1:
        return None
    name = spec[:at]
    version = spec[at + 1 :]
    if not name or not version or " " in name or " " in version:
        return None
    return name, version


def parse_bun_lock(path: Path) -> list[tuple[str, str]]:
    """Return sorted distinct (name, version) for npm packages in console/bun.lock."""
    raw = read_regular_bounded(path)
    try:
        text = raw.decode("utf-8")
        data = json.loads(strip_jsonc_trailing_commas(text))
    except (UnicodeDecodeError, ValueError) as exc:
        raise WatchError("invalid bun.lock") from exc
    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise WatchError("bun.lock missing packages object")
    found: set[tuple[str, str]] = set()
    for entry in packages.values():
        if isinstance(entry, list) and entry and isinstance(entry[0], str):
            parsed = split_npm_spec(entry[0])
            if parsed:
                found.add(parsed)
    return sorted(found)


def version_tuple(text: str) -> tuple[int, ...] | None:
    if not isinstance(text, str) or not VERSION_PARTS.fullmatch(text):
        return None
    return tuple(int(part) for part in text.split("."))


def version_less(actual: str, minimum: str) -> bool | None:
    a, b = version_tuple(actual), version_tuple(minimum)
    if a is None or b is None:
        return None
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) < b + (0,) * (width - len(b))


def in_series(actual: str, series: str) -> bool:
    return actual == series or actual.startswith(series + ".")


def severity_and_sla(raw_severity: object) -> tuple[str, int]:
    """Map advisory severity to D-082 SLA (48h critical/high, 168h other)."""
    text = str(raw_severity or "").strip().lower()
    if text in ("critical", "important", "high"):
        normalized = "critical" if text == "critical" else "high"
        return normalized, 48
    if text in ("moderate", "medium"):
        return "moderate", 168
    if text == "low":
        return "low", 168
    return "unknown", 168


def osv_severity(vuln: dict) -> tuple[str, int]:
    db_sev = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db_sev, str) and db_sev.strip():
        return severity_and_sla(db_sev)
    for item in vuln.get("severity") or []:
        if isinstance(item, dict) and isinstance(item.get("score"), str):
            # CVSS vector without parsed numeric score stays unknown unless explicit.
            continue
    return "unknown", 168


def osv_fixed_version(vuln: dict, ecosystem: str, pkg_name: str) -> str | None:
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or pkg.get("name") != pkg_name:
            continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for ev in rng.get("events") or []:
                if isinstance(ev, dict) and isinstance(ev.get("fixed"), str):
                    return sanitize_text(ev["fixed"], 64)
    return None


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).scheme != "https":
            raise WatchError("refused non-HTTPS feed redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_json(url: str, payload: dict | None = None, timeout: int = 20) -> object:
    if not url.startswith("https://"):
        raise WatchError("only HTTPS feeds are allowed")
    headers = {"User-Agent": AGENT, "Accept": "application/json"}
    body: bytes | None = None
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    opener = urllib.request.build_opener(_HttpsOnlyRedirect())
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = resp.read(MAX_FEED_BYTES + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise WatchError("feed request failed") from exc
    if len(data) > MAX_FEED_BYTES:
        raise WatchError("feed answer exceeds size limit")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise WatchError("feed answer is not valid JSON") from exc


def query_osv(
    packages: list[tuple[str, str]],
    ecosystem: str,
    source_tag: str,
    fetcher=http_json,
    timeout: int = 20,
) -> list[dict]:
    findings: list[dict] = []
    for start in range(0, len(packages), MAX_OSV_BATCH):
        batch = packages[start : start + MAX_OSV_BATCH]
        queries = [
            {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            for name, version in batch
        ]
        answer = fetcher(OSV_QUERYBATCH_URL, {"queries": queries}, timeout)
        if not isinstance(answer, dict) or not isinstance(answer.get("results"), list):
            raise WatchError(f"malformed OSV response for {source_tag}")
        results = answer["results"]
        if len(results) != len(batch):
            raise WatchError(f"OSV batch length mismatch for {source_tag}")
        for (name, version), entry in zip(batch, results, strict=True):
            if not isinstance(entry, dict):
                continue
            for vuln in entry.get("vulns") or []:
                if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
                    continue
                sev, sla = osv_severity(vuln)
                findings.append({
                    "source": source_tag,
                    "component": sanitize_text(name, 128),
                    "installed_version": sanitize_text(version, 64),
                    "advisory_id": sanitize_text(vuln["id"], 64),
                    "severity": sev,
                    "sla_hours": sla,
                    "fixed_version": osv_fixed_version(vuln, ecosystem, name),
                    "summary": sanitize_text(vuln.get("summary") or vuln.get("details") or ""),
                    "next_action": "Review advisory, prepare tested patch, run all 27 gates, and request owner signature.",
                })
    return findings


RPM_ARCH_SUFFIX = re.compile(r"\.(?:x86_64|aarch64|noarch|i686|s390x|ppc64le)$")
RPM_SEGMENT = re.compile(r"(~|\^|[0-9]+|[A-Za-z]+)")


def rpm_label_compare(a: str, b: str) -> int:
    """Compare two RPM version or release strings using rpmvercmp ordering."""
    if a == b:
        return 0
    sa = RPM_SEGMENT.findall(a)
    sb = RPM_SEGMENT.findall(b)
    for idx in range(max(len(sa), len(sb))):
        if idx >= len(sa):
            return 1 if sb[idx] == "~" else -1
        if idx >= len(sb):
            return -1 if sa[idx] == "~" else 1
        pa, pb = sa[idx], sb[idx]
        if pa == pb:
            continue
        if pa == "~":
            return -1
        if pb == "~":
            return 1
        if pa == "^":
            return -1
        if pb == "^":
            return 1
        a_num, b_num = pa.isdigit(), pb.isdigit()
        if a_num and b_num:
            ia, ib = int(pa), int(pb)
            if ia != ib:
                return -1 if ia < ib else 1
        elif a_num != b_num:
            return 1 if a_num else -1
        else:
            return -1 if pa < pb else 1
    return 0


def parse_rpm_evr(raw: str) -> tuple[int, str, str] | None:
    """Parse `[epoch:]version[-release][.arch]` into `(epoch, version, release)`."""
    text = RPM_ARCH_SUFFIX.sub("", raw.strip())
    if not text:
        return None
    epoch = 0
    if ":" in text:
        ep_raw, text = text.split(":", 1)
        if not ep_raw.isdigit():
            return None
        epoch = int(ep_raw)
    if "-" in text:
        version, release = text.split("-", 1)
    else:
        version, release = text, ""
    if not version:
        return None
    return (epoch, version, release)


def rpm_evr_less(installed: str, fixed: str) -> bool | None:
    """Return True when installed RPM EVR is strictly older than fixed RPM EVR."""
    a = parse_rpm_evr(installed)
    b = parse_rpm_evr(fixed)
    if a is None or b is None:
        return None
    if a[0] != b[0]:
        return a[0] < b[0]
    vcmp = rpm_label_compare(a[1], b[1])
    if vcmp != 0:
        return vcmp < 0
    if b[2]:
        return rpm_label_compare(a[2], b[2]) < 0
    return False


def query_almalinux_errata(
    installed_rpms: dict[str, str] | None,
    fetcher=http_json,
    timeout: int = 20,
) -> list[dict]:
    answer = fetcher(ALMA10_ERRATA_URL, None, timeout)
    if isinstance(answer, dict):
        entries = answer.get("data")
    elif isinstance(answer, list):
        entries = answer
    else:
        entries = None
    if not isinstance(entries, list):
        raise WatchError("malformed AlmaLinux errata feed")

    findings: list[dict] = []
    for erratum in entries:
        if not isinstance(erratum, dict):
            continue
        if str(erratum.get("type") or "").lower() != "security":
            continue
        err_id = erratum.get("id")
        if not isinstance(err_id, str) or not err_id:
            continue
        sev, sla = severity_and_sla(erratum.get("severity"))
        pkgs = erratum.get("packages") or []
        if not isinstance(pkgs, list):
            continue
        matched: set[tuple[str, str]] = set()
        for pkg in pkgs:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            if not isinstance(name, str) or name not in WATCHED_ALMA_RPMS:
                continue
            epoch = str(pkg.get("epoch") or "").strip()
            ver = str(pkg.get("version") or "").strip()
            rel = str(pkg.get("release") or "").strip()
            vr = f"{ver}-{rel}" if ver and rel else ver
            fixed = f"{epoch}:{vr}" if epoch and epoch != "0" and vr else vr
            fixed_evr = f"{epoch}:{vr}" if epoch and vr else vr
            if installed_rpms is not None and name in installed_rpms:
                cur = installed_rpms[name]
                if fixed_evr and rpm_evr_less(cur, fixed_evr) is False:
                    continue
            matched.add((name, fixed))
        for name, fixed in sorted(matched):
            installed = (installed_rpms or {}).get(name, "watched_stack_rpm")
            findings.append({
                "source": "almalinux_errata",
                "component": name,
                "installed_version": sanitize_text(installed, 64),
                "advisory_id": sanitize_text(err_id, 64),
                "severity": sev,
                "sla_hours": sla,
                "fixed_version": sanitize_text(fixed, 64) or None,
                "summary": sanitize_text(erratum.get("title") or erratum.get("description") or ""),
                "next_action": "Verify fixed RPM on AlmaLinux 10, rehearse update on disposable VM, and schedule owner-approved maintenance.",
            })
    return findings


def check_support_matrix(
    matrix_path: Path,
    now_unix: int,
    observation: dict | None = None,
) -> list[dict]:
    raw = read_regular_bounded(matrix_path)
    try:
        matrix = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise WatchError("invalid support-matrix.json") from exc
    if not isinstance(matrix, dict) or matrix.get("schema") != "rustiron-support-matrix/1":
        raise WatchError("unsupported support-matrix schema")

    findings: list[dict] = []
    reviewed_unix = matrix.get("reviewed_unix")
    review_days = matrix.get("review_days")
    warn_days = matrix.get("warn_before_end_days")
    if not all(isinstance(v, int) and v >= 0 for v in (reviewed_unix, review_days, warn_days)):
        raise WatchError("invalid support-matrix timing fields")

    if now_unix > reviewed_unix + review_days * 86400:
        findings.append({
            "source": "support_matrix",
            "component": "support_matrix",
            "installed_version": sanitize_text(matrix.get("reviewed") or "", 32),
            "advisory_id": "MATRIX-REVIEW-OVERDUE",
            "severity": "moderate",
            "sla_hours": 168,
            "fixed_version": None,
            "summary": f"Support matrix review is past its {review_days}-day review window.",
            "next_action": "Review upstream versions and EOL dates in crates/control/support-matrix.json.",
        })

    machine = (observation or {}).get("machine") if isinstance(observation, dict) else None
    stack = machine.get("stack") if isinstance(machine, dict) else None
    os_info = machine.get("os") if isinstance(machine, dict) else None

    for comp in matrix.get("components") or []:
        if not isinstance(comp, dict):
            continue
        name = str(comp.get("name") or "")
        series = str(comp.get("series") or "")
        minimum = str(comp.get("minimum") or "")
        when_installed = comp.get("when_installed") is True
        if when_installed:
            observed_present = isinstance(stack, dict) and stack.get(name) is not None
            if not observed_present:
                continue
        eol_unix = comp.get("end_of_life_unix")
        if isinstance(eol_unix, int):
            if now_unix >= eol_unix:
                findings.append({
                    "source": "support_matrix",
                    "component": name,
                    "installed_version": series,
                    "advisory_id": f"EOL-EXPIRED-{name.upper()}",
                    "severity": "critical",
                    "sla_hours": 48,
                    "fixed_version": None,
                    "summary": f"{name} series {series} reached end of life ({comp.get('end_of_life')}).",
                    "next_action": "Plan a supported-series upgrade and rehearse on a disposable VM.",
                })
            elif now_unix + warn_days * 86400 >= eol_unix:
                findings.append({
                    "source": "support_matrix",
                    "component": name,
                    "installed_version": series,
                    "advisory_id": f"EOL-SOON-{name.upper()}",
                    "severity": "moderate",
                    "sla_hours": 168,
                    "fixed_version": None,
                    "summary": f"{name} series {series} is within {warn_days} days of EOL ({comp.get('end_of_life')}).",
                    "next_action": "Prepare next supported-series decision and lab upgrade rehearsal.",
                })

        if observation is None:
            continue
        actual: str | None = None
        if name == "os" and isinstance(os_info, dict):
            val = os_info.get("version")
            actual = val if isinstance(val, str) else None
        elif name == "php" and isinstance(stack, dict) and isinstance(stack.get("php"), list):
            matching = [v for v in stack["php"] if isinstance(v, str) and in_series(v, series)]
            actual = sorted(matching, key=lambda v: version_tuple(v) or (0,))[-1] if matching else None
            if actual is None and stack["php"]:
                actual = str(stack["php"][0])
        elif isinstance(stack, dict):
            val = stack.get(name)
            actual = val if isinstance(val, str) else None

        if actual is None:
            if comp.get("when_installed") is True:
                continue
            continue

        if not in_series(actual, series):
            findings.append({
                "source": "support_matrix",
                "component": name,
                "installed_version": sanitize_text(actual, 64),
                "advisory_id": f"UNSUPPORTED-SERIES-{name.upper()}",
                "severity": "high",
                "sla_hours": 48,
                "fixed_version": minimum,
                "summary": f"Observed {name} {actual} is outside supported series {series}.",
                "next_action": "Rehearse upgrade to supported series on disposable VM before owner approval.",
            })
        elif version_less(actual, minimum) is True:
            findings.append({
                "source": "support_matrix",
                "component": name,
                "installed_version": sanitize_text(actual, 64),
                "advisory_id": f"BELOW-MINIMUM-{name.upper()}",
                "severity": "high",
                "sla_hours": 48,
                "fixed_version": minimum,
                "summary": f"Observed {name} {actual} is older than reviewed minimum {minimum}.",
                "next_action": "Apply reviewed stack update procedure and re-observe host.",
            })

    return findings


def extract_observed_rpms(observation: dict | None) -> dict[str, str] | None:
    if not isinstance(observation, dict):
        return None
    host = observation.get("host")
    if not isinstance(host, dict):
        return None
    pkgs = host.get("packages")
    if not isinstance(pkgs, list):
        return None
    rpms: dict[str, str] = {}
    for entry in pkgs:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str) and isinstance(entry.get("version"), str):
            rpms[entry["name"]] = entry["version"]
    return rpms or None


def make_offline_fetcher(bundle_path: Path):
    raw = read_regular_bounded(bundle_path, MAX_FEED_BYTES)
    try:
        bundle = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise WatchError("invalid offline bundle JSON") from exc
    if not isinstance(bundle, dict) or bundle.get("schema") != "rustiron-advisory-bundle/1":
        raise WatchError("unsupported offline bundle schema")

    def fetch(url: str, payload: dict | None = None, _timeout: int = 20) -> object:
        if url == OSV_QUERYBATCH_URL and isinstance(payload, dict):
            queries = payload.get("queries") or []
            eco = (queries[0].get("package") or {}).get("ecosystem") if queries else ""
            key = "osv_crates" if eco == "crates.io" else "osv_npm"
            vulns_by_pkg = bundle.get(key)
            if not isinstance(vulns_by_pkg, dict):
                raise WatchError(f"offline bundle missing {key}")
            results = []
            for q in queries:
                pkg = q.get("package") or {}
                lookup = f"{pkg.get('name')}@{q.get('version')}"
                matched = vulns_by_pkg.get(lookup) or []
                results.append({"vulns": matched} if matched else {})
            return {"results": results}
        if url == ALMA10_ERRATA_URL:
            errata = bundle.get("almalinux_errata")
            if errata is None:
                raise WatchError("offline bundle missing almalinux_errata")
            return errata
        raise WatchError("unexpected feed URL")

    return fetch


def run_watch(
    repo_root: Path,
    observation_path: Path | None = None,
    offline_bundle: Path | None = None,
    now_unix: int | None = None,
    timeout: int = 20,
    fetcher=None,
) -> tuple[dict, int]:
    now = int(datetime.now(timezone.utc).timestamp()) if now_unix is None else now_unix
    checked_at = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    crates = parse_cargo_lock(repo_root / "Cargo.lock")
    npm_pkgs = parse_bun_lock(repo_root / "console/bun.lock")
    matrix_path = repo_root / "crates/control/support-matrix.json"

    observation: dict | None = None
    if observation_path is not None:
        raw_obs = read_regular_bounded(observation_path)
        try:
            parsed = json.loads(raw_obs.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise WatchError("invalid observation JSON") from exc
        if not isinstance(parsed, dict) or parsed.get("schema") != "rustiron-lab-observation/1":
            raise WatchError("unsupported observation schema")
        observation = parsed

    if fetcher is None:
        fetcher = make_offline_fetcher(offline_bundle) if offline_bundle is not None else http_json

    findings: list[dict] = []
    feed_errors: list[dict] = []

    findings.extend(check_support_matrix(matrix_path, now, observation))

    for label, fn in [
        ("osv_crates", lambda: query_osv(crates, "crates.io", "osv_crates", fetcher, timeout)),
        ("osv_npm", lambda: query_osv(npm_pkgs, "npm", "osv_npm", fetcher, timeout)),
        ("almalinux_errata", lambda: query_almalinux_errata(extract_observed_rpms(observation), fetcher, timeout)),
    ]:
        try:
            findings.extend(fn())
        except WatchError as exc:
            feed_errors.append({"feed": label, "error": str(exc)})

    # Deduplicate and sort deterministically.
    dedup: dict[tuple[str, str, str], dict] = {}
    for item in findings:
        key = (item["source"], item["component"], item["advisory_id"])
        dedup[key] = item
    ordered = [dedup[k] for k in sorted(dedup)]

    report = {
        "schema": SCHEMA,
        "checked_at": checked_at,
        "mode": "offline_bundle" if offline_bundle is not None else "online",
        "policy": {
            "decision": "D-082",
            "critical_sla_hours": 48,
            "other_sla_hours": 168,
            "owner_signs_all_changes": True,
            "auto_apply": False,
        },
        "inventory": {
            "crates_checked": len(crates),
            "npm_packages_checked": len(npm_pkgs),
            "watched_alma_rpms": len(WATCHED_ALMA_RPMS),
            "observation_included": observation is not None,
        },
        "findings": ordered,
        "feed_errors": feed_errors,
    }

    if feed_errors:
        return report, 2
    if ordered:
        return report, 1
    return report, 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Watch security advisories for Rustiron (P09, D-065/D-082).")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--observation", type=Path, default=None)
    parser.add_argument("--offline-bundle", type=Path, default=None)
    parser.add_argument("--now", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args(argv)
    if not (1 <= args.timeout <= 60):
        print(json.dumps({"schema": SCHEMA, "error": "timeout must be 1..60 seconds"}))
        return 2
    try:
        report, code = run_watch(
            repo_root=args.repo,
            observation_path=args.observation,
            offline_bundle=args.offline_bundle,
            now_unix=args.now,
            timeout=args.timeout,
        )
    except WatchError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
