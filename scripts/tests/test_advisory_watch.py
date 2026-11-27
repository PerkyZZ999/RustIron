"""Tests for scripts/release/advisory_watch.py (P09, D-065/D-082)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/advisory_watch.py"


def load_module():
    spec = importlib.util.spec_from_file_location("advisory_watch", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


WATCH = load_module()
# Within the 120-day review window of support-matrix.json (2026-11-17 = 1794873600).
NOW_CLEAN = 1795478400  # 2026-11-24T00:00:00Z


class AdvisoryWatchTests(unittest.TestCase):
    def test_parses_real_repo_cargo_and_bun_lockfiles(self) -> None:
        crates = WATCH.parse_cargo_lock(ROOT / "Cargo.lock")
        npm = WATCH.parse_bun_lock(ROOT / "console/bun.lock")
        self.assertGreater(len(crates), 30)
        self.assertGreater(len(npm), 50)
        crate_names = {name for name, _ in crates}
        self.assertIn("serde", crate_names)
        self.assertNotIn("rustiron-executor", crate_names)
        npm_names = {name for name, _ in npm}
        self.assertIn("react", npm_names)

    def test_clean_offline_bundle_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            bundle = Path(tmp) / "bundle.json"
            bundle.write_text(
                json.dumps({
                    "schema": "rustiron-advisory-bundle/1",
                    "osv_crates": {},
                    "osv_npm": {},
                    "almalinux_errata": {"data": []},
                }),
                encoding="utf-8",
            )
            report, code = WATCH.run_watch(
                repo_root=ROOT,
                offline_bundle=bundle,
                now_unix=NOW_CLEAN,
            )
            self.assertEqual(code, 0)
            self.assertEqual(report["schema"], "rustiron-advisory-watch/1")
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["feed_errors"], [])
            self.assertFalse(report["policy"]["auto_apply"])
            self.assertTrue(report["policy"]["owner_signs_all_changes"])

    def test_detects_osv_crates_npm_and_almalinux_errata_with_d082_slas(self) -> None:
        crates = WATCH.parse_cargo_lock(ROOT / "Cargo.lock")
        npm = WATCH.parse_bun_lock(ROOT / "console/bun.lock")
        serde_ver = dict(crates)["serde"]
        react_ver = dict(npm)["react"]

        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            bundle = Path(tmp) / "bundle.json"
            bundle.write_text(
                json.dumps({
                    "schema": "rustiron-advisory-bundle/1",
                    "osv_crates": {
                        f"serde@{serde_ver}": [{
                            "id": "RUSTSEC-2026-9999",
                            "summary": "Critical parser bug\x1b[31m injected",
                            "database_specific": {"severity": "CRITICAL"},
                            "affected": [{
                                "package": {"ecosystem": "crates.io", "name": "serde"},
                                "ranges": [{"events": [{"fixed": "9.9.9"}]}],
                            }],
                        }]
                    },
                    "osv_npm": {
                        f"react@{react_ver}": [{
                            "id": "GHSA-xxxx-yyyy-zzzz",
                            "summary": "Moderate hydration issue",
                            "database_specific": {"severity": "MODERATE"},
                            "affected": [{
                                "package": {"ecosystem": "npm", "name": "react"},
                                "ranges": [{"events": [{"fixed": "19.9.9"}]}],
                            }],
                        }]
                    },
                    "almalinux_errata": {
                        "data": [
                            {
                                "id": "ALSA-2026:9001",
                                "type": "security",
                                "severity": "Important",
                                "title": "mariadb-server security update",
                                "packages": [
                                    {"name": "mariadb-server", "version": "10.11.99", "release": "1.el10"},
                                    {"name": "firefox", "version": "140.0", "release": "1.el10"},
                                ],
                            },
                            {
                                "id": "ALBA-2026:9002",
                                "type": "bugfix",
                                "severity": "Moderate",
                                "title": "non-security bugfix ignored",
                                "packages": [{"name": "systemd", "version": "257", "release": "9.el10"}],
                            },
                        ]
                    },
                }),
                encoding="utf-8",
            )
            report, code = WATCH.run_watch(
                repo_root=ROOT,
                offline_bundle=bundle,
                now_unix=NOW_CLEAN,
            )
            self.assertEqual(code, 1)
            by_id = {f["advisory_id"]: f for f in report["findings"]}
            self.assertEqual(
                set(by_id.keys()),
                {"RUSTSEC-2026-9999", "GHSA-xxxx-yyyy-zzzz", "ALSA-2026:9001"},
            )
            self.assertEqual(by_id["RUSTSEC-2026-9999"]["severity"], "critical")
            self.assertEqual(by_id["RUSTSEC-2026-9999"]["sla_hours"], 48)
            self.assertEqual(by_id["RUSTSEC-2026-9999"]["fixed_version"], "9.9.9")
            self.assertNotIn("\x1b", by_id["RUSTSEC-2026-9999"]["summary"])
            self.assertEqual(by_id["GHSA-xxxx-yyyy-zzzz"]["sla_hours"], 168)
            self.assertEqual(by_id["ALSA-2026:9001"]["component"], "mariadb-server")
            self.assertEqual(by_id["ALSA-2026:9001"]["sla_hours"], 48)

    def test_w634_rpm_evr_catches_release_only_and_epoch_only_security_fixes(self) -> None:
        # H-10: release-only rebuild (10.11.18-1.el10_2 < 10.11.18-2.el10) must be flagged.
        self.assertTrue(WATCH.rpm_evr_less("0:10.11.18-1.el10_2.x86_64", "10.11.18-2.el10"))
        self.assertFalse(WATCH.rpm_evr_less("0:10.11.18-2.el10.x86_64", "10.11.18-2.el10"))
        # Epoch bump (0:10.11.18-2.el10 < 1:10.11.18-1.el10) must be flagged.
        self.assertTrue(WATCH.rpm_evr_less("0:10.11.18-2.el10.x86_64", "1:10.11.18-1.el10"))

        def fake_fetcher(_url, _body, _timeout):
            return {
                "data": [
                    {
                        "id": "ALSA-2026:9901",
                        "type": "security",
                        "severity": "Important",
                        "title": "mariadb release-only fix",
                        "packages": [
                            {"name": "mariadb-server", "epoch": "0", "version": "10.11.18", "release": "2.el10"}
                        ],
                    },
                    {
                        "id": "ALSA-2026:9902",
                        "type": "security",
                        "severity": "Important",
                        "title": "postfix epoch fix",
                        "packages": [
                            {"name": "postfix", "epoch": "2", "version": "3.8.5", "release": "1.el10"}
                        ],
                    },
                ]
            }

        findings = WATCH.query_almalinux_errata(
            installed_rpms={
                "mariadb-server": "0:10.11.18-1.el10_2.x86_64",
                "postfix": "1:3.8.5-9.el10.x86_64",
            },
            fetcher=fake_fetcher,
        )
        ids = {f["advisory_id"] for f in findings}
        self.assertEqual(ids, {"ALSA-2026:9901", "ALSA-2026:9902"})

    def test_support_matrix_review_eol_and_observation_checks(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            bundle = Path(tmp) / "bundle.json"
            bundle.write_text(
                json.dumps({
                    "schema": "rustiron-advisory-bundle/1",
                    "osv_crates": {},
                    "osv_npm": {},
                    "almalinux_errata": {"data": []},
                }),
                encoding="utf-8",
            )
            obs = Path(tmp) / "obs.json"
            obs.write_text(
                json.dumps({
                    "schema": "rustiron-lab-observation/1",
                    "host": {"host_id": "lab", "host_epoch": "e1", "packages": []},
                    "machine": {
                        "schema": "rustiron-host-status/1",
                        "os": {"version": "10.3"},
                        "stack": {
                            "openlitespeed": "1.8.0",
                            "mariadb": "10.11.10",
                            "php": ["8.4.27"],
                            "powerdns": None,
                        },
                    },
                }),
                encoding="utf-8",
            )
            # 2028-03-01: past MariaDB EOL (2028-02-16) and past matrix review window.
            future = 1835481600
            report, code = WATCH.run_watch(
                repo_root=ROOT,
                observation_path=obs,
                offline_bundle=bundle,
                now_unix=future,
            )
            self.assertEqual(code, 1)
            ids = {f["advisory_id"] for f in report["findings"]}
            self.assertIn("MATRIX-REVIEW-OVERDUE", ids)
            self.assertIn("EOL-EXPIRED-MARIADB", ids)
            self.assertIn("UNSUPPORTED-SERIES-OPENLITESPEED", ids)
            self.assertIn("BELOW-MINIMUM-MARIADB", ids)
            self.assertNotIn("BELOW-MINIMUM-POWERDNS", ids)
            self.assertNotIn("BELOW-MINIMUM-POSTGRESQL", ids)
            self.assertNotIn("BELOW-MINIMUM-CADDY", ids)

    def test_postgres_18_7_and_caddy_support_matrix_floors(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            bundle = Path(tmp) / "bundle.json"
            bundle.write_text(
                json.dumps({
                    "schema": "rustiron-advisory-bundle/1",
                    "osv_crates": {},
                    "osv_npm": {},
                    "almalinux_errata": {"data": []},
                }),
                encoding="utf-8",
            )
            obs = Path(tmp) / "obs.json"
            obs.write_text(
                json.dumps({
                    "schema": "rustiron-lab-observation/1",
                    "host": {"host_id": "lab", "host_epoch": "e1", "packages": []},
                    "machine": {
                        "schema": "rustiron-host-status/1",
                        "os": {"version": "10.3"},
                        "stack": {
                            "openlitespeed": "1.9.4",
                            "mariadb": "10.11.18",
                            "php": ["8.4.28"],
                            "caddy": "2.9.1",
                            "postgresql": "18.6",
                        },
                    },
                }),
                encoding="utf-8",
            )
            report, code = WATCH.run_watch(
                repo_root=ROOT,
                observation_path=obs,
                offline_bundle=bundle,
                now_unix=NOW_CLEAN,
            )
            self.assertEqual(code, 1)
            ids = {f["advisory_id"] for f in report["findings"]}
            self.assertIn("BELOW-MINIMUM-CADDY", ids)
            self.assertIn("BELOW-MINIMUM-POSTGRESQL", ids)

            # Updating to 2.10.0 and 18.7 clears both findings.
            obs.write_text(
                json.dumps({
                    "schema": "rustiron-lab-observation/1",
                    "host": {"host_id": "lab", "host_epoch": "e1", "packages": []},
                    "machine": {
                        "schema": "rustiron-host-status/1",
                        "os": {"version": "10.3"},
                        "stack": {
                            "openlitespeed": "1.9.4",
                            "mariadb": "10.11.18",
                            "php": ["8.4.28"],
                            "caddy": "2.10.0",
                            "postgresql": "18.7",
                        },
                    },
                }),
                encoding="utf-8",
            )
            clean_report, clean_code = WATCH.run_watch(
                repo_root=ROOT,
                observation_path=obs,
                offline_bundle=bundle,
                now_unix=NOW_CLEAN,
            )
            self.assertEqual(clean_code, 0)
            self.assertEqual(clean_report["findings"], [])

    def test_feed_error_exits_two_and_never_claims_clean(self) -> None:
        def failing_fetcher(_url, _payload=None, _timeout=20):
            raise WATCH.WatchError("feed request failed")

        report, code = WATCH.run_watch(
            repo_root=ROOT,
            now_unix=NOW_CLEAN,
            fetcher=failing_fetcher,
        )
        self.assertEqual(code, 2)
        self.assertEqual(len(report["feed_errors"]), 3)

    def test_refuses_non_https_and_symlink_inputs(self) -> None:
        with self.assertRaises(WATCH.WatchError):
            WATCH.http_json("http://api.osv.dev/v1/querybatch")

        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            real = Path(tmp) / "real.json"
            real.write_text("{}", encoding="utf-8")
            link = Path(tmp) / "link.json"
            link.symlink_to(real)
            with self.assertRaises(WATCH.WatchError):
                WATCH.read_regular_bounded(link)


if __name__ == "__main__":
    unittest.main()
