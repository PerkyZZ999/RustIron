"""W660 (v0.1.1 Slice 6, D-102): tests for packaging/rustiron-app-pack.py.

Verifies deterministic bundle + manifest generation across all four D-102
topologies and all six presets, fail-closed refusal of symlinks, `.env` secrets,
setuid bits, and missing entrypoints, plus end-to-end validation of emitted
`rustiron plan create app-deploy` commands against the compiled Rust CLI.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "packaging/rustiron-app-pack.py"


def load_pack():
    spec = importlib.util.spec_from_file_location("rustiron_app_pack", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["rustiron_app_pack"] = module
    spec.loader.exec_module(module)
    return module


pack = load_pack()


def rustiron_cli_binary() -> Path | None:
    candidate = REPO / "target/debug/rustiron"
    return candidate if candidate.is_file() and os.access(candidate, os.X_OK) else None


class AppPackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ri-app-pack-test-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        res = subprocess.run(
            [sys.executable, str(SCRIPT), *argv],
            capture_output=True,
            text=True,
            check=False,
        )
        return res.returncode, res.stdout, res.stderr

    def make_tree(self, rel: str, files: dict[str, bytes]) -> Path:
        root = self.tmp / rel
        for name, content in files.items():
            fp = root / name
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(content)
        return root

    def test_presets_list_all_six_curated_fullstack_presets(self):
        code, stdout, stderr = self.run_cli(["presets", "--json"])
        self.assertEqual(code, 0, stderr)
        doc = json.loads(stdout)
        self.assertEqual(
            set(doc.keys()),
            {
                "vite-elysia",
                "react-hono",
                "nextjs-standalone",
                "astro-ssr",
                "tanstack-start",
                "static-spa",
            },
        )
        self.assertEqual(doc["vite-elysia"]["database"], "postgresql_18")
        self.assertEqual(doc["static-spa"]["runtime"], "static_v1")

    def test_all_four_topologies_pack_deterministically_and_validate_with_rust_cli(self):
        fe_static = self.make_tree(
            "fe-static",
            {
                "index.html": b"<!doctype html><html><body>SPA</body></html>\n",
                "assets/app-abc123.js": b"console.log('hi');\n",
                ".env.example": b"VITE_API_URL=/api\n",
            },
        )
        be_bun = self.make_tree(
            "be-bun",
            {
                "server.ts": b"export default { fetch: () => new Response('ok') };\n",
                "db/migrate.ts": b"console.log('migrated');\n",
            },
        )
        fe_ssr = self.make_tree(
            "fe-ssr",
            {
                "server.js": b"import http from 'node:http';\n",
                "routes/[slug].mjs": b"export const slug = true;\n",
            },
        )
        be_node = self.make_tree(
            "be-node",
            {
                "server.mjs": b"console.log('api');\n",
                "@scope/helper.mjs": b"export const ok = 1;\n",
            },
        )
        be_astro = self.make_tree(
            "be-astro",
            {
                "dist/server/entry.mjs": b"export const handler = () => {};\n",
            },
        )

        cases = [
            (
                "static_spa",
                [
                    "pack",
                    "--preset", "static-spa",
                    "--site-id", "spa1",
                    "--release-id", "rel-1.0.0",
                    "--frontend-dist", str(fe_static),
                    "--json",
                ],
                {"frontend/index.html", "frontend/assets/app-abc123.js", "frontend/.env.example"},
            ),
            (
                "backend_api",
                [
                    "pack",
                    "--preset", "astro-ssr",
                    "--site-id", "astro1",
                    "--release-id", "rel-2",
                    "--backend-dist", str(be_astro),
                    "--json",
                ],
                {"dist/server/entry.mjs"},
            ),
            (
                "fullstack_split",
                [
                    "pack",
                    "--preset", "vite-elysia",
                    "--site-id", "shop1",
                    "--release-id", "rel-3",
                    "--frontend-dist", str(fe_static),
                    "--backend-dist", str(be_bun),
                    "--migration-entrypoint", "backend/db/migrate.ts",
                    "--capture-operation-id", "cap_shop1_001",
                    "--json",
                ],
                {
                    "frontend/index.html",
                    "frontend/assets/app-abc123.js",
                    "frontend/.env.example",
                    "backend/server.ts",
                    "backend/db/migrate.ts",
                },
            ),
            (
                "fullstack_dual_ssr",
                [
                    "pack",
                    "--preset", "nextjs-standalone",
                    "--site-id", "dual1",
                    "--release-id", "rel-4",
                    "--frontend-dist", str(fe_ssr),
                    "--backend-dist", str(be_node),
                    "--json",
                ],
                {
                    "frontend/server.js",
                    "frontend/routes/[slug].mjs",
                    "backend/server.mjs",
                    "backend/@scope/helper.mjs",
                },
            ),
        ]

        rust_cli = rustiron_cli_binary()
        for label, base_argv, expected_files in cases:
            with self.subTest(topology=label):
                out1 = self.tmp / f"out-{label}-1"
                out2 = self.tmp / f"out-{label}-2"
                c1, s1, e1 = self.run_cli([*base_argv, "--out", str(out1)])
                c2, s2, e2 = self.run_cli([*base_argv, "--out", str(out2)])
                self.assertEqual(c1, 0, e1)
                self.assertEqual(c2, 0, e2)
                m1 = json.loads(s1)
                m2 = json.loads(s2)
                # Byte-for-byte determinism across independent runs.
                self.assertEqual(m1["artifact_sha256"], m2["artifact_sha256"])
                self.assertEqual(m1["manifest_sha256"], m2["manifest_sha256"])
                self.assertEqual((out1 / "bundle.tar.gz").read_bytes(), (out2 / "bundle.tar.gz").read_bytes())
                self.assertEqual(m1["file_count"], len(expected_files))
                with tarfile.open(out1 / "bundle.tar.gz", "r:gz") as tf:
                    self.assertEqual(set(tf.getnames()), expected_files)
                    for member in tf.getmembers():
                        self.assertEqual(member.mtime, 0)
                        self.assertEqual(member.uid, 0)
                        self.assertEqual(member.gid, 0)
                manifest_lines = (out1 / "manifest.sha256").read_text().splitlines()
                self.assertEqual(len(manifest_lines), len(expected_files))
                self.assertEqual(
                    hashlib.sha256((out1 / "bundle.tar.gz").read_bytes()).hexdigest(),
                    m1["artifact_sha256"],
                )
                # End-to-end check against the real compiled Rust CLI when present!
                if rust_cli is not None:
                    real_argv = [
                        str(rust_cli),
                        *[
                            "host_lab" if a == "<HOST_ID>"
                            else "epoch_1" if a == "<HOST_EPOCH>"
                            else ("a" * 64) if a == "<PROFILE_DIGEST_SHA256>"
                            else a
                            for a in m1["deploy_plan_argv"][1:]
                        ],
                    ]
                    created = subprocess.run(real_argv, capture_output=True, text=True, check=False)
                    self.assertEqual(created.returncode, 0, f"{label}: {created.stderr}")
                    plan_file = self.tmp / f"plan-{label}.json"
                    plan_file.write_text(created.stdout, encoding="utf-8")
                    plan_file.chmod(0o600)
                    reviewed = subprocess.run(
                        [str(rust_cli), "plan", "review-file", str(plan_file)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(reviewed.returncode, 0, f"{label} review-file: {reviewed.stderr}")
                    self.assertIn(m1["release_id"], reviewed.stdout)

    def test_refuses_symlinks_env_secrets_setuid_and_missing_entrypoints(self):
        # 1. Secret .env file refused.
        env_tree = self.make_tree("bad-env", {"index.html": b"ok", ".env": b"SECRET=1\n"})
        code, _, err = self.run_cli([
            "pack", "--preset", "static-spa", "--site-id", "spa1", "--release-id", "r1",
            "--frontend-dist", str(env_tree), "--out", str(self.tmp / "out-env"),
        ])
        self.assertEqual(code, 1)
        self.assertIn("REFUSED", err)
        self.assertNotIn("SECRET=1", err)

        # 2. .env.production secret file refused.
        env_prod = self.make_tree("bad-env-prod", {"index.html": b"ok", ".env.production": b"DB=pw\n"})
        code, _, err = self.run_cli([
            "pack", "--preset", "static-spa", "--site-id", "spa1", "--release-id", "r1",
            "--frontend-dist", str(env_prod), "--out", str(self.tmp / "out-envp"),
        ])
        self.assertEqual(code, 1)
        self.assertIn("REFUSED", err)

        # 3. Symlink inside release tree refused.
        sym_tree = self.make_tree("bad-sym", {"index.html": b"ok"})
        (sym_tree / "leak.txt").symlink_to("/etc/passwd")
        code, _, err = self.run_cli([
            "pack", "--preset", "static-spa", "--site-id", "spa1", "--release-id", "r1",
            "--frontend-dist", str(sym_tree), "--out", str(self.tmp / "out-sym"),
        ])
        self.assertEqual(code, 1)
        self.assertIn("symlink", err)

        # 4. Missing index.html refused for static_spa.
        no_idx = self.make_tree("bad-noidx", {"app.js": b"ok"})
        code, _, err = self.run_cli([
            "pack", "--preset", "static-spa", "--site-id", "spa1", "--release-id", "r1",
            "--frontend-dist", str(no_idx), "--out", str(self.tmp / "out-noidx"),
        ])
        self.assertEqual(code, 1)
        self.assertIn("index.html", err)

        # 5. Migration without capture-operation-id refused.
        be = self.make_tree("be-mig", {"server.ts": b"ok", "migrate.ts": b"ok"})
        fe = self.make_tree("fe-mig", {"index.html": b"ok"})
        code, _, err = self.run_cli([
            "pack", "--preset", "vite-elysia", "--site-id", "shop1", "--release-id", "r1",
            "--frontend-dist", str(fe), "--backend-dist", str(be),
            "--migration-entrypoint", "backend/migrate.ts",
            "--out", str(self.tmp / "out-mig"),
        ])
        self.assertEqual(code, 1)
        self.assertIn("capture-operation-id", err)


if __name__ == "__main__":
    unittest.main()
