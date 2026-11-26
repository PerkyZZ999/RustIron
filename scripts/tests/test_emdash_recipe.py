"""Unit tests for packaging/emdash-recipe.py (W602, P30, D-096)."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("emdash_recipe", ROOT / "packaging" / "emdash-recipe.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def make_starter(root: Path, version: str = "1.6.0", with_migration: bool = False) -> None:
    (root / "dist" / "server").mkdir(parents=True, exist_ok=True)
    (root / "dist" / "server" / "entry.mjs").write_text("console.log('emdash');\n", encoding="utf-8")
    if with_migration:
        (root / "dist" / "migrate.mjs").write_text("console.log('migrate');\n", encoding="utf-8")
    (root / "package.json").write_text(
        json.dumps({"name": "emdash-starter", "dependencies": {"emdash": version}}) + "\n",
        encoding="utf-8",
    )
    lock = {
        "name": "emdash-starter",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/emdash": {
                "version": version,
                "integrity": MOD.PINNED_INTEGRITY.get(f"emdash@{version}", "sha512-upgrade=="),
            }
        },
    }
    (root / "package-lock.json").write_text(json.dumps(lock) + "\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT License\nPermission is hereby granted, free of charge.\n", encoding="utf-8")


class EmdashRecipeTests(unittest.TestCase):
    def test_deterministic_release_package_and_upgrade_preparation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = base / "starter"
            make_starter(src)
            out1 = base / "out1"
            out2 = base / "out2"
            m1 = MOD.package_release(src, out1, "emdash-1.6.0-r1", "dist/server/entry.mjs")
            m2 = MOD.package_release(src, out2, "emdash-1.6.0-r1", "dist/server/entry.mjs")
            self.assertEqual(m1["artifact_sha256"], m2["artifact_sha256"])
            self.assertEqual(m1["manifest_sha256"], m2["manifest_sha256"])
            self.assertEqual((out1 / "bundle.tar.gz").read_bytes(), (out2 / "bundle.tar.gz").read_bytes())
            self.assertEqual(m1["emdash_version"], "1.6.0")
            self.assertEqual(m1["recommended_websocket"], "/_emdash/api/content/")

            # Prepare upgrade to 1.6.1 with migration entrypoint.
            src_up = base / "starter-up"
            make_starter(src_up, version="1.6.1", with_migration=True)
            out_up = base / "out-up"
            up = MOD.prepare_upgrade(
                out1 / "release-meta.json",
                src_up,
                out_up,
                "emdash-1.6.1-r1",
                "dist/server/entry.mjs",
                "dist/migrate.mjs",
                "1.6.1",
            )
            self.assertEqual(up["from_emdash_version"], "1.6.0")
            self.assertEqual(up["to_emdash_version"], "1.6.1")
            self.assertTrue(up["requires_capture"])
            self.assertEqual(len(up["target_fingerprint"]), 64)

            # Same-version upgrade refused without explicit flag.
            with self.assertRaises(MOD.Refused):
                MOD.prepare_upgrade(
                    out1 / "release-meta.json",
                    src,
                    base / "out-same",
                    "emdash-1.6.0-r2",
                    "dist/server/entry.mjs",
                    "dist/server/entry.mjs",
                    "1.6.0",
                )

    def test_refuses_symlinks_integrity_mismatch_and_missing_license(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = base / "starter"
            make_starter(src)
            # Symlink refused.
            (src / "badlink").symlink_to("package.json")
            with self.assertRaises(MOD.Refused):
                MOD.package_release(src, base / "o1", "rel-1", "dist/server/entry.mjs")
            (src / "badlink").unlink()

            # Wrong D-096 integrity hash refused.
            lock = json.loads((src / "package-lock.json").read_text(encoding="utf-8"))
            lock["packages"]["node_modules/emdash"]["integrity"] = "sha512-tampered=="
            (src / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaises(MOD.Refused):
                MOD.package_release(src, base / "o2", "rel-1", "dist/server/entry.mjs")

            # Missing LICENSE refused.
            make_starter(src)
            (src / "LICENSE").unlink()
            with self.assertRaises(MOD.Refused):
                MOD.package_release(src, base / "o3", "rel-1", "dist/server/entry.mjs")

    def test_w641_allows_scoped_npm_and_astro_route_paths_and_refuses_dotenv_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = base / "starter"
            make_starter(src)
            scoped = src / "node_modules" / "@emdash-cms" / "blocks"
            scoped.mkdir(parents=True)
            (scoped / "index.mjs").write_text("export {};\n", encoding="utf-8")
            route = src / "node_modules" / "emdash" / "src" / "astro" / "routes"
            route.mkdir(parents=True)
            (route / "sitemap-[collection].xml.ts").write_text("export {};\n", encoding="utf-8")
            meta = MOD.package_release(src, base / "ok", "emdash-1.6.0-real", "dist/server/entry.mjs")
            self.assertGreaterEqual(meta["file_count"], 6)

            # .env secret file must be refused so create-emdash secrets never enter bundles.
            (src / ".env").write_text("EMDASH_ENCRYPTION_KEY=secret\n", encoding="utf-8")
            with self.assertRaises(MOD.Refused):
                MOD.package_release(src, base / "bad-env", "emdash-1.6.0-bad", "dist/server/entry.mjs")
            (src / ".env").unlink()

            # .env.example is non-secret and permitted.
            (src / ".env.example").write_text("EMDASH_ENCRYPTION_KEY=\n", encoding="utf-8")
            meta2 = MOD.package_release(src, base / "ok-example", "emdash-1.6.0-ex", "dist/server/entry.mjs")
            self.assertGreaterEqual(meta2["file_count"], 7)


if __name__ == "__main__":
    unittest.main()
