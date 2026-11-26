"""Test the D-087 WordPress update watch tool (W531) without a network."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile


SCRIPT = Path(__file__).resolve().parents[2] / "packaging/wordpress-update-watch.py"
SPEC = importlib.util.spec_from_file_location("wordpress_update_watch", SCRIPT)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)

INVENTORY = {
    "user": "rs_blog1",
    "core": {"version": "7.1.3", "db_version": 61833, "db_current": True},
    "plugins": [
        {"folder": "akismet", "file": "akismet/akismet.php", "version": "5.7.1", "active": True},
        {"folder": "custom-premium", "file": "custom-premium/x.php", "version": "2.0", "active": True},
        {"folder": None, "file": "hello.php", "version": "1.7.2", "active": False},
        {"folder": "current-one", "file": "current-one/c.php", "version": "3.1", "active": True},
    ],
    "themes": [{"folder": "twentytwentyfour", "version": "1.5", "active": True}],
}

OFFERS = {"offers": [{"version": "7.2.1"}, {"version": "7.2.1"}, {"version": "7.1.5"},
                     {"version": "7.0.9"}]}


def fake_get(url: str):
    if "/core/version-check/" in url:
        return OFFERS
    if "plugin_information" in url:
        if "akismet" in url:
            return {"version": "5.7.2"}
        if "current-one" in url:
            return {"version": "3.1"}
        return {"error": "Plugin not found."}
    if "theme_information" in url and "twentytwentyfour" in url:
        return {"version": "1.6"}
    raise tool.Refused("unexpected")


def make_zip(folder: str, files: dict) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr(folder + "/", b"")
        for name, data in files.items():
            archive.writestr(f"{folder}/{name}", data)
    return out.getvalue()


class WatchTest(unittest.TestCase):
    def test_statuses_name_each_newer_release_and_skip_what_wordpress_org_lacks(self):
        found = {(s["kind"], s["slug"]): s for s in tool.statuses(INVENTORY, fake_get)}
        core = found[("core", "wordpress")]
        self.assertEqual((core["state"], core["to"], core["newer_branch"]), ("update", "7.1.5", "7.2.1"))
        self.assertEqual(found[("plugin", "akismet")]["to"], "5.7.2")
        self.assertEqual(found[("plugin", "custom-premium")]["state"], "unknown")
        self.assertEqual(found[("plugin", "current-one")]["state"], "current")
        self.assertNotIn(("plugin", "hello"), found)
        self.assertEqual(found[("theme", "twentytwentyfour")]["to"], "1.6")

    def test_versions_compare_as_numbers(self):
        self.assertTrue(tool.newer("1.9", "1.10"))
        self.assertTrue(tool.newer("7.1", "7.1.1"))
        self.assertFalse(tool.newer("7.1.0", "7.1"))
        self.assertIsNone(tool.newer("1.0-beta", "1.0"))

    def test_only_https_is_fetched(self):
        with self.assertRaises(tool.Refused):
            tool.fetch("http://api.wordpress.org/", 10)

    def test_prepare_builds_separate_core_and_extension_recipes(self):
        core_files = {"index.php": b"<?php\n", "wp-includes/version.php": b"<?php\n$wp_version = '7.1.5';\n"}
        core_zip = make_zip("wordpress", {**core_files, "wp-content/index.php": b"<?php\n"})
        plugin_files = {"akismet.php": b"<?php /* Version: 5.7.2 */\n"}
        plugin_zip = make_zip("akismet", plugin_files)
        theme_zip = make_zip("twentytwentyfour", {"style.css": b"/*\nVersion: 1.6\n*/\n"})

        def get_bytes(url: str, limit: int) -> bytes:
            md5 = lambda data: hashlib.md5(data, usedforsecurity=False).hexdigest()
            answers = {
                "https://wordpress.org/wordpress-7.1.5.zip": core_zip,
                "https://wordpress.org/wordpress-7.1.5.zip.sha1":
                    hashlib.sha1(core_zip, usedforsecurity=False).hexdigest().encode(),
                "https://api.wordpress.org/core/checksums/1.0/?version=7.1.5&locale=en_US": json.dumps(
                    {"checksums": {**{p: md5(d) for p, d in core_files.items()},
                                   "wp-content/index.php": md5(b"<?php\n")}}).encode(),
                "https://downloads.wordpress.org/plugin/akismet.5.7.2.zip": plugin_zip,
                "https://downloads.wordpress.org/plugin-checksums/akismet/5.7.2.json": json.dumps(
                    {"plugin": "akismet", "version": "5.7.2", "files": {
                        p: {"sha256": hashlib.sha256(d).hexdigest()} for p, d in plugin_files.items()}}).encode(),
                "https://downloads.wordpress.org/theme/twentytwentyfour.1.6.zip": theme_zip,
            }
            return answers[url]

        updates = [
            {"kind": "theme", "slug": "twentytwentyfour", "from": "1.5", "to": "1.6", "state": "update"},
            {"kind": "core", "slug": "wordpress", "from": "7.1.3", "to": "7.1.5", "state": "update"},
            {"kind": "plugin", "slug": "akismet", "from": "5.7.1", "to": "5.7.2", "state": "update"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            built = tool.prepare(updates, out, get_bytes)
            self.assertEqual([folder.name for folder in built], ["core", "extensions"])
            self.assertEqual((out / "core/components.txt").read_text(), "core wordpress 7.1.3 7.1.5\n")
            # Plugins come before themes, as the recipe orders them.
            self.assertEqual((out / "extensions/components.txt").read_text(),
                             "plugin akismet 5.7.1 5.7.2\ntheme twentytwentyfour 1.5 1.6\n")
            with tarfile.open(out / "extensions/recipe.tar") as tar:
                manifest = tar.extractfile("manifest").read()
            self.assertEqual((out / "extensions/recipe_digest").read_text(),
                             hashlib.sha256(manifest).hexdigest() + "\n")
            # The output folder must be new.
            with self.assertRaises(FileExistsError):
                tool.prepare(updates, out, get_bytes)


if __name__ == "__main__":
    unittest.main()
