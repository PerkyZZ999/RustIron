"""Test the D-084 WordPress update recipe tool (W513) without a host or network."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


SCRIPT = Path(__file__).resolve().parents[2] / "packaging/wordpress-update-recipe.py"
SPEC = importlib.util.spec_from_file_location("wordpress_update_recipe", SCRIPT)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)

PLUGIN = {"hello.php": b"<?php\n/* Plugin Name: Hello\nVersion: 1.7.2 */\n", "readme.txt": b"readme\n"}
THEME = {"style.css": b"/*\nTheme Name: T\n * Version: 1.3\n*/\n", "index.php": b"<?php\n",
         "parts/header.html": b"<header/>\n"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_zip(slug: str, files: dict, extra=(), symlink=None) -> bytes:
    out = io.BytesIO()
    # A fixed entry time: two builds a second apart give the same bytes.
    def entry(name: str) -> zipfile.ZipInfo:
        return zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))

    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr(entry(slug + "/"), b"")
        for name, data in sorted(files.items(), reverse=True):
            archive.writestr(entry(f"{slug}/{name}"), data)
        for name, data in extra:
            archive.writestr(entry(name), data)
        if symlink:
            info = entry(f"{slug}/{symlink}")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b"/etc/passwd")
    return out.getvalue()


def checksums(slug: str, version: str, files: dict) -> bytes:
    return json.dumps({"plugin": slug, "version": version,
                       "files": {path: {"md5": "x", "sha256": sha(data)} for path, data in files.items()}}).encode()


def plugin_entry(**changes):
    entry = {"kind": "plugin", "slug": "hello-dolly", "version": "1.7.2",
             "zip": make_zip("hello-dolly", PLUGIN), "list": checksums("hello-dolly", "1.7.2", PLUGIN)}
    entry.update(changes)
    return (entry["kind"], entry["slug"], entry["version"], entry["zip"], entry["list"])


def theme_entry(**changes):
    entry = {"kind": "theme", "slug": "twentytwentyfour", "version": "1.3",
             "zip": make_zip("twentytwentyfour", THEME), "list": None}
    entry.update(changes)
    return (entry["kind"], entry["slug"], entry["version"], entry["zip"], entry["list"])


CORE = {"index.php": b"<?php\nrequire 'wp-blog-header.php';\n",
        "wp-admin/about.php": b"<?php\n",
        "wp-includes/version.php": b"<?php\n$wp_version = '7.1.5';\n$wp_db_version = 60717;\n"}
CORE_CONTENT = {"wp-content/index.php": b"<?php\n", "wp-content/themes/t/style.css": b"/* Theme */\n"}


def sha1(data: bytes) -> str:
    return hashlib.sha1(data, usedforsecurity=False).hexdigest()


def md5(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def core_list(files: dict, nested_version=None) -> bytes:
    listed = {path: md5(data) for path, data in files.items()}
    return json.dumps({"checksums": {nested_version: listed} if nested_version else listed}).encode()


def core_entry(**changes):
    every = {**CORE, **CORE_CONTENT}
    archive = make_zip("wordpress", every)
    entry = {"kind": "core", "slug": "wordpress", "version": "7.1.5", "zip": archive,
             "list": core_list(every), "published": f"{sha1(archive)}\n".encode()}
    entry.update(changes)
    return (entry["kind"], entry["slug"], entry["version"], entry["zip"], entry["list"], entry["published"])


class RecipeTest(unittest.TestCase):
    def test_the_recipe_is_deterministic_and_binds_every_file_through_the_manifest(self):
        recipe, manifest = tool.build([plugin_entry(), theme_entry()])
        again, _ = tool.build([plugin_entry(), theme_entry()])
        self.assertEqual(recipe, again)
        lines = manifest.decode().splitlines()
        self.assertEqual(lines[0], "rustiron-wordpress-update/1")
        plugin_listing = "".join(f"{sha(PLUGIN[p])}  {p}\n" for p in sorted(PLUGIN)).encode()
        self.assertEqual(lines[1], "plugin hello-dolly 1.7.2 "
                         f"{sha(make_zip('hello-dolly', PLUGIN))} {sha(plugin_listing)}")
        self.assertTrue(lines[2].startswith("theme twentytwentyfour 1.3 "))
        with tarfile.open(fileobj=io.BytesIO(recipe)) as tar:
            members = tar.getmembers()
            self.assertEqual(members[0].name, "manifest")
            self.assertEqual(tar.extractfile(members[0]).read(), manifest)
            names = [member.name for member in members]
            self.assertEqual(names[1:4], ["plugin-hello-dolly.files", "plugin/hello-dolly/hello.php",
                                          "plugin/hello-dolly/readme.txt"])
            self.assertIn("theme/twentytwentyfour/parts/header.html", names)
            self.assertEqual(tar.extractfile("plugin-hello-dolly.files").read(), plugin_listing)
            for member in members:
                self.assertTrue(member.isreg())
                self.assertEqual((member.mode, member.mtime, member.uid, member.gid, member.uname),
                                 (0o644, 0, 0, 0, ""))

    def test_each_refusal_names_no_content(self):
        cases = [
            [],
            [plugin_entry()] * 2,
            [plugin_entry(kind="core")],
            [plugin_entry(slug="../x")],
            [plugin_entry(slug="Hello")],
            [plugin_entry(version="v2")],
            [plugin_entry(version="1..2")],
            [plugin_entry(list=None)],
            [plugin_entry(list=checksums("hello-dolly", "1.7.1", PLUGIN))],
            [plugin_entry(list=checksums("other", "1.7.2", PLUGIN))],
            [plugin_entry(list=checksums("hello-dolly", "1.7.2", {**PLUGIN, "extra.php": b"x"}))],
            [plugin_entry(zip=make_zip("hello-dolly", {**PLUGIN, "hello.php": b"changed"}))],
            [plugin_entry(zip=make_zip("hello-dolly", PLUGIN, extra=[("other/x.php", b"x")]))],
            [plugin_entry(zip=make_zip("hello-dolly", PLUGIN, symlink="link"))],
            [plugin_entry(zip=make_zip("hello-dolly", {**PLUGIN, "a b.php": b"x"}))],
            [plugin_entry(zip=b"not a zip")],
            [theme_entry(version="1.2")],
            [theme_entry(list=b"{}")],
            [theme_entry(zip=make_zip("twentytwentyfour", {"index.php": b"<?php\n"}))],
            [plugin_entry(slug=f"p{n}") for n in range(9)],
        ]
        for components in cases:
            with self.assertRaises(tool.Refused, msg=str(components)[:80]):
                tool.build(components)

    def test_names_from_real_releases_are_accepted(self):
        # W518-F1: Akismet ships `logo@2x.png`; Twenty Twenty-Four ships
        # variable fonts named with a comma.
        files = {**PLUGIN, "_inc/img/logo@2x.png": b"png", "fonts/A_wdth,wght.woff2": b"f"}
        entry = plugin_entry(zip=make_zip("hello-dolly", files),
                             list=checksums("hello-dolly", "1.7.2", files))
        recipe, _ = tool.build([entry])
        with tarfile.open(fileobj=io.BytesIO(recipe)) as tar:
            self.assertIn("plugin/hello-dolly/fonts/A_wdth,wght.woff2", tar.getnames())

    def test_a_plugin_and_a_theme_may_share_a_slug(self):
        same = make_zip("hello-dolly", THEME)
        _, manifest = tool.build([plugin_entry(), theme_entry(slug="hello-dolly", zip=same)])
        self.assertEqual(len(manifest.decode().splitlines()), 3)

    def test_the_command_writes_once_and_prints_the_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "p.zip").write_bytes(make_zip("hello-dolly", PLUGIN))
            (folder / "p.json").write_bytes(checksums("hello-dolly", "1.7.2", PLUGIN))
            (folder / "t.zip").write_bytes(make_zip("twentytwentyfour", THEME))
            out = folder / "out"
            out.mkdir()
            command = [sys.executable, "-I", str(SCRIPT), str(out), "--plugin", "hello-dolly", "1.7.2",
                       str(folder / "p.zip"), str(folder / "p.json"),
                       "--theme", "twentytwentyfour", "1.3", str(folder / "t.zip")]
            first = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            recipe = (out / "recipe.tar").read_bytes()
            with tarfile.open(fileobj=io.BytesIO(recipe)) as tar:
                manifest = tar.extractfile("manifest").read()
            self.assertIn(f"recipe_digest {sha(manifest)}\n", first.stdout)
            self.assertIn(f"recipe_sha256 {sha(recipe)}  recipe.tar\n", first.stdout)
            again = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(again.returncode, 1)
            self.assertIn("exists", again.stderr)
            self.assertEqual((out / "recipe.tar").read_bytes(), recipe)

    def test_a_core_release_is_checked_and_leaves_wp_content_out(self):
        # W525 (D-086).
        recipe, manifest = tool.build([core_entry()])
        lines = manifest.decode().splitlines()
        listing = "".join(f"{sha(CORE[p])}  {p}\n" for p in sorted(CORE)).encode()
        archive = make_zip("wordpress", {**CORE, **CORE_CONTENT})
        self.assertEqual(lines[1], f"core wordpress 7.1.5 {sha(archive)} {sha(listing)}")
        with tarfile.open(fileobj=io.BytesIO(recipe)) as tar:
            names = tar.getnames()
        self.assertIn("core/wordpress/wp-admin/about.php", names)
        self.assertIn("core-wordpress.files", names)
        self.assertFalse(any("wp-content" in name for name in names))
        # The API nests the list under the version without a locale.
        nested = core_list({**CORE, **CORE_CONTENT}, nested_version="7.1.5")
        self.assertEqual(tool.build([core_entry(list=nested)])[1], manifest)

    def test_each_core_refusal_names_no_content(self):
        every = {**CORE, **CORE_CONTENT}
        changed = {**every, "wp-admin/about.php": b"<?php // changed\n"}
        cases = [
            [core_entry(published=b"0" * 40)],
            # W528-F1: a SHA-256, or the archive itself, is not the published SHA-1.
            [core_entry(published=sha(make_zip("wordpress", {**CORE, **CORE_CONTENT})).encode())],
            [core_entry(published=make_zip("wordpress", {**CORE, **CORE_CONTENT}))],
            [core_entry(published=b"")],
            [core_entry(published=None)],
            [core_entry(slug="core")],
            [core_entry(list=None)],
            [core_entry(list=core_list({**every, "wp-admin/extra.php": b"x"}))],
            [core_entry(list=core_list({k: v for k, v in every.items() if k != "index.php"}))],
            [core_entry(zip=make_zip("wordpress", changed), list=core_list(every),
                        published=f"{sha1(make_zip('wordpress', changed))}".encode())],
            [core_entry(version="7.1.4")],
            [core_entry(list=json.dumps({"checksums": {"index.php": "x"}}).encode())],
            [core_entry(), plugin_entry()],
            [plugin_entry() + (b"0" * 64,)],
        ]
        for components in cases:
            with self.assertRaises(tool.Refused, msg=str(components)[:80]):
                tool.build(components)

    def test_the_command_builds_a_core_recipe(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            archive = make_zip("wordpress", {**CORE, **CORE_CONTENT})
            (folder / "w.zip").write_bytes(archive)
            (folder / "w.zip.sha1").write_bytes(sha1(archive).encode())
            (folder / "c.json").write_bytes(core_list({**CORE, **CORE_CONTENT}))
            out = folder / "out"
            out.mkdir()
            done = subprocess.run([sys.executable, "-I", str(SCRIPT), str(out), "--core", "7.1.5",
                                   str(folder / "w.zip"), str(folder / "w.zip.sha1"), str(folder / "c.json")],
                                  capture_output=True, text=True, check=False)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("core wordpress 7.1.5 ", done.stdout)


if __name__ == "__main__":
    unittest.main()
