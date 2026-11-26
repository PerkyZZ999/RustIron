"""Test the page-cache recipe preparation (W368) without a host or network."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
import zipfile


SCRIPT = Path(__file__).resolve().parents[2] / "packaging/page-cache-recipe.py"
SPEC = importlib.util.spec_from_file_location("page_cache_recipe", SCRIPT)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)

FILES = {
    "litespeed-cache.php": b"<?php // main\n",
    "readme.txt": b"=== readme ===\n",
    "src/base.cls.php": b"<?php // base\n",
    "data/const.default.json": b"{}\n",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_zip(files: dict, extra=(), symlink=None, prefix="litespeed-cache/") -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr(prefix, b"")
        for name, data in sorted(files.items(), reverse=True):
            archive.writestr(prefix + name, data)
        for name, data in extra:
            archive.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(prefix + symlink)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b"/etc/passwd")
    return out.getvalue()


def make_list(files: dict, plugin="litespeed-cache", version="7.9.3") -> bytes:
    listed = {name: {"md5": hashlib.md5(data).hexdigest(), "sha256": sha(data)}
              for name, data in files.items()}
    return json.dumps({"plugin": plugin, "version": version, "source": "x", "zip": "y",
                       "files": listed}).encode()


def convert(zip_bytes: bytes, list_bytes: bytes, **pins):
    arguments = {"zip_sha256": sha(zip_bytes), "list_sha256": sha(list_bytes),
                 "plugin": "litespeed-cache", "version": "7.9.3"}
    arguments.update(pins)
    return tool.convert(zip_bytes, list_bytes, **arguments)


class PageCacheRecipeTest(unittest.TestCase):
    def test_the_pins_are_the_reviewed_7_9_3_values(self):
        self.assertEqual(tool.VERSION, "7.9.3")
        self.assertEqual(tool.ZIP_SHA256,
                         "8ab0373e41a3e9d4329d8fa6f99f3afd096cc21ac2befb0a84dc005d8afb36d7")
        self.assertEqual(tool.LIST_SHA256,
                         "41dc8e796d55435e69abefd7274c075c694c2a7f451084095be9bfd38112d982")
        self.assertEqual(tool.TAR_NAME, "litespeed-cache-7.9.3.tar")
        self.assertEqual(tool.LIST_NAME, "litespeed-cache-7.9.3.checksums.json")

    def test_the_tar_holds_exactly_the_listed_files_with_fixed_metadata(self):
        tar_bytes = convert(make_zip(FILES), make_list(FILES))
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            members = archive.getmembers()
            self.assertEqual([m.name for m in members],
                             sorted("litespeed-cache/" + name for name in FILES))
            for member in members:
                self.assertTrue(member.isreg())
                self.assertEqual((member.mode, member.mtime, member.uid, member.gid),
                                 (0o644, 0, 0, 0))
                self.assertEqual((member.uname, member.gname), ("", ""))
                name = member.name.removeprefix("litespeed-cache/")
                self.assertEqual(archive.extractfile(member).read(), FILES[name])
        self.assertEqual(len(tar_bytes) % 10240, 0)

    def test_the_same_input_gives_the_same_bytes(self):
        zip_bytes, list_bytes = make_zip(FILES), make_list(FILES)
        self.assertEqual(convert(zip_bytes, list_bytes), convert(zip_bytes, list_bytes))
        reordered = make_zip(dict(reversed(list(FILES.items()))))
        self.assertEqual(convert(zip_bytes, list_bytes), convert(reordered, list_bytes))

    def test_wrong_pins_refuse(self):
        zip_bytes, list_bytes = make_zip(FILES), make_list(FILES)
        for pins in ({"zip_sha256": "0" * 64}, {"list_sha256": "0" * 64},
                     {"version": "7.9.4"}, {"plugin": "other"}):
            with self.subTest(pins=pins), self.assertRaises(tool.Refused):
                convert(zip_bytes, list_bytes, **pins)

    def test_the_archive_must_match_the_list_exactly(self):
        listed = make_list(FILES)
        changed = dict(FILES, **{"readme.txt": b"changed\n"})
        fewer = {k: v for k, v in FILES.items() if k != "readme.txt"}
        cases = {
            "changed bytes": make_zip(changed),
            "missing file": make_zip(fewer),
            "extra file": make_zip(dict(FILES, **{"evil.php": b"<?php\n"})),
            "outside the plugin folder": make_zip(FILES, extra=[("other/x.php", b"x")]),
            "link": make_zip(FILES, symlink="link.php"),
            "traversal": make_zip(FILES, extra=[("litespeed-cache/../x.php", b"x")]),
            "wrong top folder": make_zip(FILES, prefix="litespeed/"),
        }
        for name, zip_bytes in cases.items():
            with self.subTest(name), self.assertRaises(tool.Refused):
                convert(zip_bytes, listed)

    def test_the_list_must_be_closed_and_safe(self):
        zip_bytes = make_zip(FILES)
        bad_lists = [
            b"not json",
            json.dumps({"plugin": "litespeed-cache", "version": "7.9.3"}).encode(),
            json.dumps({"plugin": "litespeed-cache", "version": "7.9.3",
                        "files": {"a.php": {"sha256": ["0" * 64]}}}).encode(),
            json.dumps({"plugin": "litespeed-cache", "version": "7.9.3",
                        "files": {"/abs.php": {"sha256": "0" * 64}}}).encode(),
            json.dumps({"plugin": "litespeed-cache", "version": "7.9.3",
                        "files": {"a/../b.php": {"sha256": "0" * 64}}}).encode(),
            json.dumps({"plugin": "litespeed-cache", "version": "7.9.3",
                        "files": {"a b.php": {"sha256": "0" * 64}}}).encode(),
            json.dumps({"plugin": "litespeed-cache", "version": "7.9.3", "files": {}}).encode(),
        ]
        for list_bytes in bad_lists:
            with self.subTest(list_bytes=list_bytes[:40]), self.assertRaises(tool.Refused):
                convert(zip_bytes, list_bytes)

    def test_main_writes_both_files_with_fixed_modes(self):
        zip_bytes, list_bytes = make_zip(FILES), make_list(FILES)
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            (work / "in.zip").write_bytes(zip_bytes)
            (work / "list.json").write_bytes(list_bytes)
            out = work / "out"
            out.mkdir(mode=0o700)
            digest = tool.prepare(work / "in.zip", work / "list.json", out,
                                  zip_sha256=sha(zip_bytes), list_sha256=sha(list_bytes))
            tar_path, list_path = out / tool.TAR_NAME, out / tool.LIST_NAME
            self.assertEqual(digest, sha(tar_path.read_bytes()))
            self.assertEqual(list_path.read_bytes(), list_bytes)
            for path in (tar_path, list_path):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            with self.assertRaises(tool.Refused):
                tool.prepare(work / "in.zip", work / "list.json", out,
                             zip_sha256=sha(zip_bytes), list_sha256=sha(list_bytes))


if __name__ == "__main__":
    unittest.main()
