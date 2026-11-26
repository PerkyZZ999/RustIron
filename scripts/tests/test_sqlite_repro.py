"""Check native reproducibility results independently of cache consistency."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sqlite_repro", ROOT / "scripts/release/sqlite_repro.py")
REPRO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPRO)


class SQLiteReproTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rustiron-native-repro-")
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        shutil.copytree(REPRO.BUILD.DEST, self.output / "a")
        shutil.copytree(REPRO.BUILD.DEST, self.output / "b")

    def test_identical_verified_caches_match(self):
        result = REPRO.compare(self.output)
        self.assertEqual(result["status"], "reproducible")
        self.assertEqual(result["differences"], [])

    def test_different_but_internally_consistent_builds_do_not_match(self):
        changed = self.output / "b/lib/libsqlite3.a"
        changed.write_bytes(changed.read_bytes() + b"deliberate regression")
        receipt = self.output / "b/receipt.json"
        record = json.loads(receipt.read_text())
        record["artifacts"]["lib/libsqlite3.a"] = hashlib.sha256(changed.read_bytes()).hexdigest()
        receipt.write_text(json.dumps(record))
        result = REPRO.compare(self.output)
        self.assertEqual(result["status"], "different")
        self.assertEqual(result["differences"], ["lib/libsqlite3.a"])

    def test_corrupt_artifact_cannot_pass_with_a_stale_receipt(self):
        (self.output / "b/lib/libsqlite3.a").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "artifact checksum"):
            REPRO.compare(self.output)

    def test_missing_artifact_is_not_a_reproducible_build(self):
        (self.output / "b/include/sqlite3.h").unlink()
        with self.assertRaises(FileNotFoundError):
            REPRO.compare(self.output)

    def test_existing_output_is_preserved(self):
        sentinel = self.output / "sentinel"
        sentinel.write_bytes(b"preserve existing data")
        with self.assertRaises(FileExistsError):
            REPRO.build(self.output)
        self.assertEqual(sentinel.read_bytes(), b"preserve existing data")


if __name__ == "__main__":
    unittest.main()
