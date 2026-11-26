"""Check SBOM input consistency through the checker and its public command."""

import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_sbom", ROOT / "scripts/release/sbom.py")
SBOM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SBOM)


class SbomTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generated = SBOM.generate()

    def setUp(self):
        self.bom = copy.deepcopy(self.generated)
        self.sqlite = next(c for c in self.bom["components"] if c["name"] == "sqlite")
        self.cargo = next(c for c in self.bom["components"] if c["name"] == "sha2")

    def assert_rejected(self):
        self.assertTrue(SBOM.check(self.bom), "changed SBOM must be rejected")

    def test_generated_sbom_passes(self):
        self.assertEqual(SBOM.check(self.bom), [])

    def test_missing_sqlite_is_rejected(self):
        self.bom["components"].remove(self.sqlite)
        self.assert_rejected()

    def test_changed_sqlite_version_is_rejected(self):
        self.sqlite["version"] = "0.0.0"
        self.assert_rejected()

    def test_changed_sqlite_archive_checksum_is_rejected(self):
        self.sqlite["hashes"][0]["content"] = "0" * 64
        self.assert_rejected()

    def test_changed_sqlite_hash_algorithm_is_rejected(self):
        self.sqlite["hashes"][0]["alg"] = "SHA-256"
        self.assert_rejected()

    def test_changed_sqlite_url_is_rejected(self):
        self.sqlite["externalReferences"][0]["url"] = "https://example.invalid/sqlite.zip"
        self.assert_rejected()

    def test_changed_sqlite_provenance_is_rejected(self):
        self.sqlite["properties"][0]["value"] = "unverified"
        self.assert_rejected()

    def test_duplicate_sqlite_is_rejected(self):
        self.bom["components"].append(copy.deepcopy(self.sqlite))
        self.assert_rejected()

    def test_duplicate_cargo_identity_is_rejected(self):
        self.bom["components"].append(copy.deepcopy(self.cargo))
        self.assert_rejected()

    def test_duplicate_cargo_cannot_hide_an_altered_checksum(self):
        duplicate = copy.deepcopy(self.cargo)
        self.cargo["hashes"][0]["content"] = "0" * 64
        self.bom["components"].append(duplicate)
        self.assert_rejected()

    def test_cargo_purl_must_match_name_and_version(self):
        self.cargo["purl"] = "pkg:cargo/other@0.0.0"
        self.assert_rejected()

    def test_cargo_reference_must_match_identity(self):
        self.cargo["bom-ref"] = "pkg:cargo/other@0.0.0"
        self.assert_rejected()

    def test_conflicting_cargo_hashes_are_rejected(self):
        self.cargo["hashes"].append({"alg": "SHA-256", "content": "0" * 64})
        self.assert_rejected()

    def test_unknown_non_cargo_component_is_rejected(self):
        self.bom["components"].append({"type": "library", "name": "untracked", "version": "1"})
        self.assert_rejected()

    def test_duplicate_lock_provenance_is_rejected(self):
        self.bom["metadata"]["properties"].append(
            copy.deepcopy(self.bom["metadata"]["properties"][0])
        )
        self.assert_rejected()

    def test_wrong_document_format_is_rejected(self):
        self.bom["bomFormat"] = "other"
        self.assert_rejected()

    def test_non_object_document_is_rejected(self):
        self.assertTrue(SBOM.check([]))

    def test_non_object_component_is_rejected(self):
        self.bom["components"].append(None)
        self.assert_rejected()

    def test_non_list_components_are_rejected(self):
        self.bom["components"] = {}
        self.assert_rejected()

    def test_malformed_json_command_refuses_without_traceback(self):
        with tempfile.TemporaryDirectory(prefix="rustiron-sbom-test-") as temporary:
            source = Path(temporary) / "invalid.json"
            source.write_text('{"CANARY_UNTRUSTED_SBOM":')
            result = subprocess.run(
                ["python3", str(ROOT / "scripts/release/sbom.py"), "check", str(source)],
                capture_output=True, text=True, timeout=10,
            )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("CANARY_UNTRUSTED_SBOM", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
