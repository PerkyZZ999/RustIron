"""Exercise the pinned offline CycloneDX validator through its public command."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/sbom_schema.py"
PYTHON = ROOT / "target/release-schema-env/bin/python"
FIXTURE = ROOT / "docs/validation/S10-W142/sbom.cdx.json"


class SbomSchemaTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rustiron-schema-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.source = self.directory / "bom.json"
        self.bom = json.loads(FIXTURE.read_text())

    def run_check(self, content=None):
        self.source.write_text(json.dumps(self.bom) if content is None else content)
        return subprocess.run(
            [str(PYTHON), "-I", str(SCRIPT), str(self.source)],
            capture_output=True, text=True, timeout=15,
        )

    def assert_invalid(self, content=None):
        result = self.run_check(content)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("CANARY_SCHEMA_INPUT", result.stdout + result.stderr)

    def test_preserved_w142_sbom_passes(self):
        self.assertEqual(self.run_check().returncode, 0)

    def test_wrong_spec_version_is_refused(self):
        self.bom["specVersion"] = "1.7"
        self.assert_invalid()

    def test_unknown_document_schema_is_refused(self):
        self.bom["$schema"] = "https://example.invalid/CANARY_SCHEMA_INPUT"
        self.assert_invalid()

    def test_unknown_property_is_refused_without_echo(self):
        self.bom["CANARY_SCHEMA_INPUT"] = "not a permitted property"
        self.assert_invalid()

    def test_invalid_component_type_is_refused(self):
        self.bom["components"][0]["type"] = "CANARY_SCHEMA_INPUT"
        self.assert_invalid()

    def test_invalid_date_time_format_is_refused(self):
        self.bom["metadata"]["timestamp"] = "CANARY_SCHEMA_INPUT"
        self.assert_invalid()

    def test_invalid_email_format_is_refused(self):
        self.bom["metadata"]["authors"] = [{"name": "fixture", "email": "CANARY_SCHEMA_INPUT"}]
        self.assert_invalid()

    def test_invalid_iri_format_is_refused(self):
        self.bom["components"][-1]["externalReferences"][0]["url"] = "http://[CANARY_SCHEMA_INPUT"
        self.assert_invalid()

    def test_pinned_spdx_reference_accepts_known_license(self):
        self.bom["components"][0]["licenses"] = [{"license": {"id": "MIT"}}]
        self.assertEqual(self.run_check().returncode, 0)

    def test_pinned_spdx_reference_rejects_unknown_license(self):
        self.bom["components"][0]["licenses"] = [{"license": {"id": "CANARY_SCHEMA_INPUT"}}]
        self.assert_invalid()

    def test_pinned_jsf_reference_accepts_signature_shape(self):
        self.bom["signature"] = {"algorithm": "RS256", "value": "fixture-not-a-real-signature"}
        self.assertEqual(self.run_check().returncode, 0)

    def test_jsf_algorithm_uri_format_is_enforced(self):
        self.bom["signature"] = {"algorithm": "CANARY_SCHEMA_INPUT", "value": "fixture"}
        self.assert_invalid()

    def test_duplicate_json_keys_are_refused(self):
        valid = json.dumps(self.bom)
        self.assert_invalid(valid.replace('"bomFormat": "CycloneDX"', '"bomFormat":"CycloneDX","bomFormat":"CycloneDX"', 1))

    def test_malformed_json_is_refused_without_echo(self):
        self.assert_invalid('{"CANARY_SCHEMA_INPUT":')

    def test_non_finite_json_number_is_refused(self):
        self.bom["components"][0]["evidence"] = {"identity": [{"field": "purl", "confidence": float("nan")}]}
        self.assert_invalid()

    def test_oversized_input_is_refused(self):
        valid = json.dumps(self.bom)
        self.assert_invalid(" " * (4 * 1024 * 1024 + 1 - len(valid)) + valid)

    def test_fifo_input_is_refused_without_blocking(self):
        os.mkfifo(self.source)
        result = subprocess.run([str(PYTHON), "-I", str(SCRIPT), str(self.source)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_altered_schema_bytes_are_refused(self):
        spec = importlib.util.spec_from_file_location("sbom_schema", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        copied = self.directory / "schemas"
        shutil.copytree(module.SCHEMAS, copied)
        schema = copied / "bom-1.6.schema.json"
        schema.write_bytes(schema.read_bytes() + b" ")
        with self.assertRaises(module.SchemaSetupError):
            module.load_schemas(copied)

    def test_missing_dependencies_have_a_setup_error(self):
        self.source.write_text(json.dumps(self.bom))
        result = subprocess.run([str(PYTHON), "-S", str(SCRIPT), str(self.source)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn("setup", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_registry_refuses_unpinned_file_resources(self):
        canary = self.directory / "private-schema.json"
        canary.write_text('{"type":"integer"}')
        driver = (
            "import runpy; module=runpy.run_path(" + repr(str(SCRIPT)) + "); "
            "module['schema_registry'](module['load_schemas']()).get_or_retrieve(" + repr(canary.as_uri()) + ")"
        )
        result = subprocess.run([str(PYTHON), "-I", "-c", driver], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn("NoSuchResource", result.stderr)


if __name__ == "__main__":
    unittest.main()
