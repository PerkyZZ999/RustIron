"""Reject changed upstream source and corrupted project-local native cache."""
import importlib.util,json,pathlib,shutil,tempfile,unittest,hashlib
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('sqlite_build',ROOT/'scripts/prepare_sqlite.py')
BUILD=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(BUILD)

class SQLiteBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive=(ROOT/'target/native-download'/BUILD.PIN['archive']).read_bytes()

    def test_append_to_valid_archive_is_rejected_before_extraction(self):
        with self.assertRaisesRegex(ValueError,'archive checksum'):
            BUILD.verify_archive(self.archive+b'changed')

    def test_independent_amalgamation_checksum_is_enforced(self):
        with patch.dict(BUILD.PIN,{'source_sha3_256':'0'*64}):
            with self.assertRaisesRegex(ValueError,'amalgamation checksum'):
                BUILD.verify_archive(self.archive)

    def test_native_cache_checks_all_generated_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            copied=pathlib.Path(temp)/'cache';shutil.copytree(BUILD.DEST,copied)
            (copied/'lib/libsqlite3.a').write_bytes(b'changed native library')
            with self.assertRaisesRegex(ValueError,'artifact checksum'):
                BUILD.check_cache(copied)

    def test_cache_manifest_cannot_name_other_files(self):
        with tempfile.TemporaryDirectory() as temp:
            dest=pathlib.Path(temp)/'cache';dest.mkdir();canary=pathlib.Path(temp)/'INPUT_CANARY';canary.write_bytes(b'known fixture')
            receipt=json.loads((BUILD.DEST/'receipt.json').read_text());receipt['artifacts']={'../INPUT_CANARY':hashlib.sha256(canary.read_bytes()).hexdigest()};(dest/'receipt.json').write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError,'Unexpected native artifacts'):
                BUILD.check_cache(dest)

    def test_pin_change_refuses_cached_native_input(self):
        with tempfile.TemporaryDirectory() as temp:
            dest=pathlib.Path(temp)/'cache';shutil.copytree(BUILD.DEST,dest);receipt=json.loads((dest/'receipt.json').read_text());receipt['pin_sha256']='0'*64
            (dest/'receipt.json').write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError,'pin changed'):
                BUILD.check_cache(dest)

    def test_explicit_build_destination_checks_its_own_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = pathlib.Path(temp) / 'isolated'
            shutil.copytree(BUILD.DEST, dest)
            expected = json.loads((dest / 'receipt.json').read_text())
            self.assertEqual(BUILD.prepare(False, dest), expected)

    def test_explicit_build_destination_refuses_corrupt_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = pathlib.Path(temp) / 'isolated'
            shutil.copytree(BUILD.DEST, dest)
            (dest / 'lib/libsqlite3.a').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'artifact checksum'):
                BUILD.prepare(False, dest)
