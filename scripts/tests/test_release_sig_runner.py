"""Exercise the public synthetic test runner with real artifact trees."""

import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "release/release_sig_test.sh"


class ReleaseRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rustiron-runner-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source artifacts"
        self.source.mkdir()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()

    @staticmethod
    def snapshot(directory):
        result = {}
        for path in directory.rglob("*"):
            info = path.lstat()
            content = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
            link = os.readlink(path) if stat.S_ISLNK(info.st_mode) else None
            result[path.relative_to(directory).as_posix()] = (info.st_mode, info.st_nlink, content, link)
        return result

    def run_helper(self, source=True):
        arguments = [str(SCRIPT)] + ([str(self.source)] if source else [])
        process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env={**os.environ, "TMPDIR": str(self.scratch)},
                                   start_new_session=True)
        try:
            output, error = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            self.fail("signature test runner blocked on its artifact input")
        self.assertEqual(list(self.scratch.iterdir()), [], "temporary keys/copies were not cleaned")
        return process.returncode, output, error

    def assert_passes_without_source_changes(self):
        before = self.snapshot(self.source)
        code, output, error = self.run_helper()
        self.assertEqual(code, 0, output + error)
        self.assertIn("release_sig_test: PASS", output)
        self.assertEqual(output.count("ok  "), 7, output)
        self.assertEqual(self.snapshot(self.source), before)
        return output

    def assert_refused(self):
        before = self.snapshot(self.source)
        code, output, error = self.run_helper()
        self.assertEqual(code, 1, output + error)
        self.assertNotIn("release_sig_test: PASS", output)
        self.assertNotIn("CANARY_INPUT_NAME", output + error)
        self.assertEqual(self.snapshot(self.source), before)

    def test_default_seven_cases_still_pass(self):
        code, output, error = self.run_helper(source=False)
        self.assertEqual(code, 0, output + error)
        self.assertEqual(output.count("ok  "), 7, output)
        self.assertIn("release_sig_test: PASS", output)

    def test_nested_spaced_tree_is_complete_and_preserved(self):
        (self.source / "root.txt").write_text("root")
        nested = self.source / "support files"
        nested.mkdir()
        (nested / "release notes.txt").write_text("notes")
        (nested / "binary").write_bytes(b"fixture binary")
        output = self.assert_passes_without_source_changes()
        self.assertIn("artifacts: 3", output)

    def test_hidden_only_artifact_is_exercised(self):
        (self.source / ".hidden").write_bytes(b"hidden payload")
        self.assert_passes_without_source_changes()

    def test_root_metadata_is_refreshed_and_nested_metadata_remains_payload(self):
        (self.source / "SHA256SUMS").write_text("old manifest")
        (self.source / "SHA256SUMS.sig").write_text("old signature")
        nested = self.source / "metadata"
        nested.mkdir()
        (nested / "SHA256SUMS").write_text("nested payload")
        (nested / "SHA256SUMS.sig").write_text("nested signature payload")
        output = self.assert_passes_without_source_changes()
        self.assertIn("artifacts: 2", output)

    def test_regular_source_hardlinks_are_copied_independently(self):
        artifact = self.source / "binary"
        artifact.write_bytes(b"hardlinked raw artifact")
        os.link(artifact, self.source / "alias")
        self.assert_passes_without_source_changes()
        self.assertEqual(artifact.stat().st_nlink, 2)

    def test_readonly_source_modes_are_preserved_while_copies_are_tested(self):
        nested = self.source / "readonly"
        nested.mkdir()
        artifact = nested / "binary"
        artifact.write_bytes(b"readonly artifact")
        artifact.chmod(0o444)
        nested.chmod(0o555)
        self.source.chmod(0o555)
        self.assert_passes_without_source_changes()
        self.assertEqual(stat.S_IMODE(self.source.stat().st_mode), 0o555)

    def test_file_symlink_is_not_silently_followed(self):
        outside = self.root / "outside"
        outside.write_text("outside")
        (self.source / "CANARY_INPUT_NAME").symlink_to(outside)
        self.assert_refused()

    def test_directory_symlink_is_refused(self):
        (self.source / "CANARY_INPUT_NAME").symlink_to(self.root, target_is_directory=True)
        self.assert_refused()

    def test_fifo_is_refused_without_blocking(self):
        os.mkfifo(self.source / "CANARY_INPUT_NAME")
        self.assert_refused()

    def test_root_directory_symlink_is_refused(self):
        (self.source / "binary").write_text("payload")
        link = self.root / "linked root"
        link.symlink_to(self.source, target_is_directory=True)
        self.source = link
        self.assert_refused()

    def test_empty_tree_is_refused(self):
        self.assert_refused()

    def test_linked_root_metadata_is_not_hidden_by_refresh(self):
        (self.source / "binary").write_text("payload")
        outside = self.root / "old metadata"
        outside.write_text("old metadata")
        (self.source / "SHA256SUMS").symlink_to(outside)
        self.assert_refused()

    def test_executable_artifacts_are_never_run(self):
        sentinel = self.root / "executed"
        artifact = self.source / "executable"
        artifact.write_text("#!/bin/sh\ntouch '" + str(sentinel) + "'\nexit 98\n")
        artifact.chmod(0o755)
        self.assert_passes_without_source_changes()
        self.assertFalse(sentinel.exists())


if __name__ == "__main__":
    unittest.main()
