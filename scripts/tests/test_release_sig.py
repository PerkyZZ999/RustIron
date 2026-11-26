"""Exercise the public release verifier with real synthetic SSH signatures."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "release/release_sig.sh"


class ReleaseSignatureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rustiron-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.release = self.root / "release"
        self.release.mkdir()
        self.artifact = self.release / "rustiron"
        self.artifact.write_bytes(b"release fixture\n")
        self.key = self.root / "key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True, capture_output=True,
        )
        self.allowed = self.root / "allowed"
        self.allowed.write_text("release-test " + self.key.with_suffix(".pub").read_text())
        self.run_tool("manifest")
        self.run_tool("sign", self.key)

    def run_tool(self, command, *arguments, check=True):
        return subprocess.run(
            [str(SCRIPT), command, str(self.release), *map(str, arguments)],
            check=check, capture_output=True, text=True, timeout=10,
        )

    def verify(self):
        return self.run_tool("verify", self.allowed, "release-test", check=False)

    def sign_manifest(self, content):
        (self.release / "SHA256SUMS").write_text(content)
        (self.release / "SHA256SUMS.sig").unlink()
        subprocess.run(
            ["ssh-keygen", "-q", "-Y", "sign", "-n", "rustiron-release-v1",
             "-f", str(self.key), str(self.release / "SHA256SUMS")],
            check=True, capture_output=True,
        )

    def assert_rejected(self):
        result = self.verify()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REJECTED:", result.stdout)

    def test_untouched_release_verifies(self):
        self.assertEqual(self.verify().stdout, "VERIFIED\n")

    def test_added_symlink_is_rejected(self):
        (self.release / "extra").symlink_to(self.artifact)
        self.assert_rejected()

    def test_artifact_replaced_by_symlink_to_identical_bytes_is_rejected(self):
        outside = self.root / "outside"
        outside.write_bytes(self.artifact.read_bytes())
        self.artifact.unlink()
        self.artifact.symlink_to(outside)
        self.assert_rejected()

    def test_added_directory_symlink_is_rejected(self):
        (self.release / "extra").symlink_to(self.root, target_is_directory=True)
        self.assert_rejected()

    def test_added_fifo_is_rejected_without_blocking(self):
        os.mkfifo(self.release / "extra")
        self.assert_rejected()

    def test_hardlinked_artifact_is_rejected(self):
        os.link(self.artifact, self.root / "outside")
        self.assert_rejected()

    def test_symlinked_manifest_is_rejected(self):
        manifest = self.release / "SHA256SUMS"
        outside = self.root / "manifest"
        manifest.rename(outside)
        manifest.symlink_to(outside)
        self.assert_rejected()

    def test_symlinked_signature_is_rejected(self):
        signature = self.release / "SHA256SUMS.sig"
        outside = self.root / "signature"
        signature.rename(outside)
        signature.symlink_to(outside)
        self.assert_rejected()

    def test_nested_metadata_names_are_hashed(self):
        nested = self.release / "nested"
        nested.mkdir()
        (nested / "SHA256SUMS").write_text("nested artifact")
        self.run_tool("manifest")
        (self.release / "SHA256SUMS.sig").unlink()
        self.run_tool("sign", self.key)
        self.assertEqual(self.verify().returncode, 0)
        (nested / "SHA256SUMS").write_text("tampered artifact")
        self.assert_rejected()

    def test_nested_path_with_spaces_verifies(self):
        nested = self.release / "support files"
        nested.mkdir()
        (nested / "release notes.txt").write_text("release notes")
        self.run_tool("manifest")
        (self.release / "SHA256SUMS.sig").unlink()
        self.run_tool("sign", self.key)
        self.assertEqual(self.verify().returncode, 0)

    def test_signed_traversal_manifest_is_rejected(self):
        outside = self.root / "outside"
        outside.write_bytes(b"outside fixture")
        digest = hashlib.sha256(outside.read_bytes()).hexdigest()
        self.sign_manifest(f"{digest}  ../outside\n")
        self.assert_rejected()

    def test_manifest_generation_refuses_links(self):
        (self.release / "extra").symlink_to(self.artifact)
        result = self.run_tool("manifest", check=False)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_signing_refuses_changed_contents(self):
        self.artifact.write_bytes(b"changed")
        (self.release / "SHA256SUMS.sig").unlink()
        result = self.run_tool("sign", self.key, check=False)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse((self.release / "SHA256SUMS.sig").exists())


if __name__ == "__main__":
    unittest.main()
