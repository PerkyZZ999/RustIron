"""Real ssh-keygen unit and end-to-end tests for bundle_release.py and rustiron-updater.py (W647)."""

import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    path = REPO_ROOT / rel
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


bundler = _load("bundle_release_testmod", "scripts/release/bundle_release.py")
updater = _load("rustiron_updater_testmod", "packaging/rustiron-updater.py")


class ReleaseBundleAndUpdaterTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="rustiron-w647-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

        # Generate real Ed25519 signing keys (trusted + untrusted).
        self.keys_dir = self.tmp / "keys"
        self.keys_dir.mkdir(mode=0o700)
        self.release_key = self.keys_dir / "release_ed25519"
        self.other_key = self.keys_dir / "other_ed25519"
        for k in (self.release_key, self.other_key):
            subprocess.run(
                ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(k)],
                check=True,
                stdin=subprocess.DEVNULL,
            )
        pub = self.release_key.with_suffix(".pub").read_text().split()
        self.allowed_signers = self.keys_dir / "release_allowed_signers"
        self.allowed_signers.write_text(f"rustiron-release {pub[0]} {pub[1]}\n")
        self.allowed_signers.chmod(0o400)

        # Create a minimal staged management_root signed in rustiron-release-v1.
        self.mgmt = self.tmp / "management"
        self.mgmt.mkdir(mode=0o700)
        (self.mgmt / "usr/bin").mkdir(parents=True)
        (self.mgmt / "usr/bin/rustiron").write_bytes(b"#!/bin/sh\necho rustiron-v0.2.0\n")
        (self.mgmt / "usr/bin/rustiron").chmod(0o755)
        (self.mgmt / "usr/share/rustiron").mkdir(parents=True)
        (self.mgmt / "usr/share/rustiron/marker.txt").write_bytes(b"release-marker\n")
        fd = os.open(self.mgmt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            sums = bundler.release_manifest.canonical_manifest(fd)
        finally:
            os.close(fd)
        (self.mgmt / "SHA256SUMS").write_bytes(sums)
        bundler.sign_file(self.mgmt / "SHA256SUMS", self.release_key)

        # Create a synthetic console directory with runtime artifacts that MUST be excluded.
        self.console_src = self.tmp / "console-src"
        (self.console_src / "src").mkdir(parents=True)
        (self.console_src / "public").mkdir()
        (self.console_src / "node_modules/pkg").mkdir(parents=True)
        (self.console_src / "package.json").write_text('{"name":"rustiron-console","version":"0.2.0"}\n')
        (self.console_src / "bun.lock").write_text("lock-v2\n")
        (self.console_src / "src/server.ts").write_text("export const version = '0.2.0';\n")
        (self.console_src / "public/favicon.svg").write_text("<svg/>\n")
        (self.console_src / "node_modules/pkg/index.js").write_text("should-not-be-packed\n")
        (self.console_src / "auth.sqlite").write_text("secret-db-never-pack\n")
        (self.console_src / ".env").write_text("SECRET=never-pack\n")

        self.sbom = self.tmp / "sbom.cdx.json"
        self.sbom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6"}\n')

    def run_cli(self, mod, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = mod.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_pack_sign_verify_reproducible_and_excludes_secrets(self):
        out1 = self.tmp / "out1"
        out2 = self.tmp / "out2"
        r1 = bundler.pack_release(
            version="0.2.0",
            git_commit="750c522e",
            management_root=self.mgmt,
            out_dir=out1,
            channel="stable",
            journal_schema_version=44,
            console_dir=self.console_src,
            sbom_path=self.sbom,
            release_notes_url="https://example.test/releases/0.2.0",
            built_at="2026-11-26T17:00:00Z",
        )
        r2 = bundler.pack_release(
            version="0.2.0",
            git_commit="750c522e",
            management_root=self.mgmt,
            out_dir=out2,
            channel="stable",
            journal_schema_version=44,
            console_dir=self.console_src,
            sbom_path=self.sbom,
            release_notes_url="https://example.test/releases/0.2.0",
            built_at="2026-11-26T17:00:00Z",
        )
        # Reproducible build: identical tarball bytes and SHA-256!
        self.assertEqual(r1["bundle_sha256"], r2["bundle_sha256"])
        bundle = Path(r1["bundle_path"])
        bundler.sign_file(bundle, self.release_key)

        code, stdout, stderr = self.run_cli(bundler, [
            "verify", str(bundle),
            "--release-signers", str(self.allowed_signers),
            "--release-signer-id", "rustiron-release",
            "--expected-sha256", r1["bundle_sha256"],
        ])
        self.assertEqual(code, 0, stderr)
        verified = json.loads(stdout)
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["metadata"]["version"], "0.2.0")
        self.assertTrue(verified["metadata"]["includes_console"])

        # Inspect console.tar.gz inside bundle to guarantee node_modules, .sqlite, and .env were excluded.
        with bundler.verified_bundle_dir(bundle, self.allowed_signers, "rustiron-release") as info:
            with tarfile.open(info["console_archive"], "r:gz") as ctar:
                names = ctar.getnames()
            self.assertIn("src/server.ts", names)
            self.assertIn("public/favicon.svg", names)
            self.assertFalse(any("node_modules" in n for n in names))
            self.assertFalse(any(n.endswith(".sqlite") for n in names))
            self.assertNotIn(".env", names)

    def test_verify_refuses_tampering_wrong_key_cross_namespace_and_hostile_tarball(self):
        out = self.tmp / "out-sec"
        r = bundler.pack_release(
            version="0.2.0", git_commit="750c522e", management_root=self.mgmt, out_dir=out,
        )
        bundle = Path(r["bundle_path"])
        sig = bundler.sign_file(bundle, self.release_key)

        # Wrong key signature is refused.
        wrong_sig = self.tmp / "wrong.sig"
        bundler.sign_file(bundle, self.other_key, sig_out=wrong_sig)
        with self.assertRaisesRegex(bundler.BundleError, "signature verification failed"):
            with bundler.verified_bundle_dir(bundle, self.allowed_signers, "rustiron-release", sig_path=wrong_sig):
                pass

        # Cross-namespace (rustiron-plan-v1) signature is refused.
        plan_copy = self.tmp / "bundle-plan-ns.tar.gz"
        plan_copy.write_bytes(bundle.read_bytes())
        subprocess.run(
            ["/usr/bin/ssh-keygen", "-q", "-Y", "sign", "-n", "rustiron-plan-v1", "-f", str(self.release_key), str(plan_copy)],
            check=True, stdin=subprocess.DEVNULL,
        )
        plan_sig = plan_copy.with_name(plan_copy.name + ".sig")
        with self.assertRaisesRegex(bundler.BundleError, "signature verification failed"):
            with bundler.verified_bundle_dir(bundle, self.allowed_signers, "rustiron-release", sig_path=plan_sig):
                pass

        # Group-writable allowed_signers file is refused.
        self.allowed_signers.chmod(0o664)
        try:
            with self.assertRaisesRegex(bundler.BundleError, "group/world-writable"):
                with bundler.verified_bundle_dir(bundle, self.allowed_signers, "rustiron-release", sig_path=sig):
                    pass
        finally:
            self.allowed_signers.chmod(0o400)

        # Hostile tarballs (path traversal, symlink, setuid) are refused even if validly signed!
        for case, member_fn in (
            ("traversal", lambda: _tar_file("../escape.txt", b"bad")),
            ("symlink", lambda: _tar_symlink("evil_link", "/etc/passwd")),
            ("setuid", lambda: _tar_file("bin/suid", b"bad", mode=0o4755)),
        ):
            with self.subTest(case=case):
                evil = self.tmp / f"evil-{case}.tar.gz"
                evil.write_bytes(member_fn())
                bundler.sign_file(evil, self.release_key)
                with self.assertRaises(bundler.BundleError):
                    with bundler.verified_bundle_dir(evil, self.allowed_signers, "rustiron-release"):
                        pass

    def test_release_index_semver_ordering_and_updater_check_and_status(self):
        out = self.tmp / "releases"
        idx_path = out / "releases.json"

        # Pack 0.2.0-rc.1 (beta) and 0.2.0 (stable, journal v45).
        b_rc = bundler.pack_release(
            version="0.2.0-rc.1", git_commit="aaaaaaa", management_root=self.mgmt,
            out_dir=out, channel="beta", journal_schema_version=44,
        )
        b_final = bundler.pack_release(
            version="0.2.0", git_commit="bbbbbbb", management_root=self.mgmt,
            out_dir=out, channel="stable", journal_schema_version=45,
        )
        bundler.update_release_index(
            index_path=idx_path,
            bundle_path=Path(b_rc["bundle_path"]),
            bundle_url="https://releases.example.test/rustiron-0.2.0-rc.1.tar.gz",
        )
        bundler.update_release_index(
            index_path=idx_path,
            bundle_path=Path(b_final["bundle_path"]),
            bundle_url="https://releases.example.test/rustiron-0.2.0.tar.gz",
        )
        bundler.sign_file(idx_path, self.release_key)

        # SemVer check: 0.2.0 > 0.2.0-rc.1 > 0.1.0.
        self.assertGreater(bundler.parse_semver("0.2.0"), bundler.parse_semver("0.2.0-rc.1"))
        self.assertGreater(bundler.parse_semver("0.2.0-rc.1"), bundler.parse_semver("0.1.0"))

        # Synthetic installed host root at 0.1.0 (journal v44).
        host_root = self.tmp / "host-root"
        (host_root / "var/lib/rustiron/admission").mkdir(parents=True)
        (host_root / "var/lib/rustiron/install-record.json").write_text(json.dumps({
            "schema": "rustiron-install-record/1",
            "payload": {"usr/bin/rustiron": {"sha256": "0" * 64, "mode": 0o755}},
            "release_signature": {"verified": True, "signer_id": "rustiron-release", "namespace": "rustiron-release-v1"},
            "updates": [],
        }))
        (host_root / "var/lib/rustiron/admission/admission-mark").write_text("12\n")
        updater.record_installed_version(
            host_root,
            {"version": "0.1.0", "channel": "stable", "git_commit": "1111111", "journal_schema_version": 44},
            "0" * 64,
            None,
        )

        # `status --json` reports installed version & admission mark cleanly.
        code, st_out, st_err = self.run_cli(updater, ["status", "--root", str(host_root), "--json"])
        self.assertEqual(code, 0, st_err)
        st_doc = json.loads(st_out)
        self.assertTrue(st_doc["installed"])
        self.assertEqual(st_doc["version"], "0.1.0")
        self.assertEqual(st_doc["admission_mark"], "12")

        # `check --json` verifies releases.json.sig and flags update + journal migration!
        code, chk_out, chk_err = self.run_cli(updater, [
            "check",
            "--manifest-file", str(idx_path),
            "--release-signers", str(self.allowed_signers),
            "--release-signer-id", "rustiron-release",
            "--channel", "stable",
            "--root", str(host_root),
            "--json",
        ])
        self.assertEqual(code, 0, chk_err)
        chk = json.loads(chk_out)
        self.assertTrue(chk["update_available"])
        self.assertEqual(chk["current_version"], "0.1.0")
        self.assertEqual(chk["latest_version"], "0.2.0")
        self.assertTrue(chk["journal_migration_required"])

        # Unsigned / tampered index is refused fail-closed.
        idx_path.with_name("releases.json.sig").unlink()
        code, _, err = self.run_cli(updater, [
            "check",
            "--manifest-file", str(idx_path),
            "--release-signers", str(self.allowed_signers),
            "--release-signer-id", "rustiron-release",
            "--root", str(host_root),
        ])
        self.assertEqual(code, 1)
        self.assertIn("REFUSED", err)

        # Non-HTTPS URL is refused fail-closed.
        with self.assertRaisesRegex(updater.UpdaterError, "https://"):
            updater.fetch_https_bounded("http://insecure.example.test/releases.json", 1024)

    def test_console_atomic_swap_preserves_node_modules_and_rolls_back_cleanly(self):
        # Installed console v0.1.0 with existing node_modules and .live observation.
        live_console = self.tmp / "live-console"
        (live_console / "src").mkdir(parents=True)
        (live_console / "node_modules/keep-dep").mkdir(parents=True)
        (live_console / ".live").mkdir()
        (live_console / "package.json").write_text('{"name":"rustiron-console","version":"0.1.0"}\n')
        (live_console / "bun.lock").write_text("lock-v1\n")
        (live_console / "src/server.ts").write_text("export const version = '0.1.0';\n")
        (live_console / "node_modules/keep-dep/marker.js").write_text("kept\n")
        (live_console / ".live/observation.json").write_text('{"ok":true}\n')

        # Build v0.2.0 console archive and swap!
        v2_archive = self.tmp / "console-v2.tar.gz"
        v2_archive.write_bytes(bundler.build_console_archive_bytes(self.console_src))
        backup_archive = self.tmp / "console.before.tar.gz"

        res = updater.swap_console_dir(v2_archive, live_console, backup_out=backup_archive)
        self.assertTrue(res["lockfile_changed"])
        self.assertIn("0.2.0", (live_console / "src/server.ts").read_text())
        self.assertTrue((live_console / "node_modules/keep-dep/marker.js").is_file())
        self.assertTrue((live_console / ".live/observation.json").is_file())
        self.assertEqual(stat.S_IMODE(backup_archive.stat().st_mode), 0o400)

        # Rollback restores v0.1.0 while STILL preserving node_modules and .live!
        updater.swap_console_dir(backup_archive, live_console, backup_out=None)
        self.assertIn("0.1.0", (live_console / "src/server.ts").read_text())
        self.assertTrue((live_console / "node_modules/keep-dep/marker.js").is_file())
        self.assertTrue((live_console / ".live/observation.json").is_file())


def _tar_file(name: str, data: bytes, mode: int = 0o644) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = mode
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _tar_symlink(name: str, linkname: str) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            info = tarfile.TarInfo(name=name)
            info.type = tarfile.SYMTYPE
            info.linkname = linkname
            tar.addfile(info)
    return buf.getvalue()


if __name__ == "__main__":
    unittest.main()
