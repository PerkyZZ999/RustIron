"""Test the installer's root verification and copy with private fixtures."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[2] / "packaging/install-product.py"
SPEC = importlib.util.spec_from_file_location("install_product", SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def quiet(_line):
    pass


class InstallProductTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rustiron-install-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "root"
        self.target = Path(temporary.name) / "target"
        self.owner = os.getuid()
        self.root.mkdir(mode=0o700)
        self.digests = {}
        old = os.umask(0o022)
        try:
            for name, mode in installer.STATE_DIRS.items():
                (self.root / name).mkdir(parents=True, exist_ok=True)
                (self.root / name).chmod(mode)
            for name, mode in installer.PAYLOAD_MODES.items():
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                content = f"synthetic {name}\n".encode()
                path.write_bytes(content)
                path.chmod(mode)
                self.digests[name] = hashlib.sha256(content).hexdigest()
        finally:
            os.umask(old)

    def test_accepts_the_exact_assembled_inventory(self):
        installer.verify_install_root(self.root, self.digests, self.owner)

    def test_rejects_an_extra_file(self):
        (self.root / "usr/libexec/rustiron/extra").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, r"extra=\['usr/libexec/rustiron/extra'\]"):
            installer.verify_install_root(self.root, self.digests, self.owner)

    def test_rejects_changed_bytes(self):
        (self.root / "usr/bin/rustiron").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, r"changed=\['usr/bin/rustiron'\]"):
            installer.verify_install_root(self.root, self.digests, self.owner)

    def test_rejects_setuid_payload_with_matching_bytes(self):
        (self.root / "usr/bin/rustiron").chmod(0o4755)
        with self.assertRaisesRegex(ValueError, "unexpected mode for usr/bin/rustiron"):
            installer.verify_install_root(self.root, self.digests, self.owner)

    def test_rejects_an_extra_directory(self):
        (self.root / "var/lib/rustiron/executor/old").mkdir()
        with self.assertRaisesRegex(ValueError, "unexpected directory"):
            installer.verify_install_root(self.root, self.digests, self.owner)

    def prepare_target(self):
        for name in ("etc", "var/lib", "srv"):
            (self.target / name).mkdir(parents=True)

    def test_installs_payload_and_state_with_modes(self):
        self.prepare_target()
        installer.install_payload(self.root, self.target, self.digests, quiet, self.owner)
        for name, mode in installer.PAYLOAD_MODES.items():
            self.assertEqual((self.target / name).stat().st_mode & 0o7777, mode, name)
            self.assertEqual((self.target / name).read_bytes(), (self.root / name).read_bytes())
        for name, mode in installer.STATE_DIRS.items():
            self.assertTrue((self.target / name).is_dir(), name)
            self.assertEqual((self.target / name).stat().st_mode & 0o7777, mode, name)

    def test_refuses_an_existing_payload_destination(self):
        self.prepare_target()
        existing = self.target / "usr/bin/rustiron"
        existing.parent.mkdir(parents=True)
        existing.write_bytes(b"other")
        with self.assertRaises(FileExistsError):
            installer.install_payload(self.root, self.target, self.digests, quiet, self.owner)
        self.assertEqual(existing.read_bytes(), b"other")

    def install_with_sites(self, mounted):
        """Install over an existing /srv/sites that the mount table does or does not name."""
        self.prepare_target()
        sites = self.target / installer.preflight.SITES_ROOT
        sites.mkdir(mode=0o755)
        device = sites.stat().st_dev
        line = f"96 22 {os.major(device)}:{os.minor(device)} / {sites} rw - xfs /dev/vdb rw,usrquota\n"
        lines = []
        with mock.patch.object(installer.preflight, "read_mountinfo", return_value=line if mounted else ""), \
                mock.patch.object(installer.preflight, "selinux_type", return_value="var_t"):
            installer.install_payload(self.root, self.target, self.digests, lines.append, self.owner)
        return sites, lines

    def test_keeps_an_empty_sites_mount_point(self):
        # W361: the quota file system is mounted at /srv/sites before installation.
        sites, lines = self.install_with_sites(mounted=True)
        self.assertIn("KEPT empty mount point /srv/sites", lines)
        self.assertNotIn("INSTALLED /srv/sites", lines)
        self.assertEqual(sites.stat().st_mode & 0o7777, 0o755)
        self.assertEqual(list(sites.iterdir()), [])
        self.assertTrue((self.target / "srv/restore-probes").is_dir())

    def test_refuses_an_existing_sites_directory_that_is_not_a_mount(self):
        with self.assertRaisesRegex(ValueError, "existing path /srv/sites"):
            self.install_with_sites(mounted=False)

    def prepare_parent(self, template=b"disableWebAdmin 1\n"):
        self.prepare_target()
        for name in (installer.PACKAGE_PARENT_COPY, installer.PARENT_TEMPLATE, installer.OLS_PARENT):
            (self.target / name).parent.mkdir(parents=True, exist_ok=True)
        (self.target / installer.OLS_PARENT).write_bytes(b"package parent\n")
        (self.target / installer.PARENT_TEMPLATE).write_bytes(template)
        return hashlib.sha256(template).hexdigest()

    def test_replaces_the_package_parent_and_keeps_a_private_copy(self):
        digest = self.prepare_parent()
        self.assertEqual(installer.replace_parent(self.target, digest, self.owner, quiet), digest)
        parent = self.target / installer.OLS_PARENT
        copy = self.target / installer.PACKAGE_PARENT_COPY
        self.assertEqual(parent.read_bytes(), b"disableWebAdmin 1\n")
        self.assertEqual(parent.stat().st_mode & 0o7777, 0o644)
        self.assertEqual(copy.read_bytes(), b"package parent\n")
        self.assertEqual(copy.stat().st_mode & 0o7777, 0o400)
        self.assertEqual(sorted(p.name for p in parent.parent.iterdir()), ["httpd_config.conf"])

    def test_parent_replacement_refuses_an_existing_copy(self):
        digest = self.prepare_parent()
        (self.target / installer.PACKAGE_PARENT_COPY).write_bytes(b"earlier copy\n")
        with self.assertRaises(FileExistsError):
            installer.replace_parent(self.target, digest, self.owner, quiet)
        self.assertEqual((self.target / installer.OLS_PARENT).read_bytes(), b"package parent\n")

    def test_parent_replacement_refuses_changed_template_bytes(self):
        self.prepare_parent()
        with self.assertRaisesRegex(ValueError, "installed bytes differ"):
            installer.replace_parent(self.target, "0" * 64, self.owner, quiet)
        self.assertEqual((self.target / installer.OLS_PARENT).read_bytes(), b"package parent\n")

    def test_parent_replacement_refuses_a_managed_parent(self):
        digest = self.prepare_parent()
        (self.target / installer.OLS_PARENT).write_bytes(
            b"include /etc/rustiron-ols/current/*.conf\n"
        )
        with self.assertRaisesRegex(ValueError, "Rustiron-managed"):
            installer.replace_parent(self.target, digest, self.owner, quiet)
        self.assertFalse((self.target / installer.PACKAGE_PARENT_COPY).exists())

    def test_listener_check_reads_both_tables(self):
        tables = Path(self.root) / "tables"
        tables.mkdir()
        (tables / "tcp").write_text("  sl local rem st\n   0: 00000000:1BA8 00000000:0000 0A\n")
        (tables / "tcp6").write_text("  sl local rem st\n")
        paths = (str(tables / "tcp"), str(tables / "tcp6"))
        self.assertTrue(installer.listening(7080, paths))
        self.assertFalse(installer.listening(8088, paths))
        self.assertTrue(installer.listening(8088, (str(tables / "missing"),)))
        installer.wait_closed((8088,), 0, paths)
        with self.assertRaisesRegex(ValueError, "still open"):
            installer.wait_closed((7080, 8088), 0, paths)

    def test_config_test_passes_after_one_failed_attempt(self):
        calls = []

        def runner(*arguments):
            calls.append(arguments)
            if len(calls) == 1:
                raise subprocess.CalledProcessError(2, arguments)

        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(installer.config_test(runner=runner, pause=0), 2)
        self.assertIn("attempt 1 failed", out.getvalue())

    def test_config_test_fails_when_every_attempt_fails(self):
        def runner(*arguments):
            raise subprocess.CalledProcessError(2, arguments)

        with contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(subprocess.CalledProcessError):
                installer.config_test(runner=runner, pause=0)
        self.assertEqual(out.getvalue().count("failed"), installer.CONFIG_TEST_ATTEMPTS)

    def test_relabels_the_package_lsphp_that_the_php_module_labels(self):
        # W358: the rustiron_php module labels the package's lsphp as the
        # site PHP entry point. Without a relabel it kept bin_t on a clean
        # host, and the site PHP units failed with an entrypoint denial.
        source = Path(__file__).resolve().parents[2]
        rules = (source / "lab/s03/selinux/rustiron_php.fc").read_text()
        self.assertIn("/usr/local/lsws/lsphp84/bin/lsphp\t--\tgen_context(system_u:object_r:rustiron_php_exec_t,s0)", rules)
        self.assertIn("usr/local/lsws/lsphp84/bin/lsphp", installer.RELABEL)
        # Only that one file of the package tree, never the whole server root.
        self.assertFalse([name for name in installer.RELABEL
                          if name.startswith("usr/local/lsws") and not name.endswith("/bin/lsphp")])

    def test_relabels_the_ols_killmode_dropin(self):
        self.assertIn(installer.preflight.OLS_UNIT_DROPIN, installer.PAYLOAD_MODES)
        self.assertIn(installer.preflight.OLS_UNIT_DROPIN, installer.RELABEL)

    def test_relabels_the_ols_boot_guard_unit_and_dropin(self):
        # W381 (D-032).
        for name in (installer.preflight.OLS_GUARD_DROPIN,
                     "usr/lib/systemd/system/rustiron-ols-boot-guard.service"):
            self.assertIn(name, installer.PAYLOAD_MODES)
            self.assertIn(name, installer.RELABEL)

    def test_relabels_the_scheduled_capture_units(self):
        # W386 (D-035).
        for name in ("rustiron-scheduled-capture.service", "rustiron-scheduled-capture.timer",
                     "rustiron-scheduled-capture-check.service", "rustiron-scheduled-capture-check.timer"):
            path = f"usr/lib/systemd/system/{name}"
            self.assertIn(path, installer.PAYLOAD_MODES)
            self.assertIn(path, installer.RELABEL)

    INSTALLED_UNIT = (
        "FragmentPath=/usr/lib/systemd/system/lshttpd.service\n"
        "DropInPaths=/etc/systemd/system/lshttpd.service.d/50-rustiron-killmode.conf "
        "/etc/systemd/system/lshttpd.service.d/51-rustiron-boot-guard.conf\n"
        "KillMode=mixed\n"
        "NeedDaemonReload=no\n"
    )

    def test_the_effective_ols_unit_uses_only_the_rustiron_dropin(self):
        # W364: the C07 merged-unit check (W244, W245) for the product, after daemon-reload.
        with contextlib.redirect_stdout(io.StringIO()) as out:
            installer.check_ols_unit(show=lambda: self.INSTALLED_UNIT)
        self.assertIn("PASS OLS unit lshttpd.service KillMode=mixed", out.getvalue())
        cases = (
            self.INSTALLED_UNIT.replace("KillMode=mixed", "KillMode=none"),
            self.INSTALLED_UNIT.replace("50-rustiron-killmode.conf", "50-rustiron-killmode.conf "
                                        "/etc/systemd/system/lshttpd.service.d/99-local.conf"),
            self.INSTALLED_UNIT.replace("DropInPaths=/etc/systemd/system/lshttpd.service.d/50-rustiron-killmode.conf",
                                        "DropInPaths="),
            # W381: the boot guard drop-in missing.
            self.INSTALLED_UNIT.replace(" /etc/systemd/system/lshttpd.service.d/51-rustiron-boot-guard.conf", ""),
            self.INSTALLED_UNIT.replace("NeedDaemonReload=no", "NeedDaemonReload=yes"),
            self.INSTALLED_UNIT.replace("FragmentPath=/usr/lib", "FragmentPath=/etc"),
            self.INSTALLED_UNIT.replace("KillMode=mixed\n", ""),
        )
        for text in cases:
            with self.assertRaisesRegex(ValueError, "OLS unit lshttpd.service"):
                installer.check_ols_unit(show=lambda text=text: text)

    def test_configure_host_checks_the_ols_unit_after_the_reload(self):
        calls = []
        with mock.patch.object(installer, "run", side_effect=lambda *a: calls.append(a)), \
                mock.patch.object(installer, "prepare_acme_state",
                                  side_effect=lambda: calls.append("acme_state")), \
                mock.patch.object(installer, "reset_failed_optional",
                                  side_effect=lambda unit: calls.append(("reset-failed", unit))), \
                mock.patch.object(installer.preflight, "check_mariadb_loopback",
                                  side_effect=lambda: calls.append("loopback")), \
                mock.patch.object(installer, "check_ols_unit", side_effect=lambda: calls.append("check")):
            installer.configure_host()
        # W486 (W484-F3): journald restarts with its drop-in before the check;
        # W569: MariaDB restarts with its drop-in and must listen on loopback.
        self.assertEqual(calls[-6:], [("/usr/bin/systemctl", "daemon-reload"),
                                      ("/usr/bin/systemctl", "restart", "systemd-journald.service"),
                                      ("/usr/bin/journalctl", "--flush"),
                                      ("/usr/bin/systemctl", "restart", "mariadb.service"),
                                      "loopback", "check"])
        # W646: ACME state directory is created after sysusers and before restorecon.
        self.assertIn("acme_state", calls)
        # W464 (D-060) & W646: certbot timer is masked and reset-failed clears systemd 257 residual failure.
        self.assertIn(("/usr/bin/systemctl", "mask", "--now", "certbot-renew.timer"), calls)
        self.assertIn(("reset-failed", "certbot-renew.timer"), calls)

    def test_writes_the_install_record_before_the_payload(self):
        # W385: the uninstaller reads this record.
        self.prepare_target()
        (self.target / "usr/bin").mkdir(parents=True)
        lines = []
        facts = {"sha256": "a" * 64, "uid": 0, "gid": 99, "mode": 0o640, "selinux_type": "usr_t"}
        installer.install_payload(self.root, self.target, self.digests, lines.append, self.owner, facts)
        record_path = self.target / installer.INSTALL_RECORD
        self.assertEqual(record_path.stat().st_mode & 0o7777, 0o400)
        self.assertLess(lines.index(f"INSTALLED /{installer.INSTALL_RECORD}"),
                        lines.index("INSTALLED /usr/bin/rustiron"))
        record = json.loads(record_path.read_bytes())
        self.assertEqual(record["schema"], "rustiron-install-record/1")
        self.assertEqual({name: entry["sha256"] for name, entry in record["payload"].items()}, self.digests)
        self.assertEqual({name: entry["mode"] for name, entry in record["payload"].items()},
                         installer.PAYLOAD_MODES)
        self.assertIn("usr/libexec/rustiron/jobs", record["created_directories"])
        self.assertIn("etc/systemd/system/lshttpd.service.d", record["created_directories"])
        self.assertNotIn("usr/bin", record["created_directories"])
        self.assertNotIn("etc", record["created_directories"])
        self.assertEqual(record["state_directories"], sorted(installer.STATE_DIRS))
        self.assertFalse(record["sites_mount_kept"])
        self.assertEqual(record["package_parent"], facts)
        self.assertEqual(record["shipped_parent_sha256"], self.digests[installer.PARENT_TEMPLATE])
        self.assertEqual(record["modules"], sorted(installer.preflight.MODULES))
        self.assertEqual(record["users"], ["rustiron-coordinator", "rustiron-acme", "rustiron-caddy"])
        self.assertEqual(record["groups"], ["rustiron-coordinator", "rustiron-requesters", "rustiron-agents", "rustiron-acme", "rustiron-caddy"])
        self.assertEqual(record["relabelled"], ["usr/local/lsws/lsphp84/bin/lsphp"])

    def test_the_record_leaves_out_a_kept_sites_mount(self):
        self.install_with_sites(mounted=True)
        record = json.loads((self.target / installer.INSTALL_RECORD).read_bytes())
        self.assertTrue(record["sites_mount_kept"])
        self.assertNotIn("srv/sites", record["state_directories"])
        self.assertIn("srv/restore-probes", record["state_directories"])

    def test_package_parent_facts_give_bytes_owner_and_mode(self):
        self.prepare_parent()
        parent = self.target / installer.OLS_PARENT
        parent.chmod(0o640)
        with mock.patch.object(installer.preflight, "selinux_type", return_value="usr_t"):
            facts = installer.package_parent_facts(self.target, self.owner)
        self.assertEqual(facts, {"sha256": hashlib.sha256(b"package parent\n").hexdigest(),
                                 "uid": self.owner, "gid": os.getgid(), "mode": 0o640,
                                 "selinux_type": "usr_t"})

    def test_refuses_an_existing_state_directory(self):
        self.prepare_target()
        (self.target / "var/lib/rustiron").mkdir()
        with self.assertRaises(FileExistsError):
            installer.install_payload(self.root, self.target, self.digests, quiet, self.owner)

    # W392 (D-040 item 6): the host receipt key.

    def test_the_receipt_key_folder_is_an_owner_only_state_directory(self):
        self.assertEqual(installer.RECEIPT_KEY_DIR, "etc/rustiron/receipt-key")
        self.assertEqual(installer.STATE_DIRS[installer.RECEIPT_KEY_DIR], 0o700)

    def receipt_key_folder(self):
        folder = self.target / installer.RECEIPT_KEY_DIR
        folder.mkdir(parents=True)
        folder.chmod(0o700)
        return folder

    def test_generates_the_receipt_key_and_prints_only_the_public_facts(self):
        folder = self.receipt_key_folder()
        calls = []

        def runner(*arguments):
            calls.append(arguments)
            subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL, capture_output=True)

        with contextlib.redirect_stdout(io.StringIO()) as out:
            fingerprint = installer.generate_receipt_key(self.target, runner, self.owner)
        private, public = folder / "ed25519", folder / "ed25519.pub"
        self.assertEqual(private.stat().st_mode & 0o7777, 0o400)
        self.assertEqual(public.stat().st_mode & 0o7777, 0o444)
        self.assertEqual(calls[0][:2], ("/usr/bin/ssh-keygen", "-q"))
        self.assertIn(str(private), calls[0])
        self.assertIn("ed25519", calls[0])
        line = public.read_text().split()
        listed = subprocess.run(("/usr/bin/ssh-keygen", "-l", "-E", "sha256", "-f", str(public)),
                                check=True, capture_output=True, text=True).stdout.split()[1]
        self.assertEqual(fingerprint, listed)
        text = out.getvalue()
        self.assertIn(f"receipt_key.public={line[0]} {line[1]}\n", text)
        self.assertIn(f"receipt_key.fingerprint={listed}\n", text)
        self.assertNotIn("PRIVATE", text)
        self.assertNotIn(private.read_text().splitlines()[1], text)

    def test_refuses_an_existing_receipt_key(self):
        folder = self.receipt_key_folder()
        (folder / "ed25519.pub").write_text("ssh-ed25519 AAAA old\n")
        with self.assertRaises(ValueError):
            installer.generate_receipt_key(self.target, lambda *a: self.fail("ran"), self.owner)
        self.assertEqual((folder / "ed25519.pub").read_text(), "ssh-ed25519 AAAA old\n")

    # W639 (H-09): mandatory release SSHSIG verification in rustiron-release-v1.

    def make_signed_stage(self, namespace="rustiron-release-v1"):
        stage = self.target / "stage"
        stage.mkdir(parents=True, mode=0o700)
        (stage / "usr/bin").mkdir(parents=True)
        (stage / "usr/bin/rustiron").write_bytes(b"binary-bytes\n")
        (stage / "usr/bin/rustiron").chmod(0o755)
        fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            content = installer.manifest.canonical_manifest(fd)
        finally:
            os.close(fd)
        sums = stage / "SHA256SUMS"
        sums.write_bytes(content)
        key_dir = self.target / "keys"
        key_dir.mkdir(mode=0o700)
        key, other = key_dir / "release", key_dir / "other"
        for k in (key, other):
            subprocess.run(
                ("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(k)),
                check=True, stdin=subprocess.DEVNULL, capture_output=True,
            )
        allowed = key_dir / "allowed_signers"
        pub = key.with_suffix(".pub").read_text().split()
        allowed.write_text(f"release-owner {pub[0]} {pub[1]}\n")
        allowed.chmod(0o400)
        subprocess.run(
            ("/usr/bin/ssh-keygen", "-q", "-Y", "sign", "-n", namespace, "-f", str(key), str(sums)),
            check=True, stdin=subprocess.DEVNULL, capture_output=True,
        )
        return stage, allowed, key, other

    def test_release_signature_verifies_and_rejects_tamper_wrong_key_and_wrong_namespace(self):
        stage, allowed, _key, other = self.make_signed_stage()
        meta = installer.preflight.check_release_trust(
            stage, allowed, "release-owner", False, owner=self.owner,
        )
        self.assertTrue(meta["verified"])
        self.assertEqual(meta["namespace"], "rustiron-release-v1")
        self.assertEqual(meta["signer_id"], "release-owner")

        # Default without --release-signers or --allow-unsigned-lab fails closed.
        with self.assertRaisesRegex(ValueError, "release signature verification is required"):
            installer.preflight.check_release_trust(stage, None, None, False, owner=self.owner)

        # Combining --allow-unsigned-lab with --release-signers is refused.
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            installer.preflight.check_release_trust(stage, allowed, "release-owner", True, owner=self.owner)

        # Explicit --allow-unsigned-lab returns explicit unverified metadata.
        lab_meta = installer.preflight.check_release_trust(stage, None, None, True, owner=self.owner)
        self.assertEqual(lab_meta, {"verified": False, "mode": "unsigned_lab"})

        # Tampered artifact after signing is refused.
        (stage / "usr/bin/rustiron").write_bytes(b"tampered\n")
        with self.assertRaisesRegex(ValueError, "staged bytes differ from SHA256SUMS"):
            installer.preflight.verify_release_signature(stage, allowed, "release-owner", owner=self.owner)
        (stage / "usr/bin/rustiron").write_bytes(b"binary-bytes\n")

        # Missing signature is refused.
        sig_path = stage / "SHA256SUMS.sig"
        sig_backup = sig_path.read_bytes()
        sig_path.unlink()
        with self.assertRaisesRegex(ValueError, "missing release signature"):
            installer.preflight.verify_release_signature(stage, allowed, "release-owner", owner=self.owner)

        # Symlinked signature is refused.
        sig_real = self.target / "real.sig"
        sig_real.write_bytes(sig_backup)
        sig_path.symlink_to(sig_real)
        with self.assertRaises(installer.manifest.InvalidPackage):
            installer.preflight.verify_release_signature(stage, allowed, "release-owner", owner=self.owner)
        sig_path.unlink()
        sig_path.write_bytes(sig_backup)

        # Group/world-writable allowed-signers is refused.
        allowed.chmod(0o664)
        with self.assertRaisesRegex(ValueError, "not group/world-writable"):
            installer.preflight.verify_release_signature(stage, allowed, "release-owner", owner=self.owner)
        allowed.chmod(0o400)

        # Signature made with an unenrolled key is refused.
        sig_path.unlink()
        subprocess.run(
            ("/usr/bin/ssh-keygen", "-q", "-Y", "sign", "-n", "rustiron-release-v1",
             "-f", str(other), str(stage / "SHA256SUMS")),
            check=True, stdin=subprocess.DEVNULL, capture_output=True,
        )
        with self.assertRaisesRegex(ValueError, "release signature verification failed"):
            installer.preflight.verify_release_signature(stage, allowed, "release-owner", owner=self.owner)

    def test_release_signature_rejects_plan_namespace_cross_protocol_signature(self):
        stage, allowed, _key, _other = self.make_signed_stage(namespace="rustiron-plan-v1")
        with self.assertRaisesRegex(ValueError, "release signature verification failed"):
            installer.preflight.verify_release_signature(stage, allowed, "release-owner", owner=self.owner)

    def test_install_record_persists_release_signature_metadata(self):
        self.prepare_target()
        meta = {"verified": True, "namespace": "rustiron-release-v1", "signer_id": "owner", "sha256sums_sha256": "a" * 64}
        installer.install_payload(self.root, self.target, self.digests, quiet, self.owner, release_signature=meta)
        record = json.loads((self.target / installer.INSTALL_RECORD).read_bytes())
        self.assertEqual(record["release_signature"], meta)

    def test_prepare_acme_state_creates_private_subdirs_and_refuses_symlinks(self):
        self.prepare_target()
        lines = []
        installer.prepare_acme_state(
            self.target, report=lines.append, uid=self.owner, gid=os.getgid(),
        )
        base = self.target / installer.ACME_STATE
        self.assertIn(installer.ACME_STATE, installer.RELABEL)
        for path in (base, *(base / sub for sub in installer.ACME_SUBDIRS)):
            self.assertTrue(path.is_dir(), path)
            self.assertEqual(path.stat().st_mode & 0o7777, 0o700, path)
        self.assertEqual(len(lines), 4)

        # Symlink at ACME subdir is refused fail-closed.
        logs = base / "logs"
        logs.rmdir()
        logs.symlink_to(self.target / "etc")
        with self.assertRaisesRegex(ValueError, "refusing symlink"):
            installer.prepare_acme_state(
                self.target, report=quiet, uid=self.owner, gid=os.getgid(),
            )

    def test_reset_failed_optional_invokes_systemctl_reset_failed(self):
        calls = []
        installer.reset_failed_optional("certbot-renew.timer", runner=lambda *a: calls.append(a))
        self.assertEqual(calls, [("/usr/bin/systemctl", "reset-failed", "certbot-renew.timer")])


if __name__ == "__main__":
    unittest.main()
