"""Test the D-049 update command with private fixture roots."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[2] / "packaging/update-product.py"
SPEC = importlib.util.spec_from_file_location("update_product", SCRIPT)
updater = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updater)
installer = updater.installer
preflight = updater.preflight


def digest(content):
    return hashlib.sha256(content).hexdigest()


class UpdateProductTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rustiron-update-")
        self.addCleanup(temporary.cleanup)
        self.target = Path(temporary.name)
        self.owner = os.getuid()
        self.old = {}
        for name, mode in installer.PAYLOAD_MODES.items():
            path = self.target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            content = f"old {name}\n".encode()
            path.write_bytes(content)
            path.chmod(mode)
            self.old[name] = digest(content)
        self.record = {
            "schema": installer.INSTALL_RECORD_SCHEMA,
            "payload": {name: {"sha256": self.old[name], "mode": mode}
                        for name, mode in installer.PAYLOAD_MODES.items()},
            "shipped_parent_sha256": self.old[installer.PARENT_TEMPLATE],
        }
        self.record_content = (json.dumps(self.record, indent=1, sort_keys=True) + "\n").encode()
        (self.target / updater.RECORD).parent.mkdir(parents=True, exist_ok=True)
        (self.target / updater.RECORD).write_bytes(self.record_content)
        (self.target / updater.RECORD).chmod(0o400)
        self.new = dict(self.old)
        self.new["usr/libexec/rustiron/rustiron-executor"] = digest(b"new executor\n")

    def test_the_record_loads_and_a_changed_file_is_listed(self):
        record, content = updater.load_record(self.target, self.owner)
        self.assertEqual(content, self.record_content)
        self.assertEqual(updater.compatibility(record, self.new), [])
        self.assertEqual(updater.drift(self.target, record, self.owner), [])
        self.assertEqual(updater.changed(record, self.new), ["usr/libexec/rustiron/rustiron-executor"])

    def test_an_added_file_needs_a_free_destination_and_a_module_is_never_removed(self):
        # D-062 (W467): additions and removals are allowed with these rules.
        extra = "usr/libexec/rustiron/extra"
        added = {**self.new, extra: digest(b"x")}
        self.assertEqual(updater.compatibility(self.record, added, self.target), [])
        self.assertEqual(updater.added(self.record, added), [extra])
        (self.target / extra).write_bytes(b"planted\n")
        self.assertIn("exists but is not in the install record",
                      updater.compatibility(self.record, added, self.target)[0])
        nested = {**self.new, "usr/libexec/rustiron/nowhere/x": digest(b"x")}
        self.assertIn("does not exist", updater.compatibility(self.record, nested, self.target)[0])
        module = next(name for name in self.new if name.startswith(updater.MODULE_PREFIX))
        without_module = {name: value for name, value in self.new.items() if name != module}
        self.assertIn("removes the SELinux module", updater.compatibility(self.record, without_module)[0])
        without_cli = {name: value for name, value in self.new.items() if name != "usr/bin/rustiron"}
        self.assertEqual(updater.compatibility(self.record, without_cli), [])
        self.assertEqual(updater.removed(self.record, without_cli), ["usr/bin/rustiron"])

    def test_an_update_adds_and_removes_files_and_the_rollback_undoes_both(self):
        # D-062: the install record lacks the site-cron timer (an older
        # install); the new release ships it and no longer ships the CLI.
        added = "usr/lib/systemd/system/rustiron-site-cron.timer"
        gone = "usr/bin/rustiron"
        del self.record["payload"][added]
        (self.target / added).unlink()
        content = (json.dumps(self.record, indent=1, sort_keys=True) + "\n").encode()
        (self.target / updater.RECORD).chmod(0o600)
        (self.target / updater.RECORD).write_bytes(content)
        (self.target / updater.RECORD).chmod(0o400)
        record, content = updater.load_record(self.target, self.owner)
        digests = {name: value for name, value in self.old.items() if name != gone}
        digests[added] = digest(b"new timer\n")
        self.assertEqual(updater.compatibility(record, digests, self.target), [])
        created, dropped = updater.added(record, digests), updater.removed(record, digests)
        self.assertEqual((created, dropped), ([added], [gone]))
        with mock.patch.object(updater, "busy_units", return_value=[]), \
                mock.patch.object(updater, "active_units", return_value=[]), \
                mock.patch.object(updater, "stop_units"), mock.patch.object(updater, "start_units"), \
                mock.patch.object(updater, "finish_host") as finish, \
                mock.patch.object(updater, "utc_stamp", return_value="20261117T000000Z"), \
                contextlib.redirect_stdout(io.StringIO()):
            folder = updater.execute(
                self.target, [], content, lambda folder: updater.new_record(record, digests, folder, dropped),
                lambda name: (lambda: iter((b"new timer\n",))), digests, "update", self.owner,
                created=created, dropped=dropped)
        finish.assert_called_once_with(self.target, [added])
        self.assertEqual((self.target / added).read_bytes(), b"new timer\n")
        self.assertFalse((self.target / gone).exists())
        self.assertEqual((folder / updater.FILES / gone).read_bytes(), f"old {gone}\n".encode())
        after, _ = updater.load_record(self.target, self.owner)
        self.assertIn(added, after["payload"])
        self.assertNotIn(gone, after["payload"])
        self.assertEqual(updater.drift(self.target, after, self.owner), [])
        manifest = json.loads((folder / updater.UPDATE_MANIFEST).read_text())
        self.assertEqual((manifest["added"], manifest["removed"]), ([added], [gone]))
        # The rollback restores the removed file and removes the added one.
        record2, content2, old_content, old_digests, names, restored, deleted, folders = updater.plan_rollback(
            folder, self.target, self.owner)
        self.assertEqual((names, restored, deleted, folders), ([], [gone], [added], []))
        kept = folder / updater.FILES
        with mock.patch.object(updater, "busy_units", return_value=[]), \
                mock.patch.object(updater, "active_units", return_value=[]), \
                mock.patch.object(updater, "stop_units"), mock.patch.object(updater, "start_units"), \
                mock.patch.object(updater, "finish_host"), \
                mock.patch.object(updater, "utc_stamp", return_value="20261117T000001Z"), \
                contextlib.redirect_stdout(io.StringIO()):
            updater.execute(self.target, names, content2, lambda _folder: old_content,
                            lambda name: updater.chunks_of(kept / name), old_digests, "rollback", self.owner,
                            created=restored, dropped=deleted)
        self.assertEqual((self.target / gone).read_bytes(), f"old {gone}\n".encode())
        self.assertFalse((self.target / added).exists())
        self.assertEqual((self.target / updater.RECORD).read_bytes(), content)

    def test_the_journald_dropin_folder_is_created_and_removed_by_the_rollback(self):
        # D-072 (W486): the one added file whose missing standard folder the
        # updater creates; the rollback removes the folder it created.
        dropin = preflight.JOURNALD_DROPIN
        folder_name = "etc/systemd/journald.conf.d"
        del self.record["payload"][dropin]
        (self.target / dropin).unlink()
        (self.target / folder_name).rmdir()
        content = (json.dumps(self.record, indent=1, sort_keys=True) + "\n").encode()
        (self.target / updater.RECORD).chmod(0o600)
        (self.target / updater.RECORD).write_bytes(content)
        (self.target / updater.RECORD).chmod(0o400)
        record, content = updater.load_record(self.target, self.owner)
        digests = {**self.old, dropin: digest(b"[Journal]\nStorage=persistent\n")}
        self.assertEqual(updater.compatibility(record, digests, self.target), [])
        other = "etc/systemd/other.conf.d/x.conf"
        self.assertIn("does not exist",
                      updater.compatibility(record, {**digests, other: digest(b"x")}, self.target)[0])
        created = updater.added(record, digests)
        self.assertEqual(created, [dropin])
        with mock.patch.object(updater, "busy_units", return_value=[]), \
                mock.patch.object(updater, "active_units", return_value=[]), \
                mock.patch.object(updater, "stop_units"), mock.patch.object(updater, "start_units"), \
                mock.patch.object(updater, "finish_host") as finish, \
                mock.patch.object(updater, "utc_stamp", return_value="20261118T000000Z"), \
                contextlib.redirect_stdout(io.StringIO()):
            folder = updater.execute(
                self.target, [], content, lambda folder: updater.new_record(record, digests, folder),
                lambda name: (lambda: iter((b"[Journal]\nStorage=persistent\n",))), digests, "update",
                self.owner, created=created)
        finish.assert_called_once_with(self.target, [folder_name, dropin])
        self.assertEqual(stat.S_IMODE((self.target / folder_name).stat().st_mode), 0o755)
        manifest = json.loads((folder / updater.UPDATE_MANIFEST).read_text())
        self.assertEqual(manifest["created_folders"], [folder_name])
        after, _ = updater.load_record(self.target, self.owner)
        self.assertIn(folder_name, after["created_directories"])
        *_, names, restored, deleted, folders = updater.plan_rollback(folder, self.target, self.owner)
        self.assertEqual((deleted, folders), ([dropin], [folder_name]))
        record2, content2, old_content, old_digests, *_ = updater.plan_rollback(folder, self.target, self.owner)
        with mock.patch.object(updater, "busy_units", return_value=[]), \
                mock.patch.object(updater, "active_units", return_value=[]), \
                mock.patch.object(updater, "stop_units"), mock.patch.object(updater, "start_units"), \
                mock.patch.object(updater, "finish_host"), \
                mock.patch.object(updater, "utc_stamp", return_value="20261118T000001Z"), \
                contextlib.redirect_stdout(io.StringIO()):
            updater.execute(self.target, names, content2, lambda _folder: old_content,
                            lambda name: updater.chunks_of(folder / updater.FILES / name), old_digests,
                            "rollback", self.owner, created=restored, dropped=deleted, remove_empty=folders)
        self.assertFalse((self.target / folder_name).exists())
        self.assertEqual((self.target / updater.RECORD).read_bytes(), content)

    def test_a_changed_mariadb_dropin_restarts_mariadb_and_checks_loopback(self):
        # W569 (W558-F1).
        runner = mock.Mock()
        loopback = "LISTEN 0      80     127.0.0.1:3306 0.0.0.0:*\n"
        updater.finish_host(self.target, [preflight.MARIADB_DROPIN], runner, read=lambda *a: loopback)
        self.assertIn(mock.call("/usr/bin/systemctl", "restart", "mariadb.service"), runner.call_args_list)
        exposed = "LISTEN 0      80     0.0.0.0:3306 0.0.0.0:*\nLISTEN 0      80     [::]:3306    [::]:*\n"
        with self.assertRaisesRegex(ValueError, "beyond loopback on 0.0.0.0:3306, \\[::\\]:3306"):
            updater.finish_host(self.target, [preflight.MARIADB_DROPIN], runner, read=lambda *a: exposed)
        runner.reset_mock()
        updater.finish_host(self.target, ["usr/bin/rustiron"], runner)
        self.assertNotIn(mock.call("/usr/bin/systemctl", "restart", "mariadb.service"), runner.call_args_list)

    def test_a_changed_journald_dropin_restarts_journald(self):
        runner = mock.Mock()
        updater.finish_host(self.target, [preflight.JOURNALD_DROPIN], runner)
        self.assertEqual(runner.call_args_list[-2:],
                         [mock.call("/usr/bin/systemctl", "restart", "systemd-journald.service"),
                          mock.call("/usr/bin/journalctl", "--flush")])
        runner.reset_mock()
        updater.finish_host(self.target, ["usr/bin/rustiron"], runner)
        self.assertNotIn(mock.call("/usr/bin/systemctl", "restart", "systemd-journald.service"),
                         runner.call_args_list)

    def test_a_changed_sysusers_file_creates_its_identities(self):
        runner = mock.Mock()
        updater.finish_host(self.target, [installer.SYSUSERS], runner)
        self.assertIn(mock.call("/usr/bin/systemd-sysusers", f"/{installer.SYSUSERS}"), runner.call_args_list)

    def test_a_changed_parent_template_is_refused(self):
        changed = {**self.new, installer.PARENT_TEMPLATE: digest(b"another parent")}
        self.assertIn("shipped OLS parent template", updater.compatibility(self.record, changed)[0])

    def test_drifted_bytes_mode_or_type_are_refused(self):
        executor = self.target / "usr/libexec/rustiron/rustiron-executor"
        executor.write_bytes(b"hand edited\n")
        (self.target / "usr/bin/rustiron").chmod(0o775)
        dropin = self.target / installer.preflight.OLS_GUARD_DROPIN
        dropin.unlink()
        dropin.symlink_to("/etc/passwd")
        problems = updater.drift(self.target, self.record, self.owner)
        self.assertIn("/usr/libexec/rustiron/rustiron-executor differs from the install record", problems)
        self.assertIn("/usr/bin/rustiron has another owner or mode than the install record", problems)
        self.assertIn(f"/{installer.preflight.OLS_GUARD_DROPIN} is not a regular file", problems)

    def test_another_record_schema_is_refused(self):
        path = self.target / updater.RECORD
        path.chmod(0o600)
        path.write_text(json.dumps({"schema": "rustiron-install-record/0", "payload": {}}))
        with self.assertRaisesRegex(updater.Refused, "schema"):
            updater.load_record(self.target, self.owner)

    def test_replace_checks_the_digest_and_leaves_no_temporary_file(self):
        path = self.target / "usr/bin/rustiron"
        with self.assertRaisesRegex(ValueError, "written bytes differ"):
            updater.replace(path, lambda: iter((b"wrong",)), digest(b"right"), 0o755, self.owner)
        self.assertEqual(path.read_bytes(), b"old usr/bin/rustiron\n")
        self.assertFalse(path.with_name(path.name + updater.TEMP_SUFFIX).exists())
        updater.replace(path, lambda: iter((b"right",)), digest(b"right"), 0o755, self.owner)
        self.assertEqual(path.read_bytes(), b"right")
        self.assertEqual(path.stat().st_mode & 0o7777, 0o755)

    def test_new_record_adds_the_identities_of_the_new_sysusers_file(self):
        record = {**self.record, "users": ["rustiron-coordinator"],
                  "groups": ["rustiron-coordinator", "rustiron-requesters"]}
        written = json.loads(updater.new_record(record, {}, "var/lib/rustiron/updates/x"))
        self.assertEqual(written["users"], ["rustiron-coordinator", "rustiron-acme"])
        self.assertEqual(written["groups"], ["rustiron-coordinator", "rustiron-requesters", "rustiron-acme"])

    def test_new_record_changes_only_digests_and_adds_the_history(self):
        content = updater.new_record(self.record, self.new, "var/lib/rustiron/updates/X")
        written = json.loads(content)
        self.assertEqual(written["payload"]["usr/libexec/rustiron/rustiron-executor"]["sha256"],
                         self.new["usr/libexec/rustiron/rustiron-executor"])
        self.assertEqual(written["updates"], ["var/lib/rustiron/updates/X"])
        self.assertEqual(self.record.get("updates"), None)
        self.assertEqual({k: v for k, v in written.items() if k not in ("payload", "updates")},
                         {k: v for k, v in self.record.items() if k != "payload"})

    def test_busy_and_active_units_are_parsed(self):
        lister = mock.Mock(return_value="rustiron-probe-rp_1-fetch-2.service loaded active running x\n")
        self.assertEqual(updater.busy_units(lister), ["rustiron-probe-rp_1-fetch-2.service"])
        states = {"rustiron-executor.service": "active", "rustiron-coordinator.service": "active"}
        checker = lambda *arguments: states.get(arguments[-1], "inactive") + "\n"
        self.assertEqual(updater.active_units(checker), ["rustiron-coordinator.service", "rustiron-executor.service"])

    def test_a_unit_that_exits_after_its_start_fails_the_update(self):
        # W457-F1: active at the first check, failed at the third.
        answers = iter(["active\n", "active\n", "failed\n"])
        sleeps = []
        with self.assertRaisesRegex(ValueError, "rustiron-executor.service is failed"):
            updater.start_units(
                ["rustiron-executor.service"],
                runner=lambda *arguments: None,
                checker=lambda *arguments: next(answers),
                sleep=sleeps.append,
            )
        self.assertEqual(sleeps, [updater.SETTLE_INTERVAL, updater.SETTLE_INTERVAL])

    def test_units_that_stay_active_pass_every_settle_check(self):
        started, checked, sleeps = [], [], []
        units = ["rustiron-coordinator.service", "rustiron-executor.service"]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            updater.start_units(
                units,
                runner=lambda *arguments: started.append(arguments[-1]),
                checker=lambda *arguments: checked.append(arguments[-1]) or "active\n",
                sleep=sleeps.append,
            )
        self.assertEqual(started, list(reversed(units)))
        self.assertEqual(len(checked), updater.SETTLE_CHECKS * len(units))
        self.assertEqual(len(sleeps), updater.SETTLE_CHECKS - 1)
        self.assertEqual(out.getvalue(), "".join(f"ACTIVE {unit}\n" for unit in units))

    def test_finish_host_reloads_only_changed_modules(self):
        runner = mock.Mock()
        module = f"{installer.MODULE_DIR}/rustiron_php.pp"
        updater.finish_host(self.target, ["usr/bin/rustiron", module], runner)
        self.assertEqual(runner.call_args_list[0], mock.call("/usr/sbin/semodule", "-i", f"/{module}"))
        self.assertEqual(runner.call_args_list[1], mock.call("/usr/sbin/restorecon", "-v", "/usr/bin/rustiron", f"/{module}"))
        runner.reset_mock()
        updater.finish_host(self.target, ["usr/bin/rustiron"], runner)
        self.assertNotIn("/usr/sbin/semodule", [call.args[0] for call in runner.call_args_list])

    def apply_update(self, names, new_bytes):
        sources = {name: new_bytes for name in names}
        digests = {**self.old, **{name: digest(new_bytes) for name in names}}
        record, content = updater.load_record(self.target, self.owner)
        with mock.patch.object(updater, "busy_units", return_value=[]), \
                mock.patch.object(updater, "active_units", return_value=["rustiron-executor.service"]), \
                mock.patch.object(updater, "stop_units") as stop, \
                mock.patch.object(updater, "start_units") as start, \
                mock.patch.object(updater, "finish_host") as finish, \
                mock.patch.object(updater, "utc_stamp", return_value="20261115T000000Z"), \
                contextlib.redirect_stdout(io.StringIO()):
            folder = updater.execute(
                self.target, names, content, lambda folder: updater.new_record(record, digests, folder),
                lambda name: (lambda: iter((sources[name],))), digests, "update", self.owner)
        stop.assert_called_once_with(["rustiron-executor.service"])
        start.assert_called_once_with(["rustiron-executor.service"])
        finish.assert_called_once()
        return folder, digests

    def test_update_then_rollback_restores_the_exact_files_and_record(self):
        name = "usr/libexec/rustiron/rustiron-executor"
        folder, digests = self.apply_update([name], b"new executor\n")
        self.assertEqual((self.target / name).read_bytes(), b"new executor\n")
        self.assertEqual((folder / updater.FILES / name).read_bytes(), f"old {name}\n".encode())
        manifest = json.loads((folder / updater.UPDATE_MANIFEST).read_text())
        self.assertEqual(manifest["state"], "complete")
        self.assertEqual(manifest["stopped"], ["rustiron-executor.service"])
        record, _ = updater.load_record(self.target, self.owner)
        self.assertEqual(record["payload"][name]["sha256"], digests[name])
        self.assertEqual(updater.drift(self.target, record, self.owner), [])

        _record, _content, old_content, old_digests, names, restored, dropped, _folders = updater.plan_rollback(
            folder, self.target, self.owner)
        self.assertEqual((names, restored, dropped), ([name], [], []))
        self.assertEqual(old_content, self.record_content)
        self.assertEqual(old_digests[name], self.old[name])

    def test_rollback_refuses_after_a_later_change(self):
        name = "usr/libexec/rustiron/rustiron-executor"
        folder, _ = self.apply_update([name], b"new executor\n")
        (self.target / name).chmod(0o755)
        (self.target / name).write_bytes(b"changed again\n")
        with self.assertRaisesRegex(updater.Refused, "differs from the install record"):
            updater.plan_rollback(folder, self.target, self.owner)

    def test_rollback_refuses_a_folder_outside_the_updates_folder(self):
        with self.assertRaisesRegex(updater.Refused, "not an update folder"):
            updater.plan_rollback(self.target / "elsewhere", self.target, self.owner)

    def test_a_busy_operation_stops_before_any_change(self):
        with mock.patch.object(updater, "busy_units", return_value=["rustiron-capture-x.service"]), \
                self.assertRaisesRegex(updater.Refused, "operation unit active"):
            updater.execute(self.target, ["usr/bin/rustiron"], self.record_content, None, None, self.new, "update", self.owner)
        self.assertFalse((self.target / updater.UPDATES).exists())

    def test_plan_update_refuses_unsigned_staging_without_explicit_opt_in(self):
        # W639 (H-09): forward updates require --release-signers + --release-signer-id
        # unless --allow-unsigned-lab is passed explicitly.
        args = types.SimpleNamespace(
            install_root=self.target,
            management_root=self.target,
            host_job_root=self.target,
            job_profile=self.target / "profile.json",
            release_signers=None,
            release_signer_id=None,
            allow_unsigned_lab=False,
        )
        with self.assertRaisesRegex(ValueError, "release signature verification is required"):
            updater.plan_update(args, target=self.target, owner=self.owner)

    def test_execute_records_release_signature_in_update_manifest(self):
        name = "usr/libexec/rustiron/rustiron-executor"
        new_bytes = b"signed executor\n"
        digests = {**self.old, name: digest(new_bytes)}
        record, content = updater.load_record(self.target, self.owner)
        sig_meta = {
            "verified": True,
            "namespace": "rustiron-release-v1",
            "signer_id": "release-owner",
            "sha256sums_sha256": "b" * 64,
        }
        with mock.patch.object(updater, "busy_units", return_value=[]), \
                mock.patch.object(updater, "active_units", return_value=[]), \
                mock.patch.object(updater, "stop_units"), mock.patch.object(updater, "start_units"), \
                mock.patch.object(updater, "finish_host"), \
                mock.patch.object(updater, "utc_stamp", return_value="20261124T000000Z"), \
                contextlib.redirect_stdout(io.StringIO()):
            folder = updater.execute(
                self.target, [name], content, lambda f: updater.new_record(record, digests, f),
                lambda _n: (lambda: iter((new_bytes,))), digests, "update", self.owner,
                release_signature=sig_meta,
            )
        manifest = json.loads((folder / updater.UPDATE_MANIFEST).read_text())
        self.assertEqual(manifest["release_signature"], sig_meta)


if __name__ == "__main__":
    unittest.main()
