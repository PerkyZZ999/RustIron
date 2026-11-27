"""Test the installer input and collision checks with private fixtures."""

import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[2] / "packaging/install-preflight.py"
SPEC = importlib.util.spec_from_file_location("install_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)

ASSEMBLE_SPEC = importlib.util.spec_from_file_location(
    "assemble_install_root", SCRIPT.with_name("assemble-install-root.py")
)
assembler = importlib.util.module_from_spec(ASSEMBLE_SPEC)
ASSEMBLE_SPEC.loader.exec_module(assembler)


class InstallerPreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rustiron-preflight-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def stage(self):
        artifact = self.root / "usr/bin/rustiron"
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"synthetic executable")
        artifact.chmod(0o755)
        self.reseal()
        return artifact

    def reseal(self):
        self.assertEqual(preflight.manifest.main(["manifest", "manifest", str(self.root)]), 0)

    def test_required_packages_cover_site_php_and_quota_tools(self):
        # W358: provisioning verify.php calls posix_getpwuid (lsphp84-process)
        # and mysqli (lsphp84-mysqlnd); the product quota step runs the
        # quota package tools. A clean host lacked lsphp84-process.
        for package in ("openlitespeed", "lsphp84", "lsphp84-mysqlnd", "lsphp84-process",
                        "mariadb-server", "quota"):
            self.assertIn(package, preflight.REQUIRED_PACKAGES)
        source = Path(__file__).resolve().parents[2] / "crates/executor/src/provision_assets/verify.php"
        self.assertIn("posix_getpwuid", source.read_text())
        # W453 (D-054): the WordPress extensions of the profile; mbstring and
        # intl need libraries from another repository and are not required.
        for package in ("lsphp84-xml", "lsphp84-gd", "lsphp84-opcache", "lsphp84-sodium",
                        "lsphp84-bcmath"):
            self.assertIn(package, preflight.REQUIRED_PACKAGES)
        for package in ("lsphp84-mbstring", "lsphp84-intl"):
            self.assertNotIn(package, preflight.REQUIRED_PACKAGES)

    def test_stage_accepts_exact_inventory_and_modes(self):
        self.stage()
        expected = {"usr/bin/rustiron": 0o755}
        self.assertEqual(set(preflight.check_stage(self.root, expected)), set(expected))

    def test_stage_rejects_extra_file_even_after_manifest_is_regenerated(self):
        self.stage()
        (self.root / "extra").write_bytes(b"extra")
        self.reseal()
        with self.assertRaisesRegex(ValueError, "unexpected payload inventory"):
            preflight.check_stage(self.root, {"usr/bin/rustiron": 0o755})

    def test_stage_rejects_mode_drift_with_matching_file_bytes(self):
        self.stage().chmod(0o4755)
        with self.assertRaisesRegex(ValueError, "unexpected mode"):
            preflight.check_stage(self.root, {"usr/bin/rustiron": 0o755})

    def test_stage_rejects_changed_bytes(self):
        self.stage().write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "staged bytes differ"):
            preflight.check_stage(self.root, {"usr/bin/rustiron": 0o755})

    def test_fresh_destinations_have_no_conflicts(self):
        self.assertEqual(list(preflight.destination_conflicts(self.root, os.getuid())), [])

    def test_existing_state_refuses_even_when_empty(self):
        (self.root / "var/lib/rustiron").mkdir(parents=True)
        conflicts = list(preflight.destination_conflicts(self.root, os.getuid()))
        self.assertIn("existing path /var/lib/rustiron", conflicts)

    def test_dangling_unit_enablement_link_refuses(self):
        wants = self.root / "etc/systemd/system/sockets.target.wants"
        wants.mkdir(parents=True)
        (wants / "rustiron-site-php@old.socket").symlink_to("../missing")
        conflicts = list(preflight.destination_conflicts(self.root, os.getuid()))
        self.assertIn(
            "existing unit path /etc/systemd/system/sockets.target.wants/rustiron-site-php@old.socket",
            conflicts,
        )

    def test_symlinked_destination_ancestry_refuses(self):
        (self.root / "etc").symlink_to("outside")
        with self.assertRaisesRegex(ValueError, "untrusted destination parent /etc"):
            preflight.check_destination(self.root, "etc/rustiron", os.getuid())

    def sites_mount(self, mode=0o755):
        """An existing /srv/sites and a mount table line that names it as a mount root."""
        sites = self.root / preflight.SITES_ROOT
        sites.mkdir(parents=True)
        sites.chmod(mode)
        device = sites.stat().st_dev
        line = f"96 22 {os.major(device)}:{os.minor(device)} / {sites} rw,relatime - xfs /dev/vdb rw,usrquota"
        return sites, line

    def sites_conflicts(self, *lines, selinux_type="var_t"):
        table = "\n".join(("22 1 253:0 / / rw - xfs /dev/vda rw", *lines)) + "\n"
        with mock.patch.object(preflight, "read_mountinfo", return_value=table), \
                mock.patch.object(preflight, "selinux_type", return_value=selinux_type):
            return list(preflight.destination_conflicts(self.root, os.getuid()))

    def test_empty_sites_mount_point_is_accepted(self):
        # W361: the operator mounts the quota file system before installation.
        _, line = self.sites_mount()
        self.assertEqual(self.sites_conflicts(line), [])
        self.assertEqual(self.sites_conflicts(line, selinux_type="httpd_sys_content_t"), [])

    def test_existing_sites_directory_that_is_not_a_mount_refuses(self):
        self.sites_mount()
        self.assertIn("existing path /srv/sites", self.sites_conflicts())

    def test_sites_mount_with_content_mode_or_label_drift_refuses(self):
        sites, line = self.sites_mount()
        (sites / "rs_old").mkdir()
        self.assertIn("existing mount /srv/sites is not empty", self.sites_conflicts(line))
        (sites / "rs_old").rmdir()
        self.assertEqual(
            self.sites_conflicts(line, selinux_type="unlabeled_t"),
            ["existing mount /srv/sites has SELinux type unlabeled_t"],
        )
        sites.chmod(0o775)
        self.assertIn("existing mount /srv/sites must be a 0755 directory owned by root",
                      self.sites_conflicts(line))

    def test_bind_nested_over_and_foreign_device_sites_mounts_refuse(self):
        sites, line = self.sites_mount()
        bind = line.replace(" / ", " /data/sites ", 1)
        nested = f"99 96 7:2 / {sites}/rs_x rw - ext4 /dev/loop2 rw,usrquota"
        foreign = line.replace(line.split()[2], "7:9", 1)
        for table in ((bind,), (line, nested), (line, line.replace("96 22", "97 96", 1)), (foreign,)):
            self.assertIn(
                "existing mount /srv/sites is not the root of one file system",
                self.sites_conflicts(*table),
                table,
            )

    def test_symlinked_sites_root_refuses(self):
        (self.root / "srv").mkdir()
        (self.root / "elsewhere").mkdir(mode=0o755)
        (self.root / preflight.SITES_ROOT).symlink_to(self.root / "elsewhere")
        self.assertIn("existing path /srv/sites", self.sites_conflicts())

    def test_management_inventory_ships_the_ols_killmode_dropin(self):
        # W364: W245 made KillMode=mixed for lshttpd a product requirement.
        # W361 saw package workers outlive a compensation stop (KillMode=none).
        source = Path(__file__).resolve().parents[2]
        self.assertEqual(preflight.OLS_UNIT_DROPIN,
                         "etc/systemd/system/lshttpd.service.d/50-rustiron-killmode.conf")
        self.assertEqual(preflight.MANAGEMENT_FILES[preflight.OLS_UNIT_DROPIN], 0o644)
        shipped = (source / "packaging/systemd/lshttpd.service.d/50-rustiron-killmode.conf").read_bytes()
        # The same bytes that W245 proved and that C07 checks on the lab VM.
        self.assertEqual(shipped, (source / "lab/s10/lshttpd.service.d/50-rustiron-killmode.conf").read_bytes())
        self.assertIn(b"[Service]\nKillMode=mixed\n", shipped)
        self.assertNotIn(b"SuccessExitStatus", shipped)  # D-022
        stage = (source / "packaging/stage-product.sh").read_text()
        self.assertIn('"$stage/etc/systemd/system/lshttpd.service.d/50-rustiron-killmode.conf"', stage)

    def test_management_inventory_ships_the_ols_boot_guard(self):
        # W381 (D-032): lshttpd wants the guard and starts after it; the guard
        # runs the executor's fixed `ols-boot-guard` command before OLS, the
        # admin helper, and the executor.
        source = Path(__file__).resolve().parents[2]
        self.assertEqual(preflight.OLS_GUARD_DROPIN,
                         "etc/systemd/system/lshttpd.service.d/51-rustiron-boot-guard.conf")
        self.assertEqual(preflight.OLS_UNIT_DROPINS, (preflight.OLS_UNIT_DROPIN, preflight.OLS_GUARD_DROPIN))
        self.assertEqual(preflight.MANAGEMENT_FILES[preflight.OLS_GUARD_DROPIN], 0o644)
        self.assertIn("rustiron-ols-boot-guard.service", preflight.MANAGEMENT_UNITS)
        self.assertEqual(
            preflight.MANAGEMENT_FILES["usr/lib/systemd/system/rustiron-ols-boot-guard.service"], 0o644)
        dropin = (source / "packaging/systemd/lshttpd.service.d/51-rustiron-boot-guard.conf").read_text()
        self.assertIn("[Unit]\nWants=rustiron-ols-boot-guard.service\nAfter=rustiron-ols-boot-guard.service\n",
                      dropin)
        # W389 (D-038): the only [Service] line is the parent start condition.
        self.assertEqual(dropin.count("[Service]\n"), 1)
        unit = (source / "packaging/systemd/rustiron-ols-boot-guard.service").read_text()
        self.assertIn("ExecStart=/usr/libexec/rustiron/rustiron-executor ols-boot-guard\n", unit)
        self.assertIn(
            "ExecStartPost=/usr/libexec/rustiron/rustiron-admin-helper boot-restore-ejected-php\n",
            unit,
        )
        self.assertIn(
            "Before=lshttpd.service rustiron-admin-helper.service rustiron-executor.service\n", unit)
        for line in ("Type=oneshot\n", "RemainAfterExit=yes\n", "RefuseManualStart=yes\n",
                     "PrivateNetwork=yes\n", "CapabilityBoundingSet=\n",
                     "ReadWritePaths=/var/lib/rustiron /etc/rustiron-ols\n"):
            self.assertIn(line, unit)
        self.assertNotIn("[Install]", unit)
        stage = (source / "packaging/stage-product.sh").read_text()
        self.assertIn('"$stage/etc/systemd/system/lshttpd.service.d/51-rustiron-boot-guard.conf"', stage)
        self.assertIn("rustiron-ols-boot-guard.service", stage)

    def test_management_inventory_ships_the_scheduled_capture_units(self):
        # W386 (D-035): two services and two timers, staged with the other
        # management units and never enabled by the installer.
        source = Path(__file__).resolve().parents[2]
        stage = (source / "packaging/stage-product.sh").read_text()
        for name in ("rustiron-scheduled-capture.service", "rustiron-scheduled-capture.timer",
                     "rustiron-scheduled-capture-check.service", "rustiron-scheduled-capture-check.timer"):
            self.assertIn(name, preflight.MANAGEMENT_UNITS)
            self.assertEqual(preflight.MANAGEMENT_FILES[f"usr/lib/systemd/system/{name}"], 0o644)
            self.assertIn(name, stage)
        for service, command in (("rustiron-scheduled-capture.service", "schedule run"),
                                 ("rustiron-scheduled-capture-check.service", "schedule status")):
            unit = (source / "packaging/systemd" / service).read_text()
            self.assertIn(
                "ExecStart=/usr/bin/rustiron --output json --socket /run/rustiron-coordinator/control.sock "
                f"{command} --dir /var/lib/rustiron-coordinator/standing/current "
                "--rpo-target-seconds ${RUSTIRON_RPO_TARGET_SECONDS}\n", unit)
            for line in ("User=rustiron-coordinator\n", "Type=oneshot\n", "NoNewPrivileges=yes\n",
                         "CapabilityBoundingSet=\n", "PrivateNetwork=yes\n", "RestrictAddressFamilies=AF_UNIX\n",
                         "ProtectSystem=strict\n",
                         "ConditionPathExists=/var/lib/rustiron-coordinator/standing/current/grant.json.sig\n"):
                self.assertIn(line, unit)
            self.assertNotIn("[Install]", unit)
            self.assertNotIn("ReadWritePaths", unit)
        timer = (source / "packaging/systemd/rustiron-scheduled-capture.timer").read_text()
        self.assertIn("OnCalendar=*-*-* 03:00:00 America/Toronto\n", timer)
        self.assertIn("[Install]\nWantedBy=timers.target\n", timer)

    def test_ols_starts_only_with_the_shipped_parent(self):
        # W389 (D-038): the OLS package %posttrans runs `systemctl restart
        # lsws` on every upgrade, downgrade, and reinstall. With a parent
        # that is not the shipped one, that restart served the package
        # parent: WebAdmin on 0.0.0.0:7080, the sample on 0.0.0.0:8088, and
        # no Rustiron site. The start condition compares the live parent
        # with the shipped template, byte for byte. A difference (exit 1) or
        # a missing file (exit 2) skips the start: the unit stays inactive,
        # with no restart loop and no listener.
        source = Path(__file__).resolve().parents[2]
        dropin = (source / "packaging/systemd/lshttpd.service.d/51-rustiron-boot-guard.conf").read_text()
        service = dropin.split("[Service]\n", 1)[1].split("[Unit]\n", 1)[0]
        self.assertEqual(
            [line for line in service.splitlines() if line and not line.startswith("#")],
            [f"ExecCondition=/usr/bin/cmp -s /{preflight.PARENT_TEMPLATE} /{preflight.OLS_PARENT}"])
        self.assertLess(dropin.index("[Service]\n"), dropin.index("[Unit]\n"))
        self.assertNotIn("ExecStartPre", dropin)
        self.assertIn("/usr/bin/cmp", preflight.COMMANDS)

    def test_ols_starts_only_with_a_generation(self):
        # W382 (D-033): with no `current`, the package unit restarted OLS
        # every 5 s (W381). The condition skips the start instead, so the
        # unit stays `inactive` (a bootstrap fact, W355) with no restart
        # loop. systemd checks it after the boot guard (After=), which may
        # remove `current` for an interrupted bootstrap activation (D-032).
        # The check must not follow the link: SELinux refuses init_t a read
        # of the link, so ConditionPathExists skipped every start, also the
        # bootstrap start with `current` on the target (W382 run 1).
        source = Path(__file__).resolve().parents[2]
        dropin = (source / "packaging/systemd/lshttpd.service.d/51-rustiron-boot-guard.conf").read_text()
        unit_lines = dropin.split("[Unit]\n", 1)[1].splitlines()
        self.assertEqual(
            [line for line in unit_lines if line and not line.startswith("#")],
            ["Wants=rustiron-ols-boot-guard.service",
             "After=rustiron-ols-boot-guard.service",
             "ConditionPathIsSymbolicLink=/etc/rustiron-ols/current"])
        self.assertNotIn("ConditionPathExists", dropin.split("[Unit]\n", 1)[1])
        self.assertNotIn("Restart=", dropin)

    FRESH_UNIT = (
        "FragmentPath=/usr/lib/systemd/system/lshttpd.service\n"
        "DropInPaths=\n"
        "NeedDaemonReload=no\n"
    )

    def unit_conflicts(self, text):
        return list(preflight.ols_unit_conflicts(show=lambda: text))

    def test_the_vendor_ols_unit_without_a_dropin_has_no_conflict(self):
        self.assertEqual(self.unit_conflicts(self.FRESH_UNIT), [])
        self.assertEqual(self.unit_conflicts("NeedDaemonReload=no\nDropInPaths=\n"
                                             "FragmentPath=/usr/lib/systemd/system/lshttpd.service"), [])

    def test_an_existing_ols_unit_dropin_override_or_pending_reload_refuses(self):
        # Any existing drop-in could set KillMode again after the Rustiron one.
        dropin = self.FRESH_UNIT.replace("DropInPaths=", "DropInPaths=/etc/systemd/system/lshttpd.service.d/99-local.conf")
        self.assertEqual(self.unit_conflicts(dropin), [
            "OLS unit lshttpd.service DropInPaths=/etc/systemd/system/lshttpd.service.d/99-local.conf, expected ''",
        ])
        override = self.FRESH_UNIT.replace("/usr/lib/systemd/system/lshttpd.service",
                                           "/etc/systemd/system/lshttpd.service")
        self.assertEqual(len(self.unit_conflicts(override)), 1)
        pending = self.FRESH_UNIT.replace("NeedDaemonReload=no", "NeedDaemonReload=yes")
        self.assertEqual(len(self.unit_conflicts(pending)), 1)

    def test_unreadable_ols_unit_properties_refuse(self):
        for text in ("", "FragmentPath\n", self.FRESH_UNIT + "DropInPaths=\n", self.FRESH_UNIT + "KillMode=none\n"):
            conflicts = self.unit_conflicts(text)
            self.assertEqual(len(conflicts), 1, text)
            self.assertIn("unrecognized systemctl show output", conflicts[0])

        def failing():
            raise preflight.subprocess.CalledProcessError(1, "systemctl")

        self.assertEqual(len(list(preflight.ols_unit_conflicts(show=failing))), 1)

    def package_parent(self, content=b"listener Default {\n address *:8088\n}\n"):
        parent = self.root / preflight.OLS_PARENT
        parent.parent.mkdir(parents=True)
        parent.write_bytes(content)
        return parent

    def test_package_ols_parent_is_read_without_conflict(self):
        self.package_parent()
        self.assertEqual(list(preflight.ols_parent_conflicts(self.root, os.getuid())), [])
        self.assertIn(b"8088", preflight.read_package_parent(self.root, os.getuid()))

    def test_missing_ols_parent_refuses(self):
        conflicts = list(preflight.ols_parent_conflicts(self.root, os.getuid()))
        self.assertEqual(conflicts, [f"missing OLS parent /{preflight.OLS_PARENT}"])

    def test_rustiron_managed_ols_parent_refuses(self):
        self.package_parent(b"disableWebAdmin 1\ninclude   /etc/rustiron-ols/current/*.conf\n")
        with self.assertRaisesRegex(ValueError, r"existing Rustiron-managed OLS parent .*include"):
            preflight.read_package_parent(self.root, os.getuid())

    def test_writable_ols_conf_directory_refuses(self):
        parent = self.package_parent()
        parent.parent.chmod(0o770)
        with self.assertRaisesRegex(ValueError, "untrusted destination parent /usr/local/lsws/conf"):
            preflight.read_package_parent(self.root, os.getuid())

    def test_linked_ols_parent_refuses(self):
        parent = self.package_parent()
        os.link(parent, self.root / "second-link")
        with self.assertRaisesRegex(ValueError, "not a single-link regular file"):
            preflight.read_package_parent(self.root, os.getuid())
        (self.root / "second-link").unlink()
        parent.rename(parent.with_name("real.conf"))
        parent.symlink_to("real.conf")
        with self.assertRaisesRegex(ValueError, "unreadable OLS parent"):
            preflight.read_package_parent(self.root, os.getuid())

    def test_install_root_copy_rejects_replaced_source_bytes(self):
        source = self.stage()
        modes = {"usr/bin/rustiron": 0o755}
        digests = preflight.check_stage(self.root, modes)
        source.write_bytes(b"changed after preflight")
        output = self.root / "output"
        with self.assertRaisesRegex(ValueError, "source bytes changed"):
            assembler.copy_stage(self.root, output, modes, digests)

    def test_install_root_copy_refuses_a_symlinked_source_parent(self):
        source = self.stage()
        modes = {"usr/bin/rustiron": 0o755}
        digests = {"usr/bin/rustiron": hashlib.sha256(source.read_bytes()).hexdigest()}
        directory = source.parent
        original = directory.with_name("original")
        directory.rename(original)
        directory.symlink_to(original)
        with self.assertRaises(OSError):
            assembler.copy_stage(self.root, self.root / "output", modes, digests)

    def matrix(self):
        return preflight.load_matrix()

    def test_the_reviewed_stack_is_supported(self):
        matrix = self.matrix()
        versions = {"os": "10.2", "openlitespeed": "1.9.4", "php": "8.4.27", "mariadb": "10.11.18"}
        self.assertEqual(preflight.support_problems(matrix, versions, matrix["reviewed_unix"] + 1), [])
        newer = {**versions, "openlitespeed": "1.9.10", "os": "10.3"}
        self.assertEqual(preflight.support_problems(matrix, newer, matrix["reviewed_unix"] + 1), [])

    def test_unsupported_old_ended_or_unreadable_versions_are_refused(self):
        matrix = self.matrix()
        now = matrix["reviewed_unix"] + 1
        versions = {"os": "9.6", "openlitespeed": "1.9.3", "php": "8.4.x", "mariadb": "11.4.2"}
        problems = preflight.support_problems(matrix, versions, now)
        self.assertEqual(len(problems), 4, problems)
        self.assertIn("not in the supported series 10", problems[0])
        self.assertIn("older than the reviewed minimum 1.9.4", problems[1])
        self.assertIn("older than the reviewed minimum", problems[2])
        self.assertEqual(len(preflight.support_problems(matrix, {}, now)), 4)
        # W562: PowerDNS counts only where it is installed.
        installed = {"os": "10.2", "openlitespeed": "1.9.4", "php": "8.4.27", "mariadb": "10.11.18"}
        self.assertEqual(preflight.support_problems(matrix, {**installed, "powerdns": "5.1.5"}, now), [])
        old = preflight.support_problems(matrix, {**installed, "powerdns": "5.0.7"}, now)
        self.assertEqual(len(old), 1)
        self.assertIn("PowerDNS Authoritative 5.0.7 is not in the supported series 5.1", old[0])
        good = {"os": "10.2", "openlitespeed": "1.9.4", "php": "8.4.27", "mariadb": "10.11.18"}
        php_end = next(c for c in matrix["components"] if c["name"] == "php")["end_of_life_unix"]
        late = preflight.support_problems(matrix, good, php_end)
        self.assertTrue(any("past its review date" in problem for problem in late), late)
        self.assertTrue(any("PHP (lsphp84) 8.4 reached its end of life" in p for p in late), late)

    def test_mariadb_listeners_beyond_loopback_are_named(self):
        # W569 (W558-F1): the W558 lab listeners, then the loopback ones.
        exposed = "LISTEN 0      80     0.0.0.0:3306 0.0.0.0:*\nLISTEN 0      80        [::]:3306    [::]:*\n"
        self.assertEqual(preflight.exposed_mariadb(exposed), ["0.0.0.0:3306", "[::]:3306"])
        loopback = ("LISTEN 0 80 127.0.0.1:3306 0.0.0.0:*\nLISTEN 0 80 [::1]:3306 [::]:*\n"
                    "LISTEN 0 80 [::ffff:127.0.0.1]:3306 [::]:*\n")
        self.assertEqual(preflight.exposed_mariadb(loopback), [])
        self.assertEqual(preflight.exposed_mariadb("LISTEN 0 80 192.168.0.222:3306 0.0.0.0:*\n"),
                         ["192.168.0.222:3306"])
        preflight.check_mariadb_loopback(read=lambda *a: loopback)
        with self.assertRaisesRegex(ValueError, "beyond loopback"):
            preflight.check_mariadb_loopback(read=lambda *a: exposed)

    def test_installed_versions_come_from_os_release_and_rpm(self):
        packages = {"openlitespeed": "1.9.4", "lsphp84": "8.4.27", "pdns": "5.1.5"}

        def rpm(*arguments):
            if arguments[-1] not in packages:
                raise preflight.subprocess.CalledProcessError(1, arguments)
            return packages[arguments[-1]]

        versions = preflight.installed_versions({"ID": "almalinux", "VERSION_ID": "10.2"}, rpm)
        self.assertEqual(versions, {"os": "10.2", "openlitespeed": "1.9.4", "php": "8.4.27",
                                    "powerdns": "5.1.5"})
        self.assertNotIn("os", preflight.installed_versions({"ID": "rocky", "VERSION_ID": "10.2"}, rpm))

    def test_the_matrix_dates_agree(self):
        import datetime
        matrix = self.matrix()
        day = lambda text: int(datetime.datetime.fromisoformat(text + "T00:00:00+00:00").timestamp())
        self.assertEqual(matrix["reviewed_unix"], day(matrix["reviewed"]))
        for component in matrix["components"]:
            if component["end_of_life"] is None:
                self.assertIsNone(component["end_of_life_unix"])
            else:
                self.assertEqual(component["end_of_life_unix"], day(component["end_of_life"]))
            self.assertIsNotNone(preflight.version_parts(component["minimum"]))

    def test_management_inventory_ships_confined_caddy_unit_and_selinux_policy(self):
        # W657 (D-102, Decisions A1 + B1): confined Caddy edge ingress unit,
        # SELinux policy module, and immutable /etc/rustiron-caddy root.
        source = Path(__file__).resolve().parents[2]
        self.assertIn("rustiron-caddy.service", preflight.MANAGEMENT_UNITS)
        self.assertIn("rustiron_caddy", preflight.MODULES)
        self.assertIn("etc/rustiron-caddy", preflight.OWNED_ROOTS)
        self.assertEqual(
            preflight.MANAGEMENT_FILES["usr/lib/systemd/system/rustiron-caddy.service"], 0o644
        )
        self.assertEqual(
            preflight.MANAGEMENT_FILES["usr/share/rustiron/selinux/rustiron_caddy.pp"], 0o644
        )
        unit = (source / "packaging/systemd/rustiron-caddy.service").read_text()
        for expected in (
            "User=rustiron-caddy\n",
            "Group=rustiron-caddy\n",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n",
            "AmbientCapabilities=CAP_NET_BIND_SERVICE\n",
            "NoNewPrivileges=yes\n",
            "ProtectSystem=strict\n",
            "PrivateTmp=yes\n",
            "ConditionPathIsSymbolicLink=/etc/rustiron-caddy/current\n",
        ):
            self.assertIn(expected, unit)
        te = (source / "packaging/selinux/rustiron_caddy.te").read_text()
        te_rules = "\n".join(line for line in te.splitlines() if not line.lstrip().startswith("#"))
        self.assertIn("allow rustiron_caddy_t http_port_t:tcp_socket name_bind;", te_rules)
        self.assertIn("allow rustiron_caddy_t http_port_t:udp_socket name_bind;", te_rules)
        self.assertIn("read_files_pattern(rustiron_caddy_t, rustiron_tls_t, rustiron_tls_t)", te_rules)
        # Zero outbound HTTP/HTTPS, DB, or shell execution in rustiron_caddy_t.
        for forbidden in (
            "http_port_t:tcp_socket name_connect",
            "corenet_tcp_connect_http_port",
            "mysqld_port_t",
            "postgresql_port_t",
            "corecmd_exec_bin",
            "httpd_sys_rw_content_t",
        ):
            self.assertNotIn(forbidden, te_rules)
        stage = (source / "packaging/stage-product.sh").read_text()
        self.assertIn("rustiron_caddy", stage)
        self.assertIn("rustiron-caddy.service", stage)

    def test_postgresql_18_templates_loopback_check_and_opt_in_app_selinux_domains(self):
        # W658 (D-102 Decision C2): PostgreSQL 18 loopback & SCRAM-SHA-256 templates,
        # port 5432 loopback listener check, and opt-in app DB SELinux sub-types.
        source = Path(__file__).resolve().parents[2]
        self.assertEqual(
            preflight.MANAGEMENT_FILES[preflight.POSTGRES_LOOPBACK_TEMPLATE], 0o644
        )
        self.assertEqual(
            preflight.MANAGEMENT_FILES[preflight.POSTGRES_HBA_TEMPLATE], 0o644
        )
        pg_conf = (source / "packaging/postgres/zz-rustiron-loopback.conf").read_text()
        self.assertIn("listen_addresses = '127.0.0.1'", pg_conf)
        self.assertIn("password_encryption = 'scram-sha-256'", pg_conf)
        pg_hba = (source / "packaging/postgres/pg_hba.conf").read_text()
        hba_rules = [
            line.strip() for line in pg_hba.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(len(hba_rules), 4)
        for rule in hba_rules:
            self.assertNotIn("trust", rule)
            self.assertNotIn("md5", rule)
            self.assertNotIn("0.0.0.0/0", rule)
        # Loopback-only check accepts 127.0.0.1:5432 / [::1]:5432 and refuses 0.0.0.0:5432.
        preflight.check_postgres_loopback(lambda *_: "LISTEN 0 244 127.0.0.1:5432 0.0.0.0:*\n")
        preflight.check_postgres_loopback(lambda *_: "LISTEN 0 244 [::1]:5432 [::]:*\n")
        with self.assertRaisesRegex(ValueError, "PostgreSQL 18 listens beyond loopback"):
            preflight.check_postgres_loopback(lambda *_: "LISTEN 0 244 0.0.0.0:5432 0.0.0.0:*\n")
        # SELinux rustiron_app.te: rustiron_app_t stays at zero DB/outbound connect while
        # rustiron_app_mariadb_t and rustiron_app_pg_t get only their narrow DB connects.
        te = (source / "packaging/selinux/rustiron_app.te").read_text()
        te_rules = "\n".join(line for line in te.splitlines() if not line.lstrip().startswith("#"))
        self.assertIn("policy_module(rustiron_app, 0.2.1)", te_rules)
        self.assertIn("mcs_constrained(rustiron_app_t)", te_rules)
        self.assertIn("mcs_constrained(rustiron_app_mariadb_t)", te_rules)
        self.assertIn("mcs_constrained(rustiron_app_pg_t)", te_rules)
        self.assertIn("corenet_tcp_connect_mysqld_port(rustiron_app_mariadb_t)", te_rules)
        self.assertIn("corenet_tcp_connect_postgresql_port(rustiron_app_pg_t)", te_rules)
        for forbidden in (
            "corenet_tcp_connect_mysqld_port(rustiron_app_t)",
            "corenet_tcp_connect_postgresql_port(rustiron_app_t)",
            "corenet_tcp_connect_mysqld_port(rustiron_app_domain)",
            "corenet_tcp_connect_postgresql_port(rustiron_app_domain)",
            "corenet_tcp_connect_http_port",
            "corecmd_exec_bin",
        ):
            self.assertNotIn(forbidden, te_rules)

    def test_fullstack_dual_ssr_and_blue_green_slot_units_are_hardened_and_staged(self):
        # W659 (D-102 Slice 5): standby slot B and dual-SSR frontend templates.
        source = Path(__file__).resolve().parents[2]
        stage = (source / "packaging/stage-product.sh").read_text()
        for unit_name in (
            "rustiron-app-b@.service",
            "rustiron-app-web@.service",
            "rustiron-app-web-b@.service",
        ):
            self.assertIn(unit_name, preflight.SITE_UNITS)
            self.assertEqual(preflight.MANAGEMENT_FILES[f"etc/systemd/system/{unit_name}"], 0o644)
            self.assertIn(unit_name, stage)
            text = (source / "packaging/systemd" / unit_name).read_text()
            for expected in (
                "User=%i\n",
                "Group=%i\n",
                "NoNewPrivileges=yes\n",
                "ProtectSystem=strict\n",
                "ReadWritePaths=/srv/sites/%i/data /srv/sites/%i/tmp\n",
                "IPAddressDeny=any\n",
                "IPAddressAllow=localhost\n",
            ):
                self.assertIn(expected, text)
