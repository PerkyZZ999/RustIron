"""Unit tests for packaging/rustiron-install-wizard.py (W646)."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "packaging/rustiron-install-wizard.py"
SPEC = importlib.util.spec_from_file_location("rustiron_install_wizard", SCRIPT)
wizard = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = wizard
SPEC.loader.exec_module(wizard)


class InstallWizardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rustiron-wizard-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "etc/selinux").mkdir(parents=True)
        (self.root / "etc/os-release").write_text('ID="almalinux"\nVERSION_ID="10.3"\n')
        (self.root / "etc/selinux/config").write_text("SELINUX=disabled\nSELINUXTYPE=targeted\n")

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = wizard.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_plan_mode_emits_auditable_blueprint_without_writing_files(self):
        code, stdout, stderr = self.run_cli([
            "--json",
            "--root", str(self.root),
            "--host-id", "pilot_vps_1",
            "--host-epoch", "epoch_1",
            "--public-ipv4", "198.51.100.25",
            "--issuer", "pilot_signer",
            "--console-domain", "console.example.test",
        ])
        self.assertEqual(code, 0, stderr)
        doc = json.loads(stdout)
        self.assertEqual(doc["schema"], "rustiron-install-wizard-plan/1")
        self.assertFalse(doc["private_keys_on_host"])
        self.assertTrue(doc["host_inspection"]["is_almalinux_10"])
        self.assertTrue(doc["host_inspection"]["selinux_reboot_needed"])
        step_ids = [s["id"] for s in doc["steps"]]
        self.assertIn("ssh_hardening", step_ids)
        self.assertIn("selinux_enforcing", step_ids)
        self.assertIn("sites_xfs_usrquota", step_ids)
        self.assertIn("host_enrollment_and_dropins", step_ids)
        self.assertIn("console_admin_panel", step_ids)
        # Enrollment command includes ACME directory and firewall flags.
        enroll_step = next(s for s in doc["steps"] if s["id"] == "host_enrollment_and_dropins")
        enroll_cmd = enroll_step["commands"][0]
        self.assertIn("--acme-directory https://acme-v02.api.letsencrypt.org/directory", enroll_cmd)
        self.assertIn("--ols-address 198.51.100.25:80", enroll_cmd)
        self.assertIn("--ols-tls-address 198.51.100.25:443", enroll_cmd)
        self.assertIn(
            "/etc/systemd/system/rustiron-site-cron.service.d/10-ols-listener.conf",
            enroll_step["dropin_files"],
        )
        # Dry-run writes nothing to the root filesystem.
        self.assertFalse((self.root / "etc/ssh/sshd_config.d/01-rustiron-ssh.conf").exists())
        self.assertFalse((self.root / "etc/rustiron-console/env").exists())

    def test_refuses_invalid_inputs_before_any_write(self):
        bad_cases = [
            ["--ssh-port", "443"],
            ["--issuer", "rustiron_coordinator"],
            ["--public-ipv4", "not-an-ip"],
            ["--acme-directory", "http://insecure.example/dir"],
            ["--console-port", "3306"],
            ["--console-domain", "BAD_HOST"],
            ["--uid-range", "100-200"],
        ]
        for extra in bad_cases:
            with self.subTest(extra=extra):
                code, _, err = self.run_cli(["--root", str(self.root), *extra])
                self.assertEqual(code, 1)
                self.assertIn("REFUSED", err)

    def test_apply_writes_hardened_dropins_console_env_and_triggers_selinux_reboot_gate(self):
        code, stdout, stderr = self.run_cli([
            "--apply", "--json",
            "--root", str(self.root),
            "--host-id", "pilot_vps_1",
            "--public-ipv4", "198.51.100.25",
            "--ssh-port", "2222",
            "--console-domain", "console.example.test",
        ])
        self.assertEqual(code, 0, stderr)
        payload = json.loads(stdout)
        self.assertTrue(payload["apply_result"]["reboot_required"])

        ssh_dropin = self.root / "etc/ssh/sshd_config.d/01-rustiron-ssh.conf"
        self.assertEqual(stat.S_IMODE(ssh_dropin.stat().st_mode), 0o600)
        ssh_text = ssh_dropin.read_text()
        self.assertIn("Port 2222", ssh_text)
        self.assertIn("PasswordAuthentication no", ssh_text)

        # Both admin-helper and site-cron receive the enrolled OLS IP allowlist drop-in (W646 Bug #5).
        for unit in ("rustiron-admin-helper.service.d", "rustiron-site-cron.service.d"):
            dropin = self.root / "etc/systemd/system" / unit / "10-ols-listener.conf"
            self.assertIn("IPAddressAllow=198.51.100.25/32", dropin.read_text())

        env_file = self.root / "etc/rustiron-console/env"
        self.assertEqual(stat.S_IMODE(env_file.stat().st_mode), 0o600)
        env_text = env_file.read_text()
        self.assertIn("NODE_ENV=production", env_text)
        self.assertIn("RUSTIRON_CONSOLE_AUTH_REQUIRED=1", env_text)
        self.assertIn("RUSTIRON_CONSOLE_ORIGIN=https://console.example.test", env_text)
        self.assertIn("RUSTIRON_CONSOLE_SETUP_TOKEN=", env_text)
        # Setup token must never appear in stdout!
        token = next(line.split("=", 1)[1] for line in env_text.splitlines() if line.startswith("RUSTIRON_CONSOLE_SETUP_TOKEN="))
        self.assertGreaterEqual(len(token), 32)
        self.assertNotIn(token, stdout)

        # W733 (QA-02): the Console runs as the coordinator UID, the only peer its
        # socket accepts, and reads an observation the shipped timer keeps fresh.
        self.assertIn("RUSTIRON_OBSERVATION=/var/lib/rustiron-console/observe/observation.json", env_text)
        unit_text = (self.root / "etc/systemd/system/rustiron-console.service").read_text()
        self.assertIn("User=rustiron-coordinator\n", unit_text)
        self.assertIn("StateDirectory=rustiron-console\n", unit_text)
        self.assertNotIn("rustiron-build", unit_text)
        # W764: neither the unit nor the user's memberships give the executor group.
        self.assertNotIn("rustiron-requesters", unit_text)
        script = self.root / "usr/local/libexec/rustiron-console/rustiron-console-observe"
        self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o755)
        self.assertIn("runuser -u \"$OWNER\"", script.read_text())
        observe_unit = (self.root / "etc/systemd/system/rustiron-console-observe.service").read_text()
        self.assertIn(f"ExecStart=/usr/local/libexec/rustiron-console/rustiron-console-observe {wizard.CONSOLE_OBSERVATION}", observe_unit)
        timer = (self.root / "etc/systemd/system/rustiron-console-observe.timer").read_text()
        self.assertIn("OnUnitActiveSec=30s", timer)
        self.assertIn("console_admin_panel", json.dumps(payload))

        # SELinux config flipped to enforcing and /.autorelabel created.
        self.assertIn("SELINUX=enforcing", (self.root / "etc/selinux/config").read_text())
        self.assertTrue((self.root / ".autorelabel").is_file())

    def test_interactive_prompt_uses_validated_answers(self):
        answers = iter([
            "vps_alpha", "epoch_2", "203.0.113.55", "22", "owner_key", "policy_2",
            wizard.DEFAULT_ACME_DIRECTORY, "20", "yes", "panel.example.test",
        ])
        out = io.StringIO()
        cfg = wizard.prompt_interactive(
            wizard.WizardConfig(host_id="d", host_epoch="e", public_ipv4="203.0.113.1"),
            input_fn=lambda _prompt: next(answers),
            out=out,
        )
        self.assertEqual(cfg.host_id, "vps_alpha")
        self.assertEqual(cfg.public_ipv4, "203.0.113.55")
        self.assertEqual(cfg.sites_xfs_loopback_gib, 20)
        self.assertEqual(cfg.console_domain, "panel.example.test")

    def test_caddy_edge_over_ols_wizard_plan_binds_ols_loopback_and_caddy_public(self):
        # W657 (D-102, Decision A1): single-IP mixed host puts Caddy on :80/:443
        # and OpenLiteSpeed on 127.0.0.1:8080.
        code, stdout, stderr = self.run_cli([
            "--json",
            "--root", str(self.root),
            "--host-id", "mixed_vps_1",
            "--public-ipv4", "198.51.100.25",
            "--ingress-mode", "caddy_edge_over_ols",
            "--ols-loopback-port", "8080",
        ])
        self.assertEqual(code, 0, stderr)
        doc = json.loads(stdout)
        enroll_step = next(s for s in doc["steps"] if s["id"] == "host_enrollment_and_dropins")
        enroll_cmd = enroll_step["commands"][0]
        self.assertIn("--ols-address 127.0.0.1:8080", enroll_cmd)
        self.assertNotIn("--ols-tls-address", enroll_cmd)
        self.assertIn("--caddy-mode caddy_edge_over_ols", enroll_cmd)
        self.assertIn("--caddy-http-address 198.51.100.25:80", enroll_cmd)
        self.assertIn("--caddy-https-address 198.51.100.25:443", enroll_cmd)
        self.assertIn("--caddy-ols-upstream 127.0.0.1:8080", enroll_cmd)
        self.assertIn("caddy", doc["host_inspection"]["packages"])

        # caddy_multi_ip without distinct --caddy-ipv4 is refused.
        code, _, err = self.run_cli([
            "--root", str(self.root),
            "--public-ipv4", "198.51.100.25",
            "--ingress-mode", "caddy_multi_ip",
        ])
        self.assertEqual(code, 1)
        self.assertIn("REFUSED", err)

    def test_enable_postgres_emits_pinned_pgdg_18_and_hardened_loopback_step(self):
        # W658 (D-102 Decision C2): --enable-postgres adds the PGDG 18.7+ setup step.
        code, stdout, stderr = self.run_cli([
            "--json",
            "--root", str(self.root),
            "--host-id", "pg_vps_1",
            "--public-ipv4", "198.51.100.26",
            "--enable-postgres",
        ])
        self.assertEqual(code, 0, stderr)
        doc = json.loads(stdout)
        self.assertIn("postgresql18", doc["host_inspection"]["packages"])
        pg_step = next(s for s in doc["steps"] if s["id"] == "postgresql_18_setup")
        joined = "\n".join(pg_step["commands"])
        self.assertIn("pgdg-keys.sha256", joined)
        self.assertIn("rustiron-pgdg-18.repo", joined)
        self.assertIn("postgresql18-server", joined)
        self.assertIn("zz-rustiron-loopback.conf", joined)
        self.assertIn("pg_hba.conf", joined)
        self.assertIn("restorecon -RF /usr/pgsql-18/bin", joined)
        self.assertIn("postgresql-18.service", joined)


if __name__ == "__main__":
    unittest.main()
