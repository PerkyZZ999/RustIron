"""Unit tests for the D-071 per-site outbound mail relay tooling (W610)."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("mail_relay", ROOT / "packaging" / "mail-relay.py")
mail_relay = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(mail_relay)


class MailRelayRenderTests(unittest.TestCase):
    def test_host_postconf_lab_discard_keeps_mail_inside_vm(self) -> None:
        cfg = mail_relay.render_host_postconf(lab_discard=True, rate_limit=20)
        self.assertEqual(cfg["inet_interfaces"], "loopback-only")
        self.assertEqual(cfg["mydestination"], "")
        self.assertEqual(cfg["relayhost"], "")
        self.assertEqual(cfg["default_transport"], "discard:rustiron-lab-discard")
        self.assertEqual(cfg["smtpd_client_message_rate_limit"], "20")
        self.assertEqual(cfg["smtp_sasl_auth_enable"], "no")

    def test_host_postconf_smarthost_requires_tls_and_sasl(self) -> None:
        cfg = mail_relay.render_host_postconf(
            lab_discard=False, relay_host="smtp.example.net", relay_port=587, rate_limit=45
        )
        self.assertEqual(cfg["inet_interfaces"], "loopback-only")
        self.assertEqual(cfg["relayhost"], "[smtp.example.net]:587")
        self.assertEqual(cfg["default_transport"], "smtp")
        self.assertEqual(cfg["smtp_sasl_auth_enable"], "yes")
        self.assertEqual(cfg["smtp_tls_security_level"], "encrypt")
        self.assertIn("/etc/postfix/rustiron/sasl_passwd", cfg["smtp_sasl_password_maps"])

    def test_host_postconf_refuses_ambiguous_or_bad_inputs(self) -> None:
        with self.assertRaises(mail_relay.Refused):
            mail_relay.render_host_postconf(lab_discard=True, relay_host="smtp.example.net")
        with self.assertRaises(mail_relay.Refused):
            mail_relay.render_host_postconf(lab_discard=False, relay_host=None)
        with self.assertRaises(mail_relay.Refused):
            mail_relay.render_host_postconf(lab_discard=False, relay_host="bad host", relay_port=587)
        with self.assertRaises(mail_relay.Refused):
            mail_relay.render_host_postconf(lab_discard=True, rate_limit=0)
        with self.assertRaises(mail_relay.Refused):
            mail_relay.render_host_postconf(lab_discard=False, relay_host="smtp.example.net", relay_port=70000)

    def test_sender_pcre_escapes_dots_and_rejects_other_domains(self) -> None:
        pcre = mail_relay.render_sender_pcre("cp02.example.test")
        self.assertIn(r"/^[^@\s]+@cp02\.example\.test$/i OK", pcre)
        self.assertIn("REJECT 554 5.7.1", pcre)
        with self.assertRaises(mail_relay.Refused):
            mail_relay.render_sender_pcre("not a domain")

    def test_master_service_and_dropins(self) -> None:
        entry = mail_relay.render_master_service("rs_cp02", 25)
        self.assertIn("rustiron-rs_cp02/unix=rustiron-rs_cp02 unix n - n - 2 smtpd", entry)
        self.assertIn("pcre:/etc/postfix/rustiron/sender-rs_cp02.pcre", entry)
        self.assertIn("smtpd_client_message_rate_limit=25", entry)
        sock = mail_relay.render_socket_dropin("rs_cp02", "s0:c219")
        self.assertIn("SELinuxContext=system_u:system_r:rustiron_mail_relay_t:s0:c219", sock)
        with self.assertRaises(mail_relay.Refused):
            mail_relay.validate_account("../evil")
        with self.assertRaises(mail_relay.Refused):
            mail_relay.validate_mcs_level("s0:c219;rm")

    def test_detect_site_mcs_level_reads_php_dropin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dropin = Path(tmp) / "rustiron-site-php@rs_cp02.service.d"
            dropin.mkdir()
            (dropin / "10-rustiron-site.conf").write_text(
                "[Service]\nSELinuxContext=system_u:system_r:rustiron_php_t:s0:c219\n",
                encoding="utf-8",
            )
            self.assertEqual(mail_relay.detect_site_mcs_level("rs_cp02", Path(tmp)), "s0:c219")


class MailRelayBoundaryTests(unittest.TestCase):
    def test_mu_plugin_uses_unix_socket_with_zero_exec_or_mail(self) -> None:
        php = (ROOT / "packaging" / "mail" / "rustiron-mail-relay.php").read_text(encoding="utf-8")
        self.assertIn("stream_socket_client('unix://' . $socket", php)
        self.assertIn("$this->Mailer = 'smtp';", php)
        for forbidden in (
            r"\bexec\s*\(",
            r"\bshell_exec\s*\(",
            r"\bproc_open\s*\(",
            r"\bpopen\s*\(",
            r"\bpassthru\s*\(",
            r"\bsystem\s*\(",
            r"(?<!wp_)\bmail\s*\(",
        ):
            self.assertIsNone(re.search(forbidden, php), f"forbidden call matched: {forbidden}")

    def test_selinux_module_keeps_af_unix_only_and_no_php_exec(self) -> None:
        te = (ROOT / "packaging" / "selinux" / "rustiron_mail_relay.te").read_text(encoding="utf-8")
        self.assertIn("policy_module(rustiron_mail_relay", te)
        self.assertIn("rustiron_mail_relay_t", te)
        self.assertIn("postfix_master_t:unix_stream_socket connectto", te)
        self.assertNotIn("tcp_socket", te)
        self.assertNotIn("udp_socket", te)
        self.assertNotIn("execute", te)

    def test_systemd_units_enforce_af_unix_and_nnp(self) -> None:
        svc = (ROOT / "packaging" / "systemd" / "rustiron-mail-relay@.service").read_text(encoding="utf-8")
        sock = (ROOT / "packaging" / "systemd" / "rustiron-mail-relay@.socket").read_text(encoding="utf-8")
        self.assertIn("RestrictAddressFamilies=AF_UNIX", svc)
        self.assertIn("NoNewPrivileges=yes", svc)
        self.assertIn("DynamicUser=yes", svc)
        self.assertIn("ListenStream=/run/rustiron-mail/%i/smtp", sock)
        self.assertIn("SocketGroup=%i", sock)
        self.assertIn("SocketMode=0660", sock)
        self.assertIn("DirectoryMode=0750", sock)

    def test_w634_mu_plugin_install_refuses_symlinks_and_installs_cleanly(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            root = Path(tmp)
            sites = root / "sites"
            src = root / "plugin.php"
            src.write_text("<?php // relay\n", encoding="utf-8")
            outside = root / "outside"
            outside.mkdir()

            # V-01: symlinked wp-content directory must be refused.
            wp_dir = sites / "rs_bad" / "html"
            wp_dir.mkdir(parents=True)
            (wp_dir / "wp-content").symlink_to(outside)
            with self.assertRaises(mail_relay.Refused):
                mail_relay.install_mu_plugin_safe(sites, "rs_bad", src, None, None, "")
            self.assertEqual(list(outside.iterdir()), [])

            # Clean real directory installs atomically with 0440 mode.
            good_wpc = sites / "rs_good" / "html" / "wp-content"
            good_wpc.mkdir(parents=True)
            dest = mail_relay.install_mu_plugin_safe(sites, "rs_good", src, None, None, "")
            self.assertEqual(dest.read_text(encoding="utf-8"), "<?php // relay\n")
            self.assertEqual(dest.stat().st_mode & 0o777, 0o440)


if __name__ == "__main__":
    unittest.main()
