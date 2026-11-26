"""Test the Rustiron firewalld zone tool (W559) against a fake firewalld."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "packaging/firewall-zone.py"
SPEC = importlib.util.spec_from_file_location("firewall_zone", SCRIPT)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)

SSHD = ('LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:* users:(("sshd",pid=1001,fd=7))\n'
        'LISTEN 0 128 [::]:{port} [::]:* users:(("sshd",pid=1001,fd=8))\n'
        'LISTEN 0 80 0.0.0.0:3306 0.0.0.0:* users:(("mariadbd",pid=900,fd=20))\n')


class FakeHost:
    """A firewalld that loads zone files on reload, and a routed enp1s0."""

    def __init__(self, zone_file, sshd_port=22):
        self.zone_file = zone_file
        self.sshd_port = sshd_port
        self.running = True
        self.default = "public"
        self.bound = {}
        self.loaded = None
        self.calls = []
        self.fail = set()
        self.extra_service = None
        self.public_ports = []

    def zone_of(self, interface):
        return self.bound.get(interface, self.default)

    def __call__(self, argv):
        self.calls.append(argv)
        out, code = "", 0
        command = argv[0]
        if command in self.fail or " ".join(argv) in self.fail:
            return subprocess.CompletedProcess(argv, 1, "", "injected failure")
        if command == "ip":
            out = json.dumps([{"dst": "default", "dev": "enp1s0"}] if argv[2] == "-4" else [])
        elif command == "ss":
            out = SSHD.format(port=self.sshd_port)
        elif command == "restorecon":
            pass
        else:
            out, code = self.firewall(argv[1:])
        return subprocess.CompletedProcess(argv, code, out, "")

    def firewall(self, arguments):
        option = arguments[-1]
        if arguments == ["--state"]:
            return ("running" if self.running else "not running"), 0
        if arguments == ["--get-default-zone"]:
            return self.default, 0
        if option.startswith("--set-default-zone="):
            zone = option.split("=", 1)[1]
            if zone == "rustiron" and self.loaded is None:
                return "", 112
            self.default = zone
            return "", 0
        if arguments == ["--reload"]:
            self.loaded = self.zone_file.read_text() if self.zone_file.exists() else None
            return "", 0
        if arguments == ["--check-config"]:
            return "", 0
        if arguments == ["--get-zones"]:
            return "block drop public trusted" + (" rustiron" if self.loaded else ""), 0
        if arguments[0] == "--permanent":
            if len(arguments) >= 3 and arguments[1] == "--zone=public":
                if option == "--list-ports":
                    return " ".join(self.public_ports), 0
                if option.startswith("--add-port="):
                    self.public_ports.append(option.split("=", 1)[1])
                    return "", 0
            name = option.split("=", 1)[1]
            return (self.bound[name], 0) if name in self.bound else ("no zone", 2)
        if option.startswith("--get-zone-of-interface="):
            return self.zone_of(option.split("=", 1)[1]), 0
        if arguments[0] == "--zone=rustiron":
            return self.listing(option)
        raise AssertionError(f"unexpected firewall-cmd {arguments}")

    def listing(self, option):
        text = self.loaded or ""
        if option == "--list-services":
            names = re.findall(r'<service name="([^"]+)"/>', text)
            return " ".join(names + ([self.extra_service] if self.extra_service else [])), 0
        if option == "--list-ports":
            return " ".join(f"{p}/{proto}" for proto, p in
                            re.findall(r'<port protocol="(\w+)" port="(\d+)"/>', text)), 0
        if option == "--query-masquerade":
            return "no", 1
        return "", 0


class FirewallZoneTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rustiron-firewall-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.zone_file = self.folder / "rustiron.xml"
        self.host = FakeHost(self.zone_file)

    def policy(self, firewall=None, dns=False):
        document = {"schema_version": 1}
        if firewall is not None:
            document["firewall"] = firewall
        if dns:
            document["dns"] = {"listen": ["203.0.113.10"]}
        path = self.folder / "policy.json"
        path.write_text(json.dumps(document))
        return path

    def run_tool(self, *argv):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = tool.main(list(argv), runner=self.host, zone_file=self.zone_file)
        return code, output.getvalue(), errors.getvalue()

    def changes(self):
        return [call for call in self.host.calls
                if call[0] == "restorecon" or any(a.startswith("--set-default") or a == "--reload"
                                                  for a in call)]

    def test_the_zone_names_only_the_enrolled_set(self):
        text = tool.render(2222, True, True)
        self.assertEqual(re.findall(r'service name="([^"]+)"', text),
                         ["http", "https", "dns", "dhcpv6-client"])
        self.assertEqual(re.findall(r'port protocol="tcp" port="(\d+)"', text), ["2222"])
        plain = tool.render(22, False, False)
        self.assertEqual(re.findall(r'service name="([^"]+)"', plain), ["http", "https"])
        self.assertNotIn("target", plain)

    def test_the_default_run_prints_the_plan_and_changes_nothing(self):
        path = self.policy({"ssh_port": 22, "dhcpv6_client": False})
        code, output, _ = self.run_tool("--policy", str(path))
        self.assertEqual(code, 0)
        self.assertIn('<port protocol="tcp" port="22"/>', output)
        self.assertIn("plan:", output)
        self.assertEqual(self.host.calls, [])
        self.assertFalse(self.zone_file.exists())

    def test_apply_sets_the_zone_and_verifies_it(self):
        path = self.policy({"ssh_port": 22, "dhcpv6_client": True}, dns=True)
        code, output, errors = self.run_tool("--policy", str(path), "--apply")
        self.assertEqual(code, 0, errors)
        self.assertIn("verified: enp1s0 in zone rustiron", output)
        self.assertEqual(self.host.default, "rustiron")
        self.assertEqual(self.zone_file.stat().st_mode & 0o777, 0o644)
        self.assertIn('<service name="dns"/>', self.zone_file.read_text())
        before = len(self.host.calls)
        code, output, _ = self.run_tool("--policy", str(path), "--apply")
        self.assertEqual(code, 0)
        self.assertIn("unchanged", output)
        self.assertFalse(any("--reload" in call for call in self.host.calls[before:]))

    def test_a_port_without_sshd_is_refused_before_any_change(self):
        path = self.policy({"ssh_port": 2222, "dhcpv6_client": False})
        code, _, errors = self.run_tool("--policy", str(path), "--apply")
        self.assertEqual(code, 1)
        self.assertIn("sshd does not listen on TCP port 2222", errors)
        self.assertEqual(self.changes(), [])
        self.assertFalse(self.zone_file.exists())
        self.assertEqual(self.host.default, "public")

    def test_an_unknown_default_zone_or_binding_is_refused(self):
        path = self.policy({"ssh_port": 22, "dhcpv6_client": False})
        self.host.default = "trusted"
        code, _, errors = self.run_tool("--policy", str(path), "--apply")
        self.assertEqual(code, 1)
        self.assertIn("'trusted'", errors)
        self.host.default = "public"
        self.host.bound["enp1s0"] = "internal"
        code, _, errors = self.run_tool("--policy", str(path), "--apply")
        self.assertEqual(code, 1)
        self.assertIn("bound to zone 'internal'", errors)
        self.assertEqual(self.changes(), [])
        self.host.bound.clear()
        self.host.running = False
        self.assertEqual(self.run_tool("--policy", str(path), "--apply")[0], 1)

    def test_a_failed_verification_puts_the_old_default_back(self):
        path = self.policy({"ssh_port": 22, "dhcpv6_client": False})
        self.host.extra_service = "cockpit"
        code, _, errors = self.run_tool("--policy", str(path), "--apply")
        self.assertEqual(code, 1)
        self.assertIn("verification failed", errors)
        self.assertEqual(self.host.default, "public")
        self.assertFalse(self.zone_file.exists())

    def test_w634_nonstandard_ssh_port_is_preserved_in_public_on_fallback(self):
        self.host.sshd_port = 2222
        path = self.policy({"ssh_port": 2222, "dhcpv6_client": False})
        self.host.fail.add("firewall-cmd --check-config")
        code, _, errors = self.run_tool("--policy", str(path), "--apply")
        self.assertEqual(code, 1)
        self.assertIn("--check-config failed", errors)
        self.assertIn("2222/tcp", self.host.public_ports)
        self.assertEqual(self.host.default, "public")

    def test_a_failed_reload_puts_the_old_default_back(self):
        path = self.policy({"ssh_port": 22, "dhcpv6_client": False})
        self.host.fail.add("firewall-cmd --check-config")
        code, _, errors = self.run_tool("--policy", str(path), "--apply")
        self.assertEqual(code, 1)
        self.assertIn("--check-config failed", errors)
        self.assertEqual(self.host.default, "public")
        self.assertFalse(self.zone_file.exists())

    def test_the_policy_section_is_checked(self):
        for section in (None, {"ssh_port": 443, "dhcpv6_client": False},
                        {"ssh_port": "22", "dhcpv6_client": False},
                        {"ssh_port": 22, "dhcpv6_client": 1},
                        {"ssh_port": 22, "dhcpv6_client": False, "ports": [8080]}):
            path = self.policy(section)
            code, _, errors = self.run_tool("--policy", str(path))
            self.assertEqual(code, 1, section)
            self.assertIn("REFUSED", errors)

    def test_check_reports_drift_and_changes_nothing(self):
        path = self.policy({"ssh_port": 22, "dhcpv6_client": False}, dns=True)
        code, output, _ = self.run_tool("--policy", str(path), "--check")
        self.assertEqual(code, 1)
        self.assertIn(f"drift: {self.zone_file} is missing", output)
        self.assertIn("drift: firewalld has no rustiron zone loaded", output)
        self.assertIn("drift: the default zone is public", output)
        self.assertEqual(self.run_tool("--policy", str(path), "--apply")[0], 0)
        before = list(self.changes())
        code, output, _ = self.run_tool("--policy", str(path), "--check")
        self.assertEqual((code, output.strip()), (0, "verified: the rustiron zone matches the policy"))
        # A service added at runtime, and a zone file edited by hand.
        self.host.extra_service = "cockpit"
        code, output, _ = self.run_tool("--policy", str(path), "--check")
        self.assertEqual(code, 1)
        self.assertIn("--list-services", output)
        self.host.extra_service = None
        self.zone_file.write_text(self.zone_file.read_text().replace("</zone>", "  <service name=\"ssh\"/>\n</zone>"))
        code, output, _ = self.run_tool("--policy", str(path), "--check")
        self.assertEqual(code, 1)
        self.assertIn("differs from the zone the policy renders", output)
        self.assertEqual(list(self.changes()), before)
        self.host.running = False
        code, output, _ = self.run_tool("--policy", str(path), "--check")
        self.assertEqual((code, output.strip()), (1, "drift: firewalld is not running"))
        with self.assertRaises(SystemExit) as stopped, contextlib.redirect_stderr(io.StringIO()):
            tool.main(["--check", "--apply"], runner=self.host, zone_file=self.zone_file)
        self.assertEqual(stopped.exception.code, 2)

    def test_restore_sets_public_and_removes_the_zone(self):
        path = self.policy({"ssh_port": 22, "dhcpv6_client": False})
        self.assertEqual(self.run_tool("--policy", str(path), "--apply")[0], 0)
        code, output, _ = self.run_tool("--restore")
        self.assertEqual(code, 0)
        self.assertIn("plan:", output)
        self.assertEqual(self.host.default, "rustiron")
        code, output, _ = self.run_tool("--restore", "--apply")
        self.assertEqual(code, 0)
        self.assertIn("restored", output)
        self.assertEqual(self.host.default, "public")
        self.assertFalse(self.zone_file.exists())
        code, output, _ = self.run_tool("--restore", "--apply")
        self.assertEqual(code, 0)
        self.assertIn("unchanged", output)


if __name__ == "__main__":
    unittest.main()
