"""Test the product uninstaller with a private synthetic host tree (W385)."""

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


PACKAGING = Path(__file__).resolve().parents[2] / "packaging"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load("install_product", PACKAGING / "install-product.py")
uninstaller = load("uninstall_product", PACKAGING / "uninstall-product.py")

PACKAGE_PARENT = b"package parent with WebAdmin\n"
SHIPPED_PARENT = (PACKAGING / "ols/httpd_config.conf").read_bytes()
POLICY = b'{"host_id": "synthetic"}\n'
EXISTING = (
    "etc/systemd/system", "usr/bin", "usr/lib/systemd/system", "usr/lib/sysusers.d",
    "usr/libexec", "usr/share/doc", "usr/share/licenses", "usr/local/lsws/conf",
    "usr/local/lsws/lsphp84/bin", "usr/local/lsws/conf/vhosts", "var/lib", "srv",
)
STAMP = "20261113T000000Z"


def quiet(_line):
    pass


class FakeHost:
    """Answers the read-only queries and records each command."""

    def __init__(self):
        self.answers = {
            ("/usr/sbin/semanage", "port", "-l", "-C"):
                "SELinux Port Type              Proto    Port Number\n\n"
                "rustiron_ols_port_t            tcp      8090\n",
            ("/usr/sbin/semanage", "fcontext", "-l", "-C"):
                "SELinux fcontext   type   Context\n\n"
                "/srv/sites/rs_a(/.*)?   all files   system_u:object_r:httpd_sys_content_t:s0:c201\n",
            ("/usr/sbin/semodule", "-l"): "\n".join(sorted(installer.preflight.MODULES)) + "\napache\n",
            ("/usr/bin/getent", "passwd", "rustiron-coordinator"):
                "rustiron-coordinator:x:990:990::/var/lib/rustiron-coordinator:/usr/sbin/nologin\n",
            ("/usr/bin/getent", "group", "rustiron-coordinator"): "rustiron-coordinator:x:990:\n",
            ("/usr/bin/getent", "group", "rustiron-requesters"):
                "rustiron-requesters:x:989:rustiron-coordinator\n",
            uninstaller.RELAY_INSTANCES: "",
            ("/usr/bin/systemctl", "is-enabled", "rustiron-site-php@rs_a.socket"): "enabled\n",
            ("/usr/bin/systemctl", "is-enabled", "rustiron-executor.service"): "enabled\n",
            ("/usr/bin/systemctl", "show", "--property=FragmentPath", "--property=DropInPaths",
             "--property=NeedDaemonReload", "lshttpd.service"):
                "FragmentPath=/usr/lib/systemd/system/lshttpd.service\nDropInPaths=\nNeedDaemonReload=no\n",
            uninstaller.OBSERVE: json.dumps({"operations": [
                {"operation_id": "op_1", "state": "succeeded"},
            ]}),
        }
        self.calls = []
        self.unloaded = set()
        self.failing = set()

    def query(self, *arguments):
        if arguments[:5] == ("/usr/bin/systemctl", "show", "-p", "LoadState", "--value"):
            return "not-found\n" if arguments[5] in self.unloaded else "loaded\n"
        if arguments not in self.answers:
            raise subprocess.CalledProcessError(2, arguments)
        return self.answers[arguments]

    def run(self, *arguments):
        self.calls.append(arguments)
        if arguments in self.failing:
            raise subprocess.CalledProcessError(1, arguments)

    def names(self):
        return [" ".join(call) for call in self.calls]


CHAIN = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
KEY = b"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"


def standalone_vhost(account):
    return (f"docRoot /srv/sites/{account}/html/\nvhDomain {account[3:]}.example.test\n"
            f"extprocessor lsphp_{account} {{\n type lsapi\n address uds://tmp/lshttpd/{account}.sock\n"
            f" autoStart 1\n path /usr/local/lsws/lsphp84/bin/lsphp\n extUser {account}\n"
            f" extGroup {account}\n}}\nscripthandler {{\n add lsapi:lsphp_{account} php\n}}\n").encode()


SINGLE_STATIC_VHOST = (
    b"# Standalone single-name static vhost\n"
    b"docRoot /srv/sites/rs_a/html/\nvhDomain a.example.test\nenableGzip 1\n"
    b"index {\n useServer 0\n indexFiles index.html\n}\n"
    b"rewrite {\n enable 1\n autoLoadHtaccess 1\n rules <<<END_rules\n"
    rb"RewriteRule \.(php[0-9]*|phtml|phar)(/|$) - [F,NC,L]" b"\n END_rules\n}\n"
)


class UninstallProductTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rustiron-uninstall-")
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.root = base / "root"
        self.target = base / "target"
        self.owner = os.getuid()
        self.host = FakeHost()
        old = os.umask(0o022)
        self.addCleanup(os.umask, old)
        tables = base / "tcp"
        tables.write_text("  sl local rem st\n")
        self.patch("LISTEN_TABLES", (str(tables),))
        self.patch("LISTENER_CLOSE_SECONDS", 0)
        self.root.mkdir(mode=0o700)
        self.digests = {}
        for name, mode in installer.STATE_DIRS.items():
            (self.root / name).mkdir(parents=True, exist_ok=True)
            (self.root / name).chmod(mode)
        for name, mode in installer.PAYLOAD_MODES.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            content = f"synthetic {name}\n".encode()
            if name == installer.PARENT_TEMPLATE:
                # W387: the standalone parent keeps the shipped server settings.
                content = SHIPPED_PARENT
            path.write_bytes(content)
            path.chmod(mode)
            self.digests[name] = hashlib.sha256(content).hexdigest()
        self.install()

    def patch(self, name, value):
        old = getattr(uninstaller, name)
        setattr(uninstaller, name, value)
        self.addCleanup(setattr, uninstaller, name, old)

    def install(self):
        """A synthetic host after install-product.py, enrollment, and two sites."""
        for name in EXISTING:
            (self.target / name).mkdir(parents=True, exist_ok=True)
        parent = self.target / installer.OLS_PARENT
        parent.write_bytes(PACKAGE_PARENT)
        parent.chmod(0o640)
        (self.target / installer.LSPHP).write_bytes(b"lsphp\n")
        facts = installer.package_parent_facts(self.target, self.owner)
        installer.install_payload(self.root, self.target, self.digests, quiet, self.owner, facts)
        installer.replace_parent(self.target, self.digests[installer.PARENT_TEMPLATE], self.owner, quiet)
        self.write("etc/rustiron/policy.json", POLICY)
        self.write("etc/rustiron/allowed_signers", b"lab_agent ssh-ed25519 AAAA\n")
        self.write("var/lib/rustiron/executor/journal.sqlite", b"journal\n")
        self.write("var/lib/rustiron/admission/mark", b"mark\n")
        self.write("var/lib/rustiron/recipes/wordpress.tar.gz", b"recipe\n")
        self.write("var/lib/rustiron-coordinator/state.sqlite", b"coordinator\n")
        self.write("etc/systemd/system/rustiron-admin-helper.service.d/50-ols-listener.conf",
                   b"[Service]\nIPAddressAllow=127.0.0.1/32\n")
        self.write("etc/rustiron-ols/generations/g2/rs_b.vhost", b"docRoot /srv/sites/rs_b/html/\n")
        self.write("etc/rustiron-ejected/rs_a/vhost.conf", b"docRoot /srv/sites/rs_a/html/\n")
        self.write("srv/sites/rs_a/html/index.php", b"<?php echo 'a';\n")
        self.write("srv/sites/rs_b/html/index.php", b"<?php echo 'b';\n")
        for account in ("rs_a", "rs_b"):
            self.write(f"etc/systemd/system/rustiron-site-php@{account}.service.d/50-selinux.conf",
                       b"[Service]\nSELinuxContext=system_u:system_r:rustiron_php_t:s0:c201\n")
            wants = self.target / "etc/systemd/system/sockets.target.wants"
            wants.mkdir(exist_ok=True)
            (wants / f"rustiron-site-php@{account}.socket").symlink_to(
                "/etc/systemd/system/rustiron-site-php@.socket")
        self.serve(("rs_a", True), ("rs_b", False))

    def write(self, name, content):
        path = self.target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def serve(self, *sites):
        text = ""
        for account, ejected in sites:
            config = (f"/etc/rustiron-ejected/{account}/vhost.conf" if ejected
                      else f"/etc/rustiron-ols/current/{account}.vhost")
            text += (f"virtualHost {account} {{\n vhRoot /srv/sites/{account}/\n"
                     f" configFile {config}\n allowSymbolLink 0\n}}\n")
        text += "listener W385 {\n address 127.0.0.1:8090\n secure 0\n"
        for account, _ejected in sites:
            text += f" map {account} {account[3:]}.example.test\n"
        text += "}\n"
        self.write("etc/rustiron-ols/generations/g2/vhosts.conf", text.encode())
        current = self.target / "etc/rustiron-ols/current"
        if current.is_symlink():
            current.unlink()
        current.symlink_to("generations/g2")

    def eject_standalone(self, account):
        """The W387 eject render: OLS starts the PHP as the site account."""
        vhost = standalone_vhost(account)
        path = self.target / f"etc/rustiron-ejected/{account}/vhost.conf"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(vhost)
        path.chmod(0o644)
        return vhost

    def options(self, **values):
        return uninstaller.Options(**values)

    def plan(self, **values):
        return uninstaller.build_plan(self.target, self.options(**values), self.host.query,
                                      self.owner, STAMP)

    def apply(self, **values):
        plan = self.plan(**values)
        uninstaller.execute(plan, self.host.run, quiet)
        return plan

    def refusals(self, **values):
        with self.assertRaises(uninstaller.Refused) as caught:
            self.plan(**values)
        return "\n".join(caught.exception.reasons)

    def tree(self):
        found = {}
        for path in sorted(self.target.rglob("*")):
            info = path.lstat()
            content = path.read_bytes() if path.is_file() and not path.is_symlink() else None
            found[str(path.relative_to(self.target))] = (info.st_mode, content)
        return found

    def archive(self):
        return self.target / uninstaller.ARCHIVE_ROOT / f"uninstall-{STAMP}"

    # Record and refusal rules

    def test_refuses_without_an_install_record(self):
        (self.target / installer.INSTALL_RECORD).unlink()
        self.assertIn("install record", self.refusals(ols_parent="package", unserve_sites=True))

    def test_refuses_a_record_that_names_a_path_outside_the_product(self):
        record = self.target / installer.INSTALL_RECORD
        value = json.loads(record.read_bytes())
        value["payload"]["etc/passwd"] = {"sha256": "0" * 64, "mode": 0o644}
        record.chmod(0o600)
        record.write_text(json.dumps(value))
        self.assertIn("etc/passwd", self.refusals(ols_parent="package", unserve_sites=True))

    def test_the_parent_choice_is_required(self):
        self.assertIn("--ols-parent", self.refusals(ols_parent=None))

    def test_refuses_a_payload_file_with_other_bytes(self):
        path = self.target / "usr/libexec/rustiron/rustiron-executor"
        path.write_bytes(b"replaced\n")
        reasons = self.refusals(ols_parent="package", unserve_sites=True)
        self.assertIn("/usr/libexec/rustiron/rustiron-executor differs from the installed file", reasons)
        self.assertEqual(path.read_bytes(), b"replaced\n")

    # W394 (B06): links and modes swapped into the record, the payload, and
    # the archive root are refused before any change.

    def test_refuses_a_linked_install_record(self):
        record = self.target / installer.INSTALL_RECORD
        copy = self.target / "var/lib/record-copy.json"
        copy.write_bytes(record.read_bytes())
        copy.chmod(0o400)
        record.unlink()
        record.symlink_to(copy)
        before = self.tree()
        self.assertIn("install record", self.refusals(ols_parent="package", unserve_sites=True))
        self.assertEqual(self.tree(), before)
        self.assertEqual(self.host.calls, [])

    def test_refuses_a_record_that_others_can_write(self):
        record = self.target / installer.INSTALL_RECORD
        record.chmod(0o622)
        self.assertIn("writable by others", self.refusals(ols_parent="package", unserve_sites=True))

    def test_refuses_a_payload_file_swapped_for_a_link_to_the_same_bytes(self):
        path = self.target / "usr/libexec/rustiron/rustiron-executor"
        source = self.root / "usr/libexec/rustiron/rustiron-executor"
        path.unlink()
        path.symlink_to(source)
        reasons = self.refusals(ols_parent="package", unserve_sites=True)
        self.assertIn("/usr/libexec/rustiron/rustiron-executor differs from the installed file", reasons)
        self.assertTrue(path.is_symlink())
        self.assertTrue(source.is_file())
        self.assertEqual(self.host.calls, [])

    def test_refuses_an_archive_root_that_is_a_link(self):
        elsewhere = self.target / "srv/elsewhere"
        elsewhere.mkdir(mode=0o700)
        (self.target / uninstaller.ARCHIVE_ROOT).symlink_to(elsewhere)
        reasons = self.refusals(ols_parent="package", unserve_sites=True)
        self.assertIn(f"/{uninstaller.ARCHIVE_ROOT} must be a root-owned folder", reasons)
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.assertEqual(self.host.calls, [])

    def test_refuses_an_unknown_file_in_an_installed_directory(self):
        self.write("usr/libexec/rustiron/jobs/extra", b"not installed\n")
        self.assertIn("/usr/libexec/rustiron/jobs/extra was not installed",
                      self.refusals(ols_parent="package", unserve_sites=True))

    def test_refuses_an_unknown_rustiron_unit_path(self):
        self.write("etc/systemd/system/rustiron-other.service", b"[Unit]\n")
        self.assertIn("/etc/systemd/system/rustiron-other.service",
                      self.refusals(ols_parent="package", unserve_sites=True))

    def test_refuses_an_unresolved_operation_unless_accepted(self):
        self.host.answers[uninstaller.OBSERVE] = json.dumps({"operations": [
            {"operation_id": "op_7", "state": "needs_attention"},
        ]})
        self.assertIn("op_7 needs_attention", self.refusals(ols_parent="package", unserve_sites=True))
        self.plan(ols_parent="package", unserve_sites=True, accept_unresolved=True)

    def test_unresolved_states_are_found_at_any_depth(self):
        observation = {"host": {}, "sites": [{"provision": {"operation_id": "op_p", "state": "running"}}],
                       "captures": [{"operation_id": "op_c", "state": "failed"}],
                       "probes": [{"operation_id": "op_r", "state": "cleanup_incomplete"}]}
        self.assertEqual(uninstaller.unresolved_operations(observation),
                         ["op_p running", "op_r cleanup_incomplete"])

    # Served sites

    def test_reads_ejected_and_managed_sites_from_the_include(self):
        sites = uninstaller.served_sites(self.target)
        self.assertEqual([(site.account, site.ejected) for site in sites],
                         [("rs_a", True), ("rs_b", False)])

    def test_reads_the_listener_ports_from_the_include(self):
        self.assertEqual(uninstaller.listener_ports(self.target), [8090])

    def test_package_fails_while_a_listener_of_the_include_stays_open(self):
        tables = self.target.parent / "tcp-open"
        tables.write_text("  sl local rem st\n   0: 0100007F:1F9A 00000000:0000 0A\n")
        self.patch("LISTEN_TABLES", (str(tables),))
        plan = self.plan(ols_parent="package", unserve_sites=True)
        with self.assertRaisesRegex(ValueError, "still open"):
            uninstaller.execute(plan, self.host.run, quiet)
        self.assertEqual(self.host.names(), ["/usr/bin/systemctl stop lshttpd.service"])
        # Nothing after the stop ran: the parent is still the shipped parent.
        self.assertTrue((self.target / installer.INSTALL_RECORD).exists())

    def test_keep_requires_an_acknowledgement_for_a_site_that_is_not_ejected(self):
        self.assertIn("rs_b", self.refusals(ols_parent="keep"))
        self.plan(ols_parent="keep", leave_managed_sites=True)
        self.serve(("rs_a", True))
        self.plan(ols_parent="keep")

    def test_package_requires_an_acknowledgement_for_every_served_site(self):
        self.serve(("rs_a", True))
        reasons = self.refusals(ols_parent="package")
        self.assertIn("rs_a", reasons)
        self.assertIn("--unserve-sites", reasons)

    def test_package_refuses_a_parent_that_is_not_the_shipped_parent(self):
        parent = self.target / installer.OLS_PARENT
        parent.write_bytes(b"edited\n")
        self.assertIn("is not the shipped parent", self.refusals(ols_parent="package", unserve_sites=True))

    # Ejected sites with a standalone vhost (W387, D-037)

    def standalone(self, *managed):
        """rs_a ejected by W387; the probe of each served site is recorded."""
        self.eject_standalone("rs_a")
        self.serve(("rs_a", True), *((account, False) for account in managed))
        probed = []
        self.patch("probe_site", lambda address, hostname, account, static=False, leaf=None,
                   https_redirect=False:
                   probed.append((address, hostname, account) + (("static",) if static else ())
                                 + (("pinned",) if leaf is not None else ())
                                 + (("redirect",) if https_redirect else ())))
        return probed

    def test_package_keeps_a_standalone_ejected_site_with_no_acknowledgement(self):
        probed = self.standalone()
        vhost = (self.target / "etc/rustiron-ejected/rs_a/vhost.conf").read_bytes()
        self.apply(ols_parent="package")
        parent = (self.target / installer.OLS_PARENT).read_bytes().decode()
        self.assertNotIn("rustiron", parent.lower())
        self.assertNotIn("\ninclude ", parent)
        for line in ("disableWebAdmin 1", "httpdWorkers 4", "CGIRLimit {", "minUID 1000"):
            self.assertIn(line, parent)
        self.assertIn("virtualHost rs_a {\n vhRoot /srv/sites/rs_a/\n"
                      " configFile $SERVER_ROOT/conf/vhosts/rs_a/vhconf.conf\n allowSymbolLink 0\n"
                      " enableScript 1\n restrained 1\n setUIDMode 0\n}\n", parent)
        self.assertTrue(parent.endswith("listener W385 {\n address 127.0.0.1:8090\n secure 0\n"
                                        " map rs_a a.example.test\n}\n"), parent)
        copy = self.target / "usr/local/lsws/conf/vhosts/rs_a/vhconf.conf"
        self.assertEqual(copy.read_bytes(), vhost)
        self.assertEqual(copy.stat().st_mode & 0o7777, 0o640)
        self.assertEqual(copy.parent.stat().st_mode & 0o7777, 0o750)
        self.assertEqual((self.target / installer.OLS_PARENT).stat().st_mode & 0o7777, 0o640)
        # The source is evidence: archived, not left behind.
        self.assertFalse((self.target / "etc/rustiron-ejected").exists())
        self.assertEqual((self.archive() / "etc/rustiron-ejected/rs_a/vhost.conf").read_bytes(), vhost)
        calls = self.host.names()
        start = calls.index("/usr/bin/systemctl start lshttpd.service")
        self.assertLess(calls.index("/usr/bin/systemctl daemon-reload"), start)
        self.assertLess(calls.index("/usr/sbin/restorecon -v /usr/local/lsws/lsphp84/bin/lsphp"), start)
        self.assertIn("/usr/sbin/restorecon -R -F -v /usr/local/lsws/conf/vhosts/rs_a", calls)
        self.assertIn("/usr/sbin/restorecon -F -v /usr/local/lsws/conf/httpd_config.conf", calls)
        self.assertEqual(probed, [("127.0.0.1:8090", "a.example.test", "rs_a")])

    def secure_standalone(self, chain=True):
        """D-064 (W470): rs_a ejected with its certificate, on the TLS listener too."""
        probed = self.standalone()
        live = "/etc/rustiron-tls/rs_a/live"
        vhost = self.eject_standalone("rs_a") + (
            f"vhssl {{\n keyFile {live}/key.pem\n certFile {live}/fullchain.pem\n certChain 1\n}}\n"
        ).encode()
        (self.target / "etc/rustiron-ejected/rs_a/vhost.conf").write_bytes(vhost)
        vhosts = self.target / "etc/rustiron-ols/generations/g2/vhosts.conf"
        vhosts.write_bytes(vhosts.read_bytes() + (
            f"listener W385TLS {{\n address 127.0.0.1:8443\n secure 1\n keyFile {live}/key.pem\n"
            f" certFile {live}/fullchain.pem\n certChain 1\n map rs_a a.example.test\n}}\n").encode())
        if chain:
            sha = hashlib.sha256(CHAIN).hexdigest()
            self.write(f"etc/rustiron-tls/rs_a/{sha}/fullchain.pem", CHAIN)
            self.write(f"etc/rustiron-tls/rs_a/{sha}/key.pem", KEY)
            (self.target / "etc/rustiron-tls/rs_a/live").symlink_to(sha)
        self.write("var/lib/rustiron-acme/config/accounts/meta.json", b"{}\n")
        return probed

    def test_package_hands_an_ejected_sites_certificate_over(self):
        probed = self.secure_standalone()
        self.apply(ols_parent="package")
        folder = self.target / "usr/local/lsws/conf/vhosts/rs_a"
        vhost = (folder / "vhconf.conf").read_bytes().decode()
        self.assertNotIn("rustiron", vhost.lower())
        self.assertTrue(vhost.endswith(
            "vhssl {\n keyFile /usr/local/lsws/conf/vhosts/rs_a/key.pem\n"
            " certFile /usr/local/lsws/conf/vhosts/rs_a/fullchain.pem\n certChain 1\n}\n"), vhost)
        self.assertEqual((folder / "fullchain.pem").read_bytes(), CHAIN)
        self.assertEqual((folder / "key.pem").read_bytes(), KEY)
        self.assertEqual((folder / "key.pem").stat().st_mode & 0o7777, 0o600)
        parent = (self.target / installer.OLS_PARENT).read_bytes().decode()
        self.assertNotIn("rustiron", parent.lower())
        self.assertTrue(parent.endswith(
            "listener W385TLS {\n address 127.0.0.1:8443\n secure 1\n"
            " keyFile /usr/local/lsws/conf/vhosts/rs_a/key.pem\n"
            " certFile /usr/local/lsws/conf/vhosts/rs_a/fullchain.pem\n certChain 1\n"
            " map rs_a a.example.test\n}\n"), parent)
        for name in ("etc/rustiron-tls", "var/lib/rustiron-acme"):
            self.assertFalse((self.target / name).exists(), name)
            self.assertTrue((self.archive() / name).exists(), name)
        self.assertIn("/usr/bin/systemctl unmask certbot-renew.timer", self.host.names())
        # W511-F1: the marker on HTTP, the PHP login on HTTPS with the leaf.
        self.assertEqual(probed, [("127.0.0.1:8090", "a.example.test", "rs_a", "static", "redirect"),
                                  ("127.0.0.1:8443", "a.example.test", "rs_a", "pinned")])

    def test_package_preserves_http_only_single_name_static_eject(self):
        probed = self.standalone()
        self.write("etc/rustiron-ejected/rs_a/vhost.conf", SINGLE_STATIC_VHOST)
        self.apply(ols_parent="package")

        parent = (self.target / installer.OLS_PARENT).read_text()
        vhost = self.target / "usr/local/lsws/conf/vhosts/rs_a/vhconf.conf"
        self.assertEqual(vhost.read_bytes(), SINGLE_STATIC_VHOST)
        self.assertIn("\n enableScript 0\n", parent)
        self.assertTrue(parent.endswith("\n map rs_a a.example.test\n}\n"))
        self.assertNotIn("listener W385TLS", parent)
        self.assertEqual(probed, [("127.0.0.1:8090", "a.example.test", "rs_a", "static")])

    def test_package_preserves_single_name_static_tls_and_pins_its_probe(self):
        probed = self.secure_standalone()
        self.write("etc/rustiron-ejected/rs_a/vhost.conf", SINGLE_STATIC_VHOST +
                   uninstaller.ssl_block("/etc/rustiron-tls/rs_a/live").encode())
        self.apply(ols_parent="package")

        folder = self.target / "usr/local/lsws/conf/vhosts/rs_a"
        parent = (self.target / installer.OLS_PARENT).read_text()
        self.assertEqual((folder / "vhconf.conf").read_bytes(), SINGLE_STATIC_VHOST +
                         uninstaller.ssl_block("/usr/local/lsws/conf/vhosts/rs_a").encode())
        self.assertEqual((folder / "fullchain.pem").read_bytes(), CHAIN)
        self.assertEqual((folder / "key.pem").stat().st_mode & 0o7777, 0o600)
        self.assertIn("\n enableScript 0\n", parent)
        self.assertEqual(parent.count("\n map rs_a a.example.test\n"), 2)
        self.assertEqual(probed, [("127.0.0.1:8090", "a.example.test", "rs_a", "static", "redirect"),
                                  ("127.0.0.1:8443", "a.example.test", "rs_a", "static", "pinned")])

    def test_package_refuses_a_single_name_static_vhost_with_an_unexpected_map(self):
        self.standalone()
        self.write("etc/rustiron-ejected/rs_a/vhost.conf", SINGLE_STATIC_VHOST)
        config = self.target / "etc/rustiron-ols/generations/g2/vhosts.conf"
        config.write_text(config.read_text().replace("map rs_a a.example.test", "map rs_a b.example.test"))
        self.assertIn("rs_a has no valid listener map", self.refusals(ols_parent="package"))

    def certified_static_pair(self):
        probed = self.secure_standalone()
        alias_vhost = SINGLE_STATIC_VHOST.replace(
            b"# Standalone single-name static vhost", b"# Standalone static vhost", 1)
        self.write("etc/rustiron-ejected/rs_a/vhost.conf", alias_vhost +
                   uninstaller.ssl_block("/etc/rustiron-tls/rs_a/live").encode())
        return probed

    def test_package_preserves_both_names_of_the_existing_certified_static_pair(self):
        probed = self.certified_static_pair()
        config = self.target / "etc/rustiron-ols/generations/g2/vhosts.conf"
        config.write_text(config.read_text().replace("map rs_a a.example.test\n",
                                                     "map rs_a a.example.test,alias.example.test\n"))
        self.apply(ols_parent="package")

        parent = (self.target / installer.OLS_PARENT).read_text()
        self.assertEqual(parent.count("\n map rs_a a.example.test,alias.example.test\n"), 2)
        self.assertEqual(probed, [("127.0.0.1:8090", "a.example.test", "rs_a", "static", "redirect"),
                                  ("127.0.0.1:8090", "alias.example.test", "rs_a", "static", "redirect"),
                                  ("127.0.0.1:8443", "a.example.test", "rs_a", "static", "pinned"),
                                  ("127.0.0.1:8443", "alias.example.test", "rs_a", "static", "pinned")])

    def test_package_refuses_a_certified_static_pair_without_its_alias_map(self):
        self.certified_static_pair()
        self.assertIn("rs_a has no valid listener map", self.refusals(ols_parent="package"))

    def test_package_refuses_a_single_name_static_tls_map_without_its_tls_block(self):
        self.secure_standalone()
        self.write("etc/rustiron-ejected/rs_a/vhost.conf", SINGLE_STATIC_VHOST)
        self.assertIn("rs_a has no valid listener map", self.refusals(ols_parent="package"))

    def test_the_probe_accepts_only_the_exact_https_redirect_of_the_marker(self):
        # W511-F3: a redirect to the same marker over HTTPS answers the HTTP check;
        # any other answer does not.
        answers = {}
        self.patch("site_response", lambda address, hostname, path, leaf: answers[path])
        self.patch("PROBE_SECONDS", 0)
        answers["/rustiron-site.txt"] = (302, "", "", "https://a.example.test/rustiron-site.txt")
        uninstaller.probe_site("127.0.0.1:8090", "a.example.test", "rs_a", https_redirect=True)
        for location in ("https://b.example.test/rustiron-site.txt", "https://a.example.test/",
                         "http://a.example.test/rustiron-site.txt"):
            answers["/rustiron-site.txt"] = (302, "", "", location)
            with self.assertRaises(ValueError):
                uninstaller.probe_site("127.0.0.1:8090", "a.example.test", "rs_a",
                                       https_redirect=True)
        answers["/rustiron-site.txt"] = (302, "", "", "https://a.example.test/rustiron-site.txt")
        with self.assertRaises(ValueError):
            uninstaller.probe_site("127.0.0.1:8090", "a.example.test", "rs_a")

    def test_static_alias_listener_maps_are_kept_separate(self):
        self.secure_standalone()
        config = self.target / "etc/rustiron-ols/generations/g2/vhosts.conf"
        content = config.read_text()
        config.write_text(content.replace("map rs_a a.example.test", "map rs_a a.example.test,alias.example.test", 1))
        sites, _, _, _ = uninstaller.include_listener(self.target)
        self.assertEqual(sites[0].hostname, "a.example.test,alias.example.test")
        self.assertEqual(sites[0].tls_hostname, "a.example.test")

    def test_package_refuses_an_ejected_tls_site_without_its_chain(self):
        self.secure_standalone(chain=False)
        self.assertIn("rs_a: /etc/rustiron-tls/rs_a/live is not the link to an installed chain",
                      self.refusals(ols_parent="package"))

    def test_keep_keeps_the_installed_chains(self):
        self.secure_standalone()
        self.apply(ols_parent="keep")
        self.assertTrue((self.target / "etc/rustiron-tls/rs_a/live/key.pem").is_file())
        self.assertFalse((self.target / "var/lib/rustiron-acme").exists())

    def test_package_unserves_only_the_sites_that_are_not_ejected(self):
        self.standalone("rs_b")
        reasons = self.refusals(ols_parent="package")
        self.assertIn("rs_b", reasons)
        self.assertNotIn("rs_a", reasons)
        self.apply(ols_parent="package", unserve_sites=True)
        parent = (self.target / installer.OLS_PARENT).read_bytes().decode()
        self.assertIn("virtualHost rs_a {", parent)
        self.assertNotIn("rs_b", parent)
        self.assertFalse((self.target / "usr/local/lsws/conf/vhosts/rs_b").exists())

    def test_a_site_ejected_before_w387_still_needs_the_acknowledgement(self):
        self.serve(("rs_a", True))
        reasons = self.refusals(ols_parent="package")
        self.assertIn("rs_a", reasons)
        self.assertIn("Rustiron PHP unit", reasons)
        self.apply(ols_parent="package", unserve_sites=True)
        self.assertEqual((self.target / installer.OLS_PARENT).read_bytes(), PACKAGE_PARENT)

    def test_the_dry_run_shows_the_standalone_configuration(self):
        self.standalone()
        lines = []
        uninstaller.show(self.plan(ols_parent="package"), lines.append)
        text = "\n".join(lines)
        self.assertIn("STANDALONE rs_a keeps serving", text)
        self.assertIn("COPY /etc/rustiron-ejected/rs_a/vhost.conf -> "
                      "/usr/local/lsws/conf/vhosts/rs_a/vhconf.conf", text)
        self.assertIn("WRITE /usr/local/lsws/conf/httpd_config.conf (standalone parent sha256=", text)
        self.assertIn("| listener W385 {", text)
        self.assertIn("START lshttpd.service, then probe rs_a", text)
        self.assertNotIn("RESTORE /usr/local/lsws/conf/httpd_config.conf", text)
        self.assertEqual(self.host.calls, [])

    def test_package_refuses_another_vhost_folder_of_the_same_name(self):
        self.standalone()
        self.write("usr/local/lsws/conf/vhosts/rs_a/vhconf.conf", b"operator file\n")
        self.assertIn("/usr/local/lsws/conf/vhosts/rs_a", self.refusals(ols_parent="package"))

    def test_a_later_run_accepts_the_standalone_parent_and_copy_already_written(self):
        probed = self.standalone()
        plan = self.plan(ols_parent="package")
        # Run up to and including the parent write, then stop.
        for text, function in plan.actions:
            function(self.host.run)
            if text.startswith("WRITE /usr/local/lsws/conf/httpd_config.conf"):
                break
        lines = []
        later = uninstaller.build_plan(self.target, self.options(ols_parent="package"), self.host.query,
                                       self.owner, "20261113T010000Z")
        uninstaller.show(later, lines.append)
        self.assertIn("RESTORED /usr/local/lsws/conf/httpd_config.conf holds the standalone parent already",
                      "\n".join(lines))
        uninstaller.execute(later, self.host.run, quiet)
        self.assertEqual(probed, [("127.0.0.1:8090", "a.example.test", "rs_a")])

    def test_keep_names_the_php_that_ols_starts_for_a_standalone_site(self):
        self.standalone()
        lines = []
        uninstaller.show(self.plan(ols_parent="keep"), lines.append)
        self.assertIn("SERVES rs_a (ejected) through /etc/rustiron-ols/current and "
                      "/etc/rustiron-ejected/rs_a/vhost.conf; OLS starts its PHP as rs_a", "\n".join(lines))

    def test_the_standalone_parent_render(self):
        sites = [uninstaller.Site("rs_b", "", True, "b.example.test", True),
                 uninstaller.Site("rs_a", "", True, "a.example.test", True)]
        text = uninstaller.standalone_parent(SHIPPED_PARENT, sites, ("W1", "*:80")).decode()
        self.assertTrue(text.startswith("# Standalone OpenLiteSpeed server configuration"))
        self.assertLess(text.index("virtualHost rs_a"), text.index("virtualHost rs_b"))
        self.assertIn("listener W1 {\n address *:80\n secure 0\n map rs_a a.example.test\n"
                      " map rs_b b.example.test\n}\n", text)
        self.assertNotIn("\n\n\n", text)
        body = [line for line in text.splitlines() if line and not line.startswith("#")]
        shipped = [line for line in SHIPPED_PARENT.decode().splitlines()
                   if line and not line.startswith("#") and not line.startswith("include ")]
        self.assertEqual(body[:len(shipped)], shipped, "the shipped server settings, in order")
        self.assertEqual(uninstaller.probe_address("*:80"), "127.0.0.1:80")
        self.assertEqual(uninstaller.probe_address("0.0.0.0:8090"), "127.0.0.1:8090")
        self.assertEqual(uninstaller.probe_address("127.0.0.1:8090"), "127.0.0.1:8090")

    def test_only_wordpress_php_output_is_a_php_answer(self):
        # W387 run 2: a provisioned site that is not installed yet redirects
        # to its installer. That answer needs PHP and the database too.
        form = '<form name="loginform" id="loginform" action="/wp-login.php">'
        self.assertTrue(uninstaller.php_answered(200, "", form))
        self.assertTrue(uninstaller.php_answered(302, "WordPress", ""))
        self.assertFalse(uninstaller.php_answered(503, "", form))
        self.assertFalse(uninstaller.php_answered(302, "", ""))
        self.assertFalse(uninstaller.php_answered(301, "WordPress", ""))
        self.assertFalse(uninstaller.php_answered(200, "", "<?php // loginform"))

    # Dry run

    def test_the_dry_run_prints_every_action_and_changes_nothing(self):
        before = self.tree()
        lines = []
        plan = self.plan(ols_parent="package", unserve_sites=True)
        uninstaller.show(plan, lines.append)
        self.assertEqual(self.tree(), before)
        self.assertEqual(self.host.calls, [])
        text = "\n".join(lines)
        for expected in (
            "REMOVE /usr/libexec/rustiron/rustiron-executor sha256=",
            "REMOVE /etc/systemd/system/lshttpd.service.d/50-rustiron-killmode.conf",
            "REMOVE /etc/systemd/system/lshttpd.service.d/51-rustiron-boot-guard.conf",
            "ARCHIVE /etc/rustiron ->",
            "ARCHIVE /var/lib/rustiron ->",
            "RESTORE /usr/local/lsws/conf/httpd_config.conf",
            "SEMODULE remove " + " ".join(sorted(installer.preflight.MODULES)),
            "USERDEL rustiron-coordinator",
            "TENANT /srv/sites/rs_a",
        ):
            self.assertIn(expected, text)

    # Apply

    def test_package_removes_the_installation_and_archives_the_evidence(self):
        self.apply(ols_parent="package", unserve_sites=True)
        for name in installer.PAYLOAD_MODES:
            self.assertFalse((self.target / name).exists(), name)
        for name in ("usr/libexec/rustiron", "usr/share/rustiron", "etc/systemd/system/lshttpd.service.d",
                     "etc/rustiron", "var/lib/rustiron", "etc/rustiron-ols", "etc/rustiron-ejected",
                     "var/lib/rustiron-coordinator", "srv/restore-probes",
                     "etc/systemd/system/rustiron-admin-helper.service.d",
                     "etc/systemd/system/rustiron-site-php@rs_a.service.d"):
            self.assertFalse((self.target / name).exists(), name)
        for name in EXISTING:
            self.assertTrue((self.target / name).is_dir(), name)
        parent = self.target / installer.OLS_PARENT
        self.assertEqual(parent.read_bytes(), PACKAGE_PARENT)
        self.assertEqual(parent.stat().st_mode & 0o7777, 0o640)
        archive = self.archive()
        self.assertEqual(archive.stat().st_mode & 0o7777, 0o700)
        self.assertEqual((self.target / uninstaller.ARCHIVE_ROOT).stat().st_mode & 0o7777, 0o700)
        self.assertEqual((archive / "etc/rustiron/policy.json").read_bytes(), POLICY)
        for name in ("var/lib/rustiron/executor/journal.sqlite", "var/lib/rustiron/admission/mark",
                     "var/lib/rustiron/install-record.json", "var/lib/rustiron/ols-package/httpd_config.conf",
                     "var/lib/rustiron-coordinator/state.sqlite", "etc/rustiron-ejected/rs_a/vhost.conf",
                     "etc/rustiron-ols/generations/g2/vhosts.conf",
                     "etc/systemd/system/rustiron-admin-helper.service.d/50-ols-listener.conf",
                     "etc/systemd/system/rustiron-site-php@rs_b.service.d/50-selinux.conf",
                     "selinux-local-ports.txt"):
            self.assertTrue((archive / name).is_file(), name)
        manifest = (archive / "MANIFEST").read_text()
        self.assertIn(f"{hashlib.sha256(POLICY).hexdigest()}  etc/rustiron/policy.json", manifest)
        # Tenant data stays in place.
        self.assertEqual((self.target / "srv/sites/rs_a/html/index.php").read_bytes(), b"<?php echo 'a';\n")
        calls = self.host.names()
        self.assertIn("/usr/bin/chattr -i /usr/local/lsws/conf/httpd_config.conf", calls)
        self.assertIn("/usr/local/lsws/bin/openlitespeed -t", calls)
        self.assertIn("/usr/sbin/restorecon -F -v /usr/local/lsws/conf/httpd_config.conf", calls)
        port = calls.index("/usr/sbin/semanage port -d -t rustiron_ols_port_t -p tcp 8090")
        modules = calls.index("/usr/sbin/semodule -r " + " ".join(sorted(installer.preflight.MODULES)))
        self.assertLess(port, modules)
        self.assertLess(calls.index("/usr/bin/systemctl stop lshttpd.service"), port)
        self.assertIn("/usr/sbin/userdel rustiron-coordinator", calls)
        self.assertIn("/usr/sbin/groupdel rustiron-requesters", calls)
        self.assertIn("/usr/sbin/restorecon -v /usr/local/lsws/lsphp84/bin/lsphp", calls)
        self.assertIn("/usr/bin/systemctl stop rustiron-site-php@rs_a.socket "
                      "rustiron-site-sandbox-check@rs_a.timer rustiron-site-php@rs_a.service", calls)
        self.assertIn("/usr/bin/systemctl disable rustiron-site-php@rs_a.socket", calls)
        self.assertIn("/usr/bin/systemctl disable rustiron-executor.service", calls)
        self.assertNotIn("/usr/bin/systemctl start lshttpd.service", calls)

    def test_enabled_management_timers_are_stopped_and_disabled_first(self):
        # W511-F4: an enabled timer must not outlive its removed service.
        self.host.answers[("/usr/bin/systemctl", "is-enabled", "rustiron-alert-checkin.timer")] = "enabled\n"
        self.host.answers[("/usr/bin/systemctl", "is-enabled", "rustiron-site-cron.timer")] = "enabled\n"
        self.apply(ols_parent="package", unserve_sites=True)
        stop = next(call for call in self.host.names()
                    if call.startswith("/usr/bin/systemctl stop rustiron-") and "site-php@" not in call)
        units = stop.split()[2:]
        timers = [unit for unit in units if unit.endswith(".timer")]
        self.assertIn("rustiron-alert-checkin.timer", timers)
        self.assertIn("rustiron-site-cron.timer", timers)
        self.assertEqual(units[:len(timers)], timers, "timers stop before the services")
        self.assertIn("/usr/bin/systemctl disable rustiron-alert-checkin.timer rustiron-site-cron.timer "
                      "rustiron-executor.service", self.host.names())

    def test_a_failed_configuration_test_of_the_package_parent_is_reported(self):
        self.host.failing.add(("/usr/local/lsws/bin/openlitespeed", "-t"))
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.apply(ols_parent="package", unserve_sites=True)
        self.assertIn("OLS configuration test of the package parent: exit status 1", out.getvalue())
        self.assertFalse((self.target / "usr/libexec/rustiron").exists())

    def test_a_later_run_accepts_a_parent_that_is_already_restored(self):
        parent = self.target / installer.OLS_PARENT
        parent.write_bytes(PACKAGE_PARENT)
        lines = []
        uninstaller.show(self.plan(ols_parent="package", unserve_sites=True), lines.append)
        text = "\n".join(lines)
        self.assertIn("RESTORED /usr/local/lsws/conf/httpd_config.conf holds the package parent already", text)
        self.assertNotIn("RESTORE /usr", text)
        self.assertIn("RESTORECON -F /usr/local/lsws/conf/httpd_config.conf", text)

    def test_package_removes_the_stale_site_sockets_and_the_sandbox_lock(self):
        import socket
        sockets = self.target / uninstaller.SITE_SOCKETS
        sockets.mkdir(parents=True)
        bound = socket.socket(socket.AF_UNIX)
        self.addCleanup(bound.close)
        bound.bind(str(sockets / "rs_a.sock"))
        self.write(uninstaller.SANDBOX_LOCK, b"")
        self.apply(ols_parent="package", unserve_sites=True)
        self.assertFalse(sockets.exists())
        self.assertFalse((self.target / uninstaller.SANDBOX_LOCK).exists())

    def test_runtime_cleanup_keeps_an_entry_that_is_not_a_site_socket(self):
        sockets = self.target / uninstaller.SITE_SOCKETS
        self.write(f"{uninstaller.SITE_SOCKETS}/rs_a.sock", b"a regular file\n")
        uninstaller.clean_runtime(self.target)
        self.assertTrue((sockets / "rs_a.sock").is_file())

    def test_keep_keeps_the_serving_set_and_a_reduced_record(self):
        self.serve(("rs_a", True))
        self.apply(ols_parent="keep")
        kept = set(uninstaller.SERVING_PAYLOAD)
        for name in installer.PAYLOAD_MODES:
            self.assertEqual((self.target / name).exists(), name in kept, name)
        for name in ("etc/rustiron-ols/current", "etc/rustiron-ejected/rs_a/vhost.conf",
                     "var/lib/rustiron/ols-package/httpd_config.conf",
                     "etc/systemd/system/rustiron-site-php@rs_a.service.d/50-selinux.conf",
                     "etc/systemd/system/sockets.target.wants/rustiron-site-php@rs_a.socket"):
            self.assertTrue((self.target / name).exists() or (self.target / name).is_symlink(), name)
        for name in ("etc/rustiron", "var/lib/rustiron/executor", "var/lib/rustiron/admission",
                     "var/lib/rustiron-coordinator", "etc/systemd/system/lshttpd.service.d"):
            self.assertFalse((self.target / name).exists(), name)
        archive = self.archive()
        self.assertTrue((archive / "var/lib/rustiron/executor/journal.sqlite").is_file())
        self.assertTrue((archive / "var/lib/rustiron/install-record.json").is_file())
        record = json.loads((self.target / installer.INSTALL_RECORD).read_bytes())
        self.assertTrue(record["serving_kept"])
        self.assertEqual(sorted(record["payload"]), sorted(kept))
        self.assertEqual(record["modules"], sorted(uninstaller.SERVING_MODULES))
        self.assertEqual(record["users"], [])
        parent = self.target / installer.OLS_PARENT
        self.assertEqual(hashlib.sha256(parent.read_bytes()).hexdigest(),
                         self.digests[installer.PARENT_TEMPLATE])
        calls = self.host.names()
        self.assertIn("/usr/bin/chattr -i /usr/local/lsws/conf/httpd_config.conf", calls)
        removed = sorted(set(installer.preflight.MODULES) - set(uninstaller.SERVING_MODULES))
        self.assertIn("/usr/sbin/semodule -r " + " ".join(removed), calls)
        self.assertNotIn("/usr/bin/systemctl stop lshttpd.service", calls)
        self.assertFalse([call for call in calls if "rustiron-site-php@rs_a" in call])
        # A later run with the package parent removes the rest.
        self.host.calls.clear()
        self.host.answers[("/usr/sbin/semodule", "-l")] = "\n".join(uninstaller.SERVING_MODULES) + "\n"
        for name in ("passwd rustiron-coordinator", "group rustiron-coordinator", "group rustiron-requesters"):
            del self.host.answers[("/usr/bin/getent", *name.split())]
        later = uninstaller.build_plan(self.target, self.options(ols_parent="package", unserve_sites=True),
                                       self.host.query, self.owner, "20261113T010000Z")
        uninstaller.execute(later, self.host.run, quiet)
        # The management units are gone, so the later run stops none of them.
        self.assertFalse([call for call in self.host.names() if "rustiron-executor" in call])
        for name in installer.PAYLOAD_MODES:
            self.assertFalse((self.target / name).exists(), name)
        self.assertEqual(parent.read_bytes(), PACKAGE_PARENT)
        self.assertFalse((self.target / "var/lib/rustiron").exists())
        self.assertFalse((self.target / "etc/rustiron-ejected").exists())
        self.assertIn("/usr/sbin/semodule -r " + " ".join(sorted(uninstaller.SERVING_MODULES)),
                      self.host.names())

    def test_the_archive_keeps_the_receipt_public_key_and_no_private_key(self):
        # W392: the private receipt key never moves into the archive.
        self.write(f"{installer.RECEIPT_KEY_DIR}/ed25519", b"synthetic private key\n")
        self.write(f"{installer.RECEIPT_KEY_DIR}/ed25519.pub", b"ssh-ed25519 AAAA rustiron-receipt\n")
        lines = []
        uninstaller.show(self.plan(ols_parent="package", unserve_sites=True), lines.append)
        text = "\n".join(lines)
        self.assertIn("DELETE /etc/rustiron/receipt-key/ed25519 (the receipt private key; "
                      "the archive keeps the public key)", text)
        self.assertLess(text.index("DELETE /etc/rustiron/receipt-key/ed25519"),
                        text.index("ARCHIVE /etc/rustiron ->"))
        self.apply(ols_parent="package", unserve_sites=True)
        archive = self.archive()
        self.assertFalse((archive / installer.RECEIPT_KEY_DIR / "ed25519").exists())
        self.assertEqual((archive / installer.RECEIPT_KEY_DIR / "ed25519.pub").read_bytes(),
                         b"ssh-ed25519 AAAA rustiron-receipt\n")
        self.assertIn("etc/rustiron/receipt-key/ed25519.pub", (archive / "MANIFEST").read_text())

    def test_the_archive_holds_no_alert_push_link(self):
        # W510 (D-083): the Kuma push link is a credential, not evidence.
        self.write("etc/rustiron/alert-push.url", b"http://kuma.example.test/api/push/Token1\n")
        lines = []
        uninstaller.show(self.plan(ols_parent="package", unserve_sites=True), lines.append)
        text = "\n".join(lines)
        self.assertIn("DELETE /etc/rustiron/alert-push.url (the alert push link; "
                      "a credential, not evidence)", text)
        self.assertNotIn("Token1", text)
        self.assertLess(text.index("DELETE /etc/rustiron/alert-push.url"),
                        text.index("ARCHIVE /etc/rustiron ->"))
        self.apply(ols_parent="package", unserve_sites=True)
        archive = self.archive()
        self.assertFalse((archive / "etc/rustiron/alert-push.url").exists())
        self.assertNotIn("alert-push.url", (archive / "MANIFEST").read_text())

    def test_destroy_deletes_the_evidence_but_never_tenant_data(self):
        self.apply(ols_parent="package", unserve_sites=True, destroy_evidence=True)
        self.assertFalse((self.target / uninstaller.ARCHIVE_ROOT).exists())
        self.assertFalse((self.target / "etc/rustiron").exists())
        self.assertFalse((self.target / "var/lib/rustiron").exists())
        self.assertEqual((self.target / "srv/sites/rs_b/html/index.php").read_bytes(), b"<?php echo 'b';\n")

    def test_an_incomplete_installation_reports_the_missing_files(self):
        (self.target / "usr/libexec/rustiron/jobs/restic").unlink()
        lines = []
        uninstaller.show(self.plan(ols_parent="package", unserve_sites=True), lines.append)
        self.assertIn("ABSENT /usr/libexec/rustiron/jobs/restic", "\n".join(lines))

    def test_main_is_a_dry_run_without_apply(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                uninstaller.parse_arguments(["--apply", "--ols-parent", "other"])
        arguments = uninstaller.parse_arguments(["--ols-parent", "keep"])
        self.assertFalse(arguments.apply)


if __name__ == "__main__":
    unittest.main()
