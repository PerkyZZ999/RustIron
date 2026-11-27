"""Test the enrollment file writer (W358) without root or a host."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "packaging/enrollment-policy.py"
SPEC = importlib.util.spec_from_file_location("enrollment_policy", SCRIPT)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)

KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIJ" + "x" * 42
BASE = [
    "--host-id", "host_w358", "--host-epoch", "epoch_1", "--profile-digest", "a" * 64,
    "--requester", "rustiron_coordinator", "--requester-uid", "993", "--issuer", "lab_agent",
    "--signer-policy-epoch", "policy_3", "--verifier-sha256", "b" * 64,
]
PROVISIONING = [
    "--wordpress-sha256", "c" * 64, "--uid-range", "3001-3099", "--category-range", "201-299",
    "--quota-block-hard-kib", "131072", "--quota-inode-hard", "20000",
]
OLS = [
    "--ols-listener", "W358", "--ols-address", "127.0.0.1:8090",
    "--ols-parent-sha256", "d" * 64, "--ols-webadmin-port", "7080",
]
# W374: the product backup pin of the reviewed projection (W371 values).
PRODUCT_BACKUP = [
    "--product-backup-destination-id", "w371_tls_lab_9443",
    "--product-backup-digest", "e" * 64,
]


class EnrollmentPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rustiron-enroll-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.out = self.folder / "out"

    def run_tool(self, argv):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = tool.main(argv)
        return code, output.getvalue(), errors.getvalue()

    def policy(self, *extra):
        return self.run_tool(["policy", "--out", str(self.out), *BASE, *extra])

    def test_full_policy_is_canonical_private_and_closed(self):
        code, output, _ = self.policy(*PROVISIONING, *OLS)
        self.assertEqual(code, 0)
        content = self.out.read_bytes()
        self.assertFalse(content.endswith(b"\n"))
        value = json.loads(content)
        self.assertEqual(content, tool.canonical(value))
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o600)
        self.assertIn("sha256=", output)
        self.assertEqual(set(value), {
            "schema_version", "host_id", "host_epoch", "profile_digest", "requester",
            "requester_uid", "issuer", "signer_policy_epoch", "verifier_sha256",
            "provisioning", "ols"})
        self.assertEqual(value["provisioning"]["quota"], {"block_hard_kib": 131072, "inode_hard": 20000})
        self.assertEqual(value["ols"]["adopted"], [])
        self.assertEqual(value["ols"]["lscache"], [])

    def test_the_ols_tls_address_is_optional(self):
        # W461 (D-059): absent unless asked for; then the exact value.
        code, _, _ = self.run_tool(["policy", "--out", str(self.out), *BASE, *OLS])
        self.assertEqual(code, 0)
        self.assertNotIn("tls_address", json.loads(self.out.read_bytes())["ols"])
        self.out.unlink()
        code, _, _ = self.run_tool(["policy", "--out", str(self.out), *BASE, *OLS,
                                    "--ols-tls-address", "127.0.0.1:8443"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(self.out.read_bytes())["ols"]["tls_address"], "127.0.0.1:8443")

    def test_minimal_policy_has_no_optional_sections(self):
        self.assertEqual(self.policy()[0], 0)
        self.assertNotIn("provisioning", json.loads(self.out.read_bytes()))

    def test_bad_values_are_refused_and_write_nothing(self):
        cases = [
            ["--issuer", "rustiron_coordinator"],
            ["--requester-uid", "0"],
            ["--host-id", "bad host"],
            ["--verifier-sha256", "B" * 64],
            PROVISIONING[:-2],
            [*PROVISIONING[:4], "--category-range", "0-10", *PROVISIONING[6:]],
            [*PROVISIONING[:2], "--uid-range", "1000-1099", *PROVISIONING[4:]],
            [*PROVISIONING[:2], "--uid-range", "3099-3001", *PROVISIONING[4:]],
            [*PROVISIONING[:6], "--quota-block-hard-kib", "1024", *PROVISIONING[8:]],
            [*PROVISIONING[:8], "--quota-inode-hard", "999"],
            OLS[:-2],
            [*OLS[:2], "--ols-address", "localhost:8090", *OLS[4:]],
            [*OLS[:2], "--ols-address", "127.0.0.1", *OLS[4:]],
            [*OLS[:6], "--ols-webadmin-port", "8090"],
            ["--ols-listener", "8x", *OLS[2:]],
            # D-059: the TLS address needs its own port and a short listener.
            [*OLS, "--ols-tls-address", "127.0.0.1:8090"],
            [*OLS, "--ols-tls-address", "127.0.0.1:7080"],
            [*OLS, "--ols-tls-address", "localhost:8443"],
            ["--ols-listener", "L" * 30, *OLS[2:], "--ols-tls-address", "127.0.0.1:8443"],
        ]
        for extra in cases:
            with self.subTest(extra=extra):
                argv = list(BASE)
                for index in range(0, len(extra), 2):
                    if extra[index] in argv:
                        argv[argv.index(extra[index]) + 1] = extra[index + 1]
                    else:
                        argv += extra[index:index + 2]
                code, _, errors = self.run_tool(["policy", "--out", str(self.out), *argv])
                self.assertEqual(code, 1)
                self.assertIn("REFUSED", errors)
                self.assertFalse(self.out.exists())

    def test_schema_1_output_is_unchanged(self):
        # W374: SHA-256 of the W358 tool output before the schema 2 change.
        for extra, expected in (
            ([], "94ce441b83bbcae5574bb4e0c17f2dfb5c1b6fecbc8be845ca4199e6b1286072"),
            ([*PROVISIONING, *OLS], "df9ac3e9d8e5504faf505cbee177e7ab9d28944ced7adc156bf19d60b7720433"),
        ):
            with self.subTest(sections=len(extra)):
                self.out.unlink(missing_ok=True)
                code, output, _ = self.policy(*extra)
                self.assertEqual(code, 0)
                self.assertEqual(hashlib.sha256(self.out.read_bytes()).hexdigest(), expected)
                self.assertIn(f"sha256={expected}", output)
                self.assertEqual(json.loads(self.out.read_bytes())["schema_version"], 1)

    def test_the_product_backup_pin_writes_schema_2(self):
        self.assertEqual(self.policy(*PROVISIONING, *OLS)[0], 0)
        first = json.loads(self.out.read_bytes())
        self.out.unlink()
        self.assertEqual(self.policy(*PROVISIONING, *OLS, *PRODUCT_BACKUP)[0], 0)
        content = self.out.read_bytes()
        value = json.loads(content)
        self.assertEqual(content, tool.canonical(value))
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o600)
        # The executor's schema 2 shape: the schema 1 policy, schema 2, the
        # pin, and no lab `backup` section (crates/executor/src/policy.rs).
        expected = dict(first, schema_version=2, product_backup={
            "destination_id": "w371_tls_lab_9443", "destination_policy_digest": "e" * 64})
        self.assertEqual(value, expected)
        self.assertNotIn("backup", value)
        self.assertEqual(set(value["product_backup"]), {"destination_id", "destination_policy_digest"})

    def test_the_w371_policies_are_reproduced(self):
        # W374: the W371 schema 1 policy (07-enroll.log) and the schema 2
        # policy that W371 wrote by hand (13-backup-enroll.log).
        w371 = [
            "--host-id", "rustiron_w371_write", "--host-epoch", "epoch_w371_1",
            "--profile-digest", "1a547a0b9c893a63fd11135e0c92846e400fb9bdd9e7558c6fada6eeeb5db4ab",
            "--requester", "rustiron_coordinator", "--requester-uid", "993",
            "--issuer", "lab_agent", "--signer-policy-epoch", "policy_3",
            "--verifier-sha256", "39b36c54302cf75a28b57cb522a0795004b32b295c59c659ef50d02c41b02c47",
            "--wordpress-sha256", "d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5",
            "--uid-range", "3001-3099", "--category-range", "201-299",
            "--quota-block-hard-kib", "262144", "--quota-inode-hard", "20000",
            "--ols-listener", "W371", "--ols-address", "127.0.0.1:8090",
            "--ols-parent-sha256", "91d3953d2748d9a7657f1a43053bd8a1454f43bc843b5b4923755ad1f0ea8427",
            "--ols-webadmin-port", "7080",
        ]
        pin = ["--product-backup-destination-id", "w371_tls_lab_9443", "--product-backup-digest",
               "b939d47b8ca025d69a65f9f87a67495125dd024bedec02fc7d29d13a9d66252d"]
        for extra, expected in (
            ([], "463d59fd86692b616091a33c378891eb9ac627c0c288d0054bea42565b55680b"),
            (pin, "7c2eedf8d37d8bf5a70578a6922b7775e01ac1e19ad5440103f54681696e9ea7"),
        ):
            with self.subTest(schema=2 if extra else 1):
                self.out.unlink(missing_ok=True)
                code, _, _ = self.run_tool(["policy", "--out", str(self.out), *w371, *extra])
                self.assertEqual(code, 0)
                self.assertEqual(hashlib.sha256(self.out.read_bytes()).hexdigest(), expected)

    def test_a_bad_product_backup_pin_is_refused_and_writes_nothing(self):
        cases = [
            PRODUCT_BACKUP[:2],
            PRODUCT_BACKUP[2:],
            ["--product-backup-destination-id", "bad id", *PRODUCT_BACKUP[2:]],
            ["--product-backup-destination-id", "x" * 65, *PRODUCT_BACKUP[2:]],
            [*PRODUCT_BACKUP[:2], "--product-backup-digest", "E" * 64],
            [*PRODUCT_BACKUP[:2], "--product-backup-digest", "e" * 63],
        ]
        for extra in cases:
            with self.subTest(extra=extra):
                code, _, errors = self.policy(*extra)
                self.assertEqual(code, 1)
                self.assertIn("REFUSED", errors)
                self.assertFalse(self.out.exists())

    def test_the_migration_section_lists_distinct_php_versions(self):
        # W446 (D-053): MigrationPolicy in crates/executor/src/policy.rs.
        code, _, _ = self.policy(*PROVISIONING, "--migration-php-versions", "8.4,8.3")
        self.assertEqual(code, 0)
        value = json.loads(self.out.read_bytes())
        self.assertEqual(value["migration"], {"php_versions": ["8.4", "8.3"]})
        for bad in [[*PROVISIONING, "--migration-php-versions", ""],
                    [*PROVISIONING, "--migration-php-versions", "8.4,8.4"],
                    [*PROVISIONING, "--migration-php-versions", "8"],
                    [*PROVISIONING, "--migration-php-versions", "4.9"],
                    [*PROVISIONING, "--migration-php-versions", ",".join(["8.1"] * 9)],
                    ["--migration-php-versions", "8.4"]]:
            self.out.unlink(missing_ok=True)
            code, _, errors = self.policy(*bad)
            self.assertEqual(code, 1, bad)
            self.assertFalse(self.out.exists(), bad)

    def test_the_dns_section_is_closed_and_bounded(self):
        dns = ["--dns-listen", "203.0.113.10,2001:db8::10",
               "--dns-name-servers", "ns1.example.test,ns2.example.test",
               "--dns-hostmaster", "hostmaster.example.test", "--dns-secondaries", "198.51.100.53",
               "--dns-tsig-key", "rustiron-axfr", "--dns-soa", "10800,3600,604800,3600"]
        code, _, _ = self.policy(*dns)
        self.assertEqual(code, 0)
        section = json.loads(self.out.read_bytes())["dns"]
        self.assertEqual(section, {
            "listen": ["203.0.113.10", "2001:db8::10"],
            "name_servers": ["ns1.example.test", "ns2.example.test"],
            "hostmaster": "hostmaster.example.test", "secondaries": ["198.51.100.53"],
            "tsig_key": "rustiron-axfr",
            "soa": {"refresh": 10800, "retry": 3600, "expire": 604800, "negative_ttl": 3600}})
        self.out.unlink()
        # No secondaries is allowed: transfers stay off.
        empty = list(dns)
        empty[empty.index("--dns-secondaries") + 1] = ""
        self.assertEqual(self.policy(*empty)[0], 0)
        self.assertEqual(json.loads(self.out.read_bytes())["dns"]["secondaries"], [])
        self.out.unlink()
        for flag, value in [("--dns-listen", "0.0.0.0"), ("--dns-listen", "203.0.113.10,203.0.113.10"),
                            ("--dns-name-servers", "ns1.example.test"),
                            ("--dns-name-servers", "NS1.example.test,ns2.example.test"),
                            ("--dns-hostmaster", "hostmaster"), ("--dns-secondaries", "ff02::1"),
                            ("--dns-tsig-key", "Key"), ("--dns-tsig-key", "a\nb"),
                            ("--dns-soa", "600,300,604800,3600"), ("--dns-soa", "10800,3600")]:
            changed = list(dns)
            changed[changed.index(flag) + 1] = value
            code, _, errors = self.policy(*changed)
            self.assertEqual(code, 1, (flag, value))
            self.assertIn("REFUSED", errors)
            self.assertFalse(self.out.exists())
        code, _, errors = self.policy(*dns[:4])
        self.assertEqual(code, 1)
        self.assertIn("the dns section needs", errors)

    def test_the_firewall_section_names_the_ssh_port(self):
        code, _, _ = self.policy("--firewall-ssh-port", "2222", "--firewall-dhcpv6-client")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(self.out.read_bytes())["firewall"],
                         {"ssh_port": 2222, "dhcpv6_client": True})
        self.out.unlink()
        self.assertEqual(self.policy("--firewall-ssh-port", "22")[0], 0)
        self.assertEqual(json.loads(self.out.read_bytes())["firewall"],
                         {"ssh_port": 22, "dhcpv6_client": False})
        self.out.unlink()
        for extra in (["--firewall-ssh-port", "443"], ["--firewall-ssh-port", "0"],
                      ["--firewall-ssh-port", "70000"], ["--firewall-dhcpv6-client"]):
            code, _, errors = self.policy(*extra)
            self.assertEqual(code, 1, extra)
            self.assertIn("REFUSED", errors)
            self.assertFalse(self.out.exists())

    def test_an_existing_output_is_never_replaced(self):
        self.out.write_bytes(b"keep")
        self.assertEqual(self.policy()[0], 1)
        self.assertEqual(self.out.read_bytes(), b"keep")

    def signers(self, text):
        key = self.folder / "key.pub"
        key.write_text(text)
        return self.run_tool(["allowed-signers", "--out", str(self.out),
                              "--issuer", "lab_agent", "--public-key", str(key)])

    def test_allowed_signers_is_one_line_without_the_comment(self):
        self.assertEqual(self.signers(f"ssh-ed25519 {KEY} someone@pc\n")[0], 0)
        self.assertEqual(self.out.read_text(),
                         f'lab_agent namespaces="rustiron-plan-v1" ssh-ed25519 {KEY}\n')

    def test_private_keys_and_other_key_types_are_refused(self):
        for text in ("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n",
                     f"ssh-rsa {KEY}\n", f"ssh-ed25519 {KEY}\nssh-ed25519 {KEY}\n", "ssh-ed25519 a*b\n"):
            with self.subTest(text=text[:20]):
                self.assertEqual(self.signers(text)[0], 1)
                self.assertFalse(self.out.exists())


    # W483-F1: an openssh update replaces /usr/bin/ssh-keygen.
    def enrolled(self):
        code, _, _ = self.policy(*PROVISIONING, *OLS)
        self.assertEqual(code, 0)
        policy = self.folder / "installed.json"
        self.out.rename(policy)
        return policy

    def test_firewall_sets_only_the_firewall_section(self):
        self.assertEqual(self.policy()[0], 0)
        policy = self.folder / "installed.json"
        self.out.rename(policy)
        before = json.loads(policy.read_bytes())
        code, output, _ = self.run_tool(["firewall", "--policy", str(policy), "--out", str(self.out),
                                         "--firewall-ssh-port", "22"])
        self.assertEqual(code, 0)
        self.assertIn("firewall null ->", output)
        after = json.loads(self.out.read_bytes())
        self.assertEqual({**before, "firewall": {"ssh_port": 22, "dhcpv6_client": False}}, after)
        self.assertEqual(self.out.read_bytes(), tool.canonical(after))
        again = self.folder / "again.json"
        code, _, errors = self.run_tool(["firewall", "--policy", str(self.out), "--out", str(again),
                                         "--firewall-ssh-port", "22"])
        self.assertEqual(code, 1)
        self.assertIn("nothing to write", errors)
        code, _, errors = self.run_tool(["firewall", "--policy", str(policy), "--out", str(again),
                                         "--firewall-ssh-port", "80"])
        self.assertEqual(code, 1)
        self.assertFalse(again.exists())

    def test_dns_sets_only_the_dns_section(self):
        self.assertEqual(self.policy()[0], 0)
        policy = self.folder / "installed.json"
        self.out.rename(policy)
        before = json.loads(policy.read_bytes())
        dns = ["--dns-listen", "203.0.113.10", "--dns-name-servers", "ns1.example.test,ns2.example.test",
               "--dns-hostmaster", "hostmaster.example.test", "--dns-secondaries", "",
               "--dns-tsig-key", "rustiron-axfr", "--dns-soa", "10800,3600,604800,3600"]
        code, _, errors = self.run_tool(["dns", "--policy", str(policy), "--out", str(self.out), *dns])
        self.assertEqual(code, 0, errors)
        after = json.loads(self.out.read_bytes())
        self.assertEqual(set(after) - set(before), {"dns"})
        self.assertEqual({key: after[key] for key in before}, before)
        self.assertEqual(after["dns"]["listen"], ["203.0.113.10"])
        bad = list(dns)
        bad[bad.index("--dns-soa") + 1] = "10,3600,604800,3600"
        again = self.folder / "again.json"
        code, _, _ = self.run_tool(["dns", "--policy", str(policy), "--out", str(again), *bad])
        self.assertEqual(code, 1)
        self.assertFalse(again.exists())

    def test_verifier_changes_only_the_verifier_digest(self):
        policy = self.enrolled()
        code, output, _ = self.run_tool(["verifier", "--policy", str(policy), "--out", str(self.out),
                                         "--verifier", "/usr/bin/true"])
        self.assertEqual(code, 0, output)
        before, after = json.loads(policy.read_bytes()), json.loads(self.out.read_bytes())
        measured = hashlib.sha256(Path("/usr/bin/true").read_bytes()).hexdigest()
        self.assertEqual(after["verifier_sha256"], measured)
        self.assertEqual({**before, "verifier_sha256": measured}, after)
        self.assertEqual(self.out.read_bytes(), tool.canonical(after))
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o600)
        self.assertIn(f"{'b' * 64} -> {measured}", output)

    def test_verifier_refuses_a_same_digest_a_loose_policy_or_an_unsafe_file(self):
        policy = self.enrolled()
        measured = hashlib.sha256(Path("/usr/bin/true").read_bytes()).hexdigest()
        same = self.folder / "same.json"
        same.write_bytes(tool.canonical({**json.loads(policy.read_bytes()), "verifier_sha256": measured}))
        loose = self.folder / "loose.json"
        loose.write_text(json.dumps(json.loads(policy.read_bytes()), indent=1))
        mine = self.folder / "ssh-keygen"
        mine.write_bytes(b"not root's")
        link = self.folder / "link"
        link.symlink_to("/usr/bin/true")
        for source, verifier in ((same, "/usr/bin/true"), (loose, "/usr/bin/true"),
                                 (policy, str(mine)), (policy, str(link))):
            code, _, errors = self.run_tool(["verifier", "--policy", str(source), "--out", str(self.out),
                                             "--verifier", verifier])
            self.assertEqual(code, 1, (source, verifier))
            self.assertIn("REFUSED", errors)
            self.assertFalse(self.out.exists())

    def test_blast_radius_sets_bounded_section_and_refuses_bad_limits(self):
        policy = self.folder / "base.json"
        code, _, _ = self.run_tool(["policy", "--out", str(policy), *BASE])
        self.assertEqual(code, 0)
        code, _, errors = self.run_tool([
            "blast-radius", "--policy", str(policy), "--out", str(self.out),
            "--blast-radius-window-seconds", "3600",
            "--blast-radius-max-admissions", "20",
            "--blast-radius-max-ols-reloads", "4",
            "--blast-radius-max-served-sites", "16",
            "--blast-radius-max-total-admissions", "500",
            "--blast-radius-max-total-ols-reloads", "100",
        ])
        self.assertEqual(code, 0, errors)
        doc = json.loads(self.out.read_text())
        self.assertEqual(doc["blast_radius"], {
            "window_seconds": 3600,
            "max_admissions_per_window": 20,
            "max_ols_reloads_per_window": 4,
            "max_served_sites_per_activation": 16,
            "max_total_admissions": 500,
            "max_total_ols_reloads": 100,
        })
        bad_out = self.folder / "bad-br.json"
        code, _, errors = self.run_tool([
            "blast-radius", "--policy", str(policy), "--out", str(bad_out),
            "--blast-radius-window-seconds", "30",
            "--blast-radius-max-admissions", "20",
            "--blast-radius-max-ols-reloads", "4",
            "--blast-radius-max-served-sites", "16",
        ])
        self.assertEqual(code, 1)
        self.assertIn("REFUSED", errors)
        self.assertFalse(bad_out.exists())

    def test_acme_section_validates_https_directory_and_ca_bundle(self):
        code, _, errors = self.policy(
            "--acme-directory", "https://acme-v02.api.letsencrypt.org/directory",
        )
        self.assertEqual(code, 0, errors)
        doc = json.loads(self.out.read_text())
        self.assertEqual(doc["acme"], {"directory": "https://acme-v02.api.letsencrypt.org/directory"})

        # Standalone `acme` subcommand adds acme with optional ca_bundle to an existing policy.
        base = self.folder / "base-acme.json"
        self.assertEqual(self.run_tool(["policy", "--out", str(base), *BASE])[0], 0)
        out2 = self.folder / "with-acme.json"
        code, _, errors = self.run_tool([
            "acme", "--policy", str(base), "--out", str(out2),
            "--acme-directory", "https://pebble.lab.test:14000/dir",
            "--acme-ca-bundle", "/var/lib/rustiron-acme/pebble-ca.pem",
        ])
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(out2.read_text())["acme"], {
            "directory": "https://pebble.lab.test:14000/dir",
            "ca_bundle": "/var/lib/rustiron-acme/pebble-ca.pem",
        })

        # Bad URLs and path-traversal CA bundles are refused cleanly.
        for bad in (
            ["--acme-directory", "http://acme-v02.api.letsencrypt.org/directory"],
            ["--acme-directory", "https:///no-host"],
            ["--acme-directory", "https://acme.example/dir", "--acme-ca-bundle", "/etc/ssl/ca.pem"],
            ["--acme-directory", "https://acme.example/dir", "--acme-ca-bundle", "/var/lib/rustiron-acme/../etc/passwd"],
        ):
            with self.subTest(bad=bad):
                bad_out = self.folder / "bad-acme.json"
                code, _, err = self.run_tool(["policy", "--out", str(bad_out), *BASE, *bad])
                self.assertEqual(code, 1)
                self.assertIn("REFUSED", err)
                self.assertFalse(bad_out.exists())

    def test_caddy_section_supports_dual_mode_and_refuses_bad_bindings(self):
        # W657 (D-102, Decision A1): Caddy dual-mode enrollment.
        ols_edge = [
            "--ols-listener", "Edge", "--ols-address", "127.0.0.1:8080",
            "--ols-parent-sha256", "d" * 64, "--ols-webadmin-port", "7080",
        ]
        caddy_edge = [
            "--caddy-mode", "caddy_edge_over_ols",
            "--caddy-http-address", "203.0.113.10:80",
            "--caddy-https-address", "203.0.113.10:443",
            "--caddy-ols-upstream", "127.0.0.1:8080",
            "--caddy-binary-sha256", "f" * 64,
        ]
        code, _, err = self.policy(*ols_edge, *caddy_edge)
        self.assertEqual(code, 0, err)
        doc = json.loads(self.out.read_bytes())
        self.assertEqual(doc["caddy"], {
            "mode": "caddy_edge_over_ols",
            "http_address": "203.0.113.10:80",
            "https_address": "203.0.113.10:443",
            "ols_upstream": "127.0.0.1:8080",
            "binary_sha256": "f" * 64,
        })
        # Separate `caddy` subcommand sets the section on an existing policy copy.
        base_policy = self.folder / "base.json"
        self.out.unlink()
        self.assertEqual(self.run_tool(["policy", "--out", str(base_policy), *BASE, *ols_edge])[0], 0)
        code, _, err = self.run_tool(["caddy", "--policy", str(base_policy), "--out", str(self.out), *caddy_edge])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(self.out.read_bytes())["caddy"]["mode"], "caddy_edge_over_ols")

        # Refusals: missing upstream in edge mode, non-loopback upstream, admin port 2019, upstream in caddy_only.
        for bad in (
            [*ols_edge, "--caddy-mode", "caddy_edge_over_ols",
             "--caddy-http-address", "203.0.113.10:80",
             "--caddy-https-address", "203.0.113.10:443",
             "--caddy-binary-sha256", "f" * 64],
            [*ols_edge, "--caddy-mode", "caddy_edge_over_ols",
             "--caddy-http-address", "203.0.113.10:80",
             "--caddy-https-address", "203.0.113.10:443",
             "--caddy-ols-upstream", "203.0.113.10:8080",
             "--caddy-binary-sha256", "f" * 64],
            ["--caddy-mode", "caddy_only",
             "--caddy-http-address", "203.0.113.10:2019",
             "--caddy-https-address", "203.0.113.10:443",
             "--caddy-binary-sha256", "f" * 64],
            ["--caddy-mode", "caddy_only",
             "--caddy-http-address", "203.0.113.10:80",
             "--caddy-https-address", "203.0.113.10:443",
             "--caddy-ols-upstream", "127.0.0.1:8080",
             "--caddy-binary-sha256", "f" * 64],
        ):
            self.out.unlink(missing_ok=True)
            code, _, err = self.policy(*bad)
            self.assertEqual(code, 1, bad)
            self.assertIn("REFUSED", err)
            self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
