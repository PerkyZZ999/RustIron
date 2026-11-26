"""D-092 (W560): the PowerDNS repository file stays pinned.

It may serve only pdns, pdns-backend-sqlite and pdns-tools from the 5.1
train, over HTTPS, with package signatures required, the one pinned key,
and a priority above EPEL's older pdns.
"""

import configparser
import pathlib
import unittest

REPOS = pathlib.Path(__file__).resolve().parents[2] / "packaging/repos"
FINGERPRINT = "9FAA A557 7E8F CF62 093D 036C 1B0C 6205 FD38 0FBB"


class PowerDnsRepositoryPinTests(unittest.TestCase):
    def test_the_repository_serves_three_signed_packages_over_https(self):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(REPOS / "rustiron-powerdns-auth-51.repo")
        self.assertEqual(parser.sections(), ["rustiron-powerdns-auth-51"])
        repo = parser["rustiron-powerdns-auth-51"]
        self.assertEqual(repo["includepkgs"].split(), ["pdns", "pdns-backend-sqlite", "pdns-tools"])
        self.assertNotIn("includepkg", repo)
        self.assertEqual(repo["gpgcheck"], "1")
        self.assertEqual(repo["enabled"], "1")
        self.assertLess(int(repo["priority"]), 99)
        self.assertEqual(repo["baseurl"], "https://repo.powerdns.com/el/$basearch/$releasever/auth-51")
        self.assertNotIn("mirrorlist", repo)
        self.assertNotIn("metalink", repo)
        self.assertEqual(repo["gpgkey"].split(), ["file:///etc/pki/rpm-gpg/RPM-GPG-KEY-powerdns-FD380FBB"])
        self.assertIn(FINGERPRINT, (REPOS / "rustiron-powerdns-auth-51.repo").read_text())

    def test_the_key_has_one_sha256_pin(self):
        lines = (REPOS / "powerdns-keys.sha256").read_text().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], r"^[0-9a-f]{64}  RPM-GPG-KEY-powerdns-FD380FBB$")


if __name__ == "__main__":
    unittest.main()
