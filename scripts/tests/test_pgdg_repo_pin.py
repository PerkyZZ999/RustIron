"""D-102 (W658, Decision C2): the PostgreSQL 18 PGDG repository file stays pinned.

It may serve only postgresql18, postgresql18-libs, and postgresql18-server from
the PGDG 18 EL-10 train, over HTTPS, with package signatures required, the one
pinned PGDG RHEL GPG key, and a priority above default distribution repos.
"""

import configparser
import pathlib
import unittest

REPOS = pathlib.Path(__file__).resolve().parents[2] / "packaging/repos"
FINGERPRINT = "D4BF 08AE 67A0 B4C7 A1DB CCD2 40BC A2B4 08B4 0D20"


class Postgresql18RepositoryPinTests(unittest.TestCase):
    def test_the_repository_serves_three_signed_packages_over_https(self):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(REPOS / "rustiron-pgdg-18.repo")
        self.assertEqual(parser.sections(), ["rustiron-pgdg-18"])
        repo = parser["rustiron-pgdg-18"]
        self.assertEqual(
            repo["includepkgs"].split(),
            ["postgresql18", "postgresql18-libs", "postgresql18-server"],
        )
        self.assertNotIn("includepkg", repo)
        self.assertEqual(repo["gpgcheck"], "1")
        self.assertEqual(repo["enabled"], "1")
        self.assertLess(int(repo["priority"]), 99)
        self.assertEqual(
            repo["baseurl"],
            "https://download.postgresql.org/pub/repos/yum/18/redhat/rhel-$releasever-$basearch",
        )
        self.assertNotIn("mirrorlist", repo)
        self.assertNotIn("metalink", repo)
        self.assertEqual(
            repo["gpgkey"].split(),
            ["file:///etc/pki/rpm-gpg/PGDG-RPM-GPG-KEY-RHEL"],
        )
        self.assertIn(FINGERPRINT, (REPOS / "rustiron-pgdg-18.repo").read_text())

    def test_the_key_has_one_sha256_pin(self):
        lines = (REPOS / "pgdg-keys.sha256").read_text().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], r"^[0-9a-f]{64}  PGDG-RPM-GPG-KEY-RHEL$")


if __name__ == "__main__":
    unittest.main()
