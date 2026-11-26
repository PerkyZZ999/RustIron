"""D-055 (W454): the optional Remi repository file stays pinned.

It may serve only the two libraries that lsphp84-mbstring and lsphp84-intl
need, over HTTPS, with package signatures required and pinned keys.
"""

import configparser
import pathlib
import unittest

REPOS = pathlib.Path(__file__).resolve().parents[2] / "packaging/repos"


class RemiRepositoryPinTests(unittest.TestCase):
    def test_the_repository_serves_two_signed_libraries_over_https(self):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(REPOS / "rustiron-remi-php-libs.repo")
        self.assertEqual(parser.sections(), ["rustiron-remi-php-libs"])
        repo = parser["rustiron-remi-php-libs"]
        self.assertEqual(repo["includepkgs"].split(), ["oniguruma5php", "libicu78"])
        self.assertEqual(repo["gpgcheck"], "1")
        self.assertEqual(repo["enabled"], "1")
        self.assertTrue(repo["baseurl"].startswith("https://rpms.remirepo.net/enterprise/10/safe/"))
        self.assertNotIn("mirrorlist", repo)
        self.assertNotIn("metalink", repo)
        keys = repo["gpgkey"].split()
        self.assertTrue(keys and all(key.startswith("file:///etc/pki/rpm-gpg/RPM-GPG-KEY-remi") for key in keys))
        pinned = {line.split()[1] for line in (REPOS / "remi-keys.sha256").read_text().splitlines()}
        self.assertEqual({key.rsplit("/", 1)[1] for key in keys}, pinned)

    def test_every_key_has_one_sha256_pin(self):
        for line in (REPOS / "remi-keys.sha256").read_text().splitlines():
            self.assertRegex(line, r"^[0-9a-f]{64}  RPM-GPG-KEY-remi20[0-9]{2}$")


if __name__ == "__main__":
    unittest.main()
