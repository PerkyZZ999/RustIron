"""W410 (W403 F2): the site sandbox check walks a site tree as the site.

`check-site-sandbox` runs as root before each site PHP start and every 30 s.
Before W410 it ran `find` over the whole site tree as root (W403 rule R3).
Root may now list only the root-owned top level of the site (no recursion).
Every deeper walk runs as the site account with no capabilities, so root's
privileges never walk tenant content.
"""
from __future__ import annotations

import pathlib
import re
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "lab/s03/check-site-sandbox.sh"


def find_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if re.search(r"\bfind\b", line) and not line.strip().startswith("#")]


class SiteSandboxWalkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = SCRIPT.read_text()

    def test_every_find_is_either_top_level_or_runs_as_the_site(self) -> None:
        lines = find_lines(self.text)
        self.assertTrue(lines)
        for line in lines:
            top_level = "-maxdepth 1" in line or "-maxdepth 0" in line
            as_site = "setpriv" in line and "--reuid" in line and "--inh-caps=-all" in line
            self.assertTrue(top_level or as_site, line)

    def test_the_site_walk_drops_groups_and_capabilities(self) -> None:
        walks = [line for line in find_lines(self.text) if "setpriv" in line]
        self.assertTrue(walks, "no walk as the site account")
        for line in walks:
            for flag in ("--reuid", "--regid", "--clear-groups", "--inh-caps=-all", "--no-new-privs"):
                self.assertIn(flag, line)
            self.assertIn("-xdev", line)
            self.assertNotIn(" -L ", line)

    def test_a_failed_walk_still_fails_closed(self) -> None:
        self.assertRegex(self.text, r'\|\|\s*fail "label scan of')


if __name__ == "__main__":
    unittest.main()
