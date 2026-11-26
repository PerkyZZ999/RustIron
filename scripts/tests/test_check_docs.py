"""Regression checks for false passes in the documentation gate."""

import importlib.util
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch


PROJECT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_docs", PROJECT / "scripts/check_docs.py")
assert SPEC is not None and SPEC.loader is not None
CHECKS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKS)


class DocumentationGateTests(unittest.TestCase):
    def test_luminance_endpoints(self):
        self.assertAlmostEqual(CHECKS.luminance("#000000"), 0.0)
        self.assertAlmostEqual(CHECKS.luminance("#FFFFFF"), 1.0)

    def test_white_button_text_on_white_action_is_rejected(self):
        candidate = (PROJECT / "docs/DESIGN.md").read_text()
        candidate = re.sub(r'  light-action: "[^"]+"', '  light-action: "#FFFFFF"', candidate)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs/DESIGN.md").write_text(candidate)
            errors = []
            with patch.object(CHECKS, "ROOT", root):
                CHECKS.check_design_contrast(errors)
        self.assertTrue(any("light-on-action on light-action:" in error for error in errors))

    def test_broken_link_is_rejected_but_external_link_and_hard_break_are_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "example.md"
            source.write_text("Label  \n[Missing](missing.md)\n[External](https://example.org/)\n")
            errors = []
            with patch.object(CHECKS, "ROOT", root):
                count = CHECKS.check_document(source, errors)
        self.assertEqual(count, 1)
        self.assertEqual(errors, ["example.md:2: missing missing.md"])

    def test_markdown_fragment_anchors_are_validated_and_fenced_headings_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.md"
            target.write_text(
                "# D-018 — Scope\n\n"
                "## `site_readopt` (W372)\n\n"
                "## Repeat\n\n"
                "## Repeat\n\n"
                "```md\n"
                "## Not A Heading\n"
                "```\n",
                encoding="utf-8",
            )
            source = root / "source.md"
            source.write_text(
                "# Intro\n\n"
                "[Self](#intro)\n"
                "[D018](target.md#d-018--scope)\n"
                "[Underscore](target.md#site_readopt-w372)\n"
                "[Dup](target.md#repeat-1)\n"
                "[BadSelf](#missing-self)\n"
                "[BadCross](target.md#not-a-heading)\n",
                encoding="utf-8",
            )
            errors = []
            with patch.object(CHECKS, "ROOT", root):
                count = CHECKS.check_document(source, errors)
        self.assertEqual(count, 6)
        self.assertEqual(
            errors,
            [
                "source.md:7: missing anchor #missing-self",
                "source.md:8: missing anchor target.md#not-a-heading",
            ],
        )


if __name__ == "__main__":
    unittest.main()
