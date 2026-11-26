"""Test the zone set digest tool (W567) on the W566 lab listing."""

import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dns_zone_sets", ROOT / "packaging/dns-zone-sets.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)

ZONE = (ROOT / "docs/validation/S10-W566/lab/zone.txt").read_text()
# `pdnsutil zone list` output: an $ORIGIN line and tab-separated fields, unsorted.
LISTING = "$ORIGIN .\n" + "".join(
    "\t".join(line.split(" ", 4)) + "\n" for line in reversed(ZONE.splitlines()))
SPF = 'w566.test. 3600 IN TXT "v=spf1 mx ~all"\n'


class ZoneSetsTests(unittest.TestCase):
    def run_tool(self, *argv, text=LISTING):
        with tempfile.NamedTemporaryFile("w", suffix=".zone") as handle:
            handle.write(text)
            handle.flush()
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                code = tool.main([*argv, handle.name])
        return code, output.getvalue(), errors.getvalue()

    def test_a_listing_becomes_the_canonical_file(self):
        code, output, _ = self.run_tool("canonical")
        self.assertEqual(code, 0)
        self.assertEqual(output, ZONE)

    def test_wrapped_txt_preserves_each_quoted_string(self):
        listing = ('$ORIGIN .\nselector._domainkey.w566.test.\t3600\tIN\tTXT\t"v=DKIM1; "\n'
                   '\t  "p=example"\n\t  " trailing space "\n')
        code, output, errors = self.run_tool("canonical", text=listing)
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(output,
                         'selector._domainkey.w566.test. 3600 IN TXT '
                         '"v=DKIM1; " "p=example" " trailing space "\n')

    def test_continuation_after_an_address_is_refused(self):
        listing = 'w566.test.\t3600\tIN\tA\t203.0.113.18\n\t  "orphan"\n'
        code, output, errors = self.run_tool("canonical", text=listing)
        self.assertEqual((code, output), (1, ""))
        self.assertIn("continuation", errors)

    def test_legacy_unquoted_txt_is_one_string(self):
        listing = 'w566.test.\t3600\tIN\tTXT\tv=spf1 mx  ~all\n'
        code, output, errors = self.run_tool("canonical", text=listing)
        self.assertEqual((code, output, errors),
                         (0, 'w566.test. 3600 IN TXT "v=spf1 mx  ~all"\n', ""))

    def test_ambiguous_unquoted_txt_is_refused(self):
        listing = 'w566.test.\t3600\tIN\tTXT\tmixed "quotation"\n'
        code, output, errors = self.run_tool("canonical", text=listing)
        self.assertEqual((code, output), (1, ""))
        self.assertIn("unquoted TXT", errors)

    def test_root_origin_listing_supplies_absolute_names(self):
        listing = ("$ORIGIN .\nw566.test\t3600\tIN\tSOA\t"
                   "ns1.w566.test hostmaster.w566.test 11 10800 3600 604800 3600\n"
                   "www.w566.test\t300\tIN\tCNAME\tw566.test\n")
        code, output, errors = self.run_tool("canonical", text=listing)
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(output,
                         "w566.test. 3600 IN SOA ns1.w566.test. hostmaster.w566.test. "
                         "11 10800 3600 604800 3600\nwww.w566.test. 300 IN CNAME w566.test.\n")

    def test_each_set_has_its_digest_and_mail_mark(self):
        code, output, _ = self.run_tool("sets", "w566.test")
        self.assertEqual(code, 0)
        lines = output.splitlines()
        self.assertEqual(len(lines), 13)
        spf = hashlib.sha256(SPF.encode()).hexdigest()
        self.assertIn(f"w566.test. TXT {spf} [MAIL]", lines)
        self.assertTrue(any(line.startswith("w566.test. MX ") and line.endswith("[MAIL]") for line in lines))
        self.assertTrue(any(line.startswith("_dmarc.w566.test. TXT ") and line.endswith("[MAIL]") for line in lines))
        self.assertTrue(any(line.startswith("selector1._domainkey.w566.test. CNAME ") and line.endswith("[MAIL]")
                            for line in lines))
        self.assertTrue(any(line.startswith("www.w566.test. CNAME ") and not line.endswith("[MAIL]")
                            for line in lines))

    def test_one_set_prints_its_lines_or_absent(self):
        code, output, _ = self.run_tool("set", "w566.test", "w566.test.", "txt")
        self.assertEqual(code, 0)
        self.assertEqual(output, SPF + hashlib.sha256(SPF.encode()).hexdigest() + "\n")
        # The W566 plan expected this digest for the same set (op_w566_c3).
        self.assertTrue(output.splitlines()[-1].startswith("9917fdd47e63"))
        code, output, _ = self.run_tool("set", "w566.test", "new.w566.test.", "A")
        self.assertEqual((code, output), (0, "absent\n"))

    def test_a_line_that_is_not_a_record_is_refused(self):
        code, _, errors = self.run_tool("sets", "w566.test", text="w566.test. 3600 CH TXT x\n")
        self.assertEqual(code, 1)
        self.assertIn("REFUSED", errors)


if __name__ == "__main__":
    unittest.main()
