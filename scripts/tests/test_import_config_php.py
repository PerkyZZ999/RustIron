"""W450 (D-053): the site import Config asset, run with the local PHP CLI.

Each case builds <root>/html/wp-config.php and runs the asset from
<root>/tmp, as the Config step does. The asset never sees a database.
"""

import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ASSET = pathlib.Path(__file__).resolve().parents[2] / "crates/executor/src/import_assets/config.php"
PHP = shutil.which("php")
SECRET = "source-host-password-W450"
SOURCE_ROOT = "/home/blog1.example.test/public_html"
STANDARD = f"""<?php
/** The base configuration for WordPress */
define( 'DB_NAME', 'p01_wp' );
define( 'DB_USER', 'p01_u' );
define( 'DB_PASSWORD', '{SECRET}' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'AUTH_KEY', 'keep-this' );
$table_prefix = 'wp_';
if ( ! defined( 'ABSPATH' ) ) {{
    define( 'ABSPATH', __DIR__ . '/' );
}}
require_once ABSPATH . 'wp-settings.php';
"""


@unittest.skipUnless(PHP, "no php CLI on this host")
class ImportConfigTests(unittest.TestCase):
    def run_asset(self, config, files=None, paths=SOURCE_ROOT, moved=None):
        with tempfile.TemporaryDirectory(prefix="ri-w450-") as folder:
            root = pathlib.Path(folder)
            (root / "html").mkdir()
            (root / "tmp").mkdir()
            (root / "html/wp-config.php").write_text(config)
            for name, text in (files or {}).items():
                (root / "html" / name).parent.mkdir(parents=True, exist_ok=True)
                (root / "html" / name).write_text(text)
            if paths is not None:
                (root / "tmp/rustiron-import-config.paths").write_text(paths)
            shutil.copy(ASSET, root / "tmp/config.php")
            result = subprocess.run([PHP, "-q", str(root / "tmp/config.php")],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            report_text = (root / "tmp/rustiron-import-config.json").read_text()
            new = root / "tmp/rustiron-import-config.new"
            if moved is not None:
                moved["root"] = str(root)
                moved["staged"] = {p.name: p.read_text() for p in (root / "tmp").glob("rustiron-import-path.*")}
            return json.loads(report_text), report_text, (new.read_text() if new.exists() else None)

    def test_a_standard_config_gets_the_reader(self):
        report, text, new = self.run_asset(STANDARD)
        self.assertEqual(report["ok"], True, report)
        self.assertEqual(report["replaced"], 4)
        self.assertNotIn(SECRET, new)
        self.assertNotIn(SECRET, text)
        self.assertEqual(new.count("parse_ini_file(dirname(__DIR__) . '/private/db.cnf'"), 1)
        for kept in ["define( 'DB_CHARSET', 'utf8mb4' );", "define( 'AUTH_KEY', 'keep-this' );",
                     "$table_prefix = 'wp_';", "require_once ABSPATH . 'wp-settings.php';"]:
            self.assertIn(kept, new)
        self.assertNotIn("'p01_u'", new)
        with tempfile.NamedTemporaryFile("w", suffix=".php") as check:
            check.write(new)
            check.flush()
            lint = subprocess.run([PHP, "-l", check.name], capture_output=True, text=True)
            self.assertEqual(lint.returncode, 0, lint.stdout + lint.stderr)

    def test_refusals_name_a_fixed_reason_and_write_no_text(self):
        cases = {
            "repeated": STANDARD + "define( 'DB_USER', 'again' );\n",
            "missing": STANDARD.replace("define( 'DB_HOST', 'localhost' );", ""),
            "not_plain": STANDARD.replace("'localhost'", "getenv('DB_HOST')"),
            "parse": STANDARD + "function (\n",
        }
        cases["not_plain_double"] = STANDARD.replace(f"'{SECRET}'", '"pa$word"')
        cases["not_plain_concat"] = STANDARD.replace("'p01_u'", "'p01' . '_u'")
        for reason, config in cases.items():
            report, text, new = self.run_asset(config)
            self.assertEqual(report["ok"], False, reason)
            self.assertEqual(report["reason"], reason.split("_double")[0].split("_concat")[0], reason)
            self.assertIsNone(new, reason)
            self.assertNotIn(SECRET, text)

    def test_a_method_named_define_is_not_a_definition(self):
        config = STANDARD.replace("define( 'DB_HOST', 'localhost' );",
                                  "$x->define( 'DB_HOST', 'elsewhere' );")
        report, _, _ = self.run_asset(config)
        self.assertEqual((report["ok"], report["reason"]), (False, "missing"))

    def test_comments_between_tokens_are_accepted(self):
        config = STANDARD.replace("define( 'DB_HOST', 'localhost' );",
                                  "define( /* host */ 'DB_HOST', 'localhost' ) ;")
        report, _, new = self.run_asset(config)
        self.assertEqual(report["ok"], True, report)
        self.assertNotIn("'localhost' )", new)

    def test_an_oversized_config_is_refused(self):
        report, _, _ = self.run_asset(STANDARD + "//" + "x" * 1048576 + "\n")
        self.assertEqual((report["ok"], report["reason"]), (False, "read"))


    def test_the_source_document_root_moves_to_the_site_html(self):
        """D-069 (W478): only the old root and paths below it change."""
        htaccess = (f'php_value auto_prepend_file "{SOURCE_ROOT}/wp-content/firewall.php"\n'
                    f"# kept: {SOURCE_ROOT}.old-20261111/x\n")
        config = STANDARD + f"define( 'WP_TEMP_DIR', '{SOURCE_ROOT}/tmp' );\n"
        moved = {}
        report, _, new = self.run_asset(config, {
            ".htaccess": htaccess,
            ".user.ini": f"auto_prepend_file = '{SOURCE_ROOT}/wp-content/firewall.php'\n",
            "wp-content/firewall.php": f"<?php include '{SOURCE_ROOT}/wp-content/rules.php';\n",
            "wp-content/unrelated.php": "<?php // nothing to move\n",
            "wp-content/plugins/deep.php": f"<?php '{SOURCE_ROOT}';\n",
        }, moved=moved)
        self.assertEqual(report["ok"], True, report)
        html = moved["root"] + "/html"
        self.assertIn(f"'{html}/tmp'", new)
        names = [entry["name"] for entry in report["paths"]]
        self.assertEqual(names, [".htaccess", ".user.ini", "wp-content/firewall.php"])
        staged = moved["staged"]
        self.assertEqual(len(staged), 3)
        self.assertIn(f'"{html}/wp-content/firewall.php"', staged["rustiron-import-path.0"])
        self.assertIn(f"{SOURCE_ROOT}.old-20261111/x", staged["rustiron-import-path.0"])
        for index, entry in enumerate(report["paths"]):
            import hashlib
            digest = hashlib.sha256(staged[f"rustiron-import-path.{index}"].encode()).hexdigest()
            self.assertEqual(entry["sha256"], digest)

    def test_a_missing_or_odd_source_root_is_refused(self):
        for paths in [None, "/etc", "/home/../public_html", "/home/x/public_html/../.."]:
            report, _, new = self.run_asset(STANDARD, paths=paths)
            self.assertEqual((report["ok"], report["reason"]), (False, "paths_input"), paths)
            self.assertIsNone(new)


if __name__ == "__main__":
    unittest.main()
