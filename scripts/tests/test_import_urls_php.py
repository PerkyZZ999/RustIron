"""D-070: the site import hostname-change asset, run with the local PHP CLI
against a throwaway, unprivileged MariaDB on a private socket.

Each case loads rows into the site's own database, runs the asset from
<root>/tmp as the Config step does, and reads the stored bytes back.
"""

import json
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ASSET = pathlib.Path(__file__).resolve().parents[2] / "crates/executor/src/import_assets/urls.php"
PHP = shutil.which("php")
INSTALL = shutil.which("mariadb-install-db")
SERVER = shutil.which("mariadbd")
CLIENT = shutil.which("mariadb")
SOURCE = "shop.example.org"
TARGET = "testwp.example.network"


def php_value(code):
    """A PHP expression's serialize() output, from the local PHP."""
    return subprocess.run([PHP, "-r", f"echo serialize({code});"], capture_output=True,
                          check=True).stdout


def php_unserialize(raw):
    """json of unserialize() with no classes allowed, or 'false'."""
    script = "$v = unserialize(stream_get_contents(STDIN), ['allowed_classes' => false]);" \
             "echo json_encode($v === false ? false : json_decode(json_encode($v), true));"
    return json.loads(subprocess.run([PHP, "-r", script], input=raw, capture_output=True,
                                     check=True).stdout)


@unittest.skipUnless(PHP and INSTALL and SERVER and CLIENT, "no php or MariaDB on this host")
class ImportUrlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.mkdtemp(prefix="ri-d070-")
        base = pathlib.Path(cls.folder)
        cls.data = base / "data"
        cls.socket = str(base / "mysql.sock")
        subprocess.run([INSTALL, "--no-defaults", f"--datadir={cls.data}",
                        "--auth-root-authentication-method=normal", "--skip-test-db"],
                       capture_output=True, check=True)
        cls.server = subprocess.Popen(
            [SERVER, "--no-defaults", f"--datadir={cls.data}", f"--socket={cls.socket}",
             "--skip-networking", f"--pid-file={base / 'pid'}", f"--log-error={base / 'err'}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if os.path.exists(cls.socket) and cls.admin("SELECT 1", check=False).returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("MariaDB did not start")

    @classmethod
    def tearDownClass(cls):
        cls.server.send_signal(signal.SIGTERM)
        cls.server.wait(timeout=30)
        shutil.rmtree(cls.folder)

    @classmethod
    def admin(cls, sql, check=True):
        return subprocess.run([CLIENT, "--no-defaults", "-uroot", f"--socket={cls.socket}",
                               "--batch", "--skip-column-names", "-e", sql],
                              capture_output=True, text=True, check=check)

    def setUp(self):
        self.admin("DROP DATABASE IF EXISTS rs_site; CREATE DATABASE rs_site CHARACTER SET utf8mb4; "
                   "DROP USER IF EXISTS 'rs_site'@'localhost'; "
                   "CREATE USER 'rs_site'@'localhost' IDENTIFIED BY 'pw-d070'; "
                   "GRANT ALL ON rs_site.* TO 'rs_site'@'localhost';")

    def load(self, ddl, rows):
        """Creates tables and inserts (table, column, bytes) rows as hex."""
        self.admin(f"USE rs_site; {ddl}")
        for table, columns, values in rows:
            literals = ", ".join("X'" + v.hex() + "'" if isinstance(v, bytes) else str(v)
                                 for v in values)
            self.admin(f"USE rs_site; INSERT INTO {table} ({columns}) VALUES ({literals});")

    def read(self, sql):
        out = self.admin(f"USE rs_site; {sql}").stdout.splitlines()
        return [bytes.fromhex(line) for line in out]

    def run_asset(self, source=SOURCE, target=TARGET, cnf=True):
        with tempfile.TemporaryDirectory(prefix="ri-d070-site-") as folder:
            root = pathlib.Path(folder)
            (root / "tmp").mkdir()
            (root / "private").mkdir()
            if cnf:
                (root / "private/db.cnf").write_text(
                    "[client]\nuser = rs_site\npassword = pw-d070\ndatabase = rs_site\n"
                    f"socket = {self.socket}\n")
            (root / "tmp/rustiron-import-urls.input").write_text(f"{source}\n{target}\n")
            shutil.copy(ASSET, root / "tmp/urls.php")
            result = subprocess.run([PHP, "-q", str(root / "tmp/urls.php")],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            text = (root / "tmp/rustiron-import-urls.json").read_text()
            self.assertNotIn("pw-d070", text)
            return json.loads(text)

    def posts(self):
        self.load("CREATE TABLE wp_posts (ID BIGINT PRIMARY KEY, post_content LONGTEXT, "
                  "guid VARCHAR(255)) CHARACTER SET utf8mb4", [])

    def test_links_change_and_lookalikes_mail_and_guid_stay(self):
        self.posts()
        content = (f'<a href="https://{SOURCE}/a">x</a> http://{SOURCE} //{SOURCE}:8443/p '
                   f'https://{SOURCE}.evil.test/ https://{SOURCE}x.test/ https://sub.{SOURCE}/ '
                   f'ctq@{SOURCE} {{"u":"https:\\/\\/{SOURCE}\\/w"}} see https://{SOURCE}. '
                   'caf\u00e9 \U0001F69A').encode()
        self.load("", [("wp_posts", "ID, post_content, guid", [1, content, f"https://{SOURCE}/?p=1".encode()])])
        report = self.run_asset()
        self.assertTrue(report["ok"], report)
        self.assertEqual((report["rows"], report["values"]), (1, 1))
        [new] = self.read("SELECT HEX(post_content) FROM wp_posts")
        want = (f'<a href="https://{TARGET}/a">x</a> http://{TARGET} //{TARGET}:8443/p '
                f'https://{SOURCE}.evil.test/ https://{SOURCE}x.test/ https://sub.{SOURCE}/ '
                f'ctq@{SOURCE} {{"u":"https:\\/\\/{TARGET}\\/w"}} see https://{TARGET}. '
                'caf\u00e9 \U0001F69A').encode()
        self.assertEqual(new, want)
        [guid] = self.read("SELECT HEX(guid) FROM wp_posts")
        self.assertEqual(guid, f"https://{SOURCE}/?p=1".encode(), "guid is an identifier")

    def test_serialized_values_keep_valid_lengths_without_building_objects(self):
        self.load("CREATE TABLE wp_options (option_id BIGINT PRIMARY KEY, option_value LONGTEXT) "
                  "CHARACTER SET utf8mb4", [])
        nested = php_value(f"['u' => 'https://{SOURCE}/n', 'k' => 2]").decode()
        array = php_value(f"['url' => 'https://{SOURCE}/a', 'https://{SOURCE}/key' => 1, "
                          f"'nested' => '{nested}', 'f' => 1.5, 'b' => true, 'z' => null]")
        obj = php_value(f"(object) ['home' => 'http://{SOURCE}', 'list' => ['//{SOURCE}/x']]")
        # A class that does not exist here: walked as text, never built.
        hostile = (f'O:12:"Evil\\Gadget1":1:{{s:4:"path";s:{len(SOURCE) + 8}:"https://{SOURCE}";}}').encode()
        self.load("", [("wp_options", "option_id, option_value", [1, array]),
                       ("wp_options", "option_id, option_value", [2, obj]),
                       ("wp_options", "option_id, option_value", [3, hostile])])
        report = self.run_asset()
        self.assertTrue(report["ok"], report)
        self.assertEqual((report["serialized"], report["unparsed"]), (3, 0))
        first, second, third = self.read("SELECT HEX(option_value) FROM wp_options ORDER BY option_id")
        value = php_unserialize(first)
        self.assertEqual(value["url"], f"https://{TARGET}/a")
        self.assertIn(f"https://{SOURCE}/key", value, "keys stay")
        self.assertEqual(php_unserialize(value["nested"].encode())["u"], f"https://{TARGET}/n")
        self.assertEqual((value["f"], value["b"], value["z"]), (1.5, True, None))
        value = php_unserialize(second)
        self.assertEqual((value["home"], value["list"]), (f"http://{TARGET}", [f"//{TARGET}/x"]))
        self.assertIn(b'O:12:"Evil\\Gadget1":1:', third)
        self.assertIn(f's:{len(TARGET) + 8}:"https://{TARGET}";'.encode(), third)

    def test_a_broken_serialized_value_is_left_and_counted(self):
        self.load("CREATE TABLE wp_options (option_id BIGINT PRIMARY KEY, option_value LONGTEXT) "
                  "CHARACTER SET utf8mb4", [])
        broken = f'a:1:{{s:3:"url";s:99:"https://{SOURCE}";}}'.encode()
        text = f"a: note on https://{SOURCE}".encode()
        self.load("", [("wp_options", "option_id, option_value", [1, broken]),
                       ("wp_options", "option_id, option_value", [2, text])])
        report = self.run_asset()
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["unparsed"], 1)
        first, second = self.read("SELECT HEX(option_value) FROM wp_options ORDER BY option_id")
        self.assertEqual(first, broken)
        self.assertEqual(second, f"a: note on https://{TARGET}".encode(), "text, not serialized")

    def test_a_table_without_a_key_and_a_latin1_column_are_rewritten_byte_exact(self):
        self.load("CREATE TABLE log (msg TEXT) CHARACTER SET latin1", [])
        latin = f"caf\xe9 https://{SOURCE}/x".encode("latin-1")
        self.load("", [("log", "msg", [latin]), ("log", "msg", [latin]),
                       ("log", "msg", [b"nothing here"])])
        report = self.run_asset()
        self.assertTrue(report["ok"], report)
        self.assertEqual((report["rows"], report["values"]), (2, 1))
        rows = self.read("SELECT HEX(msg) FROM log ORDER BY msg")
        self.assertEqual(sorted(rows), sorted([b"nothing here"] + [f"caf\xe9 https://{TARGET}/x".encode("latin-1")] * 2))

    def test_bad_input_or_credentials_refuse_without_a_change(self):
        self.posts()
        original = f"https://{SOURCE}/".encode()
        self.load("", [("wp_posts", "ID, post_content, guid", [1, original, b"g"])])
        for source, target, cnf, reason in [
            (SOURCE, SOURCE, True, "input"),
            ("Shop.Example.org", TARGET, True, "input"),
            ("shop", TARGET, True, "input"),
            (SOURCE, "a/b.example", True, "input"),
            (SOURCE, TARGET, False, "credentials"),
        ]:
            report = self.run_asset(source, target, cnf)
            self.assertEqual(report, {"ok": False, "reason": reason})
        [value] = self.read("SELECT HEX(post_content) FROM wp_posts")
        self.assertEqual(value, original)

    def test_disposable_caches_are_deleted_and_nothing_else(self):
        # W479-F1: Elementor keeps each element's settings in base64 in its
        # element cache, so no text rewrite reaches them.
        self.load("CREATE TABLE xy_options (option_id BIGINT PRIMARY KEY, option_name VARCHAR(191), "
                  "option_value LONGTEXT) CHARACTER SET utf8mb4; "
                  "CREATE TABLE xy_postmeta (meta_id BIGINT PRIMARY KEY, post_id BIGINT, "
                  "meta_key VARCHAR(255), meta_value LONGTEXT) CHARACTER SET utf8mb4", [])
        rows = [
            ("xy_options", "option_id, option_name, option_value", [1, b"_transient_scan", b"x"]),
            ("xy_options", "option_id, option_name, option_value", [2, b"_transient_timeout_scan", b"9"]),
            ("xy_options", "option_id, option_name, option_value", [3, b"_site_transient_update", b"x"]),
            ("xy_options", "option_id, option_name, option_value", [4, b"siteurl", f"https://{SOURCE}".encode()]),
            ("xy_options", "option_id, option_name, option_value", [5, b"xtransient_lookalike", b"keep"]),
            ("xy_postmeta", "meta_id, post_id, meta_key, meta_value", [1, 7, b"_elementor_element_cache", b'{"value":"eyJ"}']),
            ("xy_postmeta", "meta_id, post_id, meta_key, meta_value", [2, 7, b"_elementor_data", f'[{{"u":"https:\\/\\/{SOURCE}"}}]'.encode()]),
        ]
        self.load("", rows)
        report = self.run_asset()
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["caches"], 4)
        self.assertEqual(self.read("SELECT HEX(option_name) FROM xy_options ORDER BY option_id"),
                         [b"siteurl", b"xtransient_lookalike"])
        self.assertEqual(self.read("SELECT HEX(meta_key) FROM xy_postmeta ORDER BY meta_id"),
                         [b"_elementor_data"])
        [data] = self.read("SELECT HEX(meta_value) FROM xy_postmeta")
        self.assertEqual(data, f'[{{"u":"https:\\/\\/{TARGET}"}}]'.encode())

    def test_another_database_is_out_of_reach(self):
        self.admin("DROP DATABASE IF EXISTS other; CREATE DATABASE other; "
                   "CREATE TABLE other.t (id INT PRIMARY KEY, v TEXT); "
                   f"INSERT INTO other.t VALUES (1, 'https://{SOURCE}/');")
        self.posts()
        report = self.run_asset()
        self.assertTrue(report["ok"], report)
        self.assertEqual(self.admin("SELECT v FROM other.t").stdout.strip(), f"https://{SOURCE}/")


if __name__ == "__main__":
    unittest.main()
