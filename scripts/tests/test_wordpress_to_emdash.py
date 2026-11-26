"""Unit tests for packaging/wordpress-to-emdash.py (W602, P30, D-096)."""
from __future__ import annotations

import http.server
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "wp_to_emdash", ROOT / "packaging" / "wordpress-to-emdash.py"
)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

SAMPLE_WXR = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"
  xmlns:excerpt="http://wordpress.org/export/1.2/excerpt/"
  xmlns:content="http://purl.org/rss/1.0/modules/content/"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:wp="http://wordpress.org/export/1.2/">
<channel>
  <title>Old WP</title>
  <wp:author>
    <wp:author_login>charles</wp:author_login>
    <wp:author_display_name>Charles</wp:author_display_name>
  </wp:author>
  <item>
    <title>Hero Image</title>
    <link>https://old.example/hero/</link>
    <wp:post_type>attachment</wp:post_type>
    <wp:status>inherit</wp:status>
    <wp:attachment_url>https://old.example/wp-content/uploads/2026/11/hero.png</wp:attachment_url>
  </item>
  <item>
    <title>Welcome Post</title>
    <link>https://old.example/2026/11/welcome-post/</link>
    <dc:creator>charles</dc:creator>
    <wp:post_type>post</wp:post_type>
    <wp:status>publish</wp:status>
    <wp:post_name>welcome-post</wp:post_name>
    <wp:post_date_gmt>2026-11-20 12:00:00</wp:post_date_gmt>
    <category domain="category" nicename="news">News</category>
    <category domain="post_tag" nicename="launch">Launch</category>
    <content:encoded><![CDATA[<p>See <img src="https://old.example/wp-content/uploads/2026/11/hero.png"> and <a href="https://old.example/about-us/">About</a>.</p>]]></content:encoded>
  </item>
  <item>
    <title>About Us</title>
    <link>https://old.example/about-us/</link>
    <dc:creator>charles</dc:creator>
    <wp:post_type>page</wp:post_type>
    <wp:status>publish</wp:status>
    <wp:post_name>about-us</wp:post_name>
    <wp:post_date_gmt>2026-11-19 10:00:00</wp:post_date_gmt>
    <content:encoded><![CDATA[<p>About page body.</p>]]></content:encoded>
  </item>
  <item>
    <title>Secret Draft</title>
    <link>https://old.example/?p=99</link>
    <dc:creator>charles</dc:creator>
    <wp:post_type>post</wp:post_type>
    <wp:status>draft</wp:status>
    <wp:post_name>secret-draft</wp:post_name>
    <content:encoded><![CDATA[<p>Not public yet.</p>]]></content:encoded>
  </item>
</channel>
</rss>
"""


class WordPressToEmdashTests(unittest.TestCase):
    def test_plan_rewrites_media_links_redirects_and_verifies_live_target(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            wxr = base / "export.xml"
            wxr.write_text(SAMPLE_WXR, encoding="utf-8")
            media = base / "uploads"
            (media / "2026" / "11").mkdir(parents=True)
            hero_bytes = b"\x89PNG\r\n\x1a\nHERO_TEST_BYTES"
            (media / "2026" / "11" / "hero.png").write_bytes(hero_bytes)

            out = base / "bundle"
            manifest = MOD.plan_migration(
                wxr, media, "https://old.example", "https://new.example", out, capture_op="op_cap_1"
            )
            self.assertEqual(manifest["counts"]["posts"], 2)
            self.assertEqual(manifest["counts"]["pages"], 1)
            self.assertEqual(manifest["counts"]["published"], 2)
            self.assertEqual(manifest["counts"]["drafts"], 1)
            self.assertEqual(manifest["counts"]["attachments"], 1)
            self.assertGreaterEqual(manifest["counts"]["rewritten_links"], 2)

            content = json.loads((out / "content.json").read_text(encoding="utf-8"))
            welcome = next(i for i in content["items"] if i["slug"] == "welcome-post")
            self.assertIn("https://new.example/media/2026/11/hero.png", welcome["body"])
            self.assertIn("https://new.example/about-us", welcome["body"])
            self.assertNotIn("https://old.example", welcome["body"])

            # Seed SQLite content table + serve ephemeral HTTP server matching target bundle.
            db = base / "emdash.sqlite"
            con = sqlite3.connect(db)
            con.execute("CREATE TABLE content (slug TEXT PRIMARY KEY, status TEXT NOT NULL)")
            for item in content["items"]:
                con.execute("INSERT INTO content VALUES (?, ?)", (item["slug"], item["status"]))
            con.commit()
            con.close()

            redirects = {
                r["from"]: r["to"]
                for r in json.loads((out / "redirects.json").read_text(encoding="utf-8"))["redirects"]
            }
            published = {i["target_path"]: i for i in content["items"] if i["status"] == "publish"}

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path in redirects:
                        self.send_response(301)
                        self.send_header("Location", redirects[self.path])
                        self.end_headers()
                        return
                    if self.path == "/media/2026/11/hero.png":
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(hero_bytes)
                        return
                    if self.path in published:
                        doc = published[self.path]
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(f"<h1>{doc['title']}</h1>{doc['body']}".encode())
                        return
                    self.send_response(404)
                    self.end_headers()

                def log_message(self, fmt, *args):
                    pass

            srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                res = MOD.verify_migration(out, f"http://127.0.0.1:{port}", sqlite_path=db)
                self.assertTrue(res["ok"])
                self.assertEqual(res["checked"]["published"], 2)
                self.assertEqual(res["checked"]["drafts"], 1)
                self.assertEqual(res["checked"]["media"], 1)
                self.assertEqual(res["checked"]["sqlite_rows"], 3)
            finally:
                srv.shutdown()
                srv.server_close()

    def test_refuses_when_referenced_media_missing_from_capture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            wxr = base / "export.xml"
            wxr.write_text(SAMPLE_WXR, encoding="utf-8")
            media = base / "empty-uploads"
            media.mkdir()
            with self.assertRaises(MOD.MigrationError):
                MOD.plan_migration(wxr, media, "https://old.example", "https://new.example", base / "out")


if __name__ == "__main__":
    unittest.main()
