"""Exit status of lab/s08/recover_unpriv.sh when the health check fails (W327).

The script runs inside bubblewrap as uid 1000 with no capabilities,
NoNewPrivs, and a private network namespace, so the real guard passes.
bubblewrap cannot mount a new sysfs, so the test supplies a net class
directory that holds only `lo`. MariaDB programs are stubs. The real PHP CLI
runs the real `health.php` against a synthetic site that is not WordPress.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'lab/s08/recover_unpriv.sh'
HEALTH = ROOT / 'lab/s08/health.php'
SITE = 'rs_demo'

SYNTHETIC_FRONT_PAGE = '''<?php
$GLOBALS['wp_version'] = 'synthetic';
function is_blog_installed(): bool { return true; }
function get_option(string $k) { return ['blogname' => 'Demo', 'siteurl' => 'http://demo.example.test'][$k] ?? null; }
function wp_count_posts() { return (object) ['publish' => 2]; }
function get_user_by(string $f, string $v) { return $v === 'rustiron_admin' ? (object) [] : false; }
echo "<html><head><title>Demo synthetic</title></head><body>ok</body></html>";
'''

# Each case replaces the health report after health.php wrote it. $out is the
# report path that health.php holds in its top-level scope.
REWRITE = SYNTHETIC_FRONT_PAGE + "register_shutdown_function(function () use ($out) { %s });\n"

STUBS = {
    'mariadb-install-db': '#!/bin/sh\nexit 0\n',
    'mariadbd': '#!/bin/sh\nexit 0\n',
    'mariadb': '#!/bin/sh\ncase "$*" in *" -N "*) printf \'2\\n1\\n\';; esac\ncat >/dev/null\nexit 0\n',
}


def sandbox_available():
    if not (shutil.which('bwrap') and shutil.which('php')):
        return False
    probe = subprocess.run(
        ['bwrap', '--ro-bind', '/', '/', '--unshare-all', '--uid', '1000', 'true'],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    return probe.returncode == 0


@unittest.skipUnless(sandbox_available(), 'needs bubblewrap with user namespaces and the PHP CLI')
class RecoverUnprivHealthTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='rustiron-recover-test-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.recovery = self.work / 'recovery'
        site = self.recovery / 'srv/sites' / SITE
        (site / 'html').mkdir(parents=True)
        (site / 'tmp').mkdir()
        (site / 'tmp/rustiron-capture.sql').write_text('-- synthetic dump\n')
        shutil.copy2(HEALTH, self.recovery / 'health.php')
        self.front_page = site / 'html/index.php'
        stubs = self.work / 'stub'
        stubs.mkdir()
        for name, body in STUBS.items():
            (stubs / name).write_text(body)
            (stubs / name).chmod(0o755)

    def run_script(self, front_page):
        self.front_page.write_text(front_page)
        command = [
            'bwrap', '--die-with-parent', '--unshare-all', '--uid', '1000', '--gid', '1000',
            '--cap-drop', 'ALL', '--ro-bind', '/usr', '/usr', '--ro-bind', '/etc', '/etc',
            '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/bin', '/sbin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/sys/class/net/lo',
            '--bind', str(self.recovery), '/recovery',
            '--ro-bind', str(SCRIPT), '/r.sh', '--ro-bind', str(self.work / 'stub'), '/stub',
            '--setenv', 'PATH', '/stub:/usr/bin',
            'sh', '/r.sh', f'/recovery/srv/sites/{SITE}', 'demo.example.test',
        ]
        return subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=120)

    def assert_refused(self, result, reason):
        self.assertIn('guard: uid=1000 capeff=0000000000000000 nonewprivs=1 non_lo_interfaces=0',
                      result.stdout)
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn(f'health=fail: {reason}', result.stderr)
        self.assertNotIn('health=pass', result.stdout)

    def test_valid_health_report_passes(self):
        result = self.run_script(SYNTHETIC_FRONT_PAGE)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('"published_posts":2', result.stdout)
        self.assertIn('"admin_exists":true', result.stdout)
        self.assertTrue(result.stdout.rstrip().endswith('health=pass'))

    def test_php_fatal_error_fails(self):
        self.assert_refused(self.run_script('<?php\nundefined_function_w327();\n'),
                            'health.php exited 255')

    def test_missing_report_fails(self):
        self.assert_refused(self.run_script(REWRITE % 'unlink($out);'),
                            'missing or invalid health JSON')

    def test_report_that_is_not_json_fails(self):
        self.assert_refused(self.run_script(REWRITE % "file_put_contents($out, 'not json');"),
                            'missing or invalid health JSON')

    def test_report_without_every_field_fails(self):
        self.assert_refused(
            self.run_script(REWRITE % "file_put_contents($out, '{\"installed\":true}');"),
            'missing or invalid health JSON')

    def test_report_that_is_a_list_fails(self):
        self.assert_refused(self.run_script(REWRITE % "file_put_contents($out, '[1,2]');"),
                            'missing or invalid health JSON')


if __name__ == '__main__':
    unittest.main()
