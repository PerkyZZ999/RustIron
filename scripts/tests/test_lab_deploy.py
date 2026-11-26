"""Exercise staged deployment snapshots and fail-before-install behavior offline."""
from pathlib import Path
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class LabDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='rustiron-deploy-test-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.source = self.work / 'source'
        self.source.mkdir()
        self.home = self.work / 'home'
        self.home.mkdir()
        self.env = {**os.environ, 'HOME': str(self.home), 'TEST_WORK': str(self.work)}

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.source).strip()

    def prepare_deploy(self):
        (self.source / 'lab/dev').mkdir(parents=True)
        shutil.copy2(ROOT / 'lab/dev/deploy.sh', self.source / 'lab/dev/deploy.sh')
        for name in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml',
                     'crates/fixture', 'native/sqlite.toml', 'scripts/prepare_sqlite.py']:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('staged fixture\n')
        self.git('init', '-q')
        self.git('add', '.')
        (self.home / '.config/rustiron-lab').mkdir(parents=True)
        ssh = self.home / '.config/rustiron-lab/ssh.sh'
        ssh.write_text('''#!/usr/bin/env python3
import os, pathlib, sys
root = pathlib.Path(os.environ['TEST_WORK'])
command = sys.argv[1]
with (root/'calls').open('a') as f: f.write(command+'\\n')
if 'mktemp' in command:
    print('/home/rustiron-build/rustiron-deploy.TEST1234')
elif 'source.tar' in command:
    (root/'source.tar').write_bytes(sys.stdin.buffer.read())
elif 'build-guest.sh' in command:
    sys.exit(int(os.environ.get('BUILD_STATUS', '0')))
elif 'install-guest.sh' in command:
    (root/'installed').touch()
elif 'prune-deploys.sh' in command:
    (root/'pruned').touch()
else:
    sys.exit(71)
''')
        ssh.chmod(0o700)

    def deploy(self, **extra):
        return subprocess.run(['sh', 'lab/dev/deploy.sh'], cwd=self.source,
                              env={**self.env, **extra}, capture_output=True, text=True, timeout=10)

    def test_build_failure_never_reaches_installation(self):
        self.prepare_deploy()
        result = self.deploy(BUILD_STATUS='23')
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertFalse((self.work / 'installed').exists())
        calls = (self.work / 'calls').read_text()
        self.assertNotIn('install-guest.sh', calls)
        self.assertNotIn('prune-deploys.sh', calls)

    def test_staged_snapshot_deploys_without_changing_index_or_worktree(self):
        self.prepare_deploy()
        (self.source / 'outside-untracked').write_text('preserve')
        before = self.git('write-tree')
        status = self.git('status', '--porcelain')
        result = self.deploy()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.work / 'installed').exists())
        # W211: retention pruning runs once, last, after a successful install.
        calls = (self.work / 'calls').read_text().splitlines()
        self.assertIn("prune-deploys.sh' 3 5", calls[-1])
        self.assertEqual(sum('prune-deploys.sh' in call for call in calls), 1)
        with tarfile.open(self.work / 'source.tar') as archive:
            self.assertEqual(archive.extractfile('crates/fixture').read(), b'staged fixture\n')
            self.assertNotIn('outside-untracked', archive.getnames())
        self.assertEqual(self.git('write-tree'), before)
        self.assertEqual(self.git('status', '--porcelain'), status)

    def test_unstaged_source_is_refused_before_ssh(self):
        self.prepare_deploy()
        (self.source / 'Cargo.toml').write_text('unstaged')
        result = self.deploy()
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.work / 'calls').exists())
        self.assertEqual((self.source / 'Cargo.toml').read_text(), 'unstaged')

    def test_untracked_source_is_refused_before_ssh(self):
        self.prepare_deploy()
        (self.source / 'crates/new-source').write_text('untracked')
        result = self.deploy()
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.work / 'calls').exists())
        self.assertTrue((self.source / 'crates/new-source').exists())

    def test_transfer_failure_never_builds_or_installs(self):
        self.prepare_deploy()
        ssh = self.home / '.config/rustiron-lab/ssh.sh'
        ssh.write_text(ssh.read_text().replace("(root/'source.tar').write_bytes(sys.stdin.buffer.read())", 'sys.exit(24)'))
        result = self.deploy()
        self.assertEqual(result.returncode, 24)
        calls = (self.work / 'calls').read_text()
        self.assertNotIn('build-guest.sh', calls)
        self.assertFalse((self.work / 'installed').exists())

    def prepare_build(self, sqlite_status=0, cargo_status=0):
        (self.source / 'scripts').mkdir()
        (self.source / 'scripts/prepare_sqlite.py').write_text(f'raise SystemExit({sqlite_status})\n')
        (self.home / '.cargo/bin').mkdir(parents=True)
        cargo = self.home / '.cargo/bin/cargo'
        cargo.write_text(f'#!/bin/sh\ntouch "$TEST_WORK/cargo-ran"\nexit {cargo_status}\n')
        cargo.chmod(0o700)

    def build(self):
        return subprocess.run(['sh', str(ROOT / 'lab/dev/build-guest.sh'), str(self.source)],
                              env=self.env, capture_output=True, text=True, timeout=10)

    def test_real_build_runner_propagates_cargo_failure(self):
        self.prepare_build(cargo_status=23)
        result = self.build()
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertTrue((self.work / 'cargo-ran').exists())

    def test_sqlite_failure_never_reaches_cargo(self):
        self.prepare_build(sqlite_status=22)
        result = self.build()
        self.assertEqual(result.returncode, 22, result.stderr)
        self.assertFalse((self.work / 'cargo-ran').exists())

    def test_missing_artifacts_cannot_report_success(self):
        self.prepare_build()
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.work / 'cargo-ran').exists())

    # W289: the operator CLI is an install input too; before, the lab ran a
    # hand-installed W251 copy that no deploy updated.
    INSTALL_INPUTS = ['rustiron-s02-executor', 'rustiron-admin-helper', 'rustiron-restore-inventory',
                      'rustiron-submit', 'rustiron-control', 'rustiron-capture-manifest', 'rustiron']

    def stage_install_inputs(self, names):
        (self.source / 'target/debug').mkdir(parents=True)
        for name in names:
            (self.source / 'target/debug' / name).write_bytes(b'benign compiled fixture')

    def test_successful_build_requires_every_install_input(self):
        self.prepare_build()
        self.stage_install_inputs(self.INSTALL_INPUTS)
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([line.split()[-1] for line in result.stdout.splitlines()],
                         [f'target/debug/{name}' for name in self.INSTALL_INPUTS])

    def test_each_missing_install_input_fails_the_build(self):
        for missing in self.INSTALL_INPUTS:
            with self.subTest(missing=missing):
                self.setUp()
                self.prepare_build()
                self.stage_install_inputs([name for name in self.INSTALL_INPUTS if name != missing])
                result = self.build()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(missing, result.stderr)


if __name__ == '__main__':
    unittest.main()
