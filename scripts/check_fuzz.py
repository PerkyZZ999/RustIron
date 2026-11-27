#!/usr/bin/env python3
"""Check the maintained parser fuzz workspace, then run bounded ASan campaigns."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
FUZZ = ROOT / 'fuzz'


class GateFailure(Exception):
    """A required command or invariant failed; its evidence remains on disk."""


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true', help='build/check and replay seeds without a timed campaign')
    parser.add_argument('--seconds', type=int, help='seconds per target (1..600; default from fuzz/config.json)')
    parser.add_argument('--output', type=Path, help='fresh evidence directory (default: unique target/fuzz-check-*)')
    args = parser.parse_args()
    config = json.loads((FUZZ / 'config.json').read_text())
    seconds = args.seconds if args.seconds is not None else config['seconds_per_target']
    if not 1 <= seconds <= 600:
        parser.error('--seconds must be between 1 and 600')
    (ROOT / 'target').mkdir(exist_ok=True)
    if args.output:
        output = args.output.resolve()
        try:
            output.mkdir(mode=0o700, parents=True, exist_ok=False)
        except FileExistsError:
            parser.error('--output must be a fresh directory; existing evidence is preserved')
    else:
        output = Path(tempfile.mkdtemp(prefix='fuzz-check-', dir=ROOT / 'target'))
    print('fuzz evidence: ' + str(output), flush=True)
    runtime = Path(tempfile.mkdtemp(prefix='fuzz-runtime-', dir=ROOT / 'target'))
    seed_directory = runtime / 'seeds'
    commands = []
    environment = {**os.environ, 'CARGO_BUILD_JOBS': str(config['build_jobs']),
                   'CARGO_NET_OFFLINE': 'true', 'RUSTFLAGS': '',
                   'RUSTC_WRAPPER': '', 'RUSTC_WORKSPACE_WRAPPER': ''}
    for name in ('RUSTC', 'CARGO', 'CARGO_ENCODED_RUSTFLAGS'):
        environment.pop(name, None)
    local_tool = ROOT / 'target/fuzz-tools/bin/cargo-fuzz'
    tool = local_tool if local_tool.is_file() else Path(shutil.which('cargo-fuzz') or '/nonexistent/cargo-fuzz')
    environment['PATH'] = str(tool.parent) + os.pathsep + os.environ.get('PATH', '')
    stable_target = ROOT / 'target/fuzz-host'
    instrumented = ROOT / 'target/fuzz-instrumented'
    root_lock = digest(ROOT / 'Cargo.lock')
    fuzz_lock = digest(FUZZ / 'Cargo.lock')

    def run(label, arguments, timeout=600, extra=None):
        started = time.monotonic()
        with (output / (label + '.txt')).open('w') as log:
            process = subprocess.Popen(list(map(str, arguments)), cwd=ROOT,
                                       env={**environment, **(extra or {})}, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                code = 124
        commands.append({'label': label, 'command': list(map(str, arguments)), 'exit_code': code,
                         'duration_seconds': round(time.monotonic() - started, 3), 'log': label + '.txt',
                         'environment': extra or {}})
        write_json(output / 'commands.json', commands)
        print(label + ': exit ' + str(code), flush=True)
        if code:
            raise GateFailure(label + ' failed; see ' + str(output / (label + '.txt')))
        return (output / (label + '.txt')).read_text()

    result = {'status': 'RUNNING', 'config': config, 'check_only': args.check_only,
              'seconds_per_target': 0 if args.check_only else seconds,
              'root_lock_sha256_before': root_lock, 'fuzz_lock_sha256_before': fuzz_lock,
              'runtime_directory': str(runtime)}
    try:
        version = run('cargo-fuzz-version', [tool, '--version'])
        if version.strip() != 'cargo-fuzz ' + config['cargo_fuzz']:
            raise GateFailure('cargo-fuzz version differs from fuzz/config.json')
        run('nightly-version', ['rustc', '+' + config['nightly'], '-vV'])
        cargo = ['cargo', '+' + config['stable']]
        manifest = ['--manifest-path', FUZZ / 'Cargo.toml']
        run('fuzz-format', [*cargo, 'fmt', *manifest, '--all', '--', '--check'])
        run('fuzz-clippy', [*cargo, 'clippy', *manifest, '--locked', '--all-targets', '--', '-D', 'warnings'],
            extra={'CARGO_TARGET_DIR': str(stable_target)})
        policy = output / 'deny.toml'
        policy.write_text((ROOT / 'deny.toml').read_text() + '''\n# Fuzz-only runtime's declared compound license; exact reviewed release.
[[licenses.exceptions]]
name = "libfuzzer-sys"
version = "=0.4.13"
allow = ["MIT", "Apache-2.0", "NCSA"]
''')
        result['deny_policy_sha256'] = digest(policy)
        run('fuzz-dependencies', ['cargo', 'deny', *manifest, '--locked', 'check', '--config', policy])
        run('seed-oracles', [*cargo, 'run', *manifest, '--locked', '--example', 'seed_corpus', '--', seed_directory],
            extra={'CARGO_TARGET_DIR': str(stable_target)})
        seeds = json.loads((seed_directory / 'seeds.json').read_text())
        result['seed_manifest'] = seeds
        targets = [entry['name'] for entry in tomllib.loads((FUZZ / 'Cargo.toml').read_text())['bin']]
        if set(targets) != {seed['target'] for seed in seeds['seeds']}:
            raise GateFailure('every declared target must have checked seed paths')
        for target in targets:
            if {seed['accepted'] for seed in seeds['seeds'] if seed['target'] == target} != {True, False}:
                raise GateFailure('every target needs positive and refusal seed paths: ' + target)
        backend = ['cargo', '+' + config['nightly'], 'fuzz']
        build = ['--build-std', '--fuzz-dir', FUZZ, '--target-dir', instrumented]
        run('fuzz-instrumented-build', [*backend, 'build', *build])
        outcomes = []
        for target in targets:
            max_input_bytes = seeds.get('target_max_input_bytes', {}).get(target, seeds['max_input_bytes'])
            if any(seed['bytes'] > max_input_bytes for seed in seeds['seeds'] if seed['target'] == target):
                raise GateFailure('target input cap would skip a checked seed: ' + target)
            artifacts = runtime / 'artifacts' / target
            artifacts.mkdir(parents=True)
            flags = [f'-seed={config["seed"]}', f'-max_len={max_input_bytes}',
                     f'-rss_limit_mb={config["rss_limit_mb"]}', f'-timeout={config["input_timeout_seconds"]}',
                     '-print_final_stats=1', '-artifact_prefix=' + str(artifacts) + '/']
            flags += ['-runs=0'] if args.check_only else [f'-max_total_time={seconds}']
            log = run('campaign-' + target, [*backend, 'run', *build, target,
                       seed_directory / target, '--', *flags], timeout=seconds + 90)
            if 'DONE' not in log or 'stat::number_of_executed_units:' not in log:
                raise GateFailure('libFuzzer completion/statistics missing for ' + target)
            if any(artifacts.iterdir()):
                raise GateFailure('crash artifacts retained for ' + target)
            outcomes.append({'target': target, 'artifacts': str(artifacts), 'crashes': 0})
        if digest(ROOT / 'Cargo.lock') != root_lock or digest(FUZZ / 'Cargo.lock') != fuzz_lock:
            raise GateFailure('a lockfile changed during locked checks/offline fuzz builds')
        result.update(status='PASS', targets=outcomes, root_lock_unchanged=True, fuzz_lock_unchanged=True,
                      retained_corpus={target: {path.name: digest(path) for path in sorted((seed_directory / target).iterdir())}
                                       for target in targets})
        # W762: a passing run keeps the corpus digests above, not its ~25 MiB runtime copy;
        # a failing run keeps the runtime folder for its crash artifacts.
        shutil.rmtree(runtime)
        result['runtime_directory_removed'] = True
    except (GateFailure, OSError) as error:
        result.update(status='FAIL', reason=str(error))
        print('FAIL: ' + str(error), flush=True)
    finally:
        write_json(output / 'result.json', result)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
