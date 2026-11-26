#!/usr/bin/env python3
"""Exercise real local binaries in a disposable private socket directory, without sudo."""

from __future__ import annotations

import hashlib
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
REQUEST_LIMIT = 262_144
RESPONSE_LIMIT = 1_048_576


def snapshots() -> dict:
    result = {}
    for name in ("/etc/os-release", "/etc/passwd", "/etc/group", "/etc/fstab"):
        try:
            path = Path(name)
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            result[name] = "unavailable"
    return result


def receive_exact(stream: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise RuntimeError("truncated smoke response")
        result.extend(part)
    return bytes(result)


def raw_request(path: Path, data: bytes) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(7)
        stream.connect(str(path))
        stream.sendall(data)
        stream.shutdown(socket.SHUT_WR)
        length = struct.unpack("!I", receive_exact(stream, 4))[0]
        assert 0 < length <= RESPONSE_LIMIT
        result = json.loads(receive_exact(stream, length))
        assert stream.recv(1) == b""
        return result


def cli(path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(ROOT / "target/debug/rustiron"), "--socket", str(path), *args],
        capture_output=True, timeout=8, check=False,
    )


def control(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(ROOT / "target/debug/rustiron-control"), *args],
        capture_output=True, timeout=8, check=False,
    )


@contextmanager
def inventory_daemon(path: Path, state: Path):
    process = subprocess.Popen(
        [str(ROOT / "target/debug/rustiron-control"), "--socket", str(path), "--state-dir", str(state)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 5
        while not path.exists():
            assert process.poll() is None, "inventory coordinator startup failed"
            assert time.monotonic() < deadline, "inventory startup deadline"
            time.sleep(0.01)
        yield
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            _, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            _, stderr = process.communicate(timeout=3)
        assert stderr == b"", "inventory coordinator emitted unexpected diagnostics"
        if path.exists():
            path.unlink()


def inventory_cases(directory: Path, cases: list[str]) -> None:
    state = directory / "state"
    state.mkdir(mode=0o700)
    assert control("--state-dir", str(state), "--init-state").returncode == 0
    path = directory / "inventory.sock"
    report = {
        "schema_version": 1, "report": {"reported_at": 42, "source": "operator_report"},
        "complete": True, "sites": [
            {"site_id": "site-a", "name": "Fixture A", "configuration_generation": "gen-a"},
            {"site_id": "site-b", "name": "Fixture B", "configuration_generation": None},
        ],
    }
    source = directory / "observations.json"
    source.write_text(json.dumps(report))
    with inventory_daemon(path, state):
        assert cli(path, "site", "list", "--output", "json").returncode == 7
        assert control("--state-dir", str(state), "--import-observations", str(source)).returncode == 7
        second = directory / "second.sock"
        assert control("--state-dir", str(state), "--socket", str(second)).returncode == 7
        assert not second.exists()
    cases.append("unobserved_store_unavailable_and_live_second_writer_refused")
    assert control("--state-dir", str(state), "--import-observations", str(source)).returncode == 0
    exported = control("--state-dir", str(state), "--export-observations")
    assert exported.returncode == 0 and json.loads(exported.stdout) == report
    cases.append("offline_observation_import_and_consistent_export")
    with inventory_daemon(path, state):
        first = cli(path, "site", "list", "--limit", "1", "--output", "json")
        assert first.returncode == 0
        page = json.loads(first.stdout)["data"]["value"]
        assert page["items"][0]["site_id"] == "site-a"
        assert page["items"][0]["ownership"] == "observed_only"
        assert page["items"][0]["inventory"] == report["report"]
        cursor = page["next_cursor"]
        inspected = cli(path, "site", "inspect", "site-a", "--output", "json")
        assert inspected.returncode == 0
        generation = json.loads(inspected.stdout)["data"]["value"]["configuration_generation"]
        assert generation["state"] == "stale" and generation["value"] == "gen-a"
        assert generation["observed_at"] == 42
        human = cli(path, "site", "inspect", "site-a", "--output", "human")
        assert human.returncode == 0 and b"operator_report; unix_seconds=42" in human.stdout
        changed = cli(path, "site", "list", "--cursor", cursor, "--limit", "2", "--output", "json")
        assert changed.returncode == 4 and json.loads(changed.stdout)["error"]["code"] == "CURSOR_EXPIRED"
    cases.append("cli_reports_provenance_and_staleness_without_adoption")
    with inventory_daemon(path, state):
        continued = cli(path, "site", "list", "--cursor", cursor, "--limit", "1", "--output", "json")
        assert continued.returncode == 0
        page = json.loads(continued.stdout)["data"]["value"]
        assert page["items"][0]["site_id"] == "site-b" and page["next_cursor"] is None
    cases.append("cursor_continues_after_real_daemon_restart")
    assert control("--state-dir", str(state), "--import-observations", str(source)).returncode == 0
    with inventory_daemon(path, state):
        expired = cli(path, "site", "list", "--cursor", cursor, "--limit", "1", "--output", "json")
        assert expired.returncode == 4 and json.loads(expired.stdout)["error"]["code"] == "CURSOR_EXPIRED"
    cases.append("replacement_expires_cursor_without_silent_restart")
    report["sites"][0]["ownership"] = "created"
    source.write_text(json.dumps(report))
    invalid = control("--state-dir", str(state), "--import-observations", str(source))
    assert invalid.returncode == 2
    assert json.loads(control("--state-dir", str(state), "--export-observations").stdout) == json.loads(exported.stdout)
    cases.append("invalid_ownership_claim_preserves_last_report")
    database = state / "control.sqlite"
    database.write_bytes(b"CANARY_NOT_A_SECRET_CORRUPT")
    failed = control("--state-dir", str(state), "--socket", str(path))
    assert failed.returncode == 7 and not path.exists()
    assert b"CANARY_NOT_A_SECRET" not in failed.stdout + failed.stderr
    assert database.read_bytes() == b"CANARY_NOT_A_SECRET_CORRUPT"
    cases.append("corrupt_store_refused_without_repair_or_canary_echo")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-build", action="store_true", help="Use prebuilt locked-workspace binaries in an isolated acceptance run")
    args = parser.parse_args()
    assert os.getuid() == os.geteuid() != 0, "run as the ordinary development user"
    if not args.no_build:
        subprocess.run(
            ["cargo", "build", "--locked", "--workspace", "--bins"],
            cwd=ROOT, check=True, stdout=sys.stderr, stderr=sys.stderr,
        )
    before = snapshots()
    cases = []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="ri-smoke-", dir="/tmp") as directory:
        path = Path(directory) / "control.sock"
        process = subprocess.Popen(
            [str(ROOT / "target/debug/rustiron-control"), "--socket", str(path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            ready_deadline = time.monotonic() + 5
            while not path.exists():
                assert process.poll() is None, "coordinator exited during startup"
                assert time.monotonic() < ready_deadline, "coordinator startup deadline"
                time.sleep(0.01)
            assert path.stat().st_mode & 0o7777 == 0o600
            result = cli(path, "doctor", "--output", "json")
            assert result.returncode == 0 and result.stderr == b""
            report = json.loads(result.stdout)["data"]["value"]
            assert report["kernel_release"]["state"] == "observed"
            for field in ("hosting_profile", "site_confinement"):
                assert report[field] == {"state": "unknown", "reason": "not_checked"}
            human = cli(path, "doctor", "--output", "human")
            assert human.returncode == 0 and human.stderr == b""
            assert b"Site confinement: unknown (NotChecked)" in human.stdout
            cases.append("real_daemon_and_cli_json_human_doctor")
            unavailable = cli(path, "site", "list", "--output", "json")
            assert unavailable.returncode == 7
            assert json.loads(unavailable.stdout)["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
            cases.append("inventory_unavailable_without_false_empty_success")
            request = (ROOT / "crates/contracts/tests/fixtures/doctor-request.json").read_bytes().strip()
            malformed = request.replace(b'"params":{}', b'"params":{},"params":{}')
            for data, expected in [
                (struct.pack("!I", REQUEST_LIMIT + 1), "REQUEST_TOO_LARGE"),
                (b"\0\0", "INVALID_REQUEST"),
                (struct.pack("!I", len(malformed)) + malformed, "INVALID_REQUEST"),
                (struct.pack("!I", len(request)) + request + b"x", "INVALID_REQUEST"),
            ]:
                assert raw_request(path, data)["error"]["code"] == expected
            cases.append("daemon_rejects_oversize_truncated_duplicate_trailing_requests")
            stalled = []
            try:
                for _ in range(8):
                    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    stream.settimeout(2)
                    stream.connect(str(path))
                    stream.sendall(b"\0")
                    stalled.append(stream)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as excess:
                    excess.settimeout(2)
                    excess.connect(str(path))
                    assert excess.recv(1) == b""
                cases.append("ninth_connection_closed_at_eight_active_handlers")
            finally:
                for stream in stalled:
                    stream.close()
            recovered = False
            for _ in range(5):
                if cli(path, "doctor", "--output", "json").returncode == 0:
                    recovered = True
                    break
                time.sleep(0.02)
            assert recovered, "worker permits must recover after disconnects"
            cases.append("daemon_recovers_after_stalled_clients_disconnect")
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                _, stderr = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                _, stderr = process.communicate(timeout=3)
            assert stderr == b"", "coordinator emitted unexpected diagnostics"
        inode = path.stat().st_ino
        repeat = subprocess.run(
            [str(ROOT / "target/debug/rustiron-control"), "--socket", str(path)],
            capture_output=True, timeout=3, check=False,
        )
        assert repeat.returncode == 7 and path.stat().st_ino == inode
        cases.append("stale_socket_refused_without_unlink_or_replacement")
        inventory_cases(Path(directory), cases)
    after = snapshots()
    assert before == after, "sampled host configuration changed during read-only smoke"
    print(json.dumps({
        "task": "S01 local inspection and inventory", "status": "passed", "uid": os.geteuid(),
        "duration_seconds": round(time.monotonic() - started, 3), "cases": cases,
        "doctor_json": report, "doctor_human": human.stdout.decode(),
        "sampled_config_sha256": before,
        "distinct_uid_scenario": "not_run; ordinary-user environment, no identity changes",
        "limits": "same-UID development socket; sampled files only, not full host/VM/security acceptance",
    }, indent=2))


if __name__ == "__main__":
    main()
