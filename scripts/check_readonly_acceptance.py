#!/usr/bin/env python3
"""S01 acceptance in a read-only host view with private process/network/runtime state."""
from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def namespaces() -> dict[str, str]:
    return {name: os.readlink(f"/proc/self/ns/{name}") for name in ("user", "mnt", "pid", "net", "ipc", "uts")}


def guard_probe(path: Path) -> dict:
    denied = False
    try:
        path.write_text("guard-probe-write")
    except OSError as error:
        assert error.errno == errno.EROFS, "probe needs the actual read-only mount denial"
        denied = True
    assert denied, "read-only guard missing; only the owned sentinel was touched"
    assert not Path("/run/dbus/system_bus_socket").exists()
    assert not Path("/run/docker.sock").exists()
    effective = next(line.split()[1] for line in Path("/proc/self/status").read_text().splitlines() if line.startswith("CapEff:"))
    assert int(effective, 16) == 0
    return {"protected_write_denied": True, "host_runtime_hidden": True, "effective_capabilities": effective, "uid": os.geteuid(), "namespaces": namespaces()}


def inaccessible_doctor() -> dict:
    with tempfile.TemporaryDirectory(prefix="ri-denied-", dir="/tmp") as directory:
        path = Path(directory) / "control.sock"
        process = subprocess.Popen([str(ROOT / "target/debug/rustiron-control"), "--socket", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not path.exists():
                assert process.poll() is None and time.monotonic() < deadline
                time.sleep(0.01)
            result = subprocess.run([str(ROOT / "target/debug/rustiron"), "--socket", str(path), "doctor", "--output", "json"], capture_output=True, timeout=8, check=True)
            assert result.stderr == b""
            data = json.loads(result.stdout)["data"]["value"]
            assert data["os_name"] == {"state": "unknown", "reason": "permission_denied"}
            assert data["os_version"] == {"state": "unknown", "reason": "permission_denied"}
            assert data["kernel_release"]["state"] == "observed"
            return data
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                _, stderr = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                _, stderr = process.communicate(timeout=3)
            assert stderr == b""


def sandbox(*command: str, release: Path | None = None) -> list[str]:
    args = ["bwrap", "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session",
            "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run", "--tmpfs", "/home", "--cap-drop", "ALL",
            "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "PYTHONDONTWRITEBYTECODE", "1", "--chdir", str(ROOT)]
    if release is not None:
        args += ["--ro-bind", str(release), "/etc/os-release"]
    return [*args, "--", *command]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--inaccessible", action="store_true")
    args = parser.parse_args()
    if args.probe:
        print(json.dumps(guard_probe(args.probe)))
        return
    if args.inaccessible:
        print(json.dumps(inaccessible_doctor()))
        return
    assert os.getuid() == os.geteuid() != 0
    subprocess.run(["cargo", "build", "--locked", "--workspace", "--bins"], cwd=ROOT, stdout=sys.stderr, stderr=sys.stderr, check=True)
    outer = namespaces()
    with tempfile.TemporaryDirectory(prefix="readonly-audit-", dir=ROOT / "target") as directory:
        sentinel = Path(directory) / "sentinel"
        sentinel.write_text("unchanged-host-sentinel")
        command = [sys.executable, str(Path(__file__).resolve()), "--probe", str(sentinel)]
        protected = subprocess.run(sandbox(*command), capture_output=True, timeout=15, check=True)
        probe = json.loads(protected.stdout)
        assert sentinel.read_text() == "unchanged-host-sentinel"
        assert all(probe["namespaces"][name] != outer[name] for name in outer)
        # Removing isolation must fail this guard; its only write is our disposable sentinel.
        unprotected = subprocess.run(command, capture_output=True, timeout=10, check=False)
        assert unprotected.returncode != 0 and sentinel.read_text() == "guard-probe-write"
        smoke = subprocess.run(sandbox(sys.executable, str(ROOT / "scripts/check_local_cli.py"), "--no-build"), capture_output=True, timeout=30, check=True)
        release = Path(directory) / "unreadable-os-release"
        release.write_text('NAME="UNREADABLE_FIXTURE"\nVERSION_ID="fixture"\n')
        release.chmod(0)
        try:
            denied = subprocess.run(sandbox(sys.executable, str(Path(__file__).resolve()), "--inaccessible", release=release), capture_output=True, timeout=15, check=True)
        finally:
            release.chmod(0o600)
    print(json.dumps({"task": "S01/W005", "status": "passed", "guard_probe": probe, "guard_mutation_detected": unprotected.returncode,
                      "smoke": json.loads(smoke.stdout), "inaccessible_doctor": json.loads(denied.stdout),
                      "limits": "constrained local acceptance, not tenant confinement, arbitrary-host audit or distinct-UID proof"}, indent=2))


if __name__ == "__main__":
    main()
