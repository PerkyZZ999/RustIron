#!/usr/bin/env python3
"""Stage fixed job executables from installed RPMs for the same host."""

import argparse
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib


TOOLS = ("restic", "mariadb", "mariadb-dump")
PROFILE_FIELDS = {"package", "evr_arch", "sha256"}
RPM_FORMAT = r"%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\t%{FILEDIGESTALGO}\n[%{FILENAMES}\t%{FILEDIGESTS}\n]"
MANIFEST = Path(__file__).resolve().parent.parent / "scripts/release/release_manifest.py"


def load_profile(path):
    with path.open("rb") as source:
        profile = tomllib.load(source)
    if set(profile) != set(TOOLS):
        raise ValueError("profile must name exactly the three fixed job tools")
    for name, pin in profile.items():
        if (
            not isinstance(pin, dict)
            or set(pin) != PROFILE_FIELDS
            or not all(isinstance(value, str) and value for value in pin.values())
            or not re.fullmatch(r"[0-9a-f]{64}", pin["sha256"])
        ):
            raise ValueError(f"invalid profile entry for {name}")
    return profile


def verify_rpm(source, pin):
    result = subprocess.run(
        ["/usr/bin/rpm", "-qf", "--qf", RPM_FORMAT, "--", str(source)],
        env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    header, _, files = result.stdout.partition("\n")
    if header.split("\t") != [pin["package"], pin["evr_arch"], "8"]:
        raise ValueError(f"RPM identity or SHA-256 algorithm mismatch for {source.name}")
    entries = [line for line in files.splitlines() if line.startswith(f"{source}\t")]
    if entries != [f"{source}\t{pin['sha256']}"]:
        raise ValueError(f"RPM file digest mismatch for {source.name}")


@contextmanager
def open_installed_tool(name, pin):
    source = Path("/usr/bin") / name
    verify_rpm(source, pin)
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as original:
        info = os.fstat(original.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_uid, info.st_gid, info.st_nlink) != (0, 0, 1)
            or stat.S_IMODE(info.st_mode) != 0o755
        ):
            raise ValueError(f"unexpected ownership, links, or mode for {name}")
        yield original


def copy_tool(name, pin, directory):
    destination = directory / name
    with open_installed_tool(name, pin) as original:
        with destination.open("xb+") as staged:
            shutil.copyfileobj(original, staged)
            staged.seek(0)
            if hashlib.file_digest(staged, "sha256").hexdigest() != pin["sha256"]:
                raise ValueError(f"installed bytes differ from the pin for {name}")
            os.fchmod(staged.fileno(), 0o755)


def stage_tools(profile, parent):
    stage = Path(tempfile.mkdtemp(prefix="rustiron-host-jobs.", dir=parent.resolve(strict=True)))
    complete = False
    try:
        directory = stage / "usr/libexec/rustiron/jobs"
        directory.mkdir(parents=True)
        for name in TOOLS:
            copy_tool(name, profile[name], directory)
        for command in ("manifest", "check"):
            subprocess.run([sys.executable, MANIFEST, command, stage], check=True)
        complete = True
        return stage
    finally:
        if not complete:
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("output_parent", type=Path)
    args = parser.parse_args()
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        parser.error("stage job tools as an unprivileged user")
    try:
        stage = stage_tools(load_profile(args.profile), args.output_parent)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Job staging failed: {error}", file=sys.stderr)
        return 1
    print(f"host_job_root={stage}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
