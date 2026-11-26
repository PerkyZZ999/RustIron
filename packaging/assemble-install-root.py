#!/usr/bin/env python3
"""Assemble a fresh offline Rustiron installation root."""

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


sys.dont_write_bytecode = True
SCRIPT = Path(__file__).resolve().with_name("install-preflight.py")
SPEC = importlib.util.spec_from_file_location("install_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)

DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
STATE_DIRS = {
    "etc/rustiron": 0o700,
    "etc/rustiron/credentials": 0o700,
    "etc/rustiron/credentials/sites": 0o700,
    # W392 (D-042): the host receipt key; install-product.py fills it.
    "etc/rustiron/receipt-key": 0o700,
    "var/lib/rustiron": 0o700,
    "var/lib/rustiron/executor": 0o700,
    "var/lib/rustiron/admission": 0o700,
    "var/lib/rustiron/scratch": 0o700,
    "var/lib/rustiron/manifests": 0o2700,
    "var/lib/rustiron/recipes": 0o755,
    "var/lib/rustiron/ols-package": 0o700,
    # W446 (D-053): root-only intake of site import archives.
    "var/lib/rustiron/migration-intake": 0o700,
    # W515 (D-084): root-only intake of WordPress update recipes.
    "var/lib/rustiron/update-intake": 0o700,
    "var/lib/rustiron/dns-intake": 0o700,
    "etc/rustiron-ols": 0o755,
    "etc/rustiron-ols/generations": 0o755,
    "etc/rustiron-ejected": 0o755,
    "srv/sites": 0o755,
    "srv/restore-probes": 0o755,
}


@contextmanager
def open_payload(root_fd, relative):
    parent = os.dup(root_fd)
    try:
        for component in relative.parts[:-1]:
            child = os.open(component, DIRECTORY_FLAGS, dir_fd=parent)
            os.close(parent)
            parent = child
        with preflight.manifest.regular_file(parent, relative.name) as source:
            yield source
    finally:
        os.close(parent)


def copy_stage(source, destination, modes, digests):
    root_fd = os.open(source, DIRECTORY_FLAGS)
    try:
        for name, mode in modes.items():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with open_payload(root_fd, Path(name)) as original, target.open("xb+") as staged:
                if stat.S_IMODE(os.fstat(original.fileno()).st_mode) != mode:
                    raise ValueError(f"source mode changed for {name}")
                shutil.copyfileobj(original, staged)
                staged.seek(0)
                if hashlib.file_digest(staged, "sha256").hexdigest() != digests[name]:
                    raise ValueError(f"source bytes changed for {name}")
                os.fchmod(staged.fileno(), mode)
    finally:
        os.close(root_fd)


def assemble(management, host_jobs, profile, parent):
    if not preflight.trusted_directory(Path("/"), parent.relative_to("/")):
        raise ValueError("output parent is unavailable")
    if stat.S_IMODE(parent.stat().st_mode) != 0o700:
        raise ValueError("output parent must have mode 0700")
    management_digests = preflight.check_stage(management, preflight.MANAGEMENT_FILES)
    job_digests = preflight.check_jobs(host_jobs, profile)
    output = Path(tempfile.mkdtemp(prefix="rustiron-install-root.", dir=parent))
    complete = False
    try:
        for name, mode in STATE_DIRS.items():
            directory = output / name
            directory.mkdir(parents=True)
            directory.chmod(mode)
        copy_stage(management, output, preflight.MANAGEMENT_FILES, management_digests)
        copy_stage(host_jobs, output, preflight.JOB_FILES, job_digests)
        for path in (output, *output.rglob("*")):
            info = path.lstat()
            if (info.st_uid, info.st_gid) != (0, 0):
                raise ValueError(f"unexpected ownership for {path.relative_to(output)}")
        complete = True
        return output
    finally:
        if not complete:
            shutil.rmtree(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("management_root", type=Path)
    parser.add_argument("host_job_root", type=Path)
    parser.add_argument("job_profile", type=Path)
    parser.add_argument("output_parent", type=Path)
    args = parser.parse_args()
    if (os.getuid(), os.geteuid(), os.getegid()) != (0, 0, 0):
        parser.error("root:root is required to assemble the installation root")
    parent = args.output_parent.absolute()
    if ".." in parent.parts:
        parser.error("output parent must be an absolute path without parent traversal")
    os.umask(0o022)
    try:
        output = assemble(args.management_root, args.host_job_root, args.job_profile, parent)
    except (OSError, ValueError, subprocess.SubprocessError, preflight.manifest.InvalidPackage) as error:
        print(f"Installation root assembly failed: {error}", file=sys.stderr)
        return 1
    print(f"install_root={output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
