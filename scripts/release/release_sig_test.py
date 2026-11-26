#!/usr/bin/env python3
"""Exercise release signatures on independent copies of an optional artifact tree."""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

import release_manifest


HERE = Path(__file__).resolve().parent
SIGNER = HERE / "release_sig.sh"
IDENTITY = "release-test@synthetic"
COMMAND_TIMEOUT_SECONDS = 30


class TestFailure(Exception):
    """A fixed test step failed; diagnostics never echo input names or contents."""


def invoke(arguments):
    return subprocess.run(list(map(str, arguments)), capture_output=True, text=True,
                          timeout=COMMAND_TIMEOUT_SECONDS)


def checked(label, arguments):
    result = invoke(arguments)
    if result.returncode != 0:
        raise TestFailure(label + " failed; check artifact types and OpenSSH setup")


def source_payloads(source):
    if not stat.S_ISDIR(source.lstat().st_mode):
        raise TestFailure("ARTIFACTS must be a real directory without symlinks")
    payloads = {}

    def traversal_error(error):
        raise error

    for directory, children, files in os.walk(source, onerror=traversal_error):
        for name in children:
            if not stat.S_ISDIR((Path(directory) / name).lstat().st_mode):
                raise TestFailure("ARTIFACTS cannot contain linked or special directories")
        for name in files:
            path = Path(directory) / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise TestFailure("ARTIFACTS cannot contain links or special files")
            relative = path.relative_to(source).as_posix()
            if relative in release_manifest.METADATA:
                continue
            # Raw regular source hardlinks are copied into independent staged files.
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise TestFailure("ARTIFACTS must contain regular files")
                payloads[relative] = hashlib.file_digest(stream, "sha256").hexdigest()
    return payloads


def staged_payloads(directory):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return {name.decode("utf-8"): checksum
                for name, checksum in release_manifest.manifest_entries(descriptor)}
    finally:
        os.close(descriptor)


def writable_directories(directory):
    directory.chmod(directory.stat().st_mode | 0o700)
    for path in directory.rglob("*"):
        if path.is_dir():
            path.chmod(path.stat().st_mode | 0o700)


def prepare_template(source, template):
    if source is None:
        template.mkdir()
        (template / "rustiron").write_bytes(b"bin\n")
        (template / "sbom.json").write_bytes(b"{}\n")
        expected = None
    else:
        expected = source_payloads(source)
        shutil.copytree(source, template, symlinks=True)
    actual = staged_payloads(template)
    if not actual or (expected is not None and actual != expected):
        raise TestFailure("artifact copy is empty or differs from the complete source payload")
    writable_directories(template)
    checked("manifest preparation", [SIGNER, "manifest", template])
    # Validate copied metadata before replacing it with fresh synthetic metadata.
    (template / "SHA256SUMS.sig").unlink(missing_ok=True)
    return sorted(actual)


def generate_keys(directory):
    directory.mkdir(mode=0o700)
    key, other = directory / "key", directory / "other"
    for path in (key, other):
        checked("synthetic key generation", ["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                                              "-C", "synthetic-release-test", "-f", path])
    allowed = directory / "allowed"
    fields = key.with_suffix(".pub").read_text().split()
    allowed.write_text(IDENTITY + " " + " ".join(fields[:2]) + "\n")
    return key, other, allowed


def fresh(template, directory, key):
    shutil.copytree(template, directory)
    checked("synthetic signing", [SIGNER, "sign", directory, key])
    return directory


def expect(label, expected, directory, allowed):
    result = invoke([SIGNER, "verify", directory, allowed, IDENTITY])
    if result.returncode != expected:
        print(f"BAD {label}: expected {expected}, got {result.returncode}")
        return False
    print(f"ok  {label}: " + ("VERIFIED" if expected == 0 else "REJECTED"))
    return True


def exercise(source):
    with tempfile.TemporaryDirectory(prefix="rustiron-release-smoke-") as temporary:
        work = Path(temporary)
        template = work / "template"
        payloads = prepare_template(source, template)
        print(f"artifacts: {len(payloads)}")
        key, other, allowed = generate_keys(work / "keys")
        outcomes = []

        directory = fresh(template, work / "intact", key)
        outcomes.append(expect("untouched release verifies", 0, directory, allowed))

        directory = fresh(template, work / "altered", key)
        artifact = directory / payloads[0]
        artifact.chmod(artifact.stat().st_mode | stat.S_IWUSR)
        with artifact.open("ab") as stream:
            stream.write(b"X")
        outcomes.append(expect("artifact altered", 1, directory, allowed))

        directory = fresh(template, work / "manifest", key)
        path = directory / "SHA256SUMS"
        content = path.read_bytes()
        path.write_bytes((b"1" if content[:1] == b"0" else b"0") + content[1:])
        outcomes.append(expect("manifest altered", 1, directory, allowed))

        directory = fresh(template, work / "extra", key)
        descriptor, _path = tempfile.mkstemp(prefix="extra-", dir=directory)
        os.close(descriptor)
        outcomes.append(expect("unlisted file added", 1, directory, allowed))

        directory = fresh(template, work / "missing", key)
        (directory / payloads[0]).unlink()
        outcomes.append(expect("listed file removed", 1, directory, allowed))

        directory = fresh(template, work / "foreign", other)
        outcomes.append(expect("signed by an unenrolled key", 1, directory, allowed))

        directory = work / "plan"
        shutil.copytree(template, directory)
        checked("plan-namespace signing", ["ssh-keygen", "-q", "-Y", "sign", "-n", "rustiron-plan-v1",
                                             "-f", key, directory / "SHA256SUMS"])
        outcomes.append(expect("plan namespace signature", 1, directory, allowed))
    return all(outcomes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="?", help="private artifact tree without concurrent writers")
    arguments = parser.parse_args()
    try:
        passed = exercise(Path(arguments.artifacts).absolute() if arguments.artifacts else None)
    except TestFailure as error:
        print("ERROR: " + str(error))
        return 1
    except (OSError, ValueError, release_manifest.InvalidPackage, subprocess.TimeoutExpired):
        print("ERROR: artifact preparation or signature command failed; check input types and OpenSSH setup")
        return 1
    print("release_sig_test: " + ("PASS" if passed else "FAIL"))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
