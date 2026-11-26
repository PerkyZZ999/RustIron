#!/usr/bin/env python3
"""Build/check canonical release file manifests without following links.

Only root SHA256SUMS and SHA256SUMS.sig are metadata. All other regular
files, including nested metadata names, are hashed. Use a private staging
directory with no concurrent writers through manifest, sign and verify.
"""

from contextlib import contextmanager
import hashlib
import os
import stat
import sys
import tempfile


METADATA = {"SHA256SUMS", "SHA256SUMS.sig"}


class InvalidPackage(Exception):
    """The package is not a supported release file tree."""


def require_regular(info):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise InvalidPackage("expected single-link regular files")


@contextmanager
def regular_file(directory, name):
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=directory,
    )
    with os.fdopen(descriptor, "rb") as source:
        require_regular(os.fstat(source.fileno()))
        yield source


def manifest_entries(directory, prefix=""):
    entries = []
    for name in os.listdir(directory):
        if "\\" in name or any(ord(char) < 32 or ord(char) == 127 for char in name):
            raise InvalidPackage("unsupported file name")
        path = prefix + name
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory,
            )
            try:
                entries.extend(manifest_entries(child, path + "/"))
            finally:
                os.close(child)
        else:
            require_regular(info)
            if not prefix and name in METADATA:
                continue
            with regular_file(directory, name) as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            entries.append((path.encode("utf-8"), digest))
    return entries


def canonical_manifest(directory):
    entries = sorted(manifest_entries(directory))
    if not entries:
        raise InvalidPackage("empty release")
    return b"".join(digest.encode("ascii") + b"  " + path + b"\n" for path, digest in entries)


def write_manifest(directory_path, directory, content):
    # Replace the directory entry, never truncate a caller-planted link.
    descriptor, temporary = tempfile.mkstemp(prefix=".rustiron-manifest-", dir=directory_path)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(content)
        os.replace(temporary, "SHA256SUMS", dst_dir_fd=directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(arguments):
    if len(arguments) != 3 or arguments[1] not in {"manifest", "check"}:
        print("usage: release_manifest.py manifest|check DIR", file=sys.stderr)
        return 2
    try:
        directory = os.open(
            arguments[2], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            expected = canonical_manifest(directory)
            if arguments[1] == "manifest":
                write_manifest(arguments[2], directory, expected)
            else:
                with regular_file(directory, "SHA256SUMS") as source:
                    actual = source.read(len(expected) + 1)
                if actual != expected:
                    raise InvalidPackage("file manifest differs")
        finally:
            os.close(directory)
    except (OSError, UnicodeError, RecursionError, InvalidPackage):
        # File names and operating-system errors can contain untrusted text.
        print("REJECTED: invalid release file tree or manifest")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
