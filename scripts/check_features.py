#!/usr/bin/env python3
"""Run cargo-hack's no-dev-dependency graph in isolation, retaining locked versions."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parent.parent


def locked_packages(path: Path) -> set[tuple]:
    data = tomllib.loads(path.read_text())
    return {
        (package["name"], package["version"], package.get("source"), package.get("checksum"))
        for package in data["package"]
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deep", action="store_true")
    args = parser.parse_args()
    baseline = locked_packages(ROOT / "Cargo.lock")
    with tempfile.TemporaryDirectory(prefix="rustiron-features-") as directory:
        isolated = Path(directory)
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
            shutil.copy2(ROOT / name, isolated / name)
        shutil.copytree(ROOT / "crates", isolated / "crates", symlinks=True)
        if (ROOT / ".cargo").exists():
            shutil.copytree(ROOT / ".cargo", isolated / ".cargo", symlinks=True)
        (isolated / "target").mkdir(exist_ok=True)
        (isolated / "target/native").symlink_to(ROOT / "target/native", target_is_directory=True)
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = str(ROOT / "target/features")
        # Only the disposable manifests/lock change when deriving the no-dev graph.
        subprocess.run(
            ["cargo", "hack", "metadata", "--workspace", "--remove-dev-deps",
             "--offline", "--format-version", "1"],
            cwd=isolated, env=environment, stdout=subprocess.DEVNULL, check=True,
        )
        if not locked_packages(isolated / "Cargo.lock") <= baseline:
            raise RuntimeError("feature graph selected a package/version/source/checksum outside Cargo.lock")
        flags = ["--feature-powerset", "--depth", "2"] if args.deep else ["--each-feature"]
        subprocess.run(
            ["cargo", "hack", "check", "--locked", "--offline", "--workspace",
             "--no-dev-deps", *flags],
            cwd=isolated, env=environment, check=True,
        )


if __name__ == "__main__":
    main()
