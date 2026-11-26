#!/usr/bin/env python3
"""Build pinned native SQLite twice without using the normal native build cache."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("prepare_sqlite", ROOT / "scripts/prepare_sqlite.py")
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


def compare(output):
    left = BUILD.check_cache(output / "a")
    right = BUILD.check_cache(output / "b")
    differences = [
        name for name in BUILD.ARTIFACTS
        if left["artifacts"][name] != right["artifacts"][name]
    ]
    return {
        "status": "different" if differences else "reproducible",
        "differences": differences,
        "artifacts_a": left["artifacts"],
        "artifacts_b": right["artifacts"],
    }


def build(output):
    output.mkdir(mode=0o700)
    epoch = subprocess.check_output(
        ["git", "log", "-1", "--format=%ct"], cwd=ROOT, text=True,
    ).strip()
    os.environ["SOURCE_DATE_EPOCH"] = epoch
    receipts = {}
    for side in ("a", "b"):
        receipts[side] = BUILD.prepare(False, output / side)
    result = compare(output)
    result["source_date_epoch"] = int(epoch)
    result["build_receipts"] = receipts
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "check"))
    parser.add_argument("output", type=Path, help="new private output directory for build; completed directory for check")
    arguments = parser.parse_args()
    try:
        result = build(arguments.output) if arguments.command == "build" else compare(arguments.output)
    except FileExistsError:
        print("ERROR: output exists; choose a fresh output directory", file=sys.stderr)
        return 2
    except FileNotFoundError:
        print("ERROR: native input or output is missing; prepare the pinned archive or select completed builds", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError):
        print("ERROR: native build or cache validation failed; inspect build output and pinned input", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 1 if result["differences"] else 0


if __name__ == "__main__":
    sys.exit(main())
