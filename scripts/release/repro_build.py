#!/usr/bin/env python3
"""Compare complete pinned Rust builds using independently compiled native SQLite."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sqlite_repro", ROOT / "scripts/release/sqlite_repro.py")
SQLITE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SQLITE)


SOURCE_FILES = (
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml",
    "native/sqlite.toml", "scripts/prepare_sqlite.py",
    "scripts/release/sqlite_repro.py", "scripts/release/repro_build.py",
    "scripts/release/repro_build.sh",
)


def source_inputs(root):
    paths = [root / name for name in SOURCE_FILES]
    legacy_config = root / ".cargo/config"
    if legacy_config.exists() or legacy_config.is_symlink():
        paths.append(legacy_config)
    crates = root / "crates"
    if not stat.S_ISDIR(crates.lstat().st_mode):
        raise ValueError("crate input tree must be a directory without symlinks")

    def traversal_error(error):
        raise error

    for directory, children, files in os.walk(crates, onerror=traversal_error):
        for name in children:
            if not stat.S_ISDIR((Path(directory) / name).lstat().st_mode):
                raise ValueError("linked or special source directory")
        paths.extend(Path(directory) / name for name in files)
    hashes = {}
    for path in sorted(paths):
        relative = path.relative_to(root)
        for parent in relative.parents:
            if not stat.S_ISDIR((root / parent).lstat().st_mode):
                raise ValueError("linked or special source ancestry")
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("source input must be a regular file without symlinks")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError("source input must be a regular file")
            hashes[relative.as_posix()] = hashlib.file_digest(source, "sha256").hexdigest()
    return {"profile": "rustiron-worktree-v1", "sha256": hashes}


def tool_identity(requested, version_arguments):
    requested = Path(requested).absolute()
    path = requested.resolve(strict=True)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        raise ValueError("build tool must be a regular executable")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("build tool must be a regular executable")
        checksum = hashlib.file_digest(source, "sha256").hexdigest()
    version = subprocess.check_output(
        [str(requested), *version_arguments], text=True, timeout=10,
        env={**os.environ, "LC_ALL": "C"},
    ).strip()
    if not version:
        raise ValueError("build tool returned no version")
    return {"requested_path": str(requested), "path": str(path), "sha256": checksum, "version": version}


def tool_inputs(toolchain):
    tools = {}
    for name, arguments in (("cargo", ["--version"]), ("rustc", ["-vV"])):
        path = subprocess.check_output(
            ["rustup", "which", "--toolchain", toolchain, name], text=True, timeout=10,
        ).strip()
        tools[name] = tool_identity(path, arguments)
    tools["cc"] = tool_identity("/usr/bin/cc", ["--version"])
    tools["ar"] = tool_identity("/usr/bin/ar", ["--version"])
    return {"profile": "rustiron-build-tools-v1", "tools": tools}


def build_inputs(toolchain, host=None):
    sources = source_inputs(ROOT)
    tools = tool_inputs(toolchain)
    if host is None:
        version = tools["tools"]["rustc"]["version"]
        host = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
    return {
        "cargo_lock_sha256": sources["sha256"]["Cargo.lock"],
        "toolchain": toolchain, "host": host, "source_inputs": sources, "build_tools": tools,
    }


def require_unchanged_inputs(expected):
    if build_inputs(expected["toolchain"], expected["host"]) != expected:
        raise ValueError("local project inputs changed during verification or build")


def validate_source_layout(metadata):
    for package in metadata["packages"]:
        if package.get("source") is None:
            manifest = Path(package["manifest_path"]).resolve(strict=True)
            if not manifest.is_relative_to(ROOT / "crates"):
                raise ValueError("local packages outside the fingerprinted crate tree are unsupported")


def expected_binaries(metadata):
    members = set(metadata["workspace_members"])
    names = []
    for package in metadata["packages"]:
        if package["id"] not in members:
            continue
        for target in package["targets"]:
            if "bin" not in target["kind"]:
                continue
            name = target["name"]
            if (target.get("required-features") or not name or name in {".", ".."}
                    or Path(name).name != name or "\\" in name
                    or any(ord(char) < 32 or ord(char) == 127 for char in name)):
                raise ValueError("unsupported binary target")
            names.append(name)
    if not names or len(names) != len(set(names)):
        raise ValueError("empty or ambiguous binary inventory")
    return sorted(names)


def binary_hashes(directory, expected):
    executable = set()
    for path in directory.iterdir():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("symlink in binary output")
        if stat.S_ISREG(info.st_mode) and info.st_mode & 0o111:
            executable.add(path.name)
    if executable != set(expected):
        raise ValueError("binary inventory differs from workspace metadata")
    hashes = {}
    for name in expected:
        with (directory / name).open("rb") as source:
            hashes[name] = hashlib.file_digest(source, "sha256").hexdigest()
    return hashes


def compare_binaries(left, right, expected):
    hashes_a = binary_hashes(left, expected)
    hashes_b = binary_hashes(right, expected)
    differences = [name for name in expected if hashes_a[name] != hashes_b[name]]
    return {
        "status": "different" if differences else "reproducible",
        "differences": differences,
        "binaries_a": hashes_a,
        "binaries_b": hashes_b,
    }


def verify_sqlite_linkage(log, binding_id, native):
    records = []
    with log.open() as source:
        for line in source:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("invalid Cargo event")
            if event.get("reason") == "build-script-executed" and event.get("package_id") == binding_id:
                records.append(event)
    if len(records) != 1:
        raise ValueError("expected one SQLite build-script record")
    record = records[0]
    linked = record.get("linked_libs")
    paths = record.get("linked_paths")
    if (not isinstance(linked, list) or not all(isinstance(entry, str) for entry in linked)
            or not isinstance(paths, list) or not all(isinstance(entry, str) for entry in paths)):
        raise ValueError("invalid SQLite build-script record")
    libraries = [entry for entry in linked if entry in {"static=sqlite3", "sqlite3", "dylib=sqlite3"}]
    expected = (native / "lib").resolve()
    if (libraries != ["static=sqlite3"] or len(paths) != 1
            or not paths[0].startswith("native=")
            or Path(paths[0].removeprefix("native=")).resolve() != expected):
        raise ValueError("SQLite linkage differs from the private native output")
    return str(expected)


def binding_package(metadata):
    bindings = [package["id"] for package in metadata["packages"] if package["name"] == "libsqlite3-sys"]
    if len(bindings) != 1:
        raise ValueError("expected one SQLite binding")
    return bindings[0]


def verify_build_inputs(output, toolchain, host):
    recorded = json.loads((output / "result.json").read_text())
    expected = build_inputs(toolchain, host)
    if not isinstance(recorded, dict) or any(recorded.get(name) != value for name, value in expected.items()):
        raise ValueError("recorded build inputs differ from current pins")
    return expected


def check(output, metadata, host):
    expected = expected_binaries(metadata)
    binding = binding_package(metadata)
    native = SQLITE.compare(output / "native")
    links = {
        side: verify_sqlite_linkage(output / f"cargo-{side}.jsonl", binding, output / "native" / side)
        for side in ("a", "b")
    }
    result = compare_binaries(
        output / "target-a" / host / "release",
        output / "target-b" / host / "release", expected,
    )
    result["native"] = native
    result["sqlite_link_paths"] = links
    result["expected_binaries"] = expected
    result["differences"].extend("native/" + name for name in native["differences"])
    result["status"] = "different" if result["differences"] else "reproducible"
    return result


def tool_environment(toolchain, tools=None):
    environment = os.environ.copy()
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "CARGO_BUILD_RUSTC",
                 "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET"):
        environment.pop(name, None)
    tools = tool_inputs(toolchain) if tools is None else tools
    environment.update({
        "RUSTC": tools["tools"]["rustc"]["path"], "CARGO": tools["tools"]["cargo"]["path"],
        "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": "", "RUSTUP_TOOLCHAIN": toolchain,
    })
    return environment


def compile_side(output, side, toolchain, host, epoch, tools):
    target = output / f"target-{side}"
    native = output / "native" / side
    environment = tool_environment(toolchain, tools)
    registry = Path(environment.get("CARGO_HOME", str(Path.home() / ".cargo"))).resolve()
    flags = [
        f"--remap-path-prefix={ROOT}=/rustiron",
        f"--remap-path-prefix={registry}=/cargo",
        f"--remap-path-prefix={target}=/target",
        f"--remap-path-prefix={native}=/sqlite",
    ]
    environment.update({
        "SOURCE_DATE_EPOCH": str(epoch), "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": str(target), "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags),
    })
    command = [
        tools["tools"]["cargo"]["path"],
        "--config", "env.SQLITE3_LIB_DIR.value=" + json.dumps(str(native / "lib")),
        "--config", "env.SQLITE3_INCLUDE_DIR.value=" + json.dumps(str(native / "include")),
        "build", "--release", "--locked", "--offline", "--workspace", "--bins",
        "--target", host, "--message-format=json-render-diagnostics",
    ]
    with (output / f"cargo-{side}.jsonl").open("w") as log:
        subprocess.run(command, cwd=ROOT, env=environment, stdout=log, check=True)
    return {"command": command, "rustflags": flags, "native_directory": str(native), "rustc": environment["RUSTC"]}


def build(output, metadata, toolchain, host, inputs=None):
    output.mkdir(mode=0o700)
    output = output.resolve()
    inputs = build_inputs(toolchain, host) if inputs is None else inputs
    require_unchanged_inputs(inputs)
    validate_source_layout(metadata)
    expected_binaries(metadata)
    binding_package(metadata)
    native = SQLITE.build(output / "native")
    require_unchanged_inputs(inputs)
    commands = {}
    if native["differences"]:
        result = {"status": "different", "differences": ["native/" + name for name in native["differences"]]}
    else:
        for side in ("a", "b"):
            commands[side] = compile_side(output, side, toolchain, host, native["source_date_epoch"], inputs["build_tools"])
            require_unchanged_inputs(inputs)
        result = check(output, metadata, host)
        require_unchanged_inputs(inputs)
        for side in ("a", "b"):
            lines = (f"{digest}  {name}\n" for name, digest in result[f"binaries_{side}"].items())
            (output / f"sha256-{side}.txt").write_text("".join(lines))
    result.update({
        "commands": commands,
        "source_date_epoch": native["source_date_epoch"],
        **inputs,
    })
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "check"))
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    try:
        toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        initial_inputs = build_inputs(toolchain)
        host = initial_inputs["host"]
        metadata = json.loads(subprocess.check_output([
            initial_inputs["build_tools"]["tools"]["cargo"]["path"], "metadata", "--locked", "--offline", "--format-version", "1",
        ], cwd=ROOT, env=tool_environment(toolchain, initial_inputs["build_tools"])))
        require_unchanged_inputs(initial_inputs)
        validate_source_layout(metadata)
        output = arguments.output.absolute()
        if arguments.command == "build":
            result = build(output, metadata, toolchain, host, initial_inputs)
        else:
            inputs = verify_build_inputs(output, toolchain, host)
            result = check(output, metadata, host)
            require_unchanged_inputs(inputs)
            result.update(inputs)
    except FileExistsError:
        print("ERROR: output exists; choose a fresh output directory", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError, StopIteration, RecursionError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print("ERROR: build, tool/source-input, inventory or private SQLite linkage verification failed; inspect output and use unchanged inputs", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 1 if result["differences"] else 0


if __name__ == "__main__":
    sys.exit(main())
