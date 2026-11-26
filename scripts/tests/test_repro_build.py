"""Verify release binary inventory and native link provenance checks."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import tomllib
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repro_build", ROOT / "scripts/release/repro_build.py")
REPRO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPRO)


def metadata():
    return {
        "workspace_members": ["member"],
        "packages": [
            {"id": "member", "name": "member", "source": None,
             "manifest_path": str(REPRO.ROOT / "crates/member/Cargo.toml"), "targets": [{"kind": ["bin"], "name": "rustiron"}]},
            {"id": "dependency", "name": "dependency", "source": "registry+fixture", "targets": [{"kind": ["bin"], "name": "dependency-tool"}]},
        ],
    }


class ReproBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rustiron-repro-test-")
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        self.left = self.output / "a"
        self.right = self.output / "b"
        self.left.mkdir()
        self.right.mkdir()
        self.binary(self.left, "rustiron", b"same binary")
        self.binary(self.right, "rustiron", b"same binary")

    @staticmethod
    def binary(directory, name, content):
        path = directory / name
        path.write_bytes(content)
        path.chmod(0o755)

    def test_expected_inventory_uses_only_workspace_targets(self):
        self.assertEqual(REPRO.expected_binaries(metadata()), ["rustiron"])

    def test_duplicate_binary_names_are_refused(self):
        document = metadata()
        document["packages"][0]["targets"].append({"kind": ["bin"], "name": "rustiron"})
        with self.assertRaises(ValueError):
            REPRO.expected_binaries(document)

    def test_empty_inventory_is_refused(self):
        document = metadata()
        document["packages"][0]["targets"] = []
        with self.assertRaises(ValueError):
            REPRO.expected_binaries(document)

    def test_conditional_binary_is_not_silently_omitted(self):
        document = metadata()
        document["packages"][0]["targets"][0]["required-features"] = ["conditional"]
        with self.assertRaises(ValueError):
            REPRO.expected_binaries(document)

    def test_matching_complete_inventories_pass(self):
        result = REPRO.compare_binaries(self.left, self.right, ["rustiron"])
        self.assertEqual(result["status"], "reproducible")
        self.assertEqual(result["differences"], [])

    def test_missing_from_both_builds_is_not_a_match(self):
        with self.assertRaises(ValueError):
            REPRO.compare_binaries(self.left, self.right, ["rustiron", "missing"])

    def test_unexpected_executable_is_refused(self):
        self.binary(self.left, "unexpected", b"extra")
        with self.assertRaises(ValueError):
            REPRO.compare_binaries(self.left, self.right, ["rustiron"])

    def test_changed_binary_is_a_mismatch(self):
        (self.right / "rustiron").write_bytes(b"different binary")
        result = REPRO.compare_binaries(self.left, self.right, ["rustiron"])
        self.assertEqual(result["status"], "different")
        self.assertEqual(result["differences"], ["rustiron"])

    def test_symlinked_binary_is_refused(self):
        (self.left / "rustiron").unlink()
        (self.left / "rustiron").symlink_to(self.right / "rustiron")
        with self.assertRaises(ValueError):
            REPRO.compare_binaries(self.left, self.right, ["rustiron"])

    def test_existing_output_is_preserved(self):
        sentinel = self.output / "sentinel"
        sentinel.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            REPRO.build(self.output, {}, "1.99.1", "host")
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_inherited_compiler_and_wrappers_are_overridden(self):
        toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        with patch.dict(os.environ, {
            "RUSTC": "/usr/bin/false", "RUSTC_WRAPPER": "/usr/bin/false",
            "RUSTC_WORKSPACE_WRAPPER": "/usr/bin/false", "CARGO_ENCODED_RUSTFLAGS": "invalid",
        }):
            environment = REPRO.tool_environment(toolchain)
        self.assertEqual(environment["RUSTC_WRAPPER"], "")
        self.assertEqual(environment["RUSTC_WORKSPACE_WRAPPER"], "")
        self.assertNotEqual(environment["RUSTC"], "/usr/bin/false")
        self.assertTrue(Path(environment["RUSTC"]).is_file())
        self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", environment)

    def link_record(self, directory):
        source = self.output / "cargo.jsonl"
        source.write_text(json.dumps({
            "reason": "build-script-executed", "package_id": "binding",
            "linked_paths": ["native=" + str(directory / "lib")],
            "linked_libs": ["static=sqlite3", "m"],
        }) + "\n")
        return source

    def test_expected_static_sqlite_link_path_passes(self):
        source = self.link_record(self.left)
        self.assertEqual(REPRO.verify_sqlite_linkage(source, "binding", self.left), str(self.left / "lib"))

    def test_shared_or_other_sqlite_link_path_is_refused(self):
        source = self.link_record(self.left)
        with self.assertRaises(ValueError):
            REPRO.verify_sqlite_linkage(source, "binding", self.right)

    def test_missing_sqlite_link_record_is_refused(self):
        source = self.output / "cargo.jsonl"
        source.write_text('{"reason":"build-finished","success":true}\n')
        with self.assertRaises(ValueError):
            REPRO.verify_sqlite_linkage(source, "binding", self.left)

    def test_dynamic_sqlite_link_is_refused(self):
        source = self.link_record(self.left)
        source.write_text(source.read_text().replace("static=sqlite3", "sqlite3"))
        with self.assertRaises(ValueError):
            REPRO.verify_sqlite_linkage(source, "binding", self.left)

    def test_malformed_link_record_is_refused(self):
        source = self.link_record(self.left)
        record = json.loads(source.read_text())
        record["linked_paths"] = [42]
        source.write_text(json.dumps(record) + "\n")
        with self.assertRaises(ValueError):
            REPRO.verify_sqlite_linkage(source, "binding", self.left)


class CompleteReproTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rustiron-full-repro-test-")
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        self.metadata = metadata()
        self.metadata["packages"].append({"id": "binding", "name": "libsqlite3-sys", "source": "registry+fixture", "targets": []})
        for side in ("a", "b"):
            native = self.output / "native" / side
            shutil.copytree(REPRO.SQLITE.BUILD.DEST, native)
            release = self.output / ("target-" + side) / "fixture-host/release"
            release.mkdir(parents=True)
            ReproBuildTests.binary(release, "rustiron", b"same binary")
            (self.output / ("cargo-" + side + ".jsonl")).write_text(json.dumps({
                "reason": "build-script-executed", "package_id": "binding",
                "linked_paths": ["native=" + str(native / "lib")],
                "linked_libs": ["static=sqlite3"],
            }) + "\n")
        self.inputs = {
            "cargo_lock_sha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest(),
            "toolchain": "1.99.1", "host": "fixture-host",
            "source_inputs": REPRO.source_inputs(ROOT),
            "build_tools": REPRO.tool_inputs("1.99.1"),
        }
        (self.output / "result.json").write_text(json.dumps(self.inputs))

    def test_complete_outputs_match(self):
        result = REPRO.check(self.output, self.metadata, "fixture-host")
        self.assertEqual(result["status"], "reproducible")
        self.assertEqual(result["expected_binaries"], ["rustiron"])
        self.assertEqual(result["differences"], [])

    def test_native_difference_is_propagated_to_the_final_result(self):
        header = self.output / "native/b/include/sqlite3.h"
        header.write_bytes(b"different native header")
        receipt = self.output / "native/b/receipt.json"
        record = json.loads(receipt.read_text())
        record["artifacts"]["include/sqlite3.h"] = hashlib.sha256(header.read_bytes()).hexdigest()
        receipt.write_text(json.dumps(record))
        result = REPRO.check(self.output, self.metadata, "fixture-host")
        self.assertEqual(result["status"], "different")
        self.assertEqual(result["differences"], ["native/include/sqlite3.h"])

    def test_second_build_cannot_use_the_first_native_library(self):
        source = self.output / "cargo-b.jsonl"
        source.write_text(source.read_text().replace("native/b/lib", "native/a/lib"))
        with self.assertRaises(ValueError):
            REPRO.check(self.output, self.metadata, "fixture-host")

    def test_a_binary_missing_from_both_outputs_cannot_pass(self):
        self.metadata["packages"][0]["targets"].append({"kind": ["bin"], "name": "missing"})
        with self.assertRaises(ValueError):
            REPRO.check(self.output, self.metadata, "fixture-host")

    def test_matching_recorded_inputs_pass(self):
        self.assertEqual(REPRO.verify_build_inputs(self.output, "1.99.1", "fixture-host"), self.inputs)

    def test_changed_lockfile_provenance_is_refused(self):
        self.inputs["cargo_lock_sha256"] = "0" * 64
        (self.output / "result.json").write_text(json.dumps(self.inputs))
        with self.assertRaises(ValueError):
            REPRO.verify_build_inputs(self.output, "1.99.1", "fixture-host")

    def test_other_toolchain_is_refused(self):
        self.inputs["toolchain"] = "other-toolchain"
        (self.output / "result.json").write_text(json.dumps(self.inputs))
        with self.assertRaises(ValueError):
            REPRO.verify_build_inputs(self.output, "1.99.1", "fixture-host")

    def test_other_host_is_refused(self):
        self.inputs["host"] = "other-host"
        (self.output / "result.json").write_text(json.dumps(self.inputs))
        with self.assertRaises(ValueError):
            REPRO.verify_build_inputs(self.output, "1.99.1", "fixture-host")

    def test_missing_build_tools_are_refused(self):
        self.inputs.pop("build_tools", None)
        (self.output / "result.json").write_text(json.dumps(self.inputs))
        with self.assertRaises(ValueError):
            REPRO.verify_build_inputs(self.output, "1.99.1", "fixture-host")

    def test_changed_recorded_build_tools_are_refused(self):
        self.inputs["build_tools"] = {"profile": "rustiron-build-tools-v1", "tools": {}}
        (self.output / "result.json").write_text(json.dumps(self.inputs))
        with self.assertRaises(ValueError):
            REPRO.verify_build_inputs(self.output, "1.99.1", "fixture-host")


class SourceInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rustiron-source-input-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "source"
        self.root.mkdir()
        files = [
            "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml",
            "native/sqlite.toml", "scripts/prepare_sqlite.py",
            "scripts/release/sqlite_repro.py", "scripts/release/repro_build.py",
            "scripts/release/repro_build.sh", "crates/member/Cargo.toml",
            "crates/member/src/main.rs", "crates/member/src/asset.php",
        ]
        for name in files:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture " + name)
        self.tools = {"profile": "rustiron-build-tools-v1", "tools": {
            name: {"requested_path": "/fixture/" + name, "path": "/fixture/" + name,
                   "sha256": "0" * 64, "version": "fixture"}
            for name in ("cargo", "rustc", "cc", "ar")
        }}
        tool_patch = patch.object(REPRO, "tool_inputs", create=True,
                                  side_effect=lambda _toolchain: json.loads(json.dumps(self.tools)))
        tool_patch.start()
        self.addCleanup(tool_patch.stop)
        self.inputs = {
            "cargo_lock_sha256": hashlib.sha256((self.root / "Cargo.lock").read_bytes()).hexdigest(),
            "toolchain": "fixture-toolchain", "host": "fixture-host",
            "build_tools": self.tools,
            "source_inputs": {"profile": "rustiron-worktree-v1", "sha256": {
                name: hashlib.sha256((self.root / name).read_bytes()).hexdigest() for name in files
            }},
        }
        self.output = Path(self.temporary.name) / "output"
        self.output.mkdir()
        (self.output / "result.json").write_text(json.dumps(self.inputs))
        self.root_patch = patch.object(REPRO, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def verify(self):
        return REPRO.verify_build_inputs(self.output, "fixture-toolchain", "fixture-host")

    def test_unchanged_source_identity_passes(self):
        self.assertEqual(self.verify(), self.inputs)

    def test_changed_rust_source_is_refused(self):
        (self.root / "crates/member/src/main.rs").write_text("changed source")
        with self.assertRaises(ValueError):
            self.verify()

    def test_missing_embedded_asset_is_refused(self):
        (self.root / "crates/member/src/asset.php").unlink()
        with self.assertRaises(ValueError):
            self.verify()

    def test_added_untracked_crate_file_is_refused(self):
        (self.root / "crates/member/src/extra.rs").write_text("untracked source")
        with self.assertRaises(ValueError):
            self.verify()

    def test_changed_cargo_configuration_is_refused(self):
        (self.root / ".cargo/config.toml").write_text("different config")
        with self.assertRaises(ValueError):
            self.verify()

    def test_new_legacy_cargo_configuration_is_refused(self):
        (self.root / ".cargo/config").write_text("new legacy config")
        with self.assertRaises(ValueError):
            self.verify()

    def test_changed_native_pin_is_refused(self):
        (self.root / "native/sqlite.toml").write_text("different pin")
        with self.assertRaises(ValueError):
            self.verify()

    def test_changed_build_helper_is_refused(self):
        (self.root / "scripts/prepare_sqlite.py").write_text("different helper")
        with self.assertRaises(ValueError):
            self.verify()

    def test_missing_source_identity_in_old_record_is_refused(self):
        del self.inputs["source_inputs"]
        (self.output / "result.json").write_text(json.dumps(self.inputs))
        with self.assertRaises(ValueError):
            self.verify()

    def test_symlinked_source_file_is_refused(self):
        source = self.root / "crates/member/src/main.rs"
        content = source.read_bytes()
        source.unlink()
        outside = Path(self.temporary.name) / "outside.rs"
        outside.write_bytes(content)
        source.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.verify()

    def test_symlinked_source_directory_is_refused(self):
        source = self.root / "crates/member/src"
        outside = Path(self.temporary.name) / "outside"
        source.rename(outside)
        source.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.verify()

    def test_fifo_source_is_refused_without_opening(self):
        source = self.root / "crates/member/src/main.rs"
        source.unlink()
        os.mkfifo(source)
        with self.assertRaises(ValueError):
            self.verify()

    def test_inputs_changed_during_native_build_stop_before_rust_builds(self):
        destination = self.output / "new"
        def native_build(_output):
            (self.root / "crates/member/src/main.rs").write_text("changed during native build")
            return {"differences": [], "source_date_epoch": 1}
        with patch.object(REPRO.SQLITE, "build", side_effect=native_build), patch.object(
            REPRO, "compile_side", side_effect=AssertionError("Rust compilation must not start"),
        ):
            with self.assertRaises(ValueError):
                REPRO.build(destination, self.build_metadata(), "fixture-toolchain", "fixture-host")
        self.assertFalse((destination / "result.json").exists())

    def test_inputs_changed_during_first_rust_build_stop_before_second(self):
        destination = self.output / "new"
        def compile_side(_output, side, *_arguments):
            self.assertEqual(side, "a", "second build must not start after an input change")
            (self.root / "crates/member/src/main.rs").write_text("changed during first Rust build")
            return {}
        with patch.object(REPRO.SQLITE, "build", return_value={"differences": [], "source_date_epoch": 1}), patch.object(
            REPRO, "compile_side", side_effect=compile_side,
        ):
            with self.assertRaises(ValueError):
                REPRO.build(destination, self.build_metadata(), "fixture-toolchain", "fixture-host")
        self.assertFalse((destination / "result.json").exists())

    def test_external_local_dependency_is_refused_before_building(self):
        document = self.build_metadata()
        outside = Path(self.temporary.name) / "Cargo.toml"
        outside.write_text("external local dependency")
        document["packages"].append({
            "id": "external", "name": "external", "source": None,
            "manifest_path": str(outside), "targets": [],
        })
        with patch.object(REPRO.SQLITE, "build", side_effect=AssertionError("native build must not start")):
            with self.assertRaises(ValueError):
                REPRO.build(self.output / "new", document, "fixture-toolchain", "fixture-host")

    def test_inputs_changed_during_comparison_cannot_publish_a_result(self):
        destination = self.output / "new"
        def compare(*_arguments):
            (self.root / "crates/member/src/main.rs").write_text("changed during comparison")
            return {"differences": [], "binaries_a": {}, "binaries_b": {}}
        with patch.object(REPRO.SQLITE, "build", return_value={"differences": [], "source_date_epoch": 1}), patch.object(
            REPRO, "compile_side", return_value={},
        ), patch.object(REPRO, "check", side_effect=compare):
            with self.assertRaises(ValueError):
                REPRO.build(destination, self.build_metadata(), "fixture-toolchain", "fixture-host")
        self.assertFalse((destination / "result.json").exists())

    def test_tool_changed_during_native_build_stops_before_rust(self):
        destination = self.output / "new"
        def native_build(_output):
            self.tools["tools"]["cc"]["sha256"] = "1" * 64
            return {"differences": [], "source_date_epoch": 1}
        with patch.object(REPRO.SQLITE, "build", side_effect=native_build), patch.object(
            REPRO, "compile_side", side_effect=AssertionError("Rust compilation must not start"),
        ):
            with self.assertRaises(ValueError):
                REPRO.build(destination, self.build_metadata(), "fixture-toolchain", "fixture-host")
        self.assertFalse((destination / "result.json").exists())

    @staticmethod
    def build_metadata():
        document = metadata()
        document["packages"].append({"id": "binding", "name": "libsqlite3-sys", "source": "registry+fixture", "targets": []})
        return document


class ToolIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rustiron-tool-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.tool = self.directory / "tool"
        self.tool.write_text("#!/bin/sh\nprintf 'fixture tool 1\\n'\n")
        self.tool.chmod(0o755)

    def test_symlink_identity_records_resolved_bytes(self):
        link = self.directory / "link"
        link.symlink_to(self.tool)
        identity = REPRO.tool_identity(link, ["--version"])
        self.assertEqual(identity["requested_path"], str(link))
        self.assertEqual(identity["path"], str(self.tool))
        self.assertEqual(identity["sha256"], hashlib.sha256(self.tool.read_bytes()).hexdigest())
        self.assertEqual(identity["version"], "fixture tool 1")

    def test_changed_bytes_with_same_version_change_identity(self):
        before = REPRO.tool_identity(self.tool, ["--version"])
        self.tool.write_text(self.tool.read_text() + "# changed bytes\n")
        after = REPRO.tool_identity(self.tool, ["--version"])
        self.assertEqual(before["version"], after["version"])
        self.assertNotEqual(before["sha256"], after["sha256"])

    def test_retargeted_symlink_changes_identity_even_for_identical_bytes(self):
        twin = self.directory / "twin"
        shutil.copy2(self.tool, twin)
        link = self.directory / "link"
        link.symlink_to(self.tool)
        before = REPRO.tool_identity(link, ["--version"])
        link.unlink()
        link.symlink_to(twin)
        after = REPRO.tool_identity(link, ["--version"])
        self.assertEqual(before["sha256"], after["sha256"])
        self.assertNotEqual(before, after)

    def test_version_probe_uses_the_selected_invocation_path(self):
        self.tool.write_text('#!/bin/sh\nprintf "%s\\n" "$0"\n')
        link = self.directory / "selected-name"
        link.symlink_to(self.tool)
        self.assertEqual(REPRO.tool_identity(link, ["--version"])["version"], str(link))

    def test_empty_tool_version_is_refused(self):
        self.tool.write_text("#!/bin/sh\nexit 0\n")
        with self.assertRaises(ValueError):
            REPRO.tool_identity(self.tool, ["--version"])

    def test_failed_version_probe_is_refused(self):
        self.tool.write_text("#!/bin/sh\nexit 1\n")
        with self.assertRaises(REPRO.subprocess.CalledProcessError):
            REPRO.tool_identity(self.tool, ["--version"])

    def test_nonexecutable_tool_is_refused(self):
        self.tool.chmod(0o644)
        with self.assertRaises(ValueError):
            REPRO.tool_identity(self.tool, ["--version"])

    def test_fifo_tool_is_refused_without_opening(self):
        self.tool.unlink()
        os.mkfifo(self.tool)
        with self.assertRaises(ValueError):
            REPRO.tool_identity(self.tool, ["--version"])

    def test_missing_tool_is_refused(self):
        self.tool.unlink()
        with self.assertRaises(FileNotFoundError):
            REPRO.tool_identity(self.tool, ["--version"])

    def test_recorded_cargo_and_rustc_override_inherited_selection(self):
        tools = {"tools": {"cargo": {"path": str(self.tool)}, "rustc": {"path": str(self.tool)}}}
        with patch.dict(os.environ, {"CARGO": "/usr/bin/false", "RUSTC": "/usr/bin/false", "RUSTUP_TOOLCHAIN": "wrong"}):
            environment = REPRO.tool_environment("fixture", tools)
        self.assertEqual(environment["CARGO"], str(self.tool))
        self.assertEqual(environment["RUSTC"], str(self.tool))
        self.assertEqual(environment["RUSTUP_TOOLCHAIN"], "fixture")

    def test_compilation_executes_the_recorded_cargo_binary(self):
        self.tool.write_text("#!/usr/bin/python3\nimport json,os,sys\nprint(json.dumps({'args':sys.argv[1:], 'rustc':os.environ['RUSTC'], 'cargo':os.environ['CARGO']}))\n")
        tools = {"tools": {"cargo": {"path": str(self.tool)}, "rustc": {"path": "/fixture/rustc"}}}
        result = REPRO.compile_side(self.directory, "a", "fixture", "host", 1, tools)
        observed = json.loads((self.directory / "cargo-a.jsonl").read_text())
        self.assertEqual(result["command"][0], str(self.tool))
        self.assertEqual(observed["args"][0], "--config")
        self.assertEqual(observed["rustc"], "/fixture/rustc")
        self.assertEqual(observed["cargo"], str(self.tool))


if __name__ == "__main__":
    unittest.main()
