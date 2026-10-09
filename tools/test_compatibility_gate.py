#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("compatibility_gate.py")
SPEC = importlib.util.spec_from_file_location("compatibility_gate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class ManifestFixture:
    @classmethod
    def setUpClass(cls) -> None:
        cls.sdk_root = Path(__file__).resolve().parents[1]
        cls.workspace_root = cls.sdk_root.parent
        cls.manifest_path = cls.sdk_root / "compatibility" / "manifest.json"
        cls.manifest = json.loads(cls.manifest_path.read_text(encoding="utf-8"))


class CompatibilityGateTests(ManifestFixture, unittest.TestCase):
    """Tool behavior: no real consumer source or checkout state is required."""

    def test_repository_commits_must_be_exact(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["repositories"]["soland"]["commit"] = "main"
        with self.assertRaisesRegex(gate.CompatibilityError, "exact 40-byte hex SHA"):
            gate.validate_manifest(mutated)

    def test_merge_order_must_follow_dependency_order(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        order = mutated["train"]["merge_order"]
        order.remove("arkret-rust-sdk")
        order.insert(order.index("arkret-spec"), "arkret-rust-sdk")
        with self.assertRaisesRegex(gate.CompatibilityError, "arkret-spec before arkret-rust-sdk"):
            gate.validate_manifest(mutated)

    def test_candidate_resolution_only_changes_named_repository(self) -> None:
        candidate = "a" * 40
        resolved = gate.resolve_manifest(self.manifest, {"garth": candidate})
        self.assertEqual(resolved["repositories"]["garth"]["commit"], candidate)
        self.assertEqual(
            resolved["repositories"]["soland"]["commit"],
            self.manifest["repositories"]["soland"]["commit"],
        )
        self.assertEqual(
            resolved["resolved_candidates"],
            [{"repository": "garth", "commit": candidate}],
        )

    def test_first_command_failure_reports_surface(self) -> None:
        document = copy.deepcopy(self.manifest)
        document["checks"] = [
            {
                "id": "probe.failure",
                "repository": "arkret-rust-sdk",
                "category": "static",
                "surface": {"kind": "type", "name": "arkret_wire::Event"},
                "working_directory": ".",
                "command": [sys.executable, "-c", "raise SystemExit(7)"],
            }
        ]
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(gate.CompatibilityError, '"kind": "type"'):
                gate.run_checks(document, Path(temporary), {"static"}, set())

    def test_source_guard_rejects_local_compatibility_dto(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "inkson" / "src" / "compat.rs"
            source.parent.mkdir(parents=True)
            source.write_text("pub struct CompatibilityDto {}\n", encoding="utf-8")
            document = {
                "repositories": {"inkson": {"checkout_path": "inkson"}},
                "policy": {
                    "source_guards": [
                        {
                            "id": "no-consumer-local-compatibility-dto",
                            "repositories": ["inkson"],
                            "pattern": r"(?i)\bcompat(?:ibility)?[_ -]?dto\b",
                        }
                    ]
                },
            }
            with self.assertRaisesRegex(gate.CompatibilityError, "compatibility-dto"):
                gate.check_source_guards(document, workspace)

    def test_runner_records_failure_continues_independent_and_blocks_dependents(self) -> None:
        checks = []
        for check_id, category, code, dependencies in [
            ("failure", "static", 7, []),
            ("independent", "static", 0, []),
            ("dependent", "static", 0, ["failure"]),
            ("filtered", "compile", 0, []),
            ("skipped", "static", 0, []),
        ]:
            checks.append({"id": check_id, "repository": "arkret-rust-sdk",
                           "surface": {"kind": "type", "name": "probe"},
                           "category": category, "working_directory": ".",
                           "command": [sys.executable, "-c", f"raise SystemExit({code})"],
                           "depends_on": dependencies})
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "results.json"
            with self.assertRaisesRegex(gate.CompatibilityError, '"exit_code": 7'):
                gate.run_checks({"checks": checks}, Path(temporary), {"static"}, {"skipped"}, report)
            results = json.loads(report.read_text(encoding="utf-8"))["checks"]
        self.assertEqual([row["status"] for row in results],
                         ["failed", "passed", "blocked", "not_run", "not_run"])
        self.assertEqual(results[2]["dependencies"], ["failure"])
        self.assertNotIn("exit_code", results[2])

    def test_all_skipped_is_not_reported_as_success(self) -> None:
        with self.assertRaisesRegex(gate.CompatibilityError, "not completed"):
            gate.run_checks(self.manifest, self.workspace_root, {"static"},
                            {check["id"] for check in self.manifest["checks"]})

    def test_dependencies_must_reference_earlier_checks(self) -> None:
        for dependency in ["unknown", self.manifest["checks"][0]["id"],
                           self.manifest["checks"][-1]["id"]]:
            mutated = copy.deepcopy(self.manifest)
            mutated["checks"][0]["depends_on"] = [dependency]
            with self.assertRaisesRegex(gate.CompatibilityError, "depends_on must name earlier checks"):
                gate.validate_manifest(mutated)

    def test_unlaunchable_check_writes_failed_report(self) -> None:
        check = copy.deepcopy(self.manifest["checks"][0])
        check["command"] = ["missing-arkret-regression-executable"]
        check["working_directory"] = "."
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            with self.assertRaisesRegex(gate.CompatibilityError, '"exit_code": 127'):
                gate.run_checks({"checks": [check]}, Path(temporary), {check["category"]}, set(), report)
            row = json.loads(report.read_text(encoding="utf-8"))["checks"][0]
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["exit_code"], 127)

    def test_executable_alias_resolves_without_changing_arguments_or_manifest(self) -> None:
        check = copy.deepcopy(self.manifest["checks"][0])
        check["working_directory"] = "."
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "argument result.json"
            arguments = ["spaces and quotes \" preserved", "literal $() & ;"]
            check["command"] = [
                "arkret-regression-executable-alias", "-c",
                "import json, pathlib, sys; pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))",
                str(output), *arguments,
            ]
            original_command = list(check["command"])
            with patch.object(gate.shutil, "which", return_value=sys.executable) as resolve:
                results = gate.run_checks({"checks": [check]}, Path(temporary),
                                          {check["category"]}, set())
            resolve.assert_called_once_with(original_command[0])
            self.assertEqual(json.loads(output.read_text()), arguments)
        self.assertEqual(results[0]["status"], "passed")
        self.assertEqual(results[0]["command"], original_command)
        self.assertEqual(check["command"], original_command)

    def test_exact_selection_runs_named_check_and_reports_unselected(self) -> None:
        checks = copy.deepcopy(self.manifest["checks"][:2])
        for check in checks:
            check["working_directory"] = "."
        checks[0]["repository"] = "soland"
        checks[0]["working_directory"] = "missing-consumer"
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "selection.json"
            with patch.object(gate.subprocess, "run") as execute:
                execute.return_value.returncode = 0
                results = gate.run_checks({"checks": checks}, Path(temporary),
                                          {"static"}, set(), report, {checks[1]["id"]})
                expected_command = list(checks[1]["command"])
                expected_command[0] = gate.shutil.which(expected_command[0]) or expected_command[0]
                execute.assert_called_once_with(expected_command, cwd=Path(temporary), check=False)
            self.assertEqual(results, json.loads(report.read_text())["checks"])
        self.assertEqual([row["status"] for row in results], ["not_run", "passed"])
        self.assertEqual(results[0]["reason"], "check not selected")

    def test_unknown_exact_selection_fails_before_execution(self) -> None:
        with patch.object(gate.subprocess, "run") as execute:
            with self.assertRaisesRegex(gate.CompatibilityError, "unknown selected checks: typo"):
                gate.run_checks(self.manifest, self.workspace_root, {"compile"}, set(), selected={"typo"})
            execute.assert_not_called()

    def test_selection_does_not_pass_unselected_prerequisite(self) -> None:
        checks = copy.deepcopy(self.manifest["checks"][:3])
        checks[1]["depends_on"] = [checks[0]["id"]]
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "blocked.json"
            with patch.object(gate.subprocess, "run") as execute:
                execute.return_value.returncode = 0
                with self.assertRaisesRegex(gate.CompatibilityError, "not completed"):
                    gate.run_checks({"checks": checks}, Path(temporary), {"static"},
                                    set(), report, {checks[1]["id"], checks[2]["id"]})
                self.assertEqual(execute.call_count, 1)
            results = json.loads(report.read_text())["checks"]
        self.assertEqual([row["status"] for row in results], ["not_run", "blocked", "passed"])

    def test_sdk_compile_matrix_is_shared_with_standalone_ci(self) -> None:
        gate.validate_manifest(self.manifest)
        checks = {check["id"]: check for check in self.manifest["checks"]}
        expected = {
            "sdk.compile-default": ["-p", "arkret"],
            "sdk.compile-no-default": ["-p", "arkret", "--no-default-features"],
            "sdk.compile-client": ["-p", "arkret", "--no-default-features", "--features", "client"],
            "sdk.compile-server": ["-p", "arkret", "--no-default-features", "--features", "server"],
            "sdk.compile-mls": ["-p", "arkret", "--no-default-features", "--features", "mls"],
            "sdk.compile-wasm-client": ["-p", "arkret", "--target", "wasm32-unknown-unknown", "--no-default-features", "--features", "client"],
            "sdk.compile-wasm-mls": ["-p", "arkret-mls", "--target", "wasm32-unknown-unknown", "--no-default-features"],
            "sdk.compile-wasm-identifiers": ["-p", "arkret-identifiers", "--target", "wasm32-unknown-unknown", "--no-default-features"],
        }
        for name, args in expected.items():
            self.assertEqual(checks[name]["command"], ["cargo", "check", *args, "--locked"])
            self.assertEqual(checks[name]["category"], "compile")
            self.assertEqual(checks[name]["working_directory"], "arkret-rust-sdk")
        workflow = (self.sdk_root / ".github/workflows/ci.yml").read_text()
        self.assertEqual(set(re.findall(r"--check (sdk\.compile[.\w-]*)", workflow)), set(expected) | {"sdk.compile"})
        self.assertNotIn("- run: cargo check --no-default-features", workflow)
        self.assertNotIn("- run: cargo check -p arkret --target", workflow)

    def test_sdk_structure_time_event_checks_are_shared_with_standalone_ci(self) -> None:
        expected = {
            "sdk.layering-regression": ["tools/test_check_layering.py"],
            "sdk.layering": ["tools/check-layering.py"],
            "sdk.test-layout-regression": ["-m", "unittest", "tools.tests.test_test_layout_gate"],
            "sdk.test-layout": ["tools/test_layout_gate.py"],
            "sdk.time-representations": ["tools/lint-time-representations.py"],
            "sdk.optional-timestamp-defaults-regression": ["tools/test_lint_optional_timestamp_defaults.py"],
            "sdk.optional-timestamp-defaults": ["tools/lint-optional-timestamp-defaults.py"],
            "sdk.event-preimage-authoring-regression": ["tools/test_lint_event_preimage_authoring.py"],
            "sdk.event-preimage-authoring": ["tools/lint-event-preimage-authoring.py"],
            "sdk.event-derived-id-minting-regression": ["tools/test_lint_event_derived_id_minting.py"],
            "sdk.event-derived-id-minting": ["tools/lint-event-derived-id-minting.py"],
        }
        checks = {check["id"]: check for check in self.manifest["checks"]}
        for name, arguments in expected.items():
            with self.subTest(check=name):
                self.assertEqual(checks[name]["command"], ["python", *arguments])
                self.assertEqual(checks[name]["repository"], "arkret-rust-sdk")
                self.assertEqual(checks[name]["working_directory"], "arkret-rust-sdk")
                self.assertEqual(checks[name]["category"], "static")
                script = arguments[-1].replace(".", "/") + ".py" if arguments[0] == "-m" else arguments[0]
                self.assertTrue((self.sdk_root / script).is_file())
        workflow = (self.sdk_root / ".github/workflows/ci.yml").read_text()
        block = workflow.split("- name: Run manifest SDK structure, time and Event checks\n", 1)[1]
        block = block.split("- name: Guard weak wire types", 1)[0]
        self.assertEqual(set(re.findall(r"--check (sdk[.\w-]+)", block)), set(expected))
        self.assertIn('--report "${{ runner.temp }}/sdk-structure-time-event.json"', block)
        self.assertIn("if: always()", block)
        self.assertIn("path: ${{ runner.temp }}/sdk-structure-time-event.json", block)
        for arguments in expected.values():
            self.assertNotIn("python " + " ".join(arguments), workflow)
        self.assertNotIn("lint-cell-family-literals.py", workflow)

    def test_github_outputs_are_exact_pins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "github-output.txt"
            gate.write_github_outputs(self.manifest, output)
            lines = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertEqual(lines["arkret_rust_sdk"], self.manifest["repositories"]["arkret-rust-sdk"]["commit"])


class CompatibilityWorkspaceTests(ManifestFixture, unittest.TestCase):
    """Integration checks against the actual sibling checkout collection."""

    def test_manifest_and_workspace_probes_are_valid(self) -> None:
        gate.check_workspace(self.manifest, self.workspace_root)

    def test_workspace_snapshot_records_exact_heads(self) -> None:
        snapshot = gate.snapshot_workspace_heads(
            self.manifest, self.workspace_root, allow_dirty=True
        )
        gate.validate_manifest(snapshot)
        self.assertRegex(snapshot["repositories"]["arkret-rust-sdk"]["commit"], r"^[0-9a-f]{40}$")

    def test_deleted_sdk_field_is_rejected_with_exact_type_and_field(self) -> None:
        failure = gate.negative_mutation(self.manifest, self.workspace_root)
        self.assertEqual(failure, "type arkret_wire::Event missing field event_id")


if __name__ == "__main__":
    selected = None
    if "--tools-only" in sys.argv and "--workspace-only" in sys.argv:
        raise SystemExit("choose only one of --tools-only or --workspace-only")
    for flag, suite in [("--tools-only", "CompatibilityGateTests"),
                        ("--workspace-only", "CompatibilityWorkspaceTests")]:
        if flag in sys.argv:
            sys.argv.remove(flag)
            selected = suite
    unittest.main(defaultTest=selected)
