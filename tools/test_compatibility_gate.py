#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("compatibility_gate.py")
SPEC = importlib.util.spec_from_file_location("compatibility_gate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class CompatibilityGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sdk_root = Path(__file__).resolve().parents[1]
        cls.workspace_root = cls.sdk_root.parent
        cls.manifest_path = cls.sdk_root / "compatibility" / "manifest.json"
        cls.manifest = json.loads(cls.manifest_path.read_text(encoding="utf-8"))

    def test_manifest_and_workspace_probes_are_valid(self) -> None:
        gate.check_workspace(self.manifest, self.workspace_root)

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

    def test_workspace_snapshot_records_exact_heads(self) -> None:
        snapshot = gate.snapshot_workspace_heads(
            self.manifest, self.workspace_root, allow_dirty=True
        )
        gate.validate_manifest(snapshot)
        self.assertRegex(snapshot["repositories"]["arkret-rust-sdk"]["commit"], r"^[0-9a-f]{40}$")

    def test_deleted_sdk_field_is_rejected_with_exact_type_and_field(self) -> None:
        failure = gate.negative_mutation(self.manifest, self.workspace_root)
        self.assertEqual(failure, "type arkret_wire::Event missing field event_id")

    def test_first_command_failure_reports_surface(self) -> None:
        document = copy.deepcopy(self.manifest)
        document["checks"] = [
            {
                "id": "probe.failure",
                "repository": "arkret-rust-sdk",
                "category": "static",
                "surface": {"kind": "type", "name": "arkret_wire::Event"},
                "working_directory": "arkret-rust-sdk",
                "command": ["python", "-c", "raise SystemExit(7)"],
            }
        ]
        with self.assertRaisesRegex(gate.CompatibilityError, '"kind": "type"'):
            gate.run_checks(document, self.workspace_root, {"static"}, set())

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

    def test_github_outputs_are_exact_pins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "github-output.txt"
            gate.write_github_outputs(self.manifest, output)
            lines = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertEqual(lines["arkret_rust_sdk"], self.manifest["repositories"]["arkret-rust-sdk"]["commit"])


if __name__ == "__main__":
    unittest.main()
