#!/usr/bin/env python3
"""Exercise precise carrier edges and the retained layering rejection rules."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "check_layering", Path(__file__).with_name("check-layering.py")
)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class LayeringTests(unittest.TestCase):
    def run_gate(self, edges: dict[str, list[str]], forbidden: str | None = None) -> tuple[int, str]:
        packages = [
            {"name": name, "dependencies": [{"name": target, "kind": None} for target in targets]}
            for name, targets in edges.items()
        ]
        output = io.StringIO()
        with patch.object(gate, "cargo_metadata", return_value={"packages": packages}), \
                patch.object(gate, "no_default_normal_tree", return_value={forbidden} if forbidden else set()), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = gate.main()
        return result, output.getvalue()

    def test_formal_carrier_reuse_edges_are_accepted(self) -> None:
        result, output = self.run_gate({
            "arkret-identity": ["arkret-models-collaboration"],
            "arkret-models-integration": ["arkret-models-collaboration"],
            "arkret-models-collaboration": [],
        })
        self.assertEqual(result, 0, output)
        self.assertIn("layering OK", output)

    def test_unrelated_cross_domain_edge_is_still_rejected(self) -> None:
        result, output = self.run_gate({"arkret-models-discovery": ["arkret-models-collaboration"]})
        self.assertEqual(result, 1)
        self.assertIn("arkret-models-discovery: forbidden edge -> arkret-models-collaboration", output)

    def test_model_to_behavior_edge_is_still_rejected(self) -> None:
        result, output = self.run_gate({"arkret-models-collaboration": ["arkret-identity"]})
        self.assertEqual(result, 1)
        self.assertIn("arkret-models-collaboration: forbidden edge -> arkret-identity", output)

    def test_carrier_reuse_does_not_allow_runtime_in_data_graph(self) -> None:
        for runtime in ["tokio", "reqwest", "openmls"]:
            with self.subTest(runtime=runtime):
                result, output = self.run_gate({"arkret-models-integration": ["arkret-models-collaboration"]}, runtime)
                self.assertEqual(result, 1)
                self.assertIn(f"forbidden third-party {runtime}", output)

    def test_umbrella_dependency_is_still_rejected(self) -> None:
        result, output = self.run_gate({"arkret-identity": ["arkret"]})
        self.assertEqual(result, 1)
        self.assertIn("umbrella", output)

    def test_unregistered_crate_is_still_rejected(self) -> None:
        result, output = self.run_gate({"arkret-unregistered-fixture": []})
        self.assertEqual(result, 1)
        self.assertIn("crate is not registered", output)


if __name__ == "__main__":
    unittest.main()
