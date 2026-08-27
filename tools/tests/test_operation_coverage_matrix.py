from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "generate-operation-coverage-matrix.py"
SPEC = importlib.util.spec_from_file_location("operation_coverage_matrix", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EvidenceSymbolTests(unittest.TestCase):
    def test_accepts_declared_method(self) -> None:
        MODULE.validate_evidence_symbol(
            "crates/server/src/applet.rs::AppletHandler::ping",
            "pub trait AppletHandler { fn ping(&self); }",
        )

    def test_rejects_stale_symbol_in_live_operation_file(self) -> None:
        with self.assertRaisesRegex(ValueError, "evidence symbol does not exist"):
            MODULE.validate_evidence_symbol(
                "crates/server/src/applet.rs::ping_handler",
                'pub const OPERATION_ID: &str = "ak.edge.applet.read.ping.v1";',
            )


if __name__ == "__main__":
    unittest.main()
