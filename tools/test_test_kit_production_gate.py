#!/usr/bin/env python3

import json
import tempfile
import unittest
from pathlib import Path

from test_kit_production_gate import audit


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class TestKitProductionGateTests(unittest.TestCase):
    def test_a_production_dependency_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(
                root / "service" / "Cargo.toml",
                '[package]\nname = "service"\n\n[dependencies]\narkret-test-kit = { path = "../x" }\n',
            )
            errors = audit(root, root / "absent.json")
        self.assertEqual(len(errors), 1)
        self.assertIn("service/Cargo.toml declares arkret-test-kit", errors[0])

    def test_a_dev_dependency_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(
                root / "service" / "Cargo.toml",
                '[package]\nname = "service"\n\n[dev-dependencies]\narkret-test-kit = { path = "../x" }\n',
            )
            self.assertEqual(audit(root, root / "absent.json"), [])

    def test_an_optional_dependency_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(
                root / "service" / "Cargo.toml",
                '[package]\nname = "service"\n\n[dependencies]\n'
                'arkret-test-kit = { path = "../x", optional = true }\n',
            )
            self.assertEqual(audit(root, root / "absent.json"), [])

    def test_a_workspace_dependency_table_alone_links_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(
                root / "Cargo.toml",
                '[workspace]\nmembers = []\n\n[workspace.dependencies]\n'
                'arkret-test-kit = { path = "crates/test-kit" }\n',
            )
            self.assertEqual(audit(root, root / "absent.json"), [])

    def test_a_recorded_harness_decision_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(
                root / "harness" / "Cargo.toml",
                '[package]\nname = "harness"\n\n[dependencies]\narkret-test-kit = { path = "../x" }\n',
            )
            decisions = root / "decisions.json"
            decisions.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "decisions": [
                            {
                                "manifest": "harness/Cargo.toml",
                                "rationale": "this crate is itself the conformance harness and has no production build",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(audit(root, decisions), [])

    def test_a_stale_decision_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root / "harness" / "Cargo.toml", '[package]\nname = "harness"\n')
            decisions = root / "decisions.json"
            decisions.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "decisions": [
                            {
                                "manifest": "harness/Cargo.toml",
                                "rationale": "this crate is itself the conformance harness and has no production build",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            errors = audit(root, decisions)
        self.assertEqual(len(errors), 1)
        self.assertIn("stale decision for harness/Cargo.toml", errors[0])

    def test_a_thin_rationale_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decisions = root / "decisions.json"
            decisions.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "decisions": [{"manifest": "harness/Cargo.toml", "rationale": "tests"}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                audit(root, decisions)


if __name__ == "__main__":
    unittest.main()
