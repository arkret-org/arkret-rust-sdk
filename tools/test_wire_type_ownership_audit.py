#!/usr/bin/env python3

import json
import tempfile
import unittest
from pathlib import Path

from wire_type_ownership_audit import audit


class WireTypeOwnershipAuditTests(unittest.TestCase):
    def test_repository_requirement_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors = audit(Path(directory), Path(__file__).with_name("wire_type_ownership_decisions.json"), {"inkson"})
        self.assertTrue(any("required repository is missing: inkson" in error for error in errors))

    def test_forbidden_sdk_mirror_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "consumer" / "src" / "models.rs"
            source.parent.mkdir(parents=True)
            source.write_text("struct MirroredOutcome {}", encoding="utf-8")
            decisions = root / "decisions.json"
            decisions.write_text(
                json.dumps(
                    {
                        "forbidden": [
                            {
                                "repository": "consumer",
                                "path": "src/models.rs",
                                "pattern": r"struct\s+MirroredOutcome\b",
                                "owner": "arkret_sdk::Outcome",
                            }
                        ],
                        "classified": [],
                    }
                ),
                encoding="utf-8",
            )

            errors = audit(root, decisions, {"consumer"})

        self.assertTrue(any("duplicates SDK owner arkret_sdk::Outcome" in error for error in errors))

    def test_classification_must_still_match_reviewed_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "consumer" / "src" / "models.rs"
            source.parent.mkdir(parents=True)
            source.write_text("struct RenamedInternalState {}", encoding="utf-8")
            decisions = root / "decisions.json"
            decisions.write_text(
                json.dumps(
                    {
                        "forbidden": [],
                        "classified": [
                            {
                                "repository": "consumer",
                                "path": "src/models.rs",
                                "pattern": r"struct\s+InternalState\b",
                                "classification": "internal_state",
                                "rationale": "Not a wire contract.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            errors = audit(root, decisions, {"consumer"})

        self.assertTrue(any("classified type disappeared" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
