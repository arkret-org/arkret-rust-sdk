#!/usr/bin/env python3

import json
import tempfile
import unittest
from pathlib import Path

from wire_type_ownership_audit import audit


class WireTypeOwnershipAuditTests(unittest.TestCase):
    def garth_audit(self, sources: dict[str, str], repository_exists: bool = True) -> list[str]:
        """Exercise the shipped Garth decisions, including future nested files."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "garth"
            if repository_exists:
                repository.mkdir()
            for relative, source in sources.items():
                path = repository / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source, encoding="utf-8")
            shipped = json.loads(Path(__file__).with_name("wire_type_ownership_decisions.json").read_text())
            decisions = root / "decisions.json"
            decisions.write_text(json.dumps({
                category: [entry for entry in shipped[category] if entry["repository"] == "garth"]
                for category in ("forbidden", "classified")
            }), encoding="utf-8")
            return audit(root, decisions, {"garth"})

    def test_garth_replacement_and_new_nested_source_cannot_erase_actor_route(self) -> None:
        for relative, identity in [("src/replica.rs", "arkret_wire::DidCoreId"),
                                   ("src/own_station_results.rs", "DidCoreId"),
                                   ("src/new/replacement.rs", "arkret_sdk::DidCoreId")]:
            with self.subTest(path=relative):
                errors = self.garth_audit({relative: f"struct HistoryRow {{ source_actor_id: {identity} }}"})
                self.assertEqual(errors, [f"garth/{relative}: duplicates SDK owner arkret_wire::ActorId"])

    def test_garth_cannot_copy_sdk_commit_stream_dtos(self) -> None:
        for name, declaration in [("CommittedEventView", "enum"),
                                  ("StreamScanOutcome", "struct"),
                                  ("StreamScanRequest", "struct")]:
            with self.subTest(name=name):
                errors = self.garth_audit({"src/new/scan.rs": f"pub {declaration} {name} {{}}"})
                self.assertEqual(len(errors), 1)
                self.assertIn("garth/src/new/scan.rs: duplicates SDK owner", errors[0])

    def test_garth_sdk_carriers_and_complete_actor_id_are_allowed(self) -> None:
        self.assertEqual(self.garth_audit({
            "src/replica.rs": "use arkret_wire::{ActorId, CommittedEventView};\n"
                              "struct StreamReplica { items: Vec<CommittedEventView> }\n"
                              "struct HistoryRow { source_actor_id: ActorId }",
            "src/own_station_results.rs": "struct OwnStationScanPage { response: "
                                          "BoundOwnStationResponse<StreamScanRequest, StreamScanOutcome> }",
        }), [])

    def test_garth_comments_and_string_examples_do_not_become_wire_types(self) -> None:
        self.assertEqual(self.garth_audit({"src/replica.rs": '''
            // struct StreamScanOutcome {}
            /* struct HistoryRow { source_actor_id: arkret_wire::DidCoreId } */
            const EXAMPLE: &str = r#"enum CommittedEventView {}"#;
        '''}), [])

    def test_required_garth_missing_repository_and_empty_scope_fail(self) -> None:
        missing = self.garth_audit({}, repository_exists=False)
        self.assertIn("required repository is missing: garth", missing)
        empty = self.garth_audit({"README.md": "present repository with no audited Rust sources"})
        self.assertEqual(len(empty), 2)
        self.assertTrue(all("audited source scope is empty: garth/src/**/*.rs" == error for error in empty))

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
