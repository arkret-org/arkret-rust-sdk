#!/usr/bin/env python3
"""Self-test for `tools/lint-event-derived-id-minting.py`.

Each case is a shape that really appears in the tree, including the one the
scanner originally missed: `unwrap_or_else(ids::generate_realm_id)` mints a Realm
id without ever writing `generate_realm_id(`.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "tools" / "lint-event-derived-id-minting.py"
SPEC = importlib.util.spec_from_file_location("lint_event_derived_id_minting", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
LINT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LINT)


class EventDerivedIdMintingAuditTests(unittest.TestCase):
    def scan(self, sources: dict[str, str], entries: list[dict[str, str]]) -> int:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "some-repo"
            for relative, text in sources.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            allowlist_path = Path(directory) / "allowlist.json"
            allowlist_path.write_text(json.dumps({"entries": entries}), encoding="utf-8")
            parsed = LINT.argparse.Namespace(
                root=root, allowlist=allowlist_path, report=False
            )
            original = LINT.argparse.ArgumentParser.parse_args
            LINT.argparse.ArgumentParser.parse_args = lambda self, *a, **k: parsed  # type: ignore[assignment]
            try:
                return LINT.main()
            finally:
                LINT.argparse.ArgumentParser.parse_args = original  # type: ignore[assignment]

    def test_prefix_list_comes_from_sdk_source(self) -> None:
        kinds = LINT.event_derived_kinds()
        # A missing `realm` or `event` would silence most of the audit.
        self.assertIn("realm", kinds)
        self.assertIn("event", kinds)
        self.assertIn("grant", kinds)

    def test_flags_an_interpolated_mint(self) -> None:
        source = 'let id = format!("ak:strand:{}", uuid_v7());\n'
        self.assertEqual(self.scan({"src/ui.rs": source}, []), 1)

    def test_flags_a_generator_passed_as_a_value(self) -> None:
        source = "let realm_id = body.realm_id.unwrap_or_else(ids::generate_realm_id);\n"
        self.assertEqual(self.scan({"src/route.rs": source}, []), 1)

    def test_flags_the_generate_kind_string_form(self) -> None:
        source = 'let strand = StrandId::new(ids::generate("strand"))?;\n'
        self.assertEqual(self.scan({"src/route.rs": source}, []), 1)

    def test_retyping_an_existing_id_is_not_minting(self) -> None:
        # The sanctioned derivation: an existing event id's payload, re-prefixed.
        source = 'let message_id = format!("ak:message:{suffix}");\n'
        self.assertEqual(self.scan({"src/project.rs": source}, []), 0)

    def test_a_producer_allocated_kind_is_not_flagged(self) -> None:
        source = (
            'let capability = CapabilityId::new('
            'new_prefixed_uuid7("ak:capability:"))?;\n'
        )
        self.assertEqual(self.scan({"src/authz.rs": source}, []), 0)

    def test_a_recorded_verdict_passes(self) -> None:
        source = 'let id = format!("ak:strand:{}", uuid_v7());\n'
        self.assertEqual(
            self.scan(
                {"src/ui.rs": source},
                [
                    {
                        "repo": "some-repo",
                        "path": "src/ui.rs",
                        "verdict": "event_derived",
                        "reason": "known defect, tracked",
                    }
                ],
            ),
            0,
        )

    def test_an_unknown_verdict_is_rejected(self) -> None:
        with self.assertRaises(RuntimeError):
            self.scan(
                {"src/ui.rs": 'let id = format!("ak:strand:{}", uuid_v7());\n'},
                [
                    {
                        "repo": "some-repo",
                        "path": "src/ui.rs",
                        "verdict": "wontfix",
                        "reason": "not one of the three admissible outcomes",
                    }
                ],
            )

    def test_a_site_that_stopped_minting_fails_its_entry(self) -> None:
        self.assertEqual(
            self.scan(
                {"src/ui.rs": "fn unrelated() {}\n"},
                [
                    {
                        "repo": "some-repo",
                        "path": "src/ui.rs",
                        "verdict": "event_derived",
                        "reason": "already fixed",
                    }
                ],
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
