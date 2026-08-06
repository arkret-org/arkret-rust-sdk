#!/usr/bin/env python3
"""Self-test for `tools/lint-event-preimage-authoring.py`.

A scanner nobody has seen fail is indistinguishable from a scanner that matches
nothing. Each case below reproduces one hand-rolled preimage that shipped, plus
the legitimate shapes the guard must keep quiet about.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "tools" / "lint-event-preimage-authoring.py"
SPEC = importlib.util.spec_from_file_location("lint_event_preimage_authoring", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
LINT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LINT)


class EventPreimageAuthoringGuardTests(unittest.TestCase):
    def scan(self, sources: dict[str, str], allowlist: list[dict[str, str]]) -> int:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "some-repo"
            for relative, text in sources.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            allowlist_path = Path(directory) / "allowlist.json"
            allowlist_path.write_text(json.dumps({"entries": allowlist}), encoding="utf-8")
            parsed = LINT.argparse.Namespace(root=root, allowlist=allowlist_path)
            original = LINT.parse_args
            LINT.parse_args = lambda: parsed  # type: ignore[assignment]
            try:
                return LINT.main()
            finally:
                LINT.parse_args = original

    def test_flags_the_inkson_agent_evidence_shape(self) -> None:
        # The copy that omitted `event_id` and rejected every valid evidence Event.
        source = """
fn verify(event: &Event) {
    object.remove("proofs");
    object.remove("unsigned");
    object.remove("actor_kind");
}
"""
        self.assertEqual(self.scan({"src/evidence.rs": source}, []), 1)

    def test_flags_a_hand_rolled_event_id_exclusion(self) -> None:
        source = 'fn preimage() { map.remove("event_id"); }\n'
        self.assertEqual(self.scan({"src/sign.rs": source}, []), 1)

    def test_allows_stripping_proofs_from_a_non_event_object(self) -> None:
        # EventBatchReceipt / PrincipalLocator / DID documents legally strip
        # their own `proofs` before signing and have neither excluded member.
        source = 'fn sign(receipt: &Receipt) { object.remove("proofs"); }\n'
        self.assertEqual(self.scan({"src/receipt.rs": source}, []), 0)

    def test_allows_the_single_implementation_when_allowlisted(self) -> None:
        source = 'pub fn event_digest_preimage() { map.remove("event_id"); }\n'
        self.assertEqual(
            self.scan(
                {"src/wire.rs": source},
                [{"repo": "some-repo", "path": "src/wire.rs", "reason": "the one implementation"}],
            ),
            0,
        )

    def test_rejects_an_allowlist_entry_that_no_longer_applies(self) -> None:
        # A stale exemption is a standing licence to hand-roll the rule again.
        self.assertEqual(
            self.scan(
                {"src/wire.rs": "fn unrelated() {}\n"},
                [{"repo": "some-repo", "path": "src/wire.rs", "reason": "outdated"}],
            ),
            1,
        )

    def test_ignores_entries_scoped_to_another_repository(self) -> None:
        self.assertEqual(
            self.scan(
                {"src/wire.rs": "fn unrelated() {}\n"},
                [{"repo": "other-repo", "path": "src/other.rs", "reason": "elsewhere"}],
            ),
            0,
        )


if __name__ == "__main__":
    unittest.main()
