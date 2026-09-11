#!/usr/bin/env python3
"""Reject hand-rolled Event digest preimages.

`conformance/encoding.md` §6 excludes exactly three top-level Envelope members from the
Event digest preimage: `event_id`, `proofs` and `unsigned`. The
SDK has exactly one implementation of that rule,
`arkret_wire::event_digest_preimage` (and `Event::digest_payload`, which
delegates to it).

Every hand-rolled copy of the rule found so far had drifted from it, and none of
them failed loudly -- a drifted preimage produces bytes no other implementation
reproduces, so a *valid* signature verifies as invalid:

  * `crates/signatures/tests/crypto_signature_fixture.rs` -- own copy;
  * `inkson/src/identity/agent_signer_evidence.rs` -- omitted `event_id`, so
    every well-formed Agent evidence Event failed as `SigningKeyMismatch`;
  * `inkson/src/views/chat/tests.rs` -- fixture signer with its own copy;
  * `soland/crates/server/tests/http_api/common.rs` -- kept `event_id` and
    stripped slots that do not exist on the envelope;
  * `arkret-spec` crypto-signature vector -- hashed the envelope, not the
    preimage.

So the guard does not look for "a wrong preimage" (undecidable in text); it
looks for the *act of building one by hand*: deleting the Event-only `event_id`
member from a JSON map. Removing `proofs` alone stays allowed -- many non-Event
signed objects (`EventBatchReceipt`, `PrincipalLocator`, DID documents) legally
strip their own `proofs` before signing, and those objects have no `event_id` to drop.

Runs over any sibling repository via `--root`, because the rule is cross-repo
and the drift was too:

    python tools/lint-event-preimage-authoring.py --root ../inkson
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALLOWLIST = REPO_ROOT / "tools" / "event_preimage_allowlist.json"

# `map.remove("event_id")`, `.swap_remove(...)`, `remove_entry(...)` -- any
# deletion of the Event-only excluded member.
HAND_ROLLED = re.compile(
    r"""(?:remove|remove_entry|swap_remove|shift_remove)\s*\(\s*"(event_id)"\s*\)"""
)
SKIP_DIRS = {".git", "target", "node_modules", "vendor", "dist", "artifacts"}
# The downstream repo-local copies of this guard (inkson and soland run one in
# their own test gate, where the sibling SDK checkout may be absent). They name
# the forbidden shapes in order to search for them, the same self-exclusion
# `soland/scripts/stale-literal-scan.sh` takes.
SKIP_FILES = {"event_preimage_authoring_guard.rs"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="reject hand-rolled Event digest preimages outside the SDK's single implementation"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="repository root to scan (defaults to the SDK repository)",
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=DEFAULT_ALLOWLIST,
        help="JSON allowlist of paths that legally delete these members",
    )
    return parser.parse_args()


def load_allowlist(path: Path, repo: str) -> dict[str, str]:
    """Entries for one repository.

    Entries are scoped by `repo` (the scan root's directory name) so the
    stale-entry check below stays meaningful: without scoping, every entry
    belonging to a sibling repository would read as stale on each scan.
    """
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        entry["path"]: entry["reason"]
        for entry in payload.get("entries", [])
        if entry["repo"] == repo
    }


def main() -> int:
    args = parse_args()
    scan_root = args.root.resolve()
    if not scan_root.is_dir():
        print(f"scan root does not exist: {scan_root}")
        return 1
    allowlist = load_allowlist(args.allowlist, scan_root.name)

    violations: list[str] = []
    used: set[str] = set()
    for path in sorted(scan_root.rglob("*.rs")):
        if any(part in SKIP_DIRS for part in path.parts) or path.name in SKIP_FILES:
            continue
        relative = path.relative_to(scan_root).as_posix()
        text = path.read_text(encoding="utf-8")
        hits = [
            (number, match.group(1))
            for number, line in enumerate(text.splitlines(), start=1)
            for match in HAND_ROLLED.finditer(line)
        ]
        if not hits:
            continue
        if relative in allowlist:
            used.add(relative)
            continue
        for number, field in hits:
            violations.append(f"{relative}:{number}: deletes {field!r} by hand")

    for stale in sorted(set(allowlist) - used):
        violations.append(
            f"{stale}: allowlisted but no longer deletes an excluded member; drop the entry"
        )

    if violations:
        print(
            "the Event digest preimage has one implementation: "
            "arkret_wire::event_digest_preimage (encoding.md section 6). "
            "Call it instead of deleting excluded members by hand:"
        )
        print("\n".join(f"  {violation}" for violation in violations))
        return 1

    print(
        f"event-preimage authoring guard passed for {scan_root.name} "
        f"({len(used)} allowlisted path(s))"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
