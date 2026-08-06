#!/usr/bin/env python3
"""Audit every point that mints an id for an event-derived kind.

`zh/models/common-fields.md` §6.0: a create-once object's id is its create
Event's `event_id` retyped. Nobody *chooses* it. So a freshly minted UUID with an
event-derived prefix names an object no receiver can agree with — and because the
value is shaped like a valid typed id, every schema, every newtype and every
round-trip test accepts it. The failure only shows up as an unresolvable
reference, or as two ids for one object after a retry.

`arkret_identifiers::new_prefixed_uuid7` carries a `debug_assert` against these
prefixes, which catches the SDK path in debug builds only. This scanner covers
the two ways around it: a `format!("ak:<kind>:{...}")` that never touches the
helper, and a release build where the assert is compiled out.

What counts as minting: an event-derived prefix on the same line as a fresh-id
generator, or a call to a `generate_<kind>_id()` / `generate("<kind>")` helper for
such a kind. *Retyping* is not minting and is not flagged --
`format!("ak:message:{suffix}")` from an existing event id is the sanctioned
derivation.

The prefix list is read out of the SDK source, so this scanner cannot drift from
`EVENT_DERIVED_ID_KIND_PREFIXES`.

The allowlist is the audit itself: one entry per file that mints, carrying the
verdict for that site. `zh/models/common-fields.md` §6.0 admits exactly three:

  * `event_derived` -- a real protocol object, so the id MUST come from the
    create Event. An entry with this category is a *known defect*, not an
    exemption, and says what blocks it.
  * `local_ref` -- a server-local correlation token standing behind no Event; it
    belongs to its own `ak:local_ref:` kind.
  * `no_id` -- the record should carry no id at all.

Plus one category for non-production code:

  * `test_fixture` -- a synthetic id for an Event that exists only inside the
    test's own store. Legitimate, but it must stay visible: a fixture id that
    leaks into a shared helper becomes a production defect.

Usage:
    python tools/lint-event-derived-id-minting.py --root ../soland
    python tools/lint-event-derived-id-minting.py --root ../soland --report
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
IDENTIFIERS = REPO_ROOT / "crates" / "identifiers" / "src" / "lib.rs"
DEFAULT_ALLOWLIST = REPO_ROOT / "tools" / "event_derived_id_minting_allowlist.json"
VERDICTS = {"event_derived", "local_ref", "no_id", "test_fixture"}
SKIP_DIRS = {".git", "target", "node_modules", "vendor", "dist", "artifacts"}
FRESH_ID = re.compile(r"uuid_v7|now_v7|new_v7|new_prefixed_uuid7|Uuid::new")


def event_derived_kinds() -> list[str]:
    """The kinds from `EVENT_DERIVED_ID_KIND_PREFIXES`, read from SDK source."""
    source = IDENTIFIERS.read_text(encoding="utf-8")
    match = re.search(
        r"EVENT_DERIVED_ID_KIND_PREFIXES:\s*&\[&str\]\s*=\s*&\[(.*?)\];",
        source,
        re.DOTALL,
    )
    if match is None:
        raise RuntimeError(f"cannot find EVENT_DERIVED_ID_KIND_PREFIXES in {IDENTIFIERS}")
    kinds = re.findall(r'"ak:([a-z_]+):"', match.group(1))
    if not kinds:
        raise RuntimeError("EVENT_DERIVED_ID_KIND_PREFIXES parsed empty")
    return kinds


def detectors(kinds: list[str]) -> list[re.Pattern[str]]:
    alternation = "|".join(kinds)
    return [
        # No `\(`: `unwrap_or_else(ids::generate_realm_id)` passes the generator
        # as a value and mints just the same. That form hid one live site.
        re.compile(rf"\bgenerate_({alternation})_id\b"),
        re.compile(rf'\bgenerate\(\s*"({alternation})"'),
    ]


def load_allowlist(path: Path, repo: str) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = {}
    for entry in payload.get("entries", []):
        if entry["repo"] != repo:
            continue
        if entry["verdict"] not in VERDICTS:
            raise RuntimeError(f"unknown verdict {entry['verdict']!r} for {entry['path']}")
        entries[entry["path"]] = entry
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(
        description="audit id minting for kinds whose ids must come from a create Event"
    )
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument(
        "--report",
        action="store_true",
        help="print every minting site with its verdict instead of only failures",
    )
    args = parser.parse_args()

    scan_root = args.root.resolve()
    if not scan_root.is_dir():
        print(f"scan root does not exist: {scan_root}")
        return 1
    kinds = event_derived_kinds()
    prefix_re = re.compile(r'"ak:(%s):' % "|".join(kinds))
    helper_res = detectors(kinds)
    allowlist = load_allowlist(args.allowlist, scan_root.name)

    sites: dict[str, list[str]] = {}
    for path in sorted(scan_root.rglob("*.rs")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        relative = path.relative_to(scan_root).as_posix()
        for number, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            minted = any(pattern.search(line) for pattern in helper_res) or (
                prefix_re.search(line) is not None and FRESH_ID.search(line) is not None
            )
            if minted:
                sites.setdefault(relative, []).append(f"{relative}:{number}: {line.strip()}")

    violations: list[str] = []
    for relative, hits in sorted(sites.items()):
        entry = allowlist.get(relative)
        if entry is None:
            violations.extend(hits)
            continue
        if args.report:
            print(f"[{entry['verdict']}] {relative} ({len(hits)} site(s)) -- {entry['reason']}")
    for stale in sorted(set(allowlist) - set(sites)):
        violations.append(f"{stale}: audited but no longer mints an event-derived id; drop the entry")

    if violations:
        print(
            "an event-derived kind's id MUST come from its create Event "
            "(zh/models/common-fields.md section 6.0). Each site below is unaudited: "
            "derive the id, move it to `ak:local_ref:`, drop it, or record the verdict in "
            f"{args.allowlist.name}:"
        )
        print("\n".join(f"  {violation}" for violation in violations))
        return 1

    audited = sum(len(hits) for hits in sites.values())
    print(
        f"event-derived id minting audit passed for {scan_root.name} "
        f"({audited} site(s) in {len(sites)} file(s), all with a recorded verdict)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
