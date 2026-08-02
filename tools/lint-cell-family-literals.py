#!/usr/bin/env python3
"""Reject duplicated registered cell-family literals outside generated constants."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATED_IDS = REPO_ROOT / "crates/wire/src/generated/event_kinds.rs"
CELL_FAMILY_LITERAL = re.compile(r'"(ak\.component\.[A-Za-z0-9_.-]+\.v1)"')
GENERATED_CONSTANT = re.compile(
    r"pub const [A-Z0-9_]+: &'static str\s*=\s*"
    r'"(ak\.component\.[A-Za-z0-9_.-]+\.v1)";'
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="reject registered cell-family literals outside generated constants"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="repository root to scan (defaults to the SDK repository)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    scan_root = args.root.resolve()
    generated = GENERATED_IDS.read_text(encoding="utf-8")
    registered = set(GENERATED_CONSTANT.findall(generated))
    if not registered:
        raise RuntimeError(f"no CellFamilyId constants found in {GENERATED_IDS}")

    violations: list[str] = []
    for path in sorted(scan_root.rglob("*.rs")):
        if any(part in {".git", "target", "node_modules"} for part in path.parts):
            continue
        if path == GENERATED_IDS:
            continue
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            for family in CELL_FAMILY_LITERAL.findall(line):
                if family in registered:
                    relative = path.relative_to(scan_root).as_posix()
                    violations.append(f"{relative}:{line_number}: {family}")

    if violations:
        print(
            "registered cell-family literals must use "
            "arkret_wire::CellFamilyId associated constants:"
        )
        print("\n".join(violations))
        return 1

    print(f"cell-family literal guard passed ({len(registered)} registered families)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
