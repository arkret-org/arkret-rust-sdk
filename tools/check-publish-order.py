#!/usr/bin/env python3
"""Verify the publish order in `.github/workflows/release-crates.yml`.

The workflow holds a flat list of workspace crates that must be published in
dependency order. This script derives that order from `cargo metadata
--no-deps` and diff-checks it against the workflow.

Usage:
    python tools/check-publish-order.py            # diff-check (CI-friendly)
    python tools/check-publish-order.py --print    # only print the derived order

Exits 0 when the workflow matches the derived order, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-crates.yml"


def cargo_metadata() -> dict:
    """Return the parsed `cargo metadata --no-deps` JSON for the workspace."""
    proc = subprocess.run(
        [
            "cargo",
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            str(REPO_ROOT / "Cargo.toml"),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return json.loads(proc.stdout)


def topological_order(metadata: dict) -> list[str]:
    """Kahn-sort the workspace packages so each crate appears after its deps.

    Ties are broken alphabetically so the ordering is deterministic and a
    consistent diff target for the workflow file.
    """
    workspace_names = {pkg["name"] for pkg in metadata["packages"]}
    deps: dict[str, set[str]] = {
        pkg["name"]: {
            dep["name"] for dep in pkg["dependencies"] if dep["name"] in workspace_names
        }
        for pkg in metadata["packages"]
    }

    order: list[str] = []
    remaining = dict(deps)
    while remaining:
        ready = sorted(name for name, edges in remaining.items() if not edges)
        if not ready:
            raise SystemExit(f"dependency cycle in: {sorted(remaining)}")
        next_name = ready[0]
        order.append(next_name)
        remaining.pop(next_name)
        for edges in remaining.values():
            edges.discard(next_name)
    return order


_CRATES_BLOCK_RE = re.compile(
    r"^      CRATES: >-\s*\n((?:        .*\n)+)", re.MULTILINE
)


def workflow_order(workflow_text: str) -> list[str]:
    """Extract the flat CRATES list from the release workflow YAML."""
    match = _CRATES_BLOCK_RE.search(workflow_text)
    if not match:
        raise SystemExit(
            f"could not find `CRATES: >-` block in {WORKFLOW.relative_to(REPO_ROOT)}"
        )
    return [token for token in match.group(1).split() if token]


def diff(expected: Iterable[str], actual: Iterable[str]) -> list[str]:
    expected = list(expected)
    actual = list(actual)
    out: list[str] = []
    if expected == actual:
        return out
    out.append("--- workflow CRATES")
    out.append("+++ cargo metadata topo order")
    for index, (lhs, rhs) in enumerate(zip(expected, actual)):
        if lhs != rhs:
            out.append(f"  {index:2d}: {lhs!r} != {rhs!r}")
    if len(expected) != len(actual):
        out.append(f"  workflow has {len(expected)} crates, derived has {len(actual)}")
    return out


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print",
        action="store_true",
        dest="print_only",
        help="print the derived publish order and exit",
    )
    args = parser.parse_args(argv)

    metadata = cargo_metadata()
    derived = topological_order(metadata)

    if args.print_only:
        for name in derived:
            print(name)
        return 0

    expected = workflow_order(WORKFLOW.read_text(encoding="utf-8"))
    delta = diff(expected, derived)
    if delta:
        print(
            "publish order in .github/workflows/release-crates.yml does not match "
            "`cargo metadata` topological sort:"
        )
        for line in delta:
            print(line)
        return 1
    print(f"publish order matches cargo metadata ({len(expected)} crates)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
