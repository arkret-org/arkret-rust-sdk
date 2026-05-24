#!/usr/bin/env python3
"""Verify the local package order in `.github/workflows/release-crates.yml`.

The workflow holds a flat list of workspace crates that must be packaged in
dependency order. Any valid topological order works; this script checks the
workflow's curated list against the workspace's actual dependency graph
(`cargo metadata --no-deps`) and complains when:

    * a crate appears before one of its workspace dependencies
    * a crate is missing from the workflow
    * the workflow names a crate the workspace no longer ships

It can also print one valid topological order for use as a starting point.

Usage:
    python tools/check-publish-order.py            # validate (CI-friendly)
    python tools/check-publish-order.py --print    # print one valid topo order

Exits 0 when the workflow is a valid topological order, 1 otherwise.
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
    """Extract the flat CRATES list from the package workflow YAML."""
    match = _CRATES_BLOCK_RE.search(workflow_text)
    if not match:
        raise SystemExit(
            f"could not find `CRATES: >-` block in {WORKFLOW.relative_to(REPO_ROOT)}"
        )
    return [token for token in match.group(1).split() if token]


def validate_workflow(
    workflow_list: list[str], workspace_deps: dict[str, set[str]]
) -> list[str]:
    """Check the workflow list is a valid topological order.

    Returns a list of human-readable problems; an empty list means the order
    is valid.
    """
    problems: list[str] = []
    workspace_names = set(workspace_deps)
    workflow_set = set(workflow_list)

    missing = sorted(workspace_names - workflow_set)
    extra = sorted(workflow_set - workspace_names)
    if missing:
        problems.append(f"workflow is missing workspace crates: {missing}")
    if extra:
        problems.append(f"workflow lists non-existent crates: {extra}")

    seen: set[str] = set()
    for crate in workflow_list:
        deps = workspace_deps.get(crate, set())
        unmet = sorted(dep for dep in deps if dep not in seen and dep in workspace_names)
        if unmet:
            problems.append(
                f"{crate!r} listed before its workspace deps: {unmet}"
            )
        seen.add(crate)
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print",
        action="store_true",
        dest="print_only",
        help="print one valid topological order and exit",
    )
    args = parser.parse_args(argv)

    metadata = cargo_metadata()
    workspace_names = {pkg["name"] for pkg in metadata["packages"]}
    workspace_deps = {
        pkg["name"]: {
            dep["name"] for dep in pkg["dependencies"] if dep["name"] in workspace_names
        }
        for pkg in metadata["packages"]
    }

    if args.print_only:
        for name in topological_order(metadata):
            print(name)
        return 0

    workflow_list = workflow_order(WORKFLOW.read_text(encoding="utf-8"))
    problems = validate_workflow(workflow_list, workspace_deps)
    if problems:
        print(
            "package order in .github/workflows/release-crates.yml is not a valid "
            "topological order:"
        )
        for line in problems:
            print(f"  {line}")
        return 1
    print(
        f"package order is a valid topological sort ({len(workflow_list)} crates)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
