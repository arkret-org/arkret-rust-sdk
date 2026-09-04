#!/usr/bin/env python3
"""Enforce reviewed ownership decisions for high-confidence wire DTOs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


SDK_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKSPACE_ROOT = SDK_ROOT.parent
DEFAULT_DECISIONS = SDK_ROOT / "tools" / "wire_type_ownership_decisions.json"


def audit(workspace_root: Path, decisions_path: Path, required: set[str]) -> list[str]:
    decisions = json.loads(decisions_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    repositories = {
        entry["repository"]
        for category in ("forbidden", "classified")
        for entry in decisions[category]
    }
    missing = sorted(repo for repo in required if not (workspace_root / repo).is_dir())
    errors.extend(f"required repository is missing: {repo}" for repo in missing)

    for entry in decisions["forbidden"]:
        path = workspace_root / entry["repository"] / entry["path"]
        if not path.is_file():
            if entry["repository"] in required:
                errors.append(f"audited source is missing: {path}")
            continue
        if re.search(entry["pattern"], path.read_text(encoding="utf-8")):
            errors.append(
                f"{entry['repository']}/{entry['path']}: duplicates SDK owner {entry['owner']}"
            )

    for entry in decisions["classified"]:
        path = workspace_root / entry["repository"] / entry["path"]
        if not path.is_file():
            if entry["repository"] in required:
                errors.append(f"classified source is missing: {path}")
            continue
        if not re.search(entry["pattern"], path.read_text(encoding="utf-8")):
            errors.append(
                f"{entry['repository']}/{entry['path']}: classified type disappeared; review and remove its decision"
            )
        if not entry.get("classification") or not entry.get("rationale"):
            errors.append(f"classification is incomplete for {entry['repository']}/{entry['path']}")

    unknown = required - repositories
    errors.extend(f"required repository has no ownership decision: {repo}" for repo in sorted(unknown))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, default=DEFAULT_WORKSPACE_ROOT)
    parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    parser.add_argument("--require-repository", action="append", default=[])
    args = parser.parse_args()
    errors = audit(args.workspace_root.resolve(), args.decisions.resolve(), set(args.require_repository))
    if errors:
        print("wire type ownership audit failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("wire type ownership audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
