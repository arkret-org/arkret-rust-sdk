#!/usr/bin/env python3
"""Reject runtime/framework dependencies from Arkret protocol leaf crates."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


LEAF_PACKAGES = (
    "arkret-canonical",
    "arkret-wire-base",
    "arkret-wire-identity",
    "arkret-wire-collab",
    "arkret-wire-edge",
    "arkret-schema",
    "arkret-policy",
    "arkret-state",
)

FORBIDDEN_PACKAGES = {
    "aws-lc-sys",
    "reqwest",
    "salvo",
    "salvo-oapi",
    "tokio",
    "zstd-sys",
}

FORBIDDEN_ARKRET_PACKAGES = {
    "arkret-http-client",
    "arkret-server",
    "arkret-state",
}


def cargo_metadata(root: Path) -> dict[str, object]:
    process = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(process.stdout)


def default_dependency_names(root: Path, package: str) -> set[str]:
    process = subprocess.run(
        [
            "cargo",
            "tree",
            "-p",
            package,
            "--no-default-features",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return {
        line.split()[0]
        for line in process.stdout.splitlines()
        if line and not line.startswith("[")
    }


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    metadata = cargo_metadata(root)
    packages = metadata["packages"]
    assert isinstance(packages, list)
    package_names = {package["name"] for package in packages}

    failures: list[str] = []
    checked = 0
    for leaf in LEAF_PACKAGES:
        if leaf not in package_names:
            continue
        checked += 1
        names = default_dependency_names(root, leaf)
        names.discard(leaf)
        forbidden = sorted(names & (FORBIDDEN_PACKAGES | FORBIDDEN_ARKRET_PACKAGES))
        if forbidden:
            failures.append(f"{leaf}: {', '.join(forbidden)}")

    if checked == 0:
        print("no core-split leaf crates exist yet; dependency guard is ready")
        return 0
    if failures:
        print("protocol leaf dependency violations:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"checked {checked} protocol leaf crate(s); no forbidden dependencies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
