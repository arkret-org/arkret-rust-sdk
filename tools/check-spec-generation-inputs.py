#!/usr/bin/env python3
"""Reject derived artifact inputs before SDK code generation starts."""

import argparse
import glob
import json
from pathlib import Path


def check_inputs(artifacts_dir: Path, generation_manifest: Path) -> None:
    artifacts_dir = artifacts_dir.resolve(strict=True)
    manifest = json.loads(generation_manifest.read_text(encoding="utf-8"))
    registry_manifest = json.loads(
        (artifacts_dir / "registry/registry-manifest.json").read_text(encoding="utf-8")
    )
    if registry_manifest.get("source_of_truth") is not True:
        raise ValueError("registry manifest must be canonical")

    registry_roles = {}
    for row in registry_manifest["registries"]:
        path = row["file"]
        if path in registry_roles:
            raise ValueError(f"duplicate registry manifest path: {path}")
        registry_roles[path] = row

    for entry in manifest["entries"]:
        for pattern in entry.get("artifacts", []):
            if Path(pattern).is_absolute() or ".." in Path(pattern).parts:
                raise ValueError(f"artifact input escapes artifacts root: {pattern}")
            matches = glob.glob(str(artifacts_dir / pattern))
            if not matches:
                raise ValueError(f"artifact input matches no file: {pattern}")
            for match in matches:
                path = Path(match).resolve(strict=True)
                if not path.is_relative_to(artifacts_dir) or not path.is_file():
                    raise ValueError(f"artifact input escapes artifacts root: {pattern}")
                relative = path.relative_to(artifacts_dir).as_posix()
                if relative.startswith("registry/"):
                    row = registry_roles.get(relative)
                    if row is None:
                        raise ValueError(f"unregistered registry input: {relative}")
                    if row.get("source_role") != "canonical" or row.get("source_of_truth") is not True:
                        raise ValueError(f"derived registry cannot be a generation input: {relative}")
                if path.suffix == ".json":
                    artifact = json.loads(path.read_text(encoding="utf-8"))
                    if artifact.get("source_of_truth") is False:
                        raise ValueError(f"derived artifact cannot be a generation input: {relative}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    check_inputs(args.artifacts_dir, args.manifest)


if __name__ == "__main__":
    main()
