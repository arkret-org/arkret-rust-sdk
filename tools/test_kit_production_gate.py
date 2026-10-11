#!/usr/bin/env python3
"""Keep the shared protocol test-kit out of production builds.

``arkret-test-kit`` derives Ed25519 signing keys from public strings: any
production path that can reach it can mint a fixture actor's signature. The
crate is therefore only ever legitimate as a ``[dev-dependencies]`` entry, as an
``optional`` dependency behind a test-support feature, or in a crate that is
itself a test harness -- and the last case needs a written decision, because
"this whole crate is tests" is a claim about the crate, not something the
manifest states.

The audit walks every ``Cargo.toml`` under the workspace root, so a new
repository is covered the moment it declares the dependency; nothing has to be
added to a list first.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CRATE = "arkret-test-kit"
DEFAULT_DECISIONS = ROOT / "tools" / "test_kit_production_decisions.json"
SKIPPED_DIRECTORIES = {".git", "target", "node_modules", ".shared-target"}
DEV_SECTIONS = ("dev-dependencies", "dev_dependencies")


def manifests(workspace_root: Path) -> list[Path]:
    found: list[Path] = []
    stack = [workspace_root]
    while stack:
        directory = stack.pop()
        try:
            entries = list(directory.iterdir())
        except (PermissionError, FileNotFoundError):
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name not in SKIPPED_DIRECTORIES:
                    stack.append(entry)
            elif entry.name == "Cargo.toml":
                found.append(entry)
    return sorted(found)


def declaration_tables(document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Every dependency table in one manifest, tagged with its section name."""
    tables: list[tuple[str, dict[str, Any]]] = []
    # [workspace.dependencies] is inert on its own: it only takes effect where a
    # member writes `{ workspace = true }`, and that member declaration is what
    # this audit reads. Auditing both would report every entry twice and force a
    # decision for a table that links nothing.
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        node = document.get(section)
        if isinstance(node, dict):
            tables.append((section, node))
    target = document.get("target")
    if isinstance(target, dict):
        for platform, node in target.items():
            if not isinstance(node, dict):
                continue
            for nested in ("dependencies", "dev-dependencies", "build-dependencies"):
                inner = node.get(nested)
                if isinstance(inner, dict):
                    tables.append((f"target.{platform}.{nested}", inner))
    return tables


def is_optional(declaration: Any) -> bool:
    return isinstance(declaration, dict) and declaration.get("optional") is True


def default_activates_dependency(document: dict[str, Any], dependency: str) -> bool:
    """Follow local Cargo feature edges, including explicit optional activation."""
    features = document.get("features", {})
    pending = ["default"]
    visited: set[str] = set()
    while pending:
        feature = pending.pop()
        if feature in visited:
            continue
        visited.add(feature)
        for edge in features.get(feature, []):
            if edge in (dependency, f"dep:{dependency}"):
                return True
            if edge.startswith(f"{dependency}/"):
                return True
            # `dependency?/feature` never activates an optional dependency.
            if edge in features:
                pending.append(edge)
    return False


def load_decisions(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("version") != 1:
        raise ValueError("test-kit production decisions version must be 1")
    decisions: dict[str, str] = {}
    for entry in document.get("decisions", []):
        manifest = entry.get("manifest")
        rationale = entry.get("rationale")
        if not isinstance(manifest, str):
            raise ValueError("every decision needs a manifest path")
        if not isinstance(rationale, str) or len(rationale.strip()) < 20:
            raise ValueError(f"decision for {manifest} needs a concrete rationale")
        decisions[manifest] = rationale
    return decisions


def signing_surface_errors(workspace_root: Path) -> list[str]:
    """Fixture derivation belongs to test-kit, never the signatures crate."""
    errors: list[str] = []
    for manifest in manifests(workspace_root):
        try:
            document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            # The declaration audit below reports malformed manifests.
            continue
        if document.get("package", {}).get("name") != "arkret-signatures":
            continue
        source_root = manifest.parent / "src"
        sources = sorted(source_root.rglob("*.rs"))
        if not sources:
            errors.append(f"{manifest}: signatures source scan is empty")
        for source in sources:
            text = source.read_text(encoding="utf-8")
            for match in re.finditer(
                r"\bdevelopment_(?:signing_key(?:_seed)?|verifying_key)\b", text
            ):
                line = text.count("\n", 0, match.start()) + 1
                errors.append(
                    f"{source.relative_to(workspace_root).as_posix()}:{line}: "
                    f"{match.group()} belongs to arkret-test-kit, not signatures"
                )
    return errors


def audit(workspace_root: Path, decisions_path: Path) -> list[str]:
    decisions = load_decisions(decisions_path)
    errors = signing_surface_errors(workspace_root)
    claimed: set[str] = set()
    for manifest in manifests(workspace_root):
        try:
            document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
            errors.append(f"cannot parse {manifest}: {error}")
            continue
        relative = manifest.relative_to(workspace_root).as_posix()
        for section, table in declaration_tables(document):
            declaration = table.get(CRATE)
            if declaration is None:
                continue
            if any(marker in section for marker in DEV_SECTIONS):
                continue
            if is_optional(declaration):
                if default_activates_dependency(document, CRATE):
                    errors.append(
                        f"{relative} activates optional {CRATE} through default features; "
                        "test-support must remain opt-in"
                    )
                continue
            rationale = decisions.get(relative)
            if rationale is None:
                errors.append(
                    f"{relative} declares {CRATE} under [{section}] without a recorded "
                    "decision; move it to [dev-dependencies], mark it optional behind a "
                    "test-support feature, or record why this crate is itself a harness"
                )
                continue
            claimed.add(relative)
    for manifest in sorted(set(decisions) - claimed):
        errors.append(
            f"stale decision for {manifest}: it no longer declares {CRATE} as a "
            "non-dev dependency"
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", type=Path, default=ROOT.parent)
    parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    parser.add_argument(
        "--require-repository",
        action="append",
        default=[],
        help="fail when this repository is absent, so a partial checkout cannot pass",
    )
    args = parser.parse_args()
    workspace_root = args.workspace_root.resolve()
    missing = [
        repository
        for repository in args.require_repository
        if not (workspace_root / repository / "Cargo.toml").exists()
    ]
    if missing:
        print(
            "test-kit production gate cannot run against a partial checkout; missing: "
            + ", ".join(sorted(missing)),
            file=sys.stderr,
        )
        return 1
    errors = audit(workspace_root, args.decisions)
    if errors:
        print("test-kit production gate failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("test-kit production gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
