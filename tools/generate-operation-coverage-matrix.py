#!/usr/bin/env python3
"""Generate the claimable-profile operation coverage matrix.

The matrix does not infer implementation from registry constants. Coverage is
credited only when tools/operation-coverage-evidence.json names an explicit SDK
API, handler, or test location containing the canonical operation id.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
DEFAULT_ARTIFACTS = REPO.parent / "arkret-spec" / "spec" / "v1" / "artifacts"
DEFAULT_EVIDENCE = REPO / "tools" / "operation-coverage-evidence.json"
DEFAULT_OUTPUT = REPO / "docs" / "operation-coverage-matrix.md"
AUDITED_CLAIMABLE_PROFILES = 66


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def evidence_path(reference: str) -> Path:
    relative = reference.split("::", 1)[0]
    return REPO / relative


RUST_ITEM_DECLARATION = re.compile(
    r"\b(?:fn|struct|enum|trait|type|const|static|mod)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)


def evidence_symbol(reference: str) -> str:
    parts = reference.split("::")
    if len(parts) < 2 or not parts[-1]:
        raise ValueError(f"evidence reference must end in a symbol: {reference}")
    return parts[-1]


def validate_evidence_symbol(reference: str, source: str) -> None:
    symbol = evidence_symbol(reference)
    declared = {match.group(1) for match in RUST_ITEM_DECLARATION.finditer(source)}
    if symbol not in declared:
        raise ValueError(f"evidence symbol does not exist: {reference}")


def operation_id_spellings(operation_id: str) -> tuple[str, str]:
    """Every way an evidence file may name one operation.

    Rust sources name operations through the generated
    `ServiceOperationId` associated constant rather than a bare wire literal,
    so both spellings prove the same binding.
    """
    associated = operation_id.removeprefix("ak.").replace(".", "_").upper()
    return operation_id, associated


def validate_evidence(
    evidence: dict[str, Any], operation_ids: set[str]
) -> dict[str, dict[str, list[str]]]:
    if evidence.get("schema") != "arkret.sdk-operation-coverage-evidence.v1":
        raise ValueError("operation coverage evidence schema mismatch")
    operations = evidence.get("operations")
    if not isinstance(operations, dict):
        raise ValueError("operation coverage evidence missing operations object")
    normalized: dict[str, dict[str, list[str]]] = {}
    for operation_id, entry in operations.items():
        if operation_id not in operation_ids:
            raise ValueError(f"evidence references unknown operation {operation_id}")
        if not isinstance(entry, dict) or set(entry) != {"api", "handler", "test"}:
            raise ValueError(f"evidence for {operation_id} must have api/handler/test")
        normalized[operation_id] = {}
        for kind in ("api", "handler", "test"):
            references = entry[kind]
            if not isinstance(references, list) or not all(
                isinstance(reference, str) and reference for reference in references
            ):
                raise ValueError(f"{operation_id}.{kind} must be a string array")
            if len(references) != len(set(references)):
                raise ValueError(f"{operation_id}.{kind} contains duplicate evidence")
            for reference in references:
                path = evidence_path(reference)
                if not path.is_file():
                    raise ValueError(f"evidence path does not exist: {reference}")
                source = path.read_text(encoding="utf-8")
                if path.suffix == ".rs":
                    validate_evidence_symbol(reference, source)
                if not any(
                    spelling in source
                    for spelling in operation_id_spellings(operation_id)
                ):
                    raise ValueError(
                        f"evidence path {reference} does not contain {operation_id}"
                    )
            normalized[operation_id][kind] = sorted(references)
    return normalized


def effective_operations(
    profile_id: str,
    requirements: dict[str, Any],
    cache: dict[str, set[str]],
    stack: tuple[str, ...] = (),
) -> set[str]:
    if profile_id in cache:
        return cache[profile_id]
    if profile_id in stack:
        raise ValueError("profile inheritance cycle: " + " -> ".join((*stack, profile_id)))
    entry = requirements.get(profile_id)
    if not isinstance(entry, dict):
        raise ValueError(f"claimable profile lacks requirements: {profile_id}")
    rows = entry.get("operation_requirements", [])
    if not isinstance(rows, list) or any(
        not isinstance(row, dict) or not isinstance(row.get("operation_id"), str)
        for row in rows
    ):
        raise ValueError(f"{profile_id}.operation_requirements must be typed rows")
    operations = {row["operation_id"] for row in rows}
    for parent in entry.get("inherits", []):
        operations.update(
            effective_operations(parent, requirements, cache, (*stack, profile_id))
        )
    cache[profile_id] = operations
    return operations


def short_evidence(references: list[str]) -> str:
    if not references:
        return "—"
    return "<br>".join(f"`{reference}`" for reference in references)


def generate(artifacts: Path, evidence_path_value: Path) -> str:
    profiles = load_json(artifacts / "profiles" / "conformance-profiles.json")
    registry = load_json(artifacts / "registry" / "operation-registry.json")
    operations = {
        entry["operation_id"]: entry
        for entry in registry.get("operations", [])
        if isinstance(entry, dict) and isinstance(entry.get("operation_id"), str)
    }
    evidence = validate_evidence(load_json(evidence_path_value), set(operations))
    claimable = sorted(
        set(profiles.get("implementation_profiles", []))
        | set(profiles.get("deployment_profiles", []))
        | set(profiles.get("hardening_profiles", []))
    )
    requirements = profiles.get("profile_requirements", {})
    roles = profiles.get("profile_roles", {})
    # Audited claimable catalog size. It dropped from 70 to 69 when the Spec
    # deleted ak.profile.disappearing.v1 along with Disappearing Messages, and
    # from 69 to 68 when the Spec deleted
    # ak.profile.morph.schema_migration_transformations.v1 (26ff6ab2); the
    # service-resolution-mirror removal leaves 66 claimable profiles. Its
    # former matrix rows referenced deleted mirror operations and must disappear.
    # The guard is here so a silent catalog change cannot slip into the matrix, not
    # to pin a number forever, so it moves with a reviewed deletion.
    if len(claimable) != AUDITED_CLAIMABLE_PROFILES:
        raise ValueError(
            f"claimable profile set changed from the audited {AUDITED_CLAIMABLE_PROFILES} "
            f"to {len(claimable)}; review the catalog boundary before regenerating"
        )

    cache: dict[str, set[str]] = {}
    rows: list[tuple[str, str, str, str, dict[str, list[str]], str]] = []
    for profile_id in claimable:
        role = roles.get(profile_id, "conformance")
        for operation_id in sorted(
            effective_operations(profile_id, requirements, cache)
        ):
            operation = operations.get(operation_id)
            if operation is None:
                raise ValueError(
                    f"profile {profile_id} requires unknown operation {operation_id}"
                )
            proof = evidence.get(operation_id, {"api": [], "handler": [], "test": []})
            present = sum(bool(proof[kind]) for kind in ("api", "handler", "test"))
            status = "complete" if present == 3 else "partial" if present else "gap"
            rows.append(
                (
                    profile_id,
                    role,
                    operation_id,
                    operation.get("http", "non-http"),
                    proof,
                    status,
                )
            )

    lines = [
        "# Claimable Profile Operation Coverage Matrix",
        "",
        "> Generated by `tools/generate-operation-coverage-matrix.py`; do not edit by hand.",
        "> Coverage is credited only from explicit evidence in `tools/operation-coverage-evidence.json`.",
        "",
        f"- Claimable profiles: {len(claimable)} (implementation + deployment + hardening profiles)",
        f"- Effective profile/operation requirements: {len(rows)}",
        f"- Complete rows: {sum(row[-1] == 'complete' for row in rows)}",
        f"- Partial rows: {sum(row[-1] == 'partial' for row in rows)}",
        f"- Gap rows: {sum(row[-1] == 'gap' for row in rows)}",
        "",
        "`gap` is an explicit non-claim: registry recognition or a generated constant is not SDK implementation evidence. Inherited requirements are expanded into every claiming child profile.",
        "",
        "| Profile | Role | Operation | Binding | SDK API | Handler | Test | Status |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for profile_id, role, operation_id, binding, proof, status in rows:
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{profile_id}`",
                    f"`{role}`",
                    f"`{operation_id}`",
                    f"`{binding}`",
                    short_evidence(proof["api"]),
                    short_evidence(proof["handler"]),
                    short_evidence(proof["test"]),
                    status,
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACTS)
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        output = generate(args.artifacts, args.evidence)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"operation coverage matrix: {error}", file=sys.stderr)
        return 1
    if args.check:
        if not args.output.is_file() or args.output.read_text(encoding="utf-8") != output:
            print(
                "operation coverage matrix drifted; run "
                "python tools/generate-operation-coverage-matrix.py",
                file=sys.stderr,
            )
            return 1
        print("operation coverage matrix is current")
        return 0
    args.output.write_text(output, encoding="utf-8", newline="\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
