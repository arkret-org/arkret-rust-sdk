#!/usr/bin/env python3
"""Guard JSON Schema identity references against Rust wire-field types.

The protocol has deliberately disjoint identity shapes: complete AccountId and
ActorId objects, stable identity cores, DIDs for resolution, and DID URLs for keys. This
audit resolves public Rust struct fields to their schema owner (an explicit
rustdoc pointer wins, otherwise the schema definition name is inferred) and
rejects shape substitutions or unsupported role-ID wrappers.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from wire_value_audit import (
    FIELD_RE,
    POINTER_RE,
    ROOT,
    STRUCT_RE,
    SchemaResolver,
    matching_brace,
    mask_non_code,
    normalize_pointer,
    preceding_docs,
    prepared_source,
    production_rust_files,
    split_top_level_fields,
)

DEFAULT_SPEC_ROOT = ROOT.parent / "arkret-spec" / "spec" / "v1" / "artifacts" / "schemas"
IDENTITY_TYPES = {
    "DidCoreId",
    "Did",
    "DidKey",
    "DidUrl",
    "CoreId",
    "PrincipalId",
    "ActorId",
    "AccountId",
    "ServiceId",
}
TYPE_RE = re.compile(r"\b(" + "|".join(sorted(IDENTITY_TYPES)) + r")\b")


@dataclass(frozen=True)
class RustField:
    path: Path
    line: int
    struct_name: str
    field_name: str
    rust_type: str
    spec_pointer: str | None

    @property
    def display(self) -> str:
        return f"{self.path.as_posix()}:{self.line}::{self.struct_name}.{self.field_name}"


def scan_source_file(path: Path, source_root: Path) -> list[RustField]:
    source, masked = prepared_source(path)
    found: list[RustField] = []
    for struct_match in STRUCT_RE.finditer(masked):
        opening = masked.find("{", struct_match.start(), struct_match.end())
        closing = matching_brace(masked, opening)
        body = source[opening + 1 : closing]
        masked_body = masked[opening + 1 : closing]
        docs = preceding_docs(source, struct_match.start())
        pointer_match = POINTER_RE.search(docs)
        pointer = normalize_pointer(pointer_match.group(1)) if pointer_match else None
        for offset, raw_field in split_top_level_fields(body, masked_body):
            field_match = FIELD_RE.search(mask_non_code(raw_field).strip())
            if not field_match:
                continue
            absolute_offset = opening + 1 + offset
            found.append(
                RustField(
                    path=path.relative_to(source_root),
                    line=source.count("\n", 0, absolute_offset) + 1,
                    struct_name=struct_match.group(1),
                    field_name=field_match.group(1),
                    rust_type=" ".join(field_match.group(2).split()),
                    spec_pointer=pointer,
                )
            )
    return found


def scan_fields(source_root: Path) -> list[RustField]:
    fields: list[RustField] = []
    for path in production_rust_files(source_root):
        fields.extend(scan_source_file(path, source_root))
    return fields


def is_did_key_scalar(node: Any) -> bool:
    """True when a resolved def narrows to a fragmentless `did:key` string.

    A def named `<something>_did` may alias `did_key`, which is strictly
    narrower than a generic `did`. Matching on the alias name alone would widen
    the required Rust type from `DidKey` back to `Did`, so the resolved pattern
    decides.
    """
    return (
        isinstance(node, dict)
        and node.get("type") == "string"
        and isinstance(node.get("pattern"), str)
        and node["pattern"].startswith("^did:key:")
    )


def referenced_identity_kind(
    resolver: SchemaResolver,
    path: Path,
    node: Any,
    seen: set[tuple[Path, int]] | None = None,
) -> str | None:
    if not isinstance(node, dict):
        return None
    reference = node.get("$ref")
    if isinstance(reference, str):
        tail = reference.rsplit("/", 1)[-1]
        if tail == "account_id":
            return "account"
        if tail == "actor_id":
            return "actor"
        if tail in {"did_core_id", "core_id"}:
            return "core"
        if tail in {"did_key", "did_key_did"}:
            return "did_key"
        if tail == "did_url":
            return "url"
        # A def whose whole body is another `$ref` is an alias, and the name it
        # was given says nothing about the scalar it narrows to:
        # `requesting_device_public_key_did` aliases `did_key`, which is a
        # strictly narrower string than a generic `did`. Follow the alias before
        # falling back to the name suffix, or the suffix silently widens the
        # required Rust type.
        if tail == "did" or tail.endswith("_did"):
            try:
                _, alias_node = resolver.resolve_ref(path, node)
            except (FileNotFoundError, KeyError, json.JSONDecodeError, TypeError):
                return "did"
            if is_did_key_scalar(alias_node):
                return "did_key"
            return "did"
        # A reference to a compound object may contain identity fields without
        # itself being an identity scalar. Only aliases whose final reference
        # names one of the scalar definitions above participate in this gate.
        return None
    marker = (path, id(node))
    seen = seen or set()
    if marker in seen:
        return None
    seen.add(marker)
    candidates: set[str] = set()
    for key in ("allOf", "anyOf", "oneOf"):
        branches = node.get(key)
        if isinstance(branches, list):
            branch_kinds = [
                referenced_identity_kind(resolver, path, branch, seen.copy())
                for branch in branches
            ]
            if any(kind is None for kind in branch_kinds):
                return None
            candidates.update(kind for kind in branch_kinds if kind is not None)
    if node.get("type") == "array" and isinstance(node.get("items"), dict):
        kind = referenced_identity_kind(resolver, path, node["items"], seen.copy())
        if kind:
            candidates.add(kind)
    return next(iter(candidates)) if len(candidates) == 1 else None


def owner_for_field(
    resolver: SchemaResolver, field: RustField
) -> tuple[Path, Any, str] | None:
    if field.spec_pointer:
        try:
            path, owner = resolver.pointer_node(field.spec_pointer)
            path, owner = resolver.resolve_ref(path, owner)
            return path, owner, field.spec_pointer
        except (FileNotFoundError, KeyError, json.JSONDecodeError, TypeError):
            return None
    inferred = resolver.inferred_owner(field.struct_name, field.field_name)
    if inferred is None:
        return None
    path, fragment, owner = inferred
    return path, owner, f"{path.name}{fragment}"


def schema_kind_for_field(
    resolver: SchemaResolver, field: RustField
) -> tuple[str | None, str | None]:
    resolved = owner_for_field(resolver, field)
    if resolved is None:
        return None, None
    path, owner, pointer = resolved
    properties = owner.get("properties") if isinstance(owner, dict) else None
    if not isinstance(properties, dict) or field.field_name not in properties:
        return None, pointer
    return (
        referenced_identity_kind(resolver, path, properties[field.field_name]),
        f"{pointer}/properties/{field.field_name}",
    )


def identity_type(rust_type: str) -> str | None:
    matches = set(TYPE_RE.findall(rust_type))
    return next(iter(matches)) if len(matches) == 1 else None


def validate(fields: Iterable[RustField], resolver: SchemaResolver) -> list[str]:
    errors: list[str] = []
    for field in fields:
        actual = identity_type(field.rust_type)
        if actual == "CoreId":
            errors.append(f"unsupported identity alias {actual}: {field.display}")
            continue
        if actual in {"PrincipalId", "ServiceId"}:
            errors.append(f"unsupported role-ID wrapper {actual}: {field.display}")
            continue
        expected_kind, pointer = schema_kind_for_field(resolver, field)
        if expected_kind is None:
            continue
        expected = {
            "account": {"AccountId"},
            "actor": {"ActorId"},
            "core": {"DidCoreId"},
            "did": {"Did"},
            "did_key": {"DidKey"},
            "url": {"DidUrl"},
        }[expected_kind]
        if actual not in expected:
            errors.append(
                f"schema identity type mismatch: {field.display} is {field.rust_type}, "
                f"but {pointer} requires {expected_kind} ({', '.join(sorted(expected))})"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--spec-root", type=Path, default=DEFAULT_SPEC_ROOT)
    args = parser.parse_args(argv)
    resolver = SchemaResolver(args.spec_root)
    fields = scan_fields(args.source_root.resolve())
    errors = validate(fields, resolver)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        print(f"identity type audit failed with {len(errors)} mismatch(es)", file=sys.stderr)
        return 1
    mapped = sum(schema_kind_for_field(resolver, field)[0] is not None for field in fields)
    print(f"identity type audit passed ({mapped} schema-mapped public fields)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
