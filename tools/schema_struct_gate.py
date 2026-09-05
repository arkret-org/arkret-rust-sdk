#!/usr/bin/env python3
"""Compare registered Rust wire-struct field sets with live Spec schemas.

The coverage boundary is deliberate and reviewable: every public named struct
whose directly attached rustdoc contains a Spec schema pointer must occur in
``schema_struct_registry.json`` as either an exact mapping or an explained
exemption. Additional mappings may register structs whose pointer is maintained
only in the registry. This keeps new counterpart declarations from bypassing
the gate while avoiding fuzzy type/schema matching.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wire_value_audit import (  # noqa: E402
    POINTER_RE,
    STRUCT_RE,
    SchemaResolver,
    mask_non_code,
    matching_brace,
    normalize_pointer,
    split_top_level_fields,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SPEC_ROOT = ROOT.parent / "arkret-spec" / "spec" / "v1" / "artifacts" / "schemas"
DEFAULT_REGISTRY = ROOT / "tools" / "schema_struct_registry.json"
SERDE_RE = re.compile(r"#\s*\[\s*serde\s*\((.*?)\)\s*\]", re.DOTALL)
RENAME_RE = re.compile(r'\brename\s*=\s*"([^"]+)"')
RENAME_ALL_RE = re.compile(r'\brename_all\s*=\s*"([^"]+)"')
SKIP_RE = re.compile(r"\b(?:skip|skip_serializing)\b")
FLATTEN_RE = re.compile(r"\bflatten\b")
NAMED_FIELD_RE = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*:(?!:)\s*(.+)\Z",
    re.DOTALL | re.MULTILINE,
)
STRUCT_TRANSFORM_RE = re.compile(r"\b(?:transparent|into|try_into)\b")


@dataclass(frozen=True)
class RustStruct:
    rust_type: str
    file: str
    name: str
    line: int
    fields: frozenset[str] | None
    has_flatten: bool
    pointer: str | None
    unsupported_reason: str | None


def direct_docs(source: str, start: int) -> str:
    """Return only rustdoc attached to this declaration, never an outer type."""
    lines = source[:start].splitlines()
    index = len(lines) - 1
    while index >= 0 and (
        not lines[index].strip() or lines[index].lstrip().startswith("#")
    ):
        index -= 1
    selected: list[str] = []
    while index >= 0 and lines[index].lstrip().startswith("///"):
        selected.append(lines[index].strip())
        index -= 1
    return "\n".join(reversed(selected))


def preceding_attributes(source: str, start: int) -> str:
    lines = source[:start].splitlines()
    selected: list[str] = []
    index = len(lines) - 1
    while index >= 0:
        stripped = lines[index].strip()
        if stripped.startswith("#[") or stripped.startswith("///") or not stripped:
            selected.append(lines[index])
            index -= 1
            continue
        break
    return "\n".join(reversed(selected))


def rename_field(name: str, style: str | None) -> str:
    if style in (None, "snake_case"):
        return name
    words = name.split("_")
    if style == "camelCase":
        return words[0] + "".join(word[:1].upper() + word[1:] for word in words[1:])
    if style == "PascalCase":
        return "".join(word[:1].upper() + word[1:] for word in words)
    if style == "kebab-case":
        return "-".join(words)
    if style == "SCREAMING_SNAKE_CASE":
        return name.upper()
    raise ValueError(f"unsupported serde rename_all style {style!r}")


def parse_struct(
    path: Path,
    match: re.Match[str],
    source: str,
    masked: str,
    root: Path,
) -> RustStruct:
    name = match.group(1)
    opening = masked.find("{", match.start(), match.end())
    closing = matching_brace(masked, opening)
    body = source[opening + 1 : closing]
    masked_body = masked[opening + 1 : closing]
    attributes = preceding_attributes(source, match.start())
    serde_attributes = " ".join(SERDE_RE.findall(attributes))
    rename_all_match = RENAME_ALL_RE.search(serde_attributes)
    rename_all = rename_all_match.group(1) if rename_all_match else None
    fields: set[str] = set()
    has_flatten = False
    unsupported_reason = (
        "struct-level serde conversion/transparent representation is not an object field set"
        if STRUCT_TRANSFORM_RE.search(serde_attributes)
        else None
    )
    for _, raw_field in split_top_level_fields(body, masked_body):
        field_match = NAMED_FIELD_RE.search(mask_non_code(raw_field).strip())
        if field_match is None:
            continue
        field_attributes = " ".join(SERDE_RE.findall(raw_field))
        if unsupported_reason is not None:
            break
        if FLATTEN_RE.search(field_attributes):
            has_flatten = True
            continue
        if SKIP_RE.search(field_attributes):
            continue
        rename_match = RENAME_RE.search(field_attributes)
        field_name = rename_match.group(1) if rename_match else rename_field(field_match.group(1), rename_all)
        fields.add(field_name)
    docs = direct_docs(source, match.start())
    pointer_match = POINTER_RE.search(docs)
    pointer = normalize_pointer(pointer_match.group(1)) if pointer_match else None
    relative = path.relative_to(root).as_posix()
    return RustStruct(
        rust_type=f"{relative}::{name}",
        file=relative,
        name=name,
        line=source.count("\n", 0, match.start()) + 1,
        fields=None if unsupported_reason else frozenset(fields),
        has_flatten=has_flatten,
        pointer=pointer,
        unsupported_reason=unsupported_reason,
    )


def scan_structs(root: Path = ROOT) -> dict[str, RustStruct]:
    found: dict[str, RustStruct] = {}
    for path in sorted((root / "crates").glob("*/src/**/*.rs")):
        source = path.read_text(encoding="utf-8")
        masked = mask_non_code(source)
        for match in STRUCT_RE.finditer(masked):
            item = parse_struct(path, match, source, masked, root)
            found[item.rust_type] = item
    return found


def schema_property_names(
    resolver: SchemaResolver,
    path: Path,
    node: Any,
    seen: set[tuple[Path, str]] | None = None,
) -> set[str]:
    """Collect object properties through cross-file refs and composition."""
    seen = set() if seen is None else seen
    if isinstance(node, dict) and isinstance(node.get("$ref"), str):
        reference = node["$ref"]
        marker = (path.resolve(), reference)
        if marker in seen:
            return set()
        seen.add(marker)
        resolved_path, resolved_node = resolver.resolve_ref(path, node)
        names = schema_property_names(resolver, resolved_path, resolved_node, seen)
    else:
        names = set()
    if not isinstance(node, dict):
        return names
    properties = node.get("properties")
    if isinstance(properties, dict):
        names.update(properties)
    for keyword in ("allOf", "oneOf", "anyOf"):
        branches = node.get(keyword)
        if isinstance(branches, list):
            for branch in branches:
                names.update(schema_property_names(resolver, path, branch, seen.copy()))
    return names


def load_registry(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("version") != 1:
        raise ValueError("schema struct registry version must be 1")
    return document


def validate(
    registry_path: Path = DEFAULT_REGISTRY,
    spec_root: Path = DEFAULT_SPEC_ROOT,
    source_root: Path = ROOT,
) -> list[str]:
    registry = load_registry(registry_path)
    structs = scan_structs(source_root)
    mappings = registry.get("mappings", [])
    exemptions = registry.get("exemptions", [])
    errors: list[str] = []
    registered: dict[str, str] = {}
    for kind, entries in (("mapping", mappings), ("exemption", exemptions)):
        for entry in entries:
            rust_type = entry.get("rust_type")
            if not isinstance(rust_type, str):
                errors.append(f"{kind} without rust_type")
                continue
            if rust_type in registered:
                errors.append(f"duplicate registration for {rust_type}")
            registered[rust_type] = kind
    for rust_type, item in structs.items():
        if item.pointer and rust_type not in registered:
            errors.append(
                f"unregistered schema counterpart {rust_type} ({item.pointer}); "
                "add an exact mapping or explained exemption"
            )
    resolver = SchemaResolver(spec_root)
    for entry in mappings:
        rust_type = entry.get("rust_type")
        pointer = entry.get("schema")
        comparison = entry.get("comparison", "exact")
        reason = entry.get("reason")
        item = structs.get(rust_type)
        if item is None:
            errors.append(f"registered Rust struct no longer exists: {rust_type}")
            continue
        if not isinstance(pointer, str):
            errors.append(f"mapping for {rust_type} has no schema pointer")
            continue
        if comparison not in {"exact", "rust_fields_subset"}:
            errors.append(f"mapping for {rust_type} has unknown comparison {comparison!r}")
            continue
        if comparison == "rust_fields_subset":
            if not item.has_flatten:
                errors.append(
                    f"subset mapping for {rust_type} requires a serde(flatten) field"
                )
                continue
            if not isinstance(reason, str) or len(reason.strip()) < 20:
                errors.append(
                    f"subset mapping for {rust_type} needs a concrete schema-only exemption reason"
                )
                continue
        elif item.has_flatten:
            errors.append(
                f"flattened mapping for {rust_type} must use comparison=rust_fields_subset"
            )
            continue
        if item.fields is None:
            errors.append(f"mapping for {rust_type} is not statically comparable: {item.unsupported_reason}")
            continue
        try:
            schema_path, node = resolver.pointer_node(pointer)
            schema_fields = schema_property_names(resolver, schema_path, node)
        except (FileNotFoundError, KeyError, ValueError, json.JSONDecodeError) as error:
            errors.append(f"cannot resolve {pointer} for {rust_type}: {error}")
            continue
        if not schema_fields:
            errors.append(f"schema target for {rust_type} has no object properties: {pointer}")
            continue
        rust_only = set(item.fields) - schema_fields
        schema_only = schema_fields - set(item.fields)
        if rust_only or (comparison == "exact" and schema_only):
            errors.append(
                f"field mismatch for {rust_type} -> {pointer}: "
                f"Rust-only={sorted(rust_only)}, "
                f"Spec-only={sorted(schema_only)}"
            )
    for entry in exemptions:
        rust_type = entry.get("rust_type")
        reason = entry.get("reason")
        if rust_type not in structs:
            errors.append(f"exempted Rust struct no longer exists: {rust_type}")
        elif structs[rust_type].has_flatten:
            errors.append(
                f"flattened Rust struct {rust_type} cannot bypass Rust-only field checking"
            )
        if not isinstance(reason, str) or len(reason.strip()) < 20:
            errors.append(f"exemption for {rust_type} needs a concrete reason")
    return errors


def bootstrap(registry_path: Path, spec_root: Path) -> None:
    structs = scan_structs()
    resolver = SchemaResolver(spec_root)
    mappings: list[dict[str, str]] = []
    exemptions: list[dict[str, str]] = []
    for item in structs.values():
        if not item.pointer:
            continue
        if item.fields is None:
            exemptions.append({"rust_type": item.rust_type, "reason": item.unsupported_reason or "unsupported shape"})
            continue
        try:
            schema_path, node = resolver.pointer_node(item.pointer)
            schema_fields = schema_property_names(resolver, schema_path, node)
        except (FileNotFoundError, KeyError, ValueError, json.JSONDecodeError) as error:
            exemptions.append({"rust_type": item.rust_type, "reason": f"Documented pointer is not a direct object node: {error}."})
            continue
        if item.has_flatten and schema_fields:
            mappings.append(
                {
                    "rust_type": item.rust_type,
                    "schema": item.pointer,
                    "comparison": "rust_fields_subset",
                    "reason": (
                        "serde(flatten) may carry schema-only fields; every declared "
                        "non-flatten Rust field remains checked against schema properties."
                    ),
                }
            )
        elif schema_fields and schema_fields == set(item.fields):
            mappings.append({"rust_type": item.rust_type, "schema": item.pointer})
        else:
            exemptions.append(
                {
                    "rust_type": item.rust_type,
                    "reason": (
                        "Documented counterpart is not field-set exact; "
                        f"Rust-only={sorted(set(item.fields) - schema_fields)}, "
                        f"Spec-only={sorted(schema_fields - set(item.fields))}."
                    ),
                }
            )
    document = {"version": 1, "mappings": mappings, "exemptions": exemptions}
    registry_path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--spec-root", type=Path, default=DEFAULT_SPEC_ROOT)
    parser.add_argument("--bootstrap", action="store_true")
    args = parser.parse_args()
    if args.bootstrap:
        bootstrap(args.registry, args.spec_root)
    errors = validate(args.registry, args.spec_root)
    if errors:
        print("schema struct gate failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    registry = load_registry(args.registry)
    print(
        "schema struct gate passed "
        f"({len(registry['mappings'])} exact mappings, {len(registry['exemptions'])} exemptions)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
