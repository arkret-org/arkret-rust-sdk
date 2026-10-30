#!/usr/bin/env python3
"""Compare registered Rust wire-struct field sets with live Spec schemas.

The coverage boundary is deliberate and reviewable: every public named struct
whose directly attached rustdoc contains a Spec schema pointer must occur in
``schema_struct_registry.json`` as either an exact mapping or an explained
exemption. Additional mappings may register structs whose pointer is maintained
only in the registry. This keeps new counterpart declarations from bypassing
the gate while avoiding fuzzy type/schema matching.

Mappings with ``schema_field_set=accepted`` compare the exact set of members
that may occur in a valid branch, excluding only schema-proven presence bans.
Existing mappings default to the declared property set; no named field can be
excluded by a mapping override.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, replace
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
    r"(?:^|(?<=\]))\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*:(?!:)\s*(.+)\Z",
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
    scalar_fields: dict[str, tuple[str, str]]
    serializable: bool = False


def attached_prefix(source: str, start: int, masked_source: str | None = None) -> str:
    """Read attached attributes and trivia, including multiline attributes."""
    masked = masked_source[:start] if masked_source is not None else mask_non_code(source[:start])
    cursor = len(masked)
    while True:
        cursor = len(masked[:cursor].rstrip())
        if cursor == 0 or masked[cursor - 1] != ']':
            return source[cursor:start]
        closing = cursor
        depth = 1
        cursor -= 1
        while cursor and depth:
            cursor -= 1
            if masked[cursor] == ']':
                depth += 1
            elif masked[cursor] == '[':
                depth -= 1
        preceding = masked[:cursor].rstrip()
        if not preceding.endswith('#'):
            return source[closing:start]
        cursor = len(preceding) - 1


def direct_docs(source: str, start: int, masked_source: str | None = None) -> str:
    return '\n'.join(line.strip() for line in attached_prefix(source, start, masked_source).splitlines()
                     if line.lstrip().startswith('///'))


def preceding_attributes(source: str, start: int, masked_source: str | None = None) -> str:
    return attached_prefix(source, start, masked_source)


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
    attributes = preceding_attributes(source, match.start(), masked)
    serde_attributes = " ".join(SERDE_RE.findall(attributes))
    rename_all_match = RENAME_ALL_RE.search(serde_attributes)
    rename_all = rename_all_match.group(1) if rename_all_match else None
    fields: set[str] = set()
    scalar_fields: dict[str, tuple[str, str]] = {}
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
        scalar_fields[field_name] = (field_match.group(2), field_attributes)
    docs = direct_docs(source, match.start(), masked)
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
        scalar_fields=scalar_fields,
        serializable=(bool(re.search(r'\bderive\s*\([^)]*\bSerialize\b', mask_non_code(attributes))) or bool(re.search(
            r'\bimpl(?:\s*<[^{};]*>)?\s+(?:serde::)?Serialize\s+for\s+' + re.escape(name) + r'\b',
            masked))),
    )


def decimal_property_formats(resolver: SchemaResolver, path: Path, node: Any,
                             seen: frozenset[str] = frozenset()) -> dict[str, str]:
    """Read only this object's members, including ref and union branches."""
    if not isinstance(node, dict):
        return {}
    result: dict[str, str] = {}
    reference = node.get('$ref')
    if isinstance(reference, str) and reference not in seen:
        target_path, target = resolver.resolve_ref(path, {'$ref': reference})
        result.update(decimal_property_formats(resolver, target_path, target, seen | {reference}))
    for name, shape in node.get('properties', {}).items():
        reference = shape.get('$ref', '') if isinstance(shape, dict) else ''
        if 'decimal-integers.schema.json#/$defs/' in reference:
            result[name] = reference.rsplit('/', 1)[-1]
    for keyword in ('allOf', 'anyOf', 'oneOf'):
        for branch in node.get(keyword, []):
            result.update(decimal_property_formats(resolver, path, branch, seen))
    return result


def scan_structs(root: Path = ROOT) -> dict[str, RustStruct]:
    found: dict[str, RustStruct] = {}
    for path in sorted((root / "crates").glob("*/src/**/*.rs")):
        source = path.read_text(encoding="utf-8")
        masked = mask_non_code(source)
        for match in STRUCT_RE.finditer(masked):
            item = parse_struct(path, match, source, masked, root)
            found[item.rust_type] = item
    return found


def declares_empty_object(node: Any) -> bool:
    """True when the schema node is a deliberately empty closed object.

    An empty property set is otherwise indistinguishable from a pointer that
    resolved to the wrong target, so the caller must keep rejecting that case.
    A def that spells out `"properties": {}` together with
    `"additionalProperties": false` is stating that the wire object carries no
    members at all, and the matching Rust counterpart is a unit struct.
    """
    return (
        isinstance(node, dict)
        and node.get("type") == "object"
        and node.get("properties") == {}
        and node.get("additionalProperties") is False
    )


def schema_property_names(
    resolver: SchemaResolver,
    path: Path,
    node: Any,
    seen: set[tuple[Path, str]] | None = None,
    *,
    accepted: bool = False,
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
        names = schema_property_names(resolver, resolved_path, resolved_node, seen, accepted=accepted)
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
                names.update(schema_property_names(resolver, path, branch, seen.copy(), accepted=accepted))
    return names - schema_forbidden_property_names(resolver, path, node) if accepted else names


def schema_forbidden_property_names(
    resolver: SchemaResolver,
    path: Path,
    node: Any,
    seen: set[tuple[Path, str]] | None = None,
) -> set[str]:
    """Remove only members proven impossible by presence-only exclusions.

    A negated multi-member required set does not forbid either member alone.
    Alternative branches forbid a member globally only when all forbid it.
    """
    if not isinstance(node, dict):
        return set()
    seen = set() if seen is None else seen
    forbidden: set[str] = set()
    if isinstance(node.get("$ref"), str):
        marker = (path.resolve(), node["$ref"])
        if marker not in seen:
            seen.add(marker)
            ref_path, ref_node = resolver.resolve_ref(path, node)
            forbidden.update(schema_forbidden_property_names(resolver, ref_path, ref_node, seen))
    excluded = node.get("not")
    if isinstance(excluded, dict):
        clauses = excluded.get("anyOf") if set(excluded) == {"anyOf"} else [excluded]
        if isinstance(clauses, list):
            for clause in clauses:
                if isinstance(clause, dict) and set(clause) == {"required"}:
                    required = clause["required"]
                    if isinstance(required, list) and len(required) == 1 and isinstance(required[0], str):
                        forbidden.add(required[0])
    for branch in node.get("allOf", []):
        forbidden.update(schema_forbidden_property_names(resolver, path, branch, seen.copy()))
    for keyword in ("oneOf", "anyOf"):
        branches = node.get(keyword)
        if isinstance(branches, list) and branches:
            forbidden.update(set.intersection(*[
                schema_forbidden_property_names(resolver, path, branch, seen.copy())
                for branch in branches
            ]))
    return forbidden


def load_registry(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return document


def named_object_candidates(spec_root: Path) -> dict[str, set[str]]:
    """Find explicit definition names and conventional root names for review.

    A name match requires an explicit binding; it never chooses that binding.
    For example DndSchedule binds to the nested schedule, not the document root.
    """
    resolver = SchemaResolver(spec_root)
    candidates: dict[str, set[str]] = {}
    for path in sorted(spec_root.glob("*.schema.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        root_name = path.name.removesuffix(".schema.json").replace("-", "_")
        declarations = [(root_name, document, path.name)]
        declarations.extend((name, node, path.name + "#/$defs/" + name)
                            for name, node in document.get("$defs", {}).items())
        for name, node, pointer in declarations:
            name = "".join(word[:1].upper() + word[1:] for word in name.split("_"))
            if isinstance(node, dict) and schema_property_names(resolver, path, node):
                candidates.setdefault(name, set()).add(pointer)
    return candidates


def custom_serializer(item: RustStruct, source_root: Path) -> str | None:
    source = (source_root / item.file).read_text(encoding='utf-8')
    masked = mask_non_code(source)
    match = re.search(r'\bimpl\s+(?:serde::)?Serialize\s+for\s+' + re.escape(item.name) + r'\b', masked)
    if not match:
        return None
    opening = masked.index('{', match.end())
    return source[opening + 1:matching_brace(masked, opening)]


def serializer_members(body: str) -> tuple[set[str], bool]:
    calls = re.findall(r'\.serialize_(?:entry|field)\s*\(\s*([^,]+),', body)
    fields = {match[1] for value in calls
              if (match := re.fullmatch(r'\s*"([^"]+)"\s*', value))}
    return fields, any(re.fullmatch(r'\s*"[^"]+"\s*', value) is None for value in calls)


def adapter_struct(adapter: str, item: RustStruct, source_root: Path) -> RustStruct:
    file_name, separator, name = adapter.rpartition('::')
    if not separator or file_name != item.file:
        raise ValueError('wire_adapter must be one named private carrier in the same source file')
    path = source_root / file_name
    source = path.read_text(encoding='utf-8')
    masked = mask_non_code(source)
    matches = list(re.finditer(r'\bstruct\s+(' + re.escape(name) + r')\s*\{', masked))
    if len(matches) != 1:
        raise ValueError('wire_adapter must resolve to exactly one declaration')
    if item.has_flatten:
        public = re.search(r'\bpub\s+struct\s+' + re.escape(item.name) + r'\b', masked)
        attributes = preceding_attributes(source, public.start(), masked) if public else ''
        if not re.search(r'\btry_from\s*=\s*"' + re.escape(name) + '"', attributes):
            raise ValueError('flattened wire_adapter must be the actual validating decode representation')
    elif name not in (custom_serializer(item, source_root) or ''):
        raise ValueError('custom serializer must use its declared wire_adapter')
    return parse_struct(path, matches[0], source, masked, source_root)


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
    # Compound spellings such as keypackage/KeyPackage and websocket/WebSocket
    # are the same lexical candidate. A match still requires an exact owner
    # binding; folding case never selects a schema on the caller's behalf.
    candidates = {name.casefold() for name in named_object_candidates(spec_root)}
    for rust_type, item in structs.items():
        if item.serializable and item.name.casefold() in candidates and rust_type not in registered:
            errors.append(
                f"unregistered named object {rust_type}; explicitly bind its canonical "
                "schema or its checked wire representation (name equality is not identity)"
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
        serializer = custom_serializer(item, source_root)
        if 'wire_adapter' in entry:
            try:
                item = adapter_struct(entry['wire_adapter'], item, source_root)
            except (ValueError, KeyError) as error:
                errors.append(f'wire representation for {rust_type}: {error}')
                continue
        if entry.get('manual_map') is True:
            if serializer is None or 'serialize_map' not in serializer:
                errors.append(f'manual_map for {rust_type} requires its actual map serializer')
                continue
            fields, _dynamic = serializer_members(serializer)
            if not fields:
                errors.append(f'manual_map for {rust_type} has no statically named members')
                continue
            item = replace(item, fields=frozenset(fields))
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
            field_set = entry.get("schema_field_set", "declared")
            if field_set not in {"declared", "accepted"}:
                raise ValueError(f"unknown schema_field_set {field_set!r}")
            schema_fields = schema_property_names(resolver, schema_path, node, accepted=field_set == "accepted")
            decimal_formats = decimal_property_formats(resolver, schema_path, node)
            if serializer is not None:
                emitted, dynamic = serializer_members(serializer)
                if emitted and not emitted <= schema_fields:
                    errors.append(f'custom serializer for {rust_type} emits unregistered members: {sorted(emitted - schema_fields)}')
                if entry.get('manual_map') is True and dynamic and node.get('additionalProperties') is not True:
                    errors.append(f'custom map serializer for {rust_type} needs an explicit open extension contract')
        except (FileNotFoundError, KeyError, ValueError, json.JSONDecodeError) as error:
            errors.append(f"cannot resolve {pointer} for {rust_type}: {error}")
            continue
        for name, format_name in decimal_formats.items():
            field_type, attributes = item.scalar_fields.get(name, ('', ''))
            if re.search(r'\b(?:u64|i64)\b', field_type):
                valid_helpers = {format_name, 'optional_' + format_name}
                if name == 'expected_version':
                    valid_helpers.add('participation_expected_version_decimal')
                if not any('serde_helpers::' + helper + '"' in attributes for helper in valid_helpers):
                    errors.append(f'decimal serialization mismatch for {rust_type}.{name}: Spec requires {format_name}')
        if not schema_fields and not declares_empty_object(node):
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
    document = {"mappings": mappings, "exemptions": exemptions}
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
    from public_model_duplicates import check as duplicate_errors
    errors.extend(duplicate_errors(scan_structs()))
    if errors:
        print("schema struct gate failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    registry = load_registry(args.registry)
    print(
        "schema struct gate passed "
        f"({len(registry['mappings'])} registered mappings, {len(registry['exemptions'])} exemptions)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
