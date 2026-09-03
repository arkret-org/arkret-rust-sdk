#!/usr/bin/env python3
"""Prototype ``$defs`` to Rust wire-type generator.

Scope is deliberately one crate wide, not the SDK: this exists to measure how
much of a hand-written models crate a schema-driven generator can reproduce,
and to make the residue explicit. Everything it cannot express is emitted as a
``GenerationGap`` rather than as approximate Rust.

Conventions it reproduces (all observed in the hand-written crates, not
invented here):

* a member outside ``required`` becomes ``Option<T>`` with
  ``skip_serializing_if = "Option::is_none"``;
* an array or map member outside ``required`` becomes the bare container with
  ``default`` plus an is-empty ``skip_serializing_if``;
* ``additionalProperties: false`` with no ``patternProperties`` becomes
  ``deny_unknown_fields``;
* an ``^x_`` ``patternProperties`` or an open object becomes a flattened
  ``extra: BTreeMap<String, Value>``;
* a timestamp binds to ``DateTime<Utc>`` through the canonical serde helper.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import bindings as bindings_module  # noqa: E402
from wire_value_audit import SchemaResolver  # noqa: E402

RUST_KEYWORDS = {
    "as", "break", "const", "continue", "crate", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
    "move", "mut", "pub", "ref", "return", "self", "static", "struct", "super",
    "trait", "true", "type", "unsafe", "use", "where", "while", "async",
    "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "typeof", "unsized", "virtual", "yield", "try",
}
TIMESTAMP_POINTER = "time.schema.json#/$defs/timestamp"
CANONICAL_TIMESTAMP = "arkret_canonical::serde_helpers::canonical_timestamp"
OPTIONAL_CANONICAL_TIMESTAMP = (
    "arkret_canonical::serde_helpers::optional_canonical_timestamp"
)


@dataclass
class GenerationGap:
    rust_type: str
    member: str | None
    pointer: str
    reason: str


@dataclass
class GeneratedField:
    name: str
    wire_name: str
    rust_type: str
    attributes: list[str] = field(default_factory=list)
    schema_maximum: int | None = None


@dataclass
class GeneratedType:
    name: str
    kind: str
    pointer: str
    attributes: list[str] = field(default_factory=list)
    fields: list[GeneratedField] = field(default_factory=list)
    variants: list[tuple[str, str, str | None]] = field(default_factory=list)
    variant_kind: str = "value"  # "value" = string enum, "newtype" = union branch
    newtype_inner: str | None = None


def child_pointer(pointer: str, suffix: str) -> str:
    """Append a JSON Pointer step, opening the fragment when there is none."""
    return f"{pointer}{suffix}" if "#" in pointer else f"{pointer}#{suffix}"


def _rebase(node: Any, file_name: str) -> Any:
    """Make document-local ``$ref`` values absolute for the owning file.

    Merging an ``allOf`` branch pulls a subtree out of its own document; a bare
    ``#/$defs/x`` inside it would then resolve against the wrong file.
    """
    if isinstance(node, dict):
        rebased = {}
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str) and value.startswith("#"):
                rebased[key] = f"{file_name}{value}"
            else:
                rebased[key] = _rebase(value, file_name)
        return rebased
    if isinstance(node, list):
        return [_rebase(item, file_name) for item in node]
    return node


def pascal(name: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in re.split(r"[_\-. ]+", name) if part)


def sanitize_ident(name: str) -> tuple[str, bool]:
    ident = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not ident or ident[0].isdigit():
        ident = f"n_{ident}"
    if ident in RUST_KEYWORDS:
        return f"r#{ident}", True
    return ident, ident != name


def variant_ident(value: str) -> str:
    parts = re.split(r"[^A-Za-z0-9]+", value)
    ident = "".join(p[:1].upper() + p[1:] for p in parts if p)
    if not ident:
        ident = "Empty"
    if ident[0].isdigit():
        ident = f"V{ident}"
    return ident


class Generator:
    def __init__(
        self,
        resolver: SchemaResolver,
        newtypes: dict[str, str],
        named_pointers: dict[str, str],
    ) -> None:
        self.resolver = resolver
        self.newtypes = newtypes
        # pointer -> Rust type name for the shapes we are generating by name.
        self.named_pointers = named_pointers
        self.gaps: list[GenerationGap] = []
        self.constraints: list[GenerationGap] = []
        self.generated: list[GeneratedType] = []
        self._anonymous: dict[str, str] = {}

    # -- schema helpers -------------------------------------------------

    def _terminal(self, path: Path, node: Any) -> tuple[str, Path, Any]:
        pointer, resolved = bindings_module.terminal_pointer(self.resolver, path, node)
        resolved_path = path
        if isinstance(node, dict) and isinstance(node.get("$ref"), str):
            resolved_path, _ = self.resolver.resolve_ref(path, node)
        return pointer, resolved_path, resolved

    def _ref_pointer(self, path: Path, node: Any) -> str | None:
        if not (isinstance(node, dict) and isinstance(node.get("$ref"), str)):
            return None
        reference = node["$ref"]
        file_part, _, fragment = reference.partition("#")
        target = (path.parent / file_part).resolve() if file_part else path
        return target.name + (f"#{fragment}" if fragment else "")

    # -- type mapping ---------------------------------------------------

    def rust_type_for(
        self,
        owner: str,
        member: str | None,
        path: Path,
        node: Any,
        hint: str,
        here: str,
    ) -> str | None:
        """Map one schema node to a Rust type, or record a gap and return None.

        ``here`` is the structural JSON Pointer of ``node``. An inline
        subschema has no ``$ref`` identity, so the structural pointer is the
        only thing that can tie it back to a Rust type the crate already names
        (``#/properties/interop_surfaces/items/properties/kind`` really is
        ``InteropSurfaceKind``).
        """
        if here in self.named_pointers:
            return self.named_pointers[here]
        direct_pointer = self._ref_pointer(path, node)
        if direct_pointer and direct_pointer in self.named_pointers:
            return self.named_pointers[direct_pointer]

        if direct_pointer:
            pointer, resolved_path, resolved = self._terminal(path, node)
            if pointer in self.named_pointers:
                return self.named_pointers[pointer]
            if pointer in self.newtypes:
                return self.newtypes[pointer]
        else:
            pointer = here
            resolved_path, resolved = path, node
        if not isinstance(resolved, dict):
            self.gaps.append(
                GenerationGap(owner, member, pointer, "non-object schema node")
            )
            return None

        merged = dict(resolved)
        if isinstance(node, dict):
            for key, value in node.items():
                if key != "$ref":
                    merged.setdefault(key, value)

        enum_values = merged.get("enum")
        if isinstance(enum_values, list) and all(isinstance(v, str) for v in enum_values):
            return self._emit_enum(hint, pointer, enum_values)

        if "const" in merged and isinstance(merged["const"], str):
            return self._emit_enum(hint, pointer, [merged["const"]])

        schema_type = merged.get("type")
        if isinstance(schema_type, list):
            non_null = [t for t in schema_type if t != "null"]
            schema_type = non_null[0] if len(non_null) == 1 else None

        if schema_type == "array":
            items = merged.get("items")
            if items is True or items is None:
                self.gaps.append(
                    GenerationGap(
                        owner, member, pointer,
                        "array items are unconstrained; element type falls back to Value",
                    )
                )
                return "Vec<Value>"
            if not isinstance(items, dict):
                self.gaps.append(
                    GenerationGap(owner, member, pointer, "array items is a tuple schema")
                )
                return None
            inner = self.rust_type_for(
                owner, member, resolved_path, items, hint, child_pointer(pointer, "/items")
            )
            if inner is None:
                return None
            if merged.get("uniqueItems"):
                self.constraints.append(
                    GenerationGap(
                        owner, member, pointer,
                        "uniqueItems is not expressible in Vec; the hand-written "
                        "crates use Vec and validate elsewhere",
                    )
                )
            return f"Vec<{inner}>"

        if schema_type == "object" or "properties" in merged:
            if "properties" in merged:
                return self._emit_struct(hint, pointer, resolved_path, merged)
            additional = merged.get("additionalProperties")
            if isinstance(additional, dict):
                inner = self.rust_type_for(
                    owner,
                    member,
                    resolved_path,
                    additional,
                    f"{hint}Value",
                    child_pointer(pointer, "/additionalProperties"),
                )
                if inner is None:
                    return None
                return f"BTreeMap<String, {inner}>"
            return "BTreeMap<String, Value>"

        if schema_type == "null":
            return "()"
        if "const" in merged and isinstance(merged["const"], bool):
            return "bool"
        if "const" in merged and isinstance(merged["const"], int):
            return "u64"
        if schema_type == "string":
            return "String"
        if schema_type == "boolean":
            return "bool"
        if schema_type == "integer":
            minimum = merged.get("minimum")
            maximum = merged.get("maximum")
            if isinstance(minimum, (int, float)) and minimum >= 0:
                if isinstance(maximum, (int, float)) and maximum <= 4294967295:
                    return "u32"
                return "u64"
            return "i64"
        if schema_type == "number":
            return "f64"

        for keyword in ("oneOf", "anyOf"):
            branches = merged.get(keyword)
            if isinstance(branches, list) and branches:
                return self._emit_union(
                    owner, member, hint, pointer, resolved_path, branches, keyword
                )

        branches = merged.get("allOf")
        if isinstance(branches, list) and branches:
            flattened = self._flatten_all_of(resolved_path, branches)
            if flattened is None:
                self.gaps.append(
                    GenerationGap(
                        owner, member, pointer,
                        "allOf branches disagree on shape; no single Rust type covers them",
                    )
                )
                return None
            branch_path, merged_branch = flattened
            for key, value in merged.items():
                if key != "allOf":
                    merged_branch.setdefault(key, value)
            return self.rust_type_for(
                owner, member, branch_path, merged_branch, hint, child_pointer(pointer, "/allOf")
            )

        self.gaps.append(
            GenerationGap(owner, member, pointer, f"untyped schema node ({sorted(merged)[:6]})")
        )
        return None

    # -- emitters -------------------------------------------------------

    def _dedupe(self, hint: str, pointer: str) -> str | None:
        existing = self._anonymous.get(pointer)
        if existing:
            return existing
        name = hint
        suffix = 1
        taken = {item.name for item in self.generated} | set(self.named_pointers.values())
        while name in taken:
            suffix += 1
            name = f"{hint}{suffix}"
        self._anonymous[pointer] = name
        return None if name == hint and pointer in self._anonymous else name

    def _emit_enum(self, hint: str, pointer: str, values: list[str]) -> str:
        if pointer in self._anonymous:
            return self._anonymous[pointer]
        name = self._reserve(hint, pointer)
        item = GeneratedType(name=name, kind="enum", pointer=pointer, variant_kind="value")
        item.attributes.append('#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]')
        uniform_snake = all(re.fullmatch(r"[a-z0-9_]+", v) for v in values)
        if uniform_snake:
            item.attributes.append('#[serde(rename_all = "snake_case")]')
        for value in values:
            ident = variant_ident(value)
            rename = None
            if uniform_snake:
                from rust_model import rename_ident

                if rename_ident(ident, "snake_case") != value:
                    rename = value
            else:
                rename = value
            item.variants.append((ident, value, rename))
        self.generated.append(item)
        return name

    def _reserve(self, hint: str, pointer: str) -> str:
        taken = {item.name for item in self.generated} | set(self.named_pointers.values())
        name = hint
        suffix = 1
        while name in taken:
            suffix += 1
            name = f"{hint}{suffix}"
        self._anonymous[pointer] = name
        return name

    def _emit_union(
        self,
        owner: str,
        member: str | None,
        hint: str,
        pointer: str,
        path: Path,
        branches: list[Any],
        keyword: str,
    ) -> str | None:
        if pointer in self._anonymous:
            return self._anonymous[pointer]
        # A discriminated union needs a shared const-valued property; without
        # one serde's only faithful representation is `untagged`.
        tag = self._discriminator(path, branches)
        name = self._reserve(hint, pointer)
        item = GeneratedType(
            name=name, kind="enum", pointer=pointer, variant_kind="newtype"
        )
        item.attributes.append("#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]")
        if tag:
            item.attributes.append(f'#[serde(tag = "{tag}", rename_all = "snake_case")]')
        else:
            item.attributes.append("#[serde(untagged)]")
        for position, branch in enumerate(branches):
            inner = self.rust_type_for(
                owner,
                member,
                path,
                branch,
                f"{hint}Variant{position}",
                child_pointer(pointer, f"/{keyword}/{position}"),
            )
            if inner is None:
                self.gaps.append(
                    GenerationGap(owner, member, pointer, f"union branch {position} unmapped")
                )
                return None
            base = variant_ident(inner.split("<")[0])
            taken = {existing for existing, _, _ in item.variants}
            ident = base
            index = 1
            while ident in taken:
                index += 1
                ident = f"{base}{index}"
            item.variants.append((ident, inner, None))
        self.generated.append(item)
        return name

    def _flatten_all_of(
        self, path: Path, branches: list[Any]
    ) -> tuple[Path, dict[str, Any]] | None:
        """Collapse an allOf into one node when the branches are compatible.

        Two shapes appear in the artifacts: a scalar narrowed by a second
        string profile (take the most specific), and a base object extended
        with extra properties (merge properties and required).
        """
        merged: dict[str, Any] = {}
        merged_path = path
        for branch in branches:
            _, branch_path, resolved = self._terminal(path, branch)
            if not isinstance(resolved, dict):
                return None
            resolved = _rebase(resolved, branch_path.name)
            merged_path = branch_path
            for key, value in resolved.items():
                if key == "properties" and isinstance(value, dict):
                    merged.setdefault("properties", {}).update(value)
                elif key == "required" and isinstance(value, list):
                    merged["required"] = sorted(set(merged.get("required", [])) | set(value))
                elif key not in merged:
                    merged[key] = value
        return (merged_path, merged) if merged else None

    def _discriminator(self, path: Path, branches: list[Any]) -> str | None:
        candidates: set[str] | None = None
        for branch in branches:
            _, resolved_path, resolved = self._terminal(path, branch)
            properties = resolved.get("properties") if isinstance(resolved, dict) else None
            if not isinstance(properties, dict):
                return None
            local = {
                key
                for key, value in properties.items()
                if isinstance(value, dict) and isinstance(value.get("const"), str)
            }
            candidates = local if candidates is None else candidates & local
            if not candidates:
                return None
        return sorted(candidates)[0] if candidates else None

    def _emit_struct(
        self, hint: str, pointer: str, path: Path, node: dict[str, Any]
    ) -> str | None:
        if pointer in self._anonymous:
            return self._anonymous[pointer]
        name = self._reserve(hint, pointer)
        item = self.build_struct(name, pointer, path, node)
        return name if item is not None else None

    # -- public entry ---------------------------------------------------

    def build_struct(
        self, name: str, pointer: str, path: Path, node: dict[str, Any]
    ) -> GeneratedType | None:
        properties = node.get("properties")
        if not isinstance(properties, dict):
            self.gaps.append(GenerationGap(name, None, pointer, "node has no properties"))
            return None
        required = set(node.get("required") or [])
        pattern_properties = node.get("patternProperties")
        additional = node.get("additionalProperties")
        unevaluated = node.get("unevaluatedProperties")
        closed = additional is False or unevaluated is False
        has_extension_slot = isinstance(pattern_properties, dict) and any(
            pattern.startswith("^x_") for pattern in pattern_properties
        )

        item = GeneratedType(name=name, kind="struct", pointer=pointer)
        item.attributes.append("#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]")
        if closed and not has_extension_slot:
            item.attributes.append("#[serde(deny_unknown_fields)]")

        for member, member_schema in properties.items():
            ident, renamed = sanitize_ident(member)
            hint = f"{name}{pascal(member)}"
            is_timestamp = self._is_timestamp(path, member_schema)
            rust_type = self.rust_type_for(
                name,
                member,
                path,
                member_schema,
                hint,
                child_pointer(pointer, f"/properties/{member}"),
            )
            if rust_type is None:
                return None
            attributes: list[str] = []
            optional = member not in required
            container_default = rust_type.startswith(("Vec<", "BTreeSet<", "BTreeMap<"))
            if optional and container_default:
                empty = "Vec::is_empty" if rust_type.startswith("Vec<") else "BTreeMap::is_empty"
                attributes.append(f'#[serde(default, skip_serializing_if = "{empty}")]')
            elif optional:
                rust_type = f"Option<{rust_type}>"
                attributes.append(
                    '#[serde(default, skip_serializing_if = "Option::is_none")]'
                )
            if is_timestamp:
                helper = OPTIONAL_CANONICAL_TIMESTAMP if optional else CANONICAL_TIMESTAMP
                attributes.append(f'#[serde(with = "{helper}")]')
            if renamed:
                attributes.append(f'#[serde(rename = "{member}")]')
            default_value = member_schema.get("default") if isinstance(member_schema, dict) else None
            if default_value is not None and not optional:
                self.gaps.append(
                    GenerationGap(
                        name,
                        member,
                        pointer,
                        f"schema default {json.dumps(default_value)} needs a named default fn",
                    )
                )
            item.fields.append(
                GeneratedField(
                    name=ident,
                    wire_name=member,
                    rust_type=rust_type,
                    attributes=attributes,
                    schema_maximum=self._declared_maximum(path, member_schema),
                )
            )

        if has_extension_slot or (not closed and properties):
            item.fields.append(
                GeneratedField(
                    name="extra",
                    wire_name="",
                    rust_type="BTreeMap<String, Value>",
                    attributes=["#[serde(default, flatten)]"],
                )
            )
        self.generated.append(item)
        return item

    def _declared_maximum(self, path: Path, node: Any) -> int | None:
        """Largest value the schema admits for an integer member, if it says.

        Without this, every integer difference looks alike; with it, a crate
        type too small for a declared maximum separates from a crate type that
        merely narrows an unbounded domain.
        """
        probe = node
        if isinstance(probe, dict) and probe.get("type") == "array":
            probe = probe.get("items")
        if isinstance(probe, dict) and isinstance(probe.get("$ref"), str):
            _, _, probe = self._terminal(path, probe)
        if not isinstance(probe, dict) or probe.get("type") != "integer":
            return None
        maximum = probe.get("maximum")
        return int(maximum) if isinstance(maximum, (int, float)) else None

    def _is_timestamp(self, path: Path, node: Any) -> bool:
        if not isinstance(node, dict):
            return False
        pointer, _, _ = self._terminal(path, node)
        return pointer == TIMESTAMP_POINTER

    def build(self, name: str, pointer: str) -> GeneratedType | None:
        try:
            path, node = self.resolver.pointer_node(pointer)
            path, node = self.resolver.resolve_ref(path, node)
        except Exception as error:  # noqa: BLE001 - reported, not raised
            self.gaps.append(GenerationGap(name, None, pointer, f"pointer error: {error}"))
            return None
        if not isinstance(node, dict):
            self.gaps.append(GenerationGap(name, None, pointer, "pointer is not a schema object"))
            return None
        if isinstance(node.get("enum"), list):
            self._emit_enum(name, pointer, node["enum"])
            return self.generated[-1]
        if "properties" in node:
            return self.build_struct(name, pointer, path, node)
        for keyword in ("oneOf", "anyOf"):
            if isinstance(node.get(keyword), list):
                self._emit_union(name, None, name, pointer, path, node[keyword], keyword)
                return self.generated[-1] if self.generated else None
        self.gaps.append(
            GenerationGap(name, None, pointer, f"unsupported root node ({sorted(node)[:6]})")
        )
        return None


def render(item: GeneratedType) -> str:
    lines = [f"/// Generated from `{item.pointer}`."]
    lines.extend(item.attributes)
    if item.kind == "struct":
        lines.append(f"pub struct {item.name} {{")
        for member in item.fields:
            for attribute in member.attributes:
                lines.append(f"    {attribute}")
            lines.append(f"    pub {member.name}: {member.rust_type},")
        lines.append("}")
    else:
        lines.append(f"pub enum {item.name} {{")
        for ident, payload, rename in item.variants:
            if rename:
                lines.append(f'    #[serde(rename = "{rename}")]')
            if item.variant_kind == "newtype":
                lines.append(f"    {ident}({payload}),")
            else:
                lines.append(f"    {ident},")
        lines.append("}")
    return "\n".join(lines)
