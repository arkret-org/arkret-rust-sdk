#!/usr/bin/env python3
"""Index every addressable node in the Spec schema artifacts.

``$defs`` is not the only place a wire shape lives: several counterparts in the
SDK mirror an inline subschema (``#/properties/limits``) or an array item
(``#/properties/claimed_profiles/items``). The index therefore walks the whole
document tree and records a JSON Pointer for every object-like or enum-like
node, so the mapping step can match on name, on property set, or on enum value
set.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

TOOLS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_ROOT))

from wire_value_audit import SchemaResolver  # noqa: E402

SKIP_KEYS = {
    "description",
    "title",
    "$comment",
    "examples",
    "default",
    "const",
    "enum",
    "x-arkret-notes",
}


@dataclass
class SchemaNode:
    file: str
    pointer: str  # "<file>#<json pointer>"
    name: str | None  # $defs name when the node is a definition
    node: Any
    properties: tuple[str, ...] = ()
    enum_values: tuple[Any, ...] = ()
    kind: str = "other"  # object | enum | scalar | union | other


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


@dataclass
class SchemaIndex:
    root: Path
    resolver: SchemaResolver = field(init=False)
    nodes: list[SchemaNode] = field(default_factory=list)
    by_pointer: dict[str, SchemaNode] = field(default_factory=dict)
    by_def_name: dict[str, list[SchemaNode]] = field(default_factory=dict)
    by_property_set: dict[frozenset[str], list[SchemaNode]] = field(default_factory=dict)
    by_enum_set: dict[frozenset[str], list[SchemaNode]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.resolver = SchemaResolver(self.root)
        for path in sorted(self.root.glob("*.schema.json")):
            document = json.loads(path.read_text(encoding="utf-8"))
            self._walk(path.name, document, "", document)

    def _classify(self, node: Any) -> tuple[str, tuple[str, ...], tuple[Any, ...]]:
        if not isinstance(node, dict):
            return "other", (), ()
        enum_values = node.get("enum")
        if isinstance(enum_values, list) and node.get("type") in (None, "string"):
            return "enum", (), tuple(enum_values)
        properties = node.get("properties")
        if isinstance(properties, dict):
            return "object", tuple(properties.keys()), ()
        if any(k in node for k in ("oneOf", "anyOf")):
            return "union", (), ()
        if node.get("type") in ("string", "integer", "number", "boolean"):
            return "scalar", (), ()
        return "other", (), ()

    def _record(self, file: str, pointer_body: str, name: str | None, node: Any) -> None:
        kind, properties, enum_values = self._classify(node)
        if kind == "other" and name is None:
            return
        pointer = f"{file}#{pointer_body}" if pointer_body else file
        entry = SchemaNode(
            file=file,
            pointer=pointer,
            name=name,
            node=node,
            properties=properties,
            enum_values=enum_values,
            kind=kind,
        )
        self.nodes.append(entry)
        self.by_pointer[pointer] = entry
        if name:
            self.by_def_name.setdefault(name, []).append(entry)
        if properties:
            self.by_property_set.setdefault(frozenset(properties), []).append(entry)
        if enum_values and all(isinstance(v, str) for v in enum_values):
            self.by_enum_set.setdefault(frozenset(enum_values), []).append(entry)

    def _walk(self, file: str, node: Any, pointer: str, _document: Any) -> None:
        if isinstance(node, dict):
            definitions = node.get("$defs")
            name = None
            if pointer.startswith("/$defs/") and pointer.count("/") == 2:
                name = pointer.rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~")
            self._record(file, pointer, name, node)
            for key, value in node.items():
                if key in SKIP_KEYS:
                    continue
                self._walk(file, value, f"{pointer}/{_escape(key)}", _document)
            if isinstance(definitions, dict):
                pass
        elif isinstance(node, list):
            for index, value in enumerate(node):
                self._walk(file, value, f"{pointer}/{index}", _document)

    def def_names(self) -> Iterable[str]:
        return self.by_def_name.keys()

    def resolve(self, pointer: str) -> tuple[Path, Any]:
        path, node = self.resolver.pointer_node(pointer)
        return self.resolver.resolve_ref(path, node)
