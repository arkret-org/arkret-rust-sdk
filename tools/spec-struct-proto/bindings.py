#!/usr/bin/env python3
"""Terminal-``$ref`` to Rust type bindings.

A generator cannot invent ``RealmId`` from ``{"type": "string", "pattern":
"^ak:realm:..."}``; the SDK newtype is a local decision that has to be declared
once and reused. ``learn`` derives the table empirically from the hand-written
crate so the prototype starts from the SDK's own convention instead of a guess,
and reports every terminal pointer the SDK spells more than one way.
"""

from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rust_model  # noqa: E402
from wire_value_audit import SchemaResolver  # noqa: E402

def terminal_pointer(resolver: SchemaResolver, path: Path, node: Any) -> tuple[str, Any]:
    """Follow ``$ref`` to the last node that actually declares a shape."""
    seen: set[tuple[Path, str]] = set()
    pointer = path.name
    while isinstance(node, dict) and isinstance(node.get("$ref"), str):
        reference = node["$ref"]
        file_part, _, fragment = reference.partition("#")
        next_path = (path.parent / file_part).resolve() if file_part else path
        marker = (next_path, fragment)
        if marker in seen:
            break
        seen.add(marker)
        target = resolver.load(next_path)
        if fragment:
            for token in fragment.lstrip("/").split("/"):
                target = target[token.replace("~1", "/").replace("~0", "~")]
        path, node = next_path, target
        pointer = next_path.name + (f"#{fragment}" if fragment else "")
    return pointer, node


def strip_option(rust_type: str) -> tuple[str, bool]:
    match = re.fullmatch(r"Option<(.+)>", rust_type.strip())
    return (match.group(1).strip(), True) if match else (rust_type.strip(), False)


def strip_container(rust_type: str) -> str:
    inner, _ = strip_option(rust_type)
    for pattern in (r"Vec<(.+)>", r"BTreeSet<(.+)>", r"BTreeMap<\s*String\s*,\s*(.+)>"):
        match = re.fullmatch(pattern, inner)
        if match:
            return strip_container(match.group(1).strip())
    return inner


def learn(
    types: dict[str, rust_model.RustType],
    mappings: list[Any],
    resolver: SchemaResolver,
) -> tuple[dict[str, str], dict[str, dict[str, int]]]:
    observed: dict[str, Counter[str]] = defaultdict(Counter)
    for entry in mappings:
        pointer = entry.pointer if hasattr(entry, "pointer") else entry.get("pointer")
        rust_type_name = (
            entry.rust_type if hasattr(entry, "rust_type") else entry.get("rust_type")
        )
        if not pointer or rust_type_name not in types:
            continue
        item = types[rust_type_name]
        try:
            path, node = resolver.pointer_node(pointer)
            path, node = resolver.resolve_ref(path, node)
        except Exception:
            continue
        properties = node.get("properties") if isinstance(node, dict) else None
        if not isinstance(properties, dict):
            continue
        for rust_field in item.fields:
            schema_field = properties.get(rust_field.wire_name)
            if not isinstance(schema_field, dict):
                continue
            probe = schema_field
            # Descend one array level so Vec<T> lines up with items.
            if probe.get("type") == "array" and isinstance(probe.get("items"), dict):
                probe = probe["items"]
            if not isinstance(probe.get("$ref"), str):
                continue
            pointer_name, terminal = terminal_pointer(resolver, path, probe)
            if isinstance(terminal, dict) and terminal.get("type") == "array":
                # An array-valued definition names the container, not the leaf.
                # Binding it to the element type would make the generator emit a
                # scalar where the wire carries a list.
                continue
            observed[pointer_name][strip_container(rust_field.rust_type)] += 1

    bindings: dict[str, str] = {}
    conflicts: dict[str, dict[str, int]] = {}
    for pointer_name, counter in observed.items():
        bindings[pointer_name] = counter.most_common(1)[0][0]
        if len(counter) > 1:
            conflicts[pointer_name] = dict(counter)
    return bindings, conflicts
