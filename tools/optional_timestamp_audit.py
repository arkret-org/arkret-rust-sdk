#!/usr/bin/env python3
"""One-time reconciliation of optional canonical timestamp fields.

For every field carrying
``#[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]``
this audit locates the owning spec schema (doc-comment pointer, then the
``$defs`` index), decides whether the field is schema-``required``, and writes
the three-way classification to ``tools/optional_timestamp_inventory.json``:

- ``optional_missing_default``: schema-optional, no ``#[serde(default)]`` ->
  defect; omission fails deserialization while producers skip ``None``.
- ``optional_has_default``: schema-optional with ``#[serde(default)]`` -> ok.
- ``required``: schema-required -> absence must stay an error; do not touch.
- ``internal``: no owning schema located -> judge by producer/consumer.
- ``schema_field_unknown``: an owner was located but does not declare the
  field -> needs manual review (possible stale doc pointer).

The reconciliation result feeds ``tools/lint-optional-timestamp-defaults.py``
(the standing gate) and its allowlist.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wire_value_audit import (  # noqa: E402
    SchemaResolver,
    normalize_pointer,
    preceding_docs,
    prepared_source,
)

_LINT_PATH = Path(__file__).resolve().with_name("lint-optional-timestamp-defaults.py")
_LINT_SPEC = importlib.util.spec_from_file_location(
    "lint_optional_timestamp_defaults", _LINT_PATH
)
assert _LINT_SPEC is not None and _LINT_SPEC.loader is not None
LINT = importlib.util.module_from_spec(_LINT_SPEC)
# dataclasses resolve __module__ through sys.modules on Python 3.14+.
sys.modules[_LINT_SPEC.name] = LINT
_LINT_SPEC.loader.exec_module(LINT)

ROOT = Path(__file__).resolve().parents[1]
CRATES = ROOT / "crates"
DEFAULT_SPEC_ROOT = (
    ROOT.parent / "arkret-spec" / "spec" / "v1" / "artifacts" / "schemas"
)
DEFAULT_INVENTORY = ROOT / "tools" / "optional_timestamp_inventory.json"

POINTER_RE = re.compile(
    r"`([^`]*(?:spec/v1/artifacts/schemas/)?[A-Za-z0-9_.-]+\.schema\.json(?:#[^`]*)?)`"
)
DEFAULT_RE = re.compile(r"\bdefault\b")
SKIP_RE = re.compile(r"\bskip_serializing_if\b")


@dataclass(frozen=True)
class TimestampSite:
    file: str
    line: int
    struct_name: str
    field_name: str
    field_type: str
    has_default: bool
    has_skip: bool
    schema_pointer: str | None
    schema_source: str
    classification: str


def iter_sites(path: Path) -> Iterable[tuple[str, str, str, int, str, bool, bool]]:
    """Yield (type, field, field_type, line, docs, has_default, has_skip) per
    adapter field.

    Field sites are located through the standing gate's attribute-group scan,
    which covers struct fields, enum-variant fields, the unqualified
    ``with = "optional_canonical_timestamp"`` import form, and the split
    ``serialize_with``/``deserialize_with`` pair form alike.
    """
    source, masked = prepared_source(path)
    seen_lines: set[int] = set()
    for block_start, block_end in LINT.serde_adapter_blocks(masked, source):
        group_start, group_end = LINT.attribute_group(masked, block_start, block_end)
        field = LINT.field_after(masked, source, group_end)
        if field is None:
            continue
        field_name, field_type, field_line = field
        if field_line in seen_lines:
            continue
        seen_lines.add(field_line)
        owner = LINT.enclosing_type(masked, group_start)
        type_name, type_offset = owner if owner else ("<unknown>", 0)
        decl_line_start = masked.rfind("\n", 0, type_offset) + 1 if owner else 0
        docs = preceding_docs(source, decl_line_start) if owner else ""
        group_masked = masked[group_start:group_end]
        has_default = bool(DEFAULT_RE.search(group_masked)) or bool(
            owner and LINT.container_has_default(masked, source, type_offset)
        )
        has_skip = bool(SKIP_RE.search(group_masked))
        yield type_name, field_name, field_type, field_line, docs, has_default, has_skip


def merge_object_shape(
    resolver: SchemaResolver, path: Path, node: Any, seen: set[int] | None = None
) -> tuple[set[str], set[str]]:
    """Return (properties, required) merged across allOf/$ref composition."""
    seen = seen or set()
    if id(node) in seen or not isinstance(node, dict):
        return set(), set()
    seen.add(id(node))
    path, node = resolver.resolve_ref(path, node)
    properties = set()
    required = set()
    if isinstance(node, dict):
        props = node.get("properties")
        if isinstance(props, dict):
            properties.update(props)
        req = node.get("required")
        if isinstance(req, list):
            required.update(str(item) for item in req)
        for keyword in ("allOf",):
            members = node.get(keyword)
            if isinstance(members, list):
                for member in members:
                    sub_props, sub_req = merge_object_shape(
                        resolver, path, member, seen
                    )
                    properties.update(sub_props)
                    required.update(sub_req)
    return properties, required


def locate_owner(
    resolver: SchemaResolver, struct_name: str, field_name: str, docs: str
) -> tuple[str | None, str, Any, Path | None]:
    pointer_match = POINTER_RE.search(docs)
    if pointer_match:
        pointer = normalize_pointer(pointer_match.group(1))
        try:
            path, node = resolver.pointer_node(pointer)
            path, node = resolver.resolve_ref(path, node)
            if isinstance(node, dict):
                return pointer, "doc-pointer", node, path
        except (KeyError, FileNotFoundError, ValueError, IndexError):
            pass
    inferred = resolver.inferred_owner(struct_name, field_name)
    if inferred is not None:
        path, fragment, node = inferred
        pointer = f"{path.name}{fragment}"
        return pointer, "def-index", node, path
    return None, "none", None, None


def classify_site(
    resolver: SchemaResolver,
    struct_name: str,
    field_name: str,
    has_default: bool,
    docs: str,
) -> tuple[str, str | None, str]:
    pointer, source_kind, node, path = locate_owner(
        resolver, struct_name, field_name, docs
    )
    if node is None or path is None:
        return "internal", None, source_kind
    properties, required = merge_object_shape(resolver, path, node)
    if field_name not in properties:
        return "schema_field_unknown", pointer, source_kind
    if field_name in required:
        return "required", pointer, source_kind
    if has_default:
        return "optional_has_default", pointer, source_kind
    return "optional_missing_default", pointer, source_kind


def run(spec_root: Path) -> list[TimestampSite]:
    resolver = SchemaResolver(spec_root)
    sites: list[TimestampSite] = []
    for path in sorted(CRATES.rglob("*.rs")):
        relative = path.relative_to(ROOT).as_posix()
        for struct_name, field_name, field_type, line, docs, has_default, has_skip in iter_sites(
            path
        ):
            classification, pointer, source_kind = classify_site(
                resolver, struct_name, field_name, has_default, docs
            )
            sites.append(
                TimestampSite(
                    file=relative,
                    line=line,
                    struct_name=struct_name,
                    field_name=field_name,
                    field_type=field_type,
                    has_default=has_default,
                    has_skip=has_skip,
                    schema_pointer=pointer,
                    schema_source=source_kind,
                    classification=classification,
                )
            )
    return sites


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec-root", type=Path, default=DEFAULT_SPEC_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_INVENTORY)
    args = parser.parse_args()

    sites = run(args.spec_root)
    counts = Counter(site.classification for site in sites)
    inventory = {
        "version": 2,
        "total": len(sites),
        "counts": dict(sorted(counts.items())),
        "sites": [asdict(site) for site in sites],
    }
    with args.output.open("w", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n")
    print(f"total sites: {len(sites)}")
    for classification, count in sorted(counts.items()):
        print(f"  {classification}: {count}")
    print(f"inventory written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
