#!/usr/bin/env python3
"""Map Rust wire types in a crate onto Spec schema nodes.

Resolution order, strongest evidence first:

1. ``tools/schema_struct_registry.json`` mapping or exemption entry.
2. A JSON Pointer in the type's own rustdoc.
3. A ``$defs`` name equal to the snake_case form of the Rust type name.
4. A schema node whose property set equals the type's wire field set, or whose
   string ``enum`` set equals the variant wire-name set.

Anything left over is reported as Rust-only, with a heuristic reason so the
reviewer can tell a local helper apart from a lost counterpart.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rust_model  # noqa: E402
from schema_index import SchemaIndex  # noqa: E402

TOOLS_ROOT = Path(__file__).resolve().parents[1]
SDK_ROOT = TOOLS_ROOT.parent
DEFAULT_SPEC_ROOT = SDK_ROOT.parent / "arkret-spec" / "spec" / "v1" / "artifacts" / "schemas"
DEFAULT_REGISTRY = TOOLS_ROOT / "schema_struct_registry.json"


@dataclass
class Mapping:
    rust_type: str
    kind: str
    file: str
    line: int
    pointer: str | None
    evidence: str
    note: str = ""
    candidates: list[str] = field(default_factory=list)


def _wire_field_names(item: rust_model.RustType) -> frozenset[str]:
    return frozenset(
        f.wire_name for f in item.fields if not f.skipped and not f.flatten
    )


def _variant_wire_names(item: rust_model.RustType) -> frozenset[str]:
    return frozenset(v.wire_name for v in item.variants if v.payload is None)


def load_registry(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    mappings = {
        entry["rust_type"].split("::")[-1]: entry["schema"]
        for entry in document.get("mappings", [])
    }
    exemptions = {
        entry["rust_type"].split("::")[-1]: entry.get("reason", "")
        for entry in document.get("exemptions", [])
    }
    return mappings, exemptions


def build(
    crate_src: Path,
    spec_root: Path = DEFAULT_SPEC_ROOT,
    registry_path: Path = DEFAULT_REGISTRY,
) -> tuple[list[Mapping], dict[str, rust_model.RustType], SchemaIndex]:
    types = rust_model.parse_crate(crate_src, SDK_ROOT)
    index = SchemaIndex(spec_root)
    registry, exemptions = load_registry(registry_path)
    results: list[Mapping] = []

    for name, item in sorted(types.items()):
        base = dict(rust_type=name, kind=item.kind, file=item.file, line=item.line)

        if name in registry:
            results.append(
                Mapping(**base, pointer=registry[name], evidence="registry")
            )
            continue
        if name in exemptions:
            results.append(
                Mapping(
                    **base,
                    pointer=None,
                    evidence="registry-exemption",
                    note=exemptions[name],
                )
            )
            continue
        if item.doc_pointer:
            results.append(
                Mapping(**base, pointer=item.doc_pointer, evidence="rustdoc-pointer")
            )
            continue

        snake = rust_model.pascal_to_snake(name)
        by_name = index.by_def_name.get(snake) or index.by_def_name.get(name) or []
        if len(by_name) == 1:
            results.append(
                Mapping(**base, pointer=by_name[0].pointer, evidence="name-unique")
            )
            continue
        if len(by_name) > 1:
            results.append(
                Mapping(
                    **base,
                    pointer=None,
                    evidence="name-ambiguous",
                    candidates=[n.pointer for n in by_name],
                )
            )
            continue

        # A single shared member name is not evidence: "services" alone matched
        # an unrelated event payload. Require two members before trusting a
        # property-set match, and require the match to be unambiguous.
        if item.kind == "struct" and len(_wire_field_names(item)) >= 2:
            matches = index.by_property_set.get(_wire_field_names(item), [])
            if matches:
                results.append(
                    Mapping(
                        **base,
                        pointer=matches[0].pointer,
                        evidence="property-set",
                        candidates=[n.pointer for n in matches],
                    )
                )
                continue
        # A one-value enum is still good evidence when the value is unique in
        # the artifacts (a const discriminant like "self_claimed" names exactly
        # one node); a one-member struct is not, so it stays excluded above.
        if item.kind == "enum" and item.variants and not any(
            v.payload for v in item.variants
        ):
            matches = index.by_enum_set.get(_variant_wire_names(item), [])
            if len(_variant_wire_names(item)) < 2 and len(matches) != 1:
                matches = []
            if matches:
                results.append(
                    Mapping(
                        **base,
                        pointer=matches[0].pointer,
                        evidence="enum-set",
                        candidates=[n.pointer for n in matches],
                    )
                )
                continue

        near = _nearest(index, item)
        if near is not None:
            pointer, score, missing, extra = near
            results.append(
                Mapping(
                    **base,
                    pointer=pointer,
                    evidence="near-match",
                    note=(
                        f"jaccard={score:.2f}; rust-only={sorted(extra)}; "
                        f"spec-only={sorted(missing)}"
                    ),
                )
            )
            continue

        results.append(
            Mapping(**base, pointer=None, evidence="unmapped", note=_reason(item))
        )
    return results, types, index


NEAR_MATCH_FLOOR = 0.5


def _nearest(
    index: SchemaIndex, item: rust_model.RustType
) -> tuple[str, float, set[str], set[str]] | None:
    """Best partial match by property or enum-value overlap.

    A near match is how field-set drift shows up: the counterpart is obvious to
    a human but no longer set-equal, so the exact indexes miss it.
    """
    if item.kind == "struct" and item.fields:
        target = set(_wire_field_names(item))
        buckets = index.by_property_set
    elif item.kind == "enum" and item.variants and not any(
        v.payload for v in item.variants
    ):
        target = set(_variant_wire_names(item))
        buckets = index.by_enum_set
    else:
        return None
    if len(target) < 2:
        return None
    best: tuple[str, float, set[str], set[str]] | None = None
    for candidate_set, nodes in buckets.items():
        union = target | set(candidate_set)
        if not union:
            continue
        score = len(target & set(candidate_set)) / len(union)
        if score < NEAR_MATCH_FLOOR:
            continue
        if best is None or score > best[1]:
            best = (
                nodes[0].pointer,
                score,
                set(candidate_set) - target,
                target - set(candidate_set),
            )
    return best


def _reason(item: rust_model.RustType) -> str:
    if not item.is_serde:
        return "not a serde type (local helper or error type)"
    if item.kind == "newtype":
        return "newtype wrapper over an existing type"
    if item.kind == "unit_struct":
        return "unit struct (error marker)"
    if item.untagged:
        return "untagged union; no single schema node carries the name"
    if item.kind == "enum" and any(v.payload for v in item.variants):
        return "data-carrying enum; likely mirrors a oneOf branch set"
    return "no name, property-set, or enum-set match in the spec artifacts"


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--crate", default="models-discovery")
    parser.add_argument("--spec-root", type=Path, default=DEFAULT_SPEC_ROOT)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    crate_src = SDK_ROOT / "crates" / args.crate / "src"
    mappings, _types, _index = build(crate_src, args.spec_root)
    buckets: dict[str, list[Mapping]] = {}
    for entry in mappings:
        buckets.setdefault(entry.evidence, []).append(entry)
    for evidence in sorted(buckets):
        print(f"== {evidence}: {len(buckets[evidence])}")
        for entry in buckets[evidence]:
            suffix = f" -> {entry.pointer}" if entry.pointer else f"  ({entry.note})"
            print(f"   {entry.rust_type} [{entry.kind}]{suffix}")
    if args.json:
        args.json.write_text(
            json.dumps([entry.__dict__ for entry in mappings], indent=2),
            encoding="utf-8",
            newline="\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
