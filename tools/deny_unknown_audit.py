#!/usr/bin/env python3
"""Audit `#[serde(deny_unknown_fields)]` distribution against Spec openness.

Enforces the unknown-field strictness policy (see arkret-work
`2026-07-14-sdk-wire-strong-type-convergence.md`, section "2026-07-15 decision"):

  1. No `cfg`-gated `deny_unknown_fields` (runtime accept/reject must be
     identical in every build; environment may only change signal strength).
  2. A Rust type mirroring a Spec object with `additionalProperties: true`
     (or a non-`false` additionalProperties schema / `unevaluatedProperties`
     that permits extras) MUST NOT carry `deny_unknown_fields` (C class).
  3. A type carrying `deny_unknown_fields` MUST NOT also flatten an extra map
     (the closed object would silently re-open).

The forward half of gate 2 ("every `additionalProperties: false` object has a
Rust owner that denies") is covered by the field-level owner inventory in
`wire_value_audit.py`; this tool validates the reverse: that every existing
`deny_unknown_fields` sits on a genuinely closed boundary.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wire_value_audit import (  # noqa: E402
    POINTER_RE,
    SchemaResolver,
    mask_non_code,
    matching_brace,
    normalize_pointer,
    preceding_docs,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SPEC_ROOT = ROOT.parent / "arkret-spec" / "spec" / "v1" / "artifacts" / "schemas"
DEFAULT_ALLOWLIST = ROOT / "tools" / "deny_unknown_allowlist.json"
DEFAULT_INVENTORY = ROOT / "tools" / "deny_unknown_inventory.json"

DENY_RE = re.compile(r"deny_unknown_fields")
TYPE_DECL_RE = re.compile(r"\b(struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)")
CFG_ATTR_RE = re.compile(r"#\s*\[\s*cfg(?:_attr)?\s*\(")
FLATTEN_RE = re.compile(r"#\s*\[\s*serde\s*\([^)]*\bflatten\b")

# Cryptographic / canonical boundaries: deny is a completeness floor here, and
# these get explicit unknown-field negative tests. Membership is by file path.
A_CLASS_MARKERS = (
    "signatures/",
    "identity_key_log.rs",
    "cross_signing.rs",
    "mls_governance_proof.rs",
    "mls_payloads.rs",
    "operation_payloads/",
    "event_wire.rs",
    "sdk_conformance.rs",
    "proof.rs",
    "jwt.rs",
    "signer.rs",
)


@dataclass(frozen=True)
class DenySite:
    crate: str
    file: str
    line: int
    kind: str
    value_kind: str
    spec_pointer: str | None
    cfg_gated: bool
    flatten_extra: bool


def preceding_attr_block(masked: str, decl_start: int) -> tuple[int, str]:
    """Return (block_start, block_text) for the attribute/doc run above a decl.

    Walks backward over the contiguous run of attribute (`#[...]`) and doc lines
    directly above the declaration, stopping at the first blank separator.
    """
    text = masked
    start = decl_start
    # Start of the line containing decl_start.
    line_start = text.rfind("\n", 0, decl_start) + 1
    idx = line_start
    while idx > 0:
        prev_line_end = idx - 1
        prev_line_start = text.rfind("\n", 0, prev_line_end) + 1
        stripped = text[prev_line_start:prev_line_end].strip()
        if stripped.startswith("#[") or stripped.startswith("#!") or stripped == "" or stripped.startswith("//"):
            idx = prev_line_start
            start = prev_line_start
            if stripped == "":
                # allow a single blank line inside the attr block, then stop if next is blank too
                break
            continue
        break
    return start, text[start:line_start]


def scan_file(path: Path, source_root: Path) -> list[DenySite]:
    source = path.read_text(encoding="utf-8")
    masked = mask_non_code(source)
    relative = path.relative_to(source_root).as_posix()
    crate = relative.split("/", 2)[1] if "/" in relative else relative
    sites: list[DenySite] = []
    for match in DENY_RE.finditer(masked):
        decl = TYPE_DECL_RE.search(masked, match.end())
        if decl is None:
            continue
        kind = decl.group(1)
        value_kind = decl.group(2)
        decl_start = decl.start()
        _, block_text = preceding_attr_block(masked, decl_start)
        # Only associate this deny with the decl if the deny lies within the
        # attribute block directly above it (no other type decl in between).
        between = masked[match.end() : decl_start]
        if TYPE_DECL_RE.search(between):
            continue
        # A `cfg_attr` line that also carries `deny_unknown_fields` gates the
        # deny on a build config -- forbidden, since runtime accept/reject must
        # not fork per build.
        cfg_gated = False
        for raw_line in block_text.splitlines():
            s = raw_line.strip()
            if "deny_unknown_fields" in s and CFG_ATTR_RE.search(s):
                cfg_gated = True
                break
        # Detect a flattened extra map inside the type body.
        flatten_extra = False
        opening = masked.find("{", decl.end())
        if opening != -1 and kind == "struct":
            try:
                closing = matching_brace(masked, opening)
            except ValueError:
                closing = -1
            if closing != -1:
                body = source[opening + 1 : closing]
                flatten_extra = bool(FLATTEN_RE.search(body))
        # `preceding_docs` walks backward from the declaration over the derive
        # and doc lines, so it must receive the decl position, not the block
        # start (which would exclude the doc comments themselves).
        docs = preceding_docs(source, decl_start)
        pointer_match = POINTER_RE.search(docs)
        pointer = normalize_pointer(pointer_match.group(1)) if pointer_match else None
        line = source.count("\n", 0, match.start()) + 1
        sites.append(
            DenySite(
                crate=crate,
                file=relative,
                line=line,
                kind=kind,
                value_kind=value_kind,
                spec_pointer=pointer,
                cfg_gated=cfg_gated,
                flatten_extra=flatten_extra,
            )
        )
    return sites


def scan_sites(source_root: Path) -> list[DenySite]:
    sites: list[DenySite] = []
    for path in sorted((source_root / "crates").glob("**/*.rs")):
        sites.extend(scan_file(path, source_root))
    return sorted(sites, key=lambda s: (s.file, s.line))


def name_inferred_node(resolver: SchemaResolver, site: DenySite) -> tuple[str | None, Any, Path | None]:
    name = resolver.rust_name_to_schema_name(site.value_kind)
    candidates = resolver.build_def_index().get(name, [])
    unique = list(dict.fromkeys((p, frag) for p, frag, _ in candidates))
    if len(unique) == 1:
        p, frag = unique[0]
        _, node = resolver.resolve_ref(p, resolver.pointer_node(f"{p.name}{frag}")[1] if frag else resolver.load(p))
        return f"{p.name}{frag}", node, p
    return None, None, None


def resolve_owner_node(resolver: SchemaResolver, site: DenySite) -> tuple[str | None, Any, Path | None]:
    """Return (effective_pointer, resolved_node, schema_path) for the type's Spec owner.

    Prefer the declared doc pointer, but fall back to name inference whenever the
    pointer is missing or resolves to something whose openness is indefinite --
    the two strategies are complementary (a pointer may target a `oneOf` wrapper
    schema, while name inference lands on the concrete object def). The schema
    file path is threaded along so that composition branches with relative or
    fragment-only `$ref`s resolve against the owning document, not the spec root
    directory.
    """
    pointer_result: tuple[str | None, Any, Path | None] = (None, None, None)
    if site.spec_pointer:
        try:
            path, node = resolver.pointer_node(site.spec_pointer)
            path, node = resolver.resolve_ref(path, node)
            pointer_result = (site.spec_pointer, node, path)
        except (FileNotFoundError, KeyError, json.JSONDecodeError, TypeError):
            pointer_result = (None, None, None)
    if pointer_result[1] is not None and object_openness(
        resolver, pointer_result[1], pointer_result[2]
    ) in {"closed", "open"}:
        return pointer_result
    inferred = name_inferred_node(resolver, site)
    if inferred[1] is not None and object_openness(resolver, inferred[1], inferred[2]) in {"closed", "open"}:
        return inferred
    return pointer_result if pointer_result[1] is not None else inferred


def object_openness(resolver: SchemaResolver, node: Any, path: Path | None = None) -> str:
    """closed | open | unspecified | non_object."""
    if not isinstance(node, dict):
        return "unspecified"
    node_type = node.get("type")
    is_object = node_type == "object" or (isinstance(node_type, list) and "object" in node_type)
    has_props = isinstance(node.get("properties"), dict)
    uneval = node.get("unevaluatedProperties")
    additional = node.get("additionalProperties")
    if additional is False or uneval is False:
        return "closed"
    if additional is True or additional == {} or isinstance(additional, dict):
        return "open"
    if uneval is True:
        return "open"
    # oneOf/anyOf/allOf composition without a top-level additionalProperties:
    for union_key in ("oneOf", "anyOf", "allOf"):
        branches = node.get(union_key)
        if isinstance(branches, list):
            shapes = set()
            for branch in branches:
                # Resolve branch $refs against the owning schema file when it
                # is known; the spec root is a directory, so fragment-only or
                # relative refs cannot resolve against it.
                bpath = path if path is not None else resolver.root
                try:
                    bpath, resolved = resolver.resolve_ref(bpath, branch)
                except (FileNotFoundError, KeyError, json.JSONDecodeError, TypeError):
                    shapes.add("unspecified")
                    continue
                shapes.add(object_openness(resolver, resolved, bpath))
            if "open" in shapes:
                return "open"
            if shapes <= {"closed"} and shapes:
                return "closed"
            return "unspecified"
    if is_object or has_props:
        # object with properties but no explicit additionalProperties: ambiguous
        return "unspecified"
    return "unspecified"


def a_or_b(site: DenySite) -> str:
    return "A" if any(marker in site.file for marker in A_CLASS_MARKERS) else "B"


def load_allowlist(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {entry["rust_type"]: entry for entry in payload.get("entries", [])}


def report(sites: list[DenySite], resolver: SchemaResolver, allowlist: dict[str, dict[str, Any]]) -> dict[str, Any]:
    entries = []
    for site in sites:
        key = f"{site.file}::{site.value_kind}"
        pointer, node, owner_path = resolve_owner_node(resolver, site)
        openness = object_openness(resolver, node, owner_path) if node is not None else "unresolved"
        if openness == "closed":
            classification = a_or_b(site)
        elif openness == "open":
            classification = "C_violation"
        else:
            classification = "needs_review"
        override = allowlist.get(key)
        if override and override.get("classification"):
            classification = override["classification"]
        entries.append(
            {
                "rust_type": key,
                "crate": site.crate,
                "file": site.file,
                "line": site.line,
                "kind": site.kind,
                "value_kind": site.value_kind,
                "spec_pointer": pointer or site.spec_pointer,
                "schema_openness": openness,
                "classification": classification,
                "cfg_gated": site.cfg_gated,
                "flatten_extra": site.flatten_extra,
            }
        )
    return {
        "summary": {
            "total": len(entries),
            "by_classification": dict(sorted(Counter(e["classification"] for e in entries).items())),
            "by_openness": dict(sorted(Counter(e["schema_openness"] for e in entries).items())),
            "by_crate": dict(sorted(Counter(e["crate"] for e in entries).items())),
        },
        "entries": entries,
    }


def validate(payload: dict[str, Any], allowlist: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen = set()
    for entry in payload["entries"]:
        key = entry["rust_type"]
        seen.add(key)
        if entry["cfg_gated"]:
            errors.append(f"cfg-gated deny_unknown_fields (runtime behavior must not fork per build): {key}")
        if entry["flatten_extra"]:
            errors.append(f"deny_unknown_fields type also flattens an extra map (closed object re-opened): {key}")
        if entry["classification"] == "C_violation":
            errors.append(
                "deny_unknown_fields on an open (additionalProperties permits extras) object; "
                f"remove the deny so unknown fields are dropped, not rejected: {key} -> {entry['spec_pointer']}"
            )
    for key in sorted(set(allowlist) - seen):
        errors.append(f"stale deny allowlist entry (type no longer denies unknown fields): {key}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, default=DEFAULT_SPEC_ROOT)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--write-report", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    sites = scan_sites(args.source_root)
    resolver = SchemaResolver(args.spec_root)
    allowlist = load_allowlist(args.allowlist)
    payload = report(sites, resolver, allowlist)
    rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if args.write_report:
        args.write_report.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    if args.check:
        errors = validate(payload, allowlist)
        if args.inventory.exists() and args.source_root.resolve() == ROOT.resolve():
            tracked = json.loads(args.inventory.read_text(encoding="utf-8"))
            if tracked != payload:
                errors.append(
                    "deny inventory drifted; regenerate tools/deny_unknown_inventory.json"
                )
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
