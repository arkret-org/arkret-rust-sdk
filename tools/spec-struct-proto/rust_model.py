#!/usr/bin/env python3
"""Parse Rust wire types into a serde-level model.

The model is intentionally shallow: it records what serde would do with a
declaration (wire member names, optionality, omission rules, container
representation) rather than the full Rust AST. That is the level at which a
generated type and a hand-written type must agree, and it is the level the
comparison in ``compare.py`` operates on.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

TOOLS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_ROOT))

from wire_value_audit import (  # noqa: E402
    POINTER_RE,
    mask_non_code,
    matching_brace,
    normalize_pointer,
    split_top_level_fields,
)

STRUCT_RE = re.compile(r"\bpub\s+struct\s+([A-Za-z_][A-Za-z0-9_]*)")
ENUM_RE = re.compile(r"\bpub\s+enum\s+([A-Za-z_][A-Za-z0-9_]*)")
SERDE_RE = re.compile(r"#\s*\[\s*serde\s*\((.*?)\)\s*\]", re.DOTALL)
RENAME_RE = re.compile(r'\brename\s*=\s*"([^"]+)"')
RENAME_ALL_RE = re.compile(r'\brename_all\s*=\s*"([^"]+)"')
TAG_RE = re.compile(r'\btag\s*=\s*"([^"]+)"')
CONTENT_RE = re.compile(r'\bcontent\s*=\s*"([^"]+)"')
WITH_RE = re.compile(r'\bwith\s*=\s*"([^"]+)"')
SKIP_SERIALIZING_IF_RE = re.compile(r'\bskip_serializing_if\s*=\s*"([^"]+)"')
DEFAULT_RE = re.compile(r'\bdefault(?:\s*=\s*"([^"]+)")?')
NAMED_FIELD_RE = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*:(?!:)\s*(.+)\Z",
    re.DOTALL | re.MULTILINE,
)


def rename_ident(name: str, style: str | None) -> str:
    if style is None:
        return name
    words = [w for w in re.split(r"(?<=[a-z0-9])(?=[A-Z])|_", name) if w]
    lowered = [w.lower() for w in words]
    if style == "snake_case":
        return "_".join(lowered)
    if style == "camelCase":
        return lowered[0] + "".join(w[:1].upper() + w[1:] for w in lowered[1:])
    if style == "PascalCase":
        return "".join(w[:1].upper() + w[1:] for w in lowered)
    if style == "kebab-case":
        return "-".join(lowered)
    if style == "SCREAMING_SNAKE_CASE":
        return "_".join(lowered).upper()
    if style == "lowercase":
        return "".join(lowered)
    if style == "UPPERCASE":
        return "".join(lowered).upper()
    return name


def pascal_to_snake(name: str) -> str:
    first = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", first).lower()


@dataclass
class RustField:
    name: str
    wire_name: str
    rust_type: str
    optional: bool
    has_default: bool
    default_path: str | None
    skip_serializing_if: str | None
    with_module: str | None
    flatten: bool
    skipped: bool
    doc_pointer: str | None


@dataclass
class RustVariant:
    name: str
    wire_name: str
    payload: str | None  # None = unit, "tuple:<T>" or "struct"


@dataclass
class RustType:
    name: str
    kind: str  # "struct" | "newtype" | "unit_struct" | "enum"
    file: str
    line: int
    rename_all: str | None
    deny_unknown_fields: bool
    transparent: bool
    tag: str | None
    content: str | None
    untagged: bool
    doc_pointer: str | None
    docs: str
    fields: list[RustField] = field(default_factory=list)
    variants: list[RustVariant] = field(default_factory=list)
    newtype_inner: str | None = None
    derives: list[str] = field(default_factory=list)

    @property
    def is_serde(self) -> bool:
        return "Serialize" in self.derives or "Deserialize" in self.derives


def preceding_attributes(source: str, start: int) -> str:
    lines = source[:start].splitlines()
    selected: list[str] = []
    index = len(lines) - 1
    depth = 0
    while index >= 0:
        stripped = lines[index].strip()
        if stripped.startswith("#[") or stripped.startswith("///") or not stripped:
            selected.append(lines[index])
            index -= 1
            continue
        # Continuation lines of a multi-line attribute.
        if depth or stripped.endswith(")") or stripped.endswith(","):
            probe = index
            joined: list[str] = []
            while probe >= 0 and not lines[probe].lstrip().startswith("#["):
                joined.append(lines[probe])
                probe -= 1
                if len(joined) > 12:
                    break
            if probe >= 0 and lines[probe].lstrip().startswith("#["):
                selected.extend(joined)
                selected.append(lines[probe])
                index = probe - 1
                continue
        break
    return "\n".join(reversed(selected))


def direct_docs(source: str, start: int) -> str:
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


def derive_list(attributes: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(r"derive\s*\(([^)]*)\)", attributes, re.DOTALL):
        found.extend(part.strip().split("::")[-1] for part in match.group(1).split(","))
    return [item for item in found if item]


def _parse_field(raw_field: str) -> RustField | None:
    # mask_non_code preserves offsets, so a match on the masked text can slice
    # the original. Matching the stripped text instead would find the field name
    # inside a preceding doc comment and cut the type out of the rustdoc.
    masked = mask_non_code(raw_field)
    field_match = NAMED_FIELD_RE.search(masked)
    if field_match is None:
        return None
    name = field_match.group(1)
    colon = masked.index(":", field_match.end(1))
    rust_type = raw_field[colon + 1 :].strip().rstrip(",").strip()
    rust_type = re.sub(r"\s+", " ", rust_type)
    serde_attributes = " ".join(SERDE_RE.findall(raw_field))
    default_match = DEFAULT_RE.search(serde_attributes)
    docs_pointer = POINTER_RE.search(raw_field)
    return RustField(
        name=name,
        wire_name=name,
        rust_type=rust_type,
        optional=rust_type.startswith("Option<"),
        has_default=default_match is not None,
        default_path=default_match.group(1) if default_match else None,
        skip_serializing_if=(
            SKIP_SERIALIZING_IF_RE.search(serde_attributes).group(1)
            if SKIP_SERIALIZING_IF_RE.search(serde_attributes)
            else None
        ),
        with_module=(
            WITH_RE.search(serde_attributes).group(1)
            if WITH_RE.search(serde_attributes)
            else None
        ),
        flatten="flatten" in serde_attributes,
        skipped=bool(re.search(r"\bskip\b(?!_)", serde_attributes)),
        doc_pointer=normalize_pointer(docs_pointer.group(1)) if docs_pointer else None,
    )


def _split_variants(body: str, masked_body: str) -> Iterable[tuple[int, str]]:
    return split_top_level_fields(body, masked_body)


def parse_file(path: Path, root: Path) -> list[RustType]:
    source = path.read_text(encoding="utf-8")
    masked = mask_non_code(source)
    relative = path.relative_to(root).as_posix()
    results: list[RustType] = []

    for regex, kind in ((STRUCT_RE, "struct"), (ENUM_RE, "enum")):
        for match in regex.finditer(masked):
            name = match.group(1)
            attributes = preceding_attributes(source, match.start())
            serde_attributes = " ".join(SERDE_RE.findall(attributes))
            rename_all_match = RENAME_ALL_RE.search(serde_attributes)
            docs = direct_docs(source, match.start())
            pointer_match = POINTER_RE.search(docs)
            item = RustType(
                name=name,
                kind=kind,
                file=relative,
                line=source.count("\n", 0, match.start()) + 1,
                rename_all=rename_all_match.group(1) if rename_all_match else None,
                deny_unknown_fields="deny_unknown_fields" in serde_attributes,
                transparent="transparent" in serde_attributes,
                tag=(
                    TAG_RE.search(serde_attributes).group(1)
                    if TAG_RE.search(serde_attributes)
                    else None
                ),
                content=(
                    CONTENT_RE.search(serde_attributes).group(1)
                    if CONTENT_RE.search(serde_attributes)
                    else None
                ),
                untagged="untagged" in serde_attributes,
                doc_pointer=(
                    normalize_pointer(pointer_match.group(1)) if pointer_match else None
                ),
                docs=docs,
                derives=derive_list(attributes),
            )
            tail = masked[match.end() :]
            brace = tail.find("{")
            paren = tail.find("(")
            semi = tail.find(";")
            candidates = [c for c in (brace, paren, semi) if c >= 0]
            if not candidates:
                continue
            first = min(candidates)
            if first == semi:
                item.kind = "unit_struct"
                results.append(item)
                continue
            if first == paren and kind == "struct":
                item.kind = "newtype"
                open_index = match.end() + paren
                close = masked.find(")", open_index)
                inner = source[open_index + 1 : close].strip()
                item.newtype_inner = re.sub(r"^pub\s+", "", inner).strip()
                results.append(item)
                continue
            open_index = match.end() + brace
            close = matching_brace(masked, open_index)
            body = source[open_index + 1 : close]
            masked_body = masked[open_index + 1 : close]
            if kind == "struct":
                for _, raw_field in split_top_level_fields(body, masked_body):
                    parsed = _parse_field(raw_field)
                    if parsed is None:
                        continue
                    rename = RENAME_RE.search(" ".join(SERDE_RE.findall(raw_field)))
                    parsed.wire_name = (
                        rename.group(1)
                        if rename
                        else rename_ident(parsed.name, item.rename_all)
                    )
                    item.fields.append(parsed)
            else:
                for _, raw_variant in _split_variants(body, masked_body):
                    text = raw_variant.strip()
                    if not text:
                        continue
                    variant_match = re.search(
                        r"([A-Za-z_][A-Za-z0-9_]*)\s*(\(|\{)?", mask_non_code(text)
                    )
                    # Skip attribute-only leading lines.
                    cleaned = "\n".join(
                        line
                        for line in text.splitlines()
                        if not line.strip().startswith("#") and not line.strip().startswith("///")
                    ).strip()
                    variant_match = re.match(
                        r"([A-Za-z_][A-Za-z0-9_]*)\s*(\(|\{)?", cleaned
                    )
                    if variant_match is None:
                        continue
                    vname = variant_match.group(1)
                    opener = variant_match.group(2)
                    payload = None
                    if opener == "(":
                        payload = "tuple"
                    elif opener == "{":
                        payload = "struct"
                    rename = RENAME_RE.search(" ".join(SERDE_RE.findall(raw_variant)))
                    item.variants.append(
                        RustVariant(
                            name=vname,
                            wire_name=(
                                rename.group(1)
                                if rename
                                else rename_ident(vname, item.rename_all)
                            ),
                            payload=payload,
                        )
                    )
            results.append(item)
    return results


def parse_crate(crate_src: Path, root: Path) -> dict[str, RustType]:
    found: dict[str, RustType] = {}
    for path in sorted(crate_src.rglob("*.rs")):
        for item in parse_file(path, root):
            found[item.name] = item
    return found
