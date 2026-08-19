#!/usr/bin/env python3
"""Gate: optional canonical timestamp fields must accept omission.

A field carrying all three of

- type ``Option<DateTime<Utc>>``,
- ``skip_serializing_if = "Option::is_none"``,
- ``with = "...optional_canonical_timestamp"``,

is a field the producer omits when ``None``. Without ``#[serde(default)]``
the same type then rejects its own wire form on deserialize (missing field is
an error). The adapter may appear as the two-way ``with = "...optional_
canonical_timestamp"`` module or as the split ``serialize_with`` /
``deserialize_with`` pair naming the helper functions directly. Any such
field on a deserializable type MUST carry ``#[serde(default)]`` unless it is
listed in ``tools/optional_timestamp_default_allowlist.json`` with a written
reason. ``serialize_with``-only fields on ``Serialize``-only signing
transcripts cannot break round-trips and are out of scope.

Schema-``required`` fields without ``default`` are the deliberate fail-closed
shape and are *not* exempt by default; they only pass through this gate when
they are not ``Option`` + ``skip_serializing_if`` triples (the usual case) or
carry an explicit allowlist reason.

Self-tests live in ``tools/test_lint_optional_timestamp_defaults.py``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wire_value_audit import matching_delimiter, prepared_source  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALLOWLIST = ROOT / "tools" / "optional_timestamp_default_allowlist.json"

SERDE_ATTR_RE = re.compile(r"#\s*\[\s*serde\s*\(")
FIELD_RE = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*,?\s*$"
)
TYPE_RE = re.compile(r"\b(?:struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)")
DEFAULT_KEY_RE = re.compile(r"\bdefault\b")
DESERIALIZE_DERIVE_RE = re.compile(r"\bDeserialize\b")
# The two-way serde adapter (`with = "...optional_canonical_timestamp"`) plus
# its split pair forms. A one-way `serialize_with` on a Serialize-only
# transcript cannot break round-trips, so it is in scope only when the
# enclosing type also derives `Deserialize`.
WITH_ADAPTER_RE = re.compile(r"\bwith\s*=\s*\"[^\"]*optional_canonical_timestamp\"")
DESERIALIZE_ADAPTER_RE = re.compile(
    r"\bdeserialize_with\s*=\s*\"[^\"]*deserialize_optional_canonical_timestamp\""
)
SERIALIZE_ADAPTER_RE = re.compile(
    r"\bserialize_with\s*=\s*\"[^\"]*serialize_optional_canonical_timestamp\""
)
ADAPTER_RES = (WITH_ADAPTER_RE, DESERIALIZE_ADAPTER_RE, SERIALIZE_ADAPTER_RE)


@dataclass(frozen=True)
class Violation:
    file: str
    line: int
    type_name: str
    field_name: str


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def adapter_forms(block_text: str) -> set[str]:
    forms = set()
    if WITH_ADAPTER_RE.search(block_text):
        forms.add("with")
    if DESERIALIZE_ADAPTER_RE.search(block_text):
        forms.add("deserialize_with")
    if SERIALIZE_ADAPTER_RE.search(block_text):
        forms.add("serialize_with")
    return forms


def serde_adapter_blocks(masked: str, source: str) -> list[tuple[int, int]]:
    """Return (start, end) byte spans of ``#[serde(...)]`` blocks naming the adapter."""
    spans = []
    for match in SERDE_ATTR_RE.finditer(masked):
        bracket = masked.find("[", match.start())
        end = matching_delimiter(masked, bracket)
        if adapter_forms(source[match.start() : end + 1]):
            spans.append((match.start(), end + 1))
    return spans


def attribute_group(masked: str, block_start: int, block_end: int) -> tuple[int, int]:
    """Expand a serde attribute block to the full contiguous attribute group.

    Walks upward/downward over sibling ``#[...]`` blocks (skipping whitespace
    and masked-out doc comments), stopping at real code. Container-level
    attributes such as a struct-level ``#[serde(default)]`` belong to the
    group on purpose: they change omission semantics for every field.
    """
    start = block_start
    while True:
        index = start - 1
        while index >= 0 and masked[index] in " \t\r\n":
            index -= 1
        if index < 0 or masked[index] != "]":
            break
        depth = 0
        opening = index
        while opening >= 0:
            if masked[opening] == "]":
                depth += 1
            elif masked[opening] == "[":
                depth -= 1
                if depth == 0:
                    break
            opening -= 1
        if opening <= 0 or masked[opening - 1] != "#":
            break
        start = opening - 1
    end = block_end
    while True:
        index = end
        while index < len(masked) and masked[index] in " \t\r\n":
            index += 1
        if masked.startswith("#[", index):
            end = matching_delimiter(masked, index + 1) + 1
        else:
            break
    return start, end


def field_after(
    masked: str, source: str, group_end: int
) -> tuple[str, str, int] | None:
    index = group_end
    while True:
        newline = masked.find("\n", index)
        if newline == -1:
            return None
        index = newline + 1
        line_end = masked.find("\n", index)
        if line_end == -1:
            line_end = len(masked)
        line = masked[index:line_end]
        if not line.strip():
            continue
        match = FIELD_RE.match(line)
        if not match:
            return None
        # Line numbers come from `source`: masking drops newlines after
        # backslash continuations inside string literals.
        return match.group(1), match.group(2), line_of(source, index)


def enclosing_type(masked: str, offset: int) -> tuple[str, int] | None:
    found = None
    for match in TYPE_RE.finditer(masked, 0, offset):
        found = (match.group(1), match.start())
    return found


def container_attr_blocks(masked: str, source: str, type_offset: int) -> list[str]:
    """Raw texts of the attribute blocks directly above a type declaration."""
    blocks = []
    index = masked.rfind("\n", 0, type_offset) + 1
    while True:
        index -= 1
        while index >= 0 and masked[index] in " \t\r\n":
            index -= 1
        if index < 0 or masked[index] != "]":
            return blocks
        depth = 0
        opening = index
        while opening >= 0:
            if masked[opening] == "]":
                depth += 1
            elif masked[opening] == "[":
                depth -= 1
                if depth == 0:
                    break
            opening -= 1
        if opening <= 0 or masked[opening - 1] != "#":
            return blocks
        blocks.append(source[opening - 1 : index + 1])
        index = opening - 1


def container_has_default(masked: str, source: str, type_offset: int) -> bool:
    """True when the type declaration itself carries ``#[serde(default)]``."""
    for block in container_attr_blocks(masked, source, type_offset):
        if block.lstrip().startswith("#[serde(") and DEFAULT_KEY_RE.search(
            re.sub(r'"[^"]*"', '""', block)
        ):
            return True
    return False


def container_derives_deserialize(
    masked: str, source: str, type_offset: int
) -> bool:
    """True when the type declaration derives ``Deserialize``."""
    for block in container_attr_blocks(masked, source, type_offset):
        if "derive(" in block and DESERIALIZE_DERIVE_RE.search(
            re.sub(r'"[^"]*"', '""', block)
        ):
            return True
    return False


def scan_file(path: Path, relative: str) -> list[Violation]:
    source, masked = prepared_source(path)
    violations = []
    for block_start, block_end in serde_adapter_blocks(masked, source):
        forms = adapter_forms(source[block_start:block_end])
        group_start, group_end = attribute_group(masked, block_start, block_end)
        group_masked = masked[group_start:group_end]
        field = field_after(masked, source, group_end)
        if field is None:
            continue
        field_name, field_type, field_line = field
        if "Option" not in field_type or "DateTime" not in field_type:
            continue
        if "skip_serializing_if" not in group_masked:
            continue
        if DEFAULT_KEY_RE.search(group_masked):
            continue
        owner = enclosing_type(masked, group_start)
        type_name, type_offset = owner if owner else ("<unknown>", 0)
        round_trip = forms & {"with", "deserialize_with"} or (
            forms
            and owner is not None
            and container_derives_deserialize(masked, source, type_offset)
        )
        if not round_trip:
            continue
        if owner and container_has_default(masked, source, type_offset):
            continue
        violations.append(
            Violation(
                file=relative,
                line=field_line,
                type_name=type_name,
                field_name=field_name,
            )
        )
    return violations


def load_allowlist(path: Path) -> dict[tuple[str, str, str], str]:
    document = json.loads(path.read_text(encoding="utf-8"))
    entries = {}
    for entry in document.get("entries", []):
        key = (entry.get("file", ""), entry.get("type", ""), entry.get("field", ""))
        reason = entry.get("reason", "")
        entries[key] = reason
    return entries


def allowlist_key_errors(
    allowlist: dict[tuple[str, str, str], str],
) -> list[str]:
    errors = []
    for (file, type_name, field), reason in allowlist.items():
        label = f"{file}::{type_name}.{field}"
        if not all((file, type_name, field)):
            errors.append(f"{label}: allowlist entry needs file, type and field")
        elif not reason.strip():
            errors.append(f"{label}: allowlist entry must state a reason")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    args = parser.parse_args()

    crates = args.root / "crates"
    allowlist = load_allowlist(args.allowlist)

    errors: list[str] = allowlist_key_errors(allowlist)

    used: set[tuple[str, str, str]] = set()
    for path in sorted(crates.rglob("*.rs")):
        relative = path.relative_to(args.root).as_posix()
        for violation in scan_file(path, relative):
            key = (violation.file, violation.type_name, violation.field_name)
            if key in allowlist:
                used.add(key)
                continue
            errors.append(
                f"{violation.file}:{violation.line}: "
                f"{violation.type_name}.{violation.field_name} is an optional canonical "
                "timestamp the producer omits when None; add #[serde(default)] or an "
                "allowlist entry with a reason"
            )

    for key, _reason in allowlist.items():
        if key not in used and all(key):
            errors.append(
                f"{key[0]}::{key[1]}.{key[2]}: stale allowlist entry; the field now "
                "carries #[serde(default)] or is gone"
            )

    if errors:
        print("optional timestamp default gate failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("optional timestamp default gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
