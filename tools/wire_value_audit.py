#!/usr/bin/env python3
"""Inventory weakly typed protocol surfaces across the Arkret workspace.

The audit covers public ``Value`` fields plus production protocol JSON
construction, string-path mutation, discriminator/data APIs, and manual
closed-union dispatch.  Test-only code and RFC 7807/9457 problem bodies are
outside the production-authoring scope by design.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ModuleNotFoundError:  # Keep the audit runnable with the Python standard library.
    yaml = None


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = ROOT.parent
DEFAULT_SPEC_ROOT = ROOT.parent / "arkret-spec" / "spec" / "v1" / "artifacts" / "schemas"
DEFAULT_ALLOWLIST = ROOT / "tools" / "wire_value_allowlist.json"
DEFAULT_INVENTORY = ROOT / "tools" / "wire_value_inventory.json"
VALUE_RE = re.compile(r"(?<![A-Za-z0-9_])(?:serde_json::)?Value(?![A-Za-z0-9_])")
STRUCT_RE = re.compile(r"\bpub\s+struct\s+([A-Za-z_][A-Za-z0-9_]*)[^;{]*\{")
FIELD_RE = re.compile(
    r"\bpub\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)\Z",
    re.DOTALL,
)
POINTER_RE = re.compile(
    r"`([^`]*(?:spec/v1/artifacts/schemas/)?[A-Za-z0-9_.-]+\.schema\.json(?:#[^`]*)?)`"
)
CFG_TEST_RE = re.compile(r"#\s*\[\s*cfg\s*\([^\]]*\btest\b[^\]]*\)\s*\]")
CFG_TEST_MODULE_RE = re.compile(
    r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]"
    r"\s*(?:#\s*\[[^\]]*\]\s*)*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*;"
)
CFG_DISABLED_RE = re.compile(r"#\s*\[\s*cfg\s*\(\s*any\s*\(\s*\)\s*\)\s*\]")
TEST_ATTRIBUTE_RE = re.compile(r"#\s*\[\s*test\s*\]")
JSON_MACRO_RE = re.compile(r"\b(?:serde_json::)?json!\s*([({\[])")
FUNCTION_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^{};]*>)?\s*\(",
    re.MULTILINE,
)
MATCH_RE = re.compile(r"\bmatch\s+([^\n{]+)\{")
DISCRIMINATOR_EXPRESSION_RE = re.compile(
    r"\b(?:[A-Za-z0-9_]+_)?(?:kind|type|status|class|variant|state)\b"
)
PROTOCOL_FIELDS = {
    "actor_id",
    "algorithm",
    "body",
    "call_id",
    "class",
    "content",
    "data",
    "device_id",
    "event_id",
    "final_state",
    "kind",
    "metadata",
    "operation_kind",
    "payload",
    "proofs",
    "realm_id",
    "request",
    "response",
    "result",
    "schema",
    "seal_ref",
    "signature",
    "signal_kind",
    "state",
    "status",
    "type",
    "variant",
}
DISCRIMINATOR_FIELDS = {
    "algorithm",
    "class",
    "final_state",
    "kind",
    "operation_kind",
    "schema",
    "signal_kind",
    "state",
    "status",
    "type",
    "variant",
}
DATA_FIELDS = {"body", "content", "data", "metadata", "payload", "request", "response", "result", "value"}
SKIP_PATH_PARTS = {
    ".git",
    "benches",
    "examples",
    "fixtures",
    "target",
    "test",
    "test-support",
    "testdata",
    "tests",
}
# Repository-relative directories holding gitignored, locally generated
# output. They are not tracked production source, so scanning them would make
# the inventory depend on whichever developer tools last ran in the checkout.
GITIGNORED_GENERATED_DIRECTORIES = {"tools/spec-struct-proto/out"}
NON_PRODUCTION_REPOSITORIES = {"arkret-spec", "arkret-work", "cotest"}
VALID_CLASSIFICATIONS = {
    "closed_discriminated",
    "independent",
    "internal_or_fixture",
    "open_json",
    "polymorphic_boundary",
}
_SOURCE_CACHE: dict[Path, tuple[str, str]] = {}


def load_yaml_mapping(source: str) -> dict[str, Any]:
    """Parse the mapping subset needed for OpenAPI JSON-pointer traversal."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    block_scalar_indent: int | None = None
    for raw_line in source.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if block_scalar_indent is not None:
            if indent > block_scalar_indent:
                continue
            block_scalar_indent = None
        line = raw_line.strip()
        if line.startswith("-") or ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        key = key.strip().strip("'\"")
        raw_value = raw_value.strip()
        while stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if raw_value in {"|", ">", "|-", ">-", "|+", ">+"}:
            parent[key] = ""
            block_scalar_indent = indent
        elif not raw_value:
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        elif raw_value == "{}":
            parent[key] = {}
        elif raw_value == "[]":
            parent[key] = []
        elif raw_value.lower() in {"true", "false"}:
            parent[key] = raw_value.lower() == "true"
        elif raw_value.lower() in {"null", "~"}:
            parent[key] = None
        elif re.fullmatch(r"-?[0-9]+", raw_value):
            parent[key] = int(raw_value)
        else:
            parent[key] = raw_value.strip("'\"")
    return root


@dataclass(frozen=True)
class PublicValueField:
    repository: str
    crate: str
    file: str
    line: int
    struct_name: str
    field_name: str
    rust_type: str
    spec_pointer: str | None
    discriminator: str | None

    @property
    def key(self) -> str:
        return f"{self.file}::{self.struct_name}.{self.field_name}"


@dataclass(frozen=True)
class WeakTypingFinding:
    key: str
    category: str
    repository: str
    path: str
    line: int
    symbol: str
    discriminator: str | None
    data_field: str | None
    evidence: str


def mask_non_code(source: str) -> str:
    chars = list(source)
    index = 0
    state = "code"
    block_depth = 0
    while index < len(chars):
        current = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""
        if state == "code":
            if current == "/" and following == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if current == "/" and following == "*":
                chars[index] = chars[index + 1] = " "
                index += 2
                block_depth = 1
                state = "block_comment"
                continue
            if current == '"':
                chars[index] = " "
                index += 1
                state = "string"
                continue
            if current == "'" and following and following != "s":
                end = source.find("'", index + 1, min(index + 8, len(source)))
                if end != -1 and "\n" not in source[index:end]:
                    for offset in range(index, end + 1):
                        chars[offset] = " "
                    index = end + 1
                    continue
            index += 1
            continue
        if state == "line_comment":
            if current == "\n":
                state = "code"
            else:
                chars[index] = " "
            index += 1
            continue
        if state == "block_comment":
            if current == "/" and following == "*":
                chars[index] = chars[index + 1] = " "
                block_depth += 1
                index += 2
                continue
            if current == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
                continue
            if current != "\n":
                chars[index] = " "
            index += 1
            continue
        if state == "string":
            if current == "\\":
                chars[index] = " "
                if index + 1 < len(chars):
                    chars[index + 1] = " "
                index += 2
                continue
            if current == '"':
                chars[index] = " "
                state = "code"
            elif current != "\n":
                chars[index] = " "
            index += 1
    return "".join(chars)


def matching_brace(masked: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError(f"unclosed struct body at byte {opening}")


def matching_delimiter(masked: str, opening: int) -> int:
    pairs = {"(": ")", "{": "}", "[": "]"}
    opener = masked[opening]
    closer = pairs[opener]
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == opener:
            depth += 1
        elif masked[index] == closer:
            depth -= 1
            if depth == 0:
                return index
    raise ValueError(f"unclosed delimiter at byte {opening}")


def mask_cfg_test_items(source: str, masked: str) -> tuple[str, str]:
    """Blank complete cfg(test) items while retaining line numbering."""
    chars = list(source)
    masked_chars = list(masked)
    test_attributes = (
        list(CFG_TEST_RE.finditer(masked))
        + list(CFG_DISABLED_RE.finditer(masked))
        + list(TEST_ATTRIBUTE_RE.finditer(masked))
    )
    for match in reversed(sorted(test_attributes, key=lambda item: item.start())):
        opening = masked.find("{", match.end())
        semicolon = masked.find(";", match.end())
        comma = masked.find(",", match.end())
        field_prefix = masked[match.end() : comma] if comma != -1 else ""
        is_struct_field = (
            comma != -1
            and ":" in field_prefix
            and not re.search(r"\b(?:fn|const|static|type|impl|mod)\b", field_prefix)
            and (opening == -1 or comma < opening)
            and (semicolon == -1 or comma < semicolon)
        )
        if is_struct_field:
            end = comma + 1
        elif opening == -1 or (semicolon != -1 and semicolon < opening):
            end = semicolon + 1 if semicolon != -1 else match.end()
        else:
            try:
                end = matching_brace(masked, opening) + 1
            except ValueError:
                end = len(source)
        for index in range(match.start(), end):
            if chars[index] != "\n":
                chars[index] = " "
            if masked_chars[index] != "\n":
                masked_chars[index] = " "
    return "".join(chars), "".join(masked_chars)


def prepared_source(path: Path) -> tuple[str, str]:
    resolved = path.resolve()
    cached = _SOURCE_CACHE.get(resolved)
    if cached is not None:
        return cached
    source = path.read_text(encoding="utf-8")
    prepared = mask_cfg_test_items(source, mask_non_code(source))
    _SOURCE_CACHE[resolved] = prepared
    return prepared


def function_symbol(
    functions: list[tuple[int, str]], offset: int
) -> str:
    index = bisect.bisect_right(functions, (offset, "\uffff")) - 1
    return functions[index][1] if index >= 0 else "<module>"


def stable_evidence_key(
    category: str, path: str, symbol: str, evidence: str
) -> str:
    normalized = re.sub(r"\s+", " ", evidence).strip()
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"{category}:{path}::{symbol}:{digest}"


def repository_roots(source_root: Path) -> list[tuple[str, Path]]:
    source_root = source_root.resolve()
    if (source_root / "crates").is_dir() and source_root.name == ROOT.name:
        workspace = source_root.parent
    elif source_root == WORKSPACE_ROOT.resolve():
        workspace = source_root
    else:
        return [(source_root.name, source_root)]
    repositories = []
    for candidate in sorted(workspace.iterdir()):
        if (
            not candidate.is_dir()
            or candidate.name in NON_PRODUCTION_REPOSITORIES
            or not (candidate / ".git").exists()
            or not (candidate / "Cargo.toml").exists()
        ):
            continue
        repositories.append((candidate.name, candidate))
    return repositories


def production_rust_files(repository: Path) -> Iterable[Path]:
    found = []
    for directory, child_directories, files in os.walk(repository):
        relative_directory = Path(directory).relative_to(repository)
        child_directories[:] = sorted(
            name
            for name in child_directories
            if name not in SKIP_PATH_PARTS
            and (relative_directory / name).as_posix()
            not in GITIGNORED_GENERATED_DIRECTORIES
        )
        base = Path(directory)
        found.extend(
            base / name
            for name in files
            if name.endswith(".rs")
            and name != "tests.rs"
            and not Path(name).stem.endswith("_tests")
            and not Path(name).stem.startswith("test_")
        )
    test_roots = {root for path in found for root in cfg_test_module_roots(path)}
    yield from sorted(
        path
        for path in found
        if not any(path == root or root in path.parents for root in test_roots)
    )


def cfg_test_module_roots(path: Path) -> list[Path]:
    """Return the file and directory roots of `#[cfg(test)] mod name;` items.

    An out-of-line module declared under `cfg(test)` is compiled only into the
    test harness, so its file and nested module directory are test source even
    when the module name carries no test marker.
    """
    masked = mask_non_code(path.read_text(encoding="utf-8"))
    parent = (
        path.parent
        if path.name in {"lib.rs", "main.rs", "mod.rs"}
        else path.with_suffix("")
    )
    roots: list[Path] = []
    for match in CFG_TEST_MODULE_RE.finditer(masked):
        name = match.group(1)
        roots.extend((parent / f"{name}.rs", parent / name))
    return roots


def workspace_path(repository: str, path: Path, repository_root: Path) -> str:
    relative = path.relative_to(repository_root).as_posix()
    return relative if repository == ROOT.name else f"{repository}/{relative}"


def split_top_level_fields(body: str, masked_body: str) -> Iterable[tuple[int, str]]:
    start = 0
    round_depth = square_depth = brace_depth = angle_depth = 0
    for index, char in enumerate(masked_body):
        if char == "(":
            round_depth += 1
        elif char == ")":
            round_depth = max(0, round_depth - 1)
        elif char == "[":
            square_depth += 1
        elif char == "]":
            square_depth = max(0, square_depth - 1)
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth = max(0, brace_depth - 1)
        elif char == "<":
            angle_depth += 1
        elif char == ">":
            angle_depth = max(0, angle_depth - 1)
        elif (
            char == ","
            and round_depth == 0
            and square_depth == 0
            and brace_depth == 0
            and angle_depth == 0
        ):
            yield start, body[start:index]
            start = index + 1
    if body[start:].strip():
        yield start, body[start:]


def preceding_docs(source: str, struct_start: int) -> str:
    lines = source[:struct_start].splitlines()
    selected: list[str] = []
    saw_doc = False
    for line in reversed(lines):
        stripped = line.strip()
        if stripped.startswith("///") or stripped.startswith("//!"):
            selected.append(stripped)
            saw_doc = True
            continue
        if stripped.startswith("#[") or stripped == "" or (saw_doc and stripped.startswith("//")):
            continue
        break
    return "\n".join(reversed(selected))


def normalize_pointer(raw: str) -> str:
    value = re.sub(r"\s*///\s*", "", raw).replace("\\", "/")
    value = re.sub(r"\s+", "", value)
    marker = "spec/v1/artifacts/schemas/"
    if marker in value:
        value = value.split(marker, 1)[1]
    schema_marker = ".schema.json/"
    if "#" not in value and schema_marker in value:
        value = value.replace(schema_marker, ".schema.json#/", 1)
    return value


def scan_file(
    path: Path, repository_root: Path, repository: str
) -> list[PublicValueField]:
    source, masked = prepared_source(path)
    relative = workspace_path(repository, path, repository_root)
    repository_relative = path.relative_to(repository_root).as_posix()
    parts = repository_relative.split("/")
    crate = parts[1] if len(parts) > 2 and parts[0] == "crates" else repository
    found: list[PublicValueField] = []
    for match in STRUCT_RE.finditer(masked):
        struct_name = match.group(1)
        opening = masked.find("{", match.start(), match.end())
        closing = matching_brace(masked, opening)
        body = source[opening + 1 : closing]
        masked_body = masked[opening + 1 : closing]
        docs = preceding_docs(source, match.start())
        pointer_match = POINTER_RE.search(docs)
        pointer = normalize_pointer(pointer_match.group(1)) if pointer_match else None
        parsed_fields = []
        for offset, raw_field in split_top_level_fields(body, masked_body):
            code = mask_non_code(raw_field).strip()
            field_match = FIELD_RE.search(code)
            if not field_match:
                continue
            parsed_fields.append((offset, field_match))
        discriminator = next(
            (
                match.group(1)
                for _, match in parsed_fields
                if (
                    match.group(1) != "schema"
                    and (
                        match.group(1) in DISCRIMINATOR_FIELDS
                        or match.group(1).endswith("_kind")
                    )
                    and not VALUE_RE.search(match.group(2))
                )
            ),
            None,
        )
        for offset, field_match in parsed_fields:
            field_name = field_match.group(1)
            rust_type = " ".join(field_match.group(2).split())
            if not VALUE_RE.search(rust_type):
                continue
            absolute_offset = opening + 1 + offset
            line = source.count("\n", 0, absolute_offset) + 1
            found.append(
                PublicValueField(
                    repository=repository,
                    crate=crate,
                    file=relative,
                    line=line,
                    struct_name=struct_name,
                    field_name=field_name,
                    rust_type=rust_type,
                    spec_pointer=pointer,
                    discriminator=discriminator,
                )
            )
    return found


def scan_fields(source_root: Path = WORKSPACE_ROOT) -> list[PublicValueField]:
    fields: list[PublicValueField] = []
    for repository, repository_root in repository_roots(source_root):
        for path in production_rust_files(repository_root):
            fields.extend(scan_file(path, repository_root, repository))
    return sorted(fields, key=lambda field: field.key)


def json_object_fields(source: str) -> set[str]:
    quoted = re.findall(r'["\']([A-Za-z_][A-Za-z0-9_]*)["\']\s*:', source)
    bare = re.findall(r"(?<![:A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\s*:", source)
    return set(quoted) | set(bare)


def compact_evidence(source: str, limit: int = 280) -> str:
    compact = re.sub(r"\s+", " ", source).strip()
    return compact if len(compact) <= limit else compact[: limit - 3] + "..."


def is_rfc_problem_body(fields: set[str], path: str, symbol: str) -> bool:
    rfc_fields = {"type", "title", "status", "detail", "instance"}
    return (
        {"type", "title", "status"}.issubset(fields)
        and not fields.intersection({"kind", "payload", "content", "event_id", "realm_id"})
    ) or (
        ("problem" in path.lower() or "problem" in symbol.lower())
        and fields.issubset(rfc_fields | {"error", "errors", "extensions"})
    )


def is_schema_or_conformance_fixture(symbol: str) -> bool:
    """Recognize exact non-authoring JSON producers retained by the audit scope.

    Schema documents, OpenAPI description documents and checked-in
    conformance/KAT vectors intentionally build JSON syntax trees whose object
    keys are schema or OpenAPI keywords (``type``, ``schema``, ``content``,
    response ``status``), not Arkret protocol fields. They are neither protocol
    outbound authoring nor a raw discriminator/data API, and no authoritative
    SDK type can ever replace them. Keep this symbol-level rather than
    excluding a directory or whole file so production helpers beside them
    remain scanned.
    """
    normalized = symbol.lower()
    return (
        normalized == "built_in_schema_vectors"
        or normalized == "openapi_query_operations"
        or normalized.endswith(
            ("_openapi_document", "_schema_document", "_schema_vectors")
        )
        or normalized.startswith("kat_")
        or normalized.endswith("_kat")
        or "_kat_" in normalized
    )


def mutation_evidence(source: str) -> Iterable[tuple[int, str, str]]:
    patterns = [
        re.compile(
            r"(?:\.[ \t]*)?(insert|remove)\s*\(\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']"
        ),
        re.compile(
            r"\[\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']\s*\]\s*=(?!=|>)"
        ),
    ]
    for pattern in patterns:
        for match in pattern.finditer(source):
            if len(match.groups()) == 2:
                operation, field = match.group(1), match.group(2)
            else:
                operation, field = "index_assign", match.group(1)
            if field in PROTOCOL_FIELDS or field in DATA_FIELDS:
                yield match.start(), operation, field


def scan_dynamic_file(
    path: Path, repository_root: Path, repository: str
) -> list[WeakTypingFinding]:
    source, masked = prepared_source(path)
    functions = [(match.start(), match.group(1)) for match in FUNCTION_RE.finditer(masked)]
    relative = workspace_path(repository, path, repository_root)
    findings: list[WeakTypingFinding] = []

    for match in JSON_MACRO_RE.finditer(masked):
        opening = match.start(1)
        try:
            closing = matching_delimiter(masked, opening)
        except ValueError:
            continue
        segment = source[match.start() : closing + 1]
        fields = json_object_fields(segment)
        protocol_fields = fields.intersection(PROTOCOL_FIELDS | DATA_FIELDS)
        if len(protocol_fields) < 2:
            continue
        symbol = function_symbol(functions, match.start())
        if is_rfc_problem_body(fields, relative, symbol):
            continue
        if is_schema_or_conformance_fixture(symbol):
            continue
        discriminators = sorted(fields.intersection(DISCRIMINATOR_FIELDS))
        data_fields = sorted(fields.intersection(DATA_FIELDS))
        evidence = compact_evidence(segment)
        findings.append(
            WeakTypingFinding(
                key=stable_evidence_key("json_authoring", relative, symbol, segment),
                category="json_authoring",
                repository=repository,
                path=relative,
                line=source.count("\n", 0, match.start()) + 1,
                symbol=symbol,
                discriminator=",".join(discriminators) or None,
                data_field=",".join(data_fields or sorted(protocol_fields)),
                evidence=evidence,
            )
        )

    for offset, operation, field in mutation_evidence(source):
        line_start = source.rfind("\n", 0, offset) + 1
        line_end = source.find("\n", offset)
        line_end = len(source) if line_end == -1 else line_end
        evidence = source[line_start:line_end].strip()
        symbol = function_symbol(functions, offset)
        key_source = f"{operation}:{field}:{evidence}"
        findings.append(
            WeakTypingFinding(
                key=stable_evidence_key("json_path_mutation", relative, symbol, key_source),
                category="json_path_mutation",
                repository=repository,
                path=relative,
                line=source.count("\n", 0, offset) + 1,
                symbol=symbol,
                discriminator=None,
                data_field=field,
                evidence=compact_evidence(evidence),
            )
        )

    for match in FUNCTION_RE.finditer(masked):
        # FUNCTION_RE consumes the function-parameter opening delimiter.  Using
        # the first `(` in the whole match accidentally selects the visibility
        # restriction in `pub(super)`, `pub(crate)` and `pub(in path)`.
        opening = match.end() - 1
        try:
            closing = matching_delimiter(masked, opening)
        except (KeyError, ValueError):
            continue
        parameters = source[opening + 1 : closing]
        parsed = re.findall(
            r"(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^,\n]+(?:<[^>\n]+>)?)",
            parameters,
        )
        discriminator_parameters = [
            name
            for name, rust_type in parsed
            if (
                name in DISCRIMINATOR_FIELDS
                or name.endswith("_kind")
                or "Kind" in rust_type
            )
            # Service/projection context objects are commonly named `state`;
            # they do not select the adjacent JSON shape.
            and not (
                name == "state"
                and re.search(r"\b(?:AppState|ProjectionState)\b", rust_type)
            )
        ]
        data_parameters = [
            name
            for name, rust_type in parsed
            if name in DATA_FIELDS and VALUE_RE.search(rust_type)
        ]
        if not discriminator_parameters or not data_parameters:
            continue
        symbol = match.group(1)
        signature = source[match.start() : closing + 1]
        findings.append(
            WeakTypingFinding(
                key=f"paired_api:{relative}::{symbol}",
                category="paired_api",
                repository=repository,
                path=relative,
                line=source.count("\n", 0, match.start()) + 1,
                symbol=symbol,
                discriminator=",".join(discriminator_parameters),
                data_field=",".join(data_parameters),
                evidence=compact_evidence(signature),
            )
        )

    for match in MATCH_RE.finditer(masked):
        expression = match.group(1).strip()
        if not DISCRIMINATOR_EXPRESSION_RE.search(expression):
            continue
        opening = masked.find("{", match.start(), match.end())
        try:
            closing = matching_brace(masked, opening)
        except ValueError:
            continue
        body = source[opening + 1 : closing]
        reads = set(
            re.findall(
                r"(?:\.get(?:_mut)?\s*\(\s*|\[\s*)[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']",
                body,
            )
        ).intersection(PROTOCOL_FIELDS | DATA_FIELDS)
        if not reads:
            continue
        symbol = function_symbol(functions, match.start())
        evidence = source[match.start() : closing + 1]
        findings.append(
            WeakTypingFinding(
                key=stable_evidence_key("closed_dispatch", relative, symbol, evidence),
                category="closed_dispatch",
                repository=repository,
                path=relative,
                line=source.count("\n", 0, match.start()) + 1,
                symbol=symbol,
                discriminator=compact_evidence(expression, 120),
                data_field=",".join(sorted(reads)),
                evidence=compact_evidence(evidence),
            )
        )
    return findings


def scan_dynamic_findings(source_root: Path = WORKSPACE_ROOT) -> list[WeakTypingFinding]:
    findings: list[WeakTypingFinding] = []
    for repository, repository_root in repository_roots(source_root):
        for path in production_rust_files(repository_root):
            findings.extend(scan_dynamic_file(path, repository_root, repository))
    unique = {finding.key: finding for finding in findings}
    return [unique[key] for key in sorted(unique)]


class SchemaResolver:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.cache: dict[Path, Any] = {}
        self.def_index: dict[str, list[tuple[Path, str, Any]]] | None = None

    def load(self, path: Path) -> Any:
        resolved = path.resolve()
        if resolved not in self.cache:
            if resolved.is_dir():
                raise FileNotFoundError(f"schema path is a directory: {resolved}")
            source = resolved.read_text(encoding="utf-8")
            if resolved.suffix.lower() in {".yaml", ".yml"}:
                self.cache[resolved] = (
                    yaml.safe_load(source) if yaml is not None else load_yaml_mapping(source)
                )
            else:
                self.cache[resolved] = json.loads(source)
        return self.cache[resolved]

    def pointer_node(self, pointer: str) -> tuple[Path, Any]:
        pointer = normalize_pointer(pointer)
        file_part, separator, fragment = pointer.partition("#")
        path = (self.root / file_part).resolve()
        node = self.load(path)
        if separator and fragment:
            for token in fragment.lstrip("/").split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                if isinstance(node, dict) and token not in node:
                    path, node = self.resolve_ref(path, node)
                node = self.pointer_child(node, token)
        return path, node

    @staticmethod
    def pointer_child(node: Any, token: str) -> Any:
        if isinstance(node, list):
            return node[int(token)]
        return node[token]

    def resolve_ref(self, path: Path, node: Any, seen: set[tuple[Path, str]] | None = None) -> tuple[Path, Any]:
        seen = seen or set()
        while isinstance(node, dict) and isinstance(node.get("$ref"), str):
            reference = node["$ref"]
            file_part, separator, fragment = reference.partition("#")
            next_path = (path.parent / file_part).resolve() if file_part else path
            marker = (next_path, fragment)
            if marker in seen:
                break
            seen.add(marker)
            target = self.load(next_path)
            if separator and fragment:
                for token in fragment.lstrip("/").split("/"):
                    token = token.replace("~1", "/").replace("~0", "~")
                    target = self.pointer_child(target, token)
            path, node = next_path, target
        return path, node

    def build_def_index(self) -> dict[str, list[tuple[Path, str, Any]]]:
        if self.def_index is not None:
            return self.def_index
        index: dict[str, list[tuple[Path, str, Any]]] = {}
        for path in sorted(self.root.glob("*.schema.json")):
            document = self.load(path)
            root_name = path.name.removesuffix(".schema.json").replace("-", "_")
            index.setdefault(root_name, []).append((path, "", document))
            definitions = document.get("$defs") if isinstance(document, dict) else None
            if not isinstance(definitions, dict):
                continue
            for name, node in definitions.items():
                candidate = (path, f"#/$defs/{name}", node)
                index.setdefault(name, []).append(candidate)
                normalized = self.rust_name_to_schema_name(name)
                if normalized != name:
                    index.setdefault(normalized, []).append(candidate)
        self.def_index = index
        return index

    @staticmethod
    def rust_name_to_schema_name(struct_name: str) -> str:
        first = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", struct_name)
        return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", first).lower()

    def inferred_owner(self, struct_name: str, field_name: str) -> tuple[Path, str, Any] | None:
        name = self.rust_name_to_schema_name(struct_name)
        candidates = []
        for path, fragment, node in self.build_def_index().get(name, []):
            resolved_path, resolved = self.resolve_ref(path, node)
            properties = resolved.get("properties") if isinstance(resolved, dict) else None
            has_field = isinstance(properties, dict) and field_name in properties
            has_extra = (
                field_name == "extra"
                and isinstance(resolved, dict)
                and (
                    resolved.get("type") == "object"
                    or isinstance(resolved.get("properties"), dict)
                )
            )
            if has_field or has_extra:
                candidates.append((path, fragment, resolved))
        candidates = list(dict.fromkeys((path, fragment) for path, fragment, _ in candidates))
        if len(candidates) == 1:
            path, fragment = candidates[0]
            document = self.load(path)
            node = document
            if fragment:
                for token in fragment.lstrip("#/").split("/"):
                    token = token.replace("~1", "/").replace("~0", "~")
                    node = node[token]
            _, node = self.resolve_ref(path, node)
            return path, fragment, node
        return None

    def field_shape(
        self, pointer: str | None, struct_name: str, field_name: str
    ) -> tuple[str, str | None]:
        try:
            path: Path | None = None
            owner: Any = None
            effective_pointer = pointer
            if pointer:
                path, owner = self.pointer_node(pointer)
                path, owner = self.resolve_ref(path, owner)
                normalized_pointer = pointer.rstrip("/")
                if normalized_pointer.endswith(f"/properties/{field_name}"):
                    return self.classify_node(path, owner), pointer
                if normalized_pointer.endswith(
                    ("/additionalProperties", "/unevaluatedProperties")
                ):
                    if owner is False:
                        return "closed", pointer
                    return "open_map", pointer
                if "/patternProperties/" in normalized_pointer:
                    return self.classify_node(path, owner), pointer
            properties = owner.get("properties") if isinstance(owner, dict) else None
            if not isinstance(properties, dict) or field_name not in properties:
                if pointer and field_name == "extra" and isinstance(owner, dict):
                    pattern_properties = owner.get("patternProperties")
                    if isinstance(pattern_properties, dict):
                        for pattern, pattern_value in pattern_properties.items():
                            if not pattern.startswith("^x_"):
                                continue
                            escaped_pattern = pattern.replace("~", "~0").replace("/", "~1")
                            return (
                                "open_map",
                                normalize_pointer(
                                    f"{effective_pointer}/patternProperties/{escaped_pattern}"
                                ),
                            )
                    additional = owner.get("additionalProperties")
                    if additional is False or owner.get("unevaluatedProperties") is False:
                        return "closed", pointer
                    if additional is None:
                        return "open_map", pointer
                    if additional is True or isinstance(additional, dict):
                        return "open_map", normalize_pointer(
                            f"{pointer}/additionalProperties"
                        )
                inferred = self.inferred_owner(struct_name, field_name)
                if inferred is None:
                    return "unknown", pointer
                path, fragment, owner = inferred
                effective_pointer = f"{path.name}{fragment}"
                properties = owner.get("properties")
                if field_name == "extra":
                    additional = owner.get("additionalProperties")
                    if additional is False or owner.get("unevaluatedProperties") is False:
                        return "closed", effective_pointer
                    if additional is None:
                        return "open_map", effective_pointer
                    if additional is True or isinstance(additional, dict):
                        return "open_map", normalize_pointer(
                            f"{effective_pointer}/additionalProperties"
                        )
            field = properties[field_name]
            assert path is not None
            shape = self.classify_node(path, field)
            return shape, normalize_pointer(
                f"{effective_pointer}/properties/{field_name}"
            )
        except (FileNotFoundError, KeyError, json.JSONDecodeError):
            return "unknown", None

    def classify_node(self, path: Path, node: Any) -> str:
        if node is True or node == {}:
            return "open_json"
        if node is False or not isinstance(node, dict):
            return "closed"
        path, node = self.resolve_ref(path, node)
        if node is True or node == {}:
            return "open_json"
        if not isinstance(node, dict):
            return "closed"
        if "const" in node or "enum" in node:
            return "closed"
        for union_key in ("oneOf", "anyOf"):
            branches = node.get(union_key)
            if isinstance(branches, list):
                shapes = {self.classify_node(path, branch) for branch in branches}
                return "open_json" if shapes == {"open_json"} else "closed"
        all_of = node.get("allOf")
        if isinstance(all_of, list) and not any(
            key in node for key in ("type", "properties", "items", "const", "enum")
        ):
            shapes = {self.classify_node(path, branch) for branch in all_of}
            return "open_json" if shapes == {"open_json"} else "closed"
        node_type = node.get("type")
        if node_type == "object" or (
            isinstance(node_type, list) and "object" in node_type
        ):
            additional = node.get("additionalProperties")
            properties = node.get("properties")
            if additional is True or additional == {}:
                return "open_map"
            # JSON Schema permits additional properties by default. A schema
            # that lists known properties without closing the object is still
            # an open map at this boundary.
            if additional is None and node.get("unevaluatedProperties") is not False:
                return "open_map"
            if isinstance(additional, dict) and not properties and not node.get("required"):
                value_shape = self.classify_node(path, additional)
                if value_shape in {"open_json", "open_json_container", "open_map"}:
                    return "open_json_container"
            return "closed"
        if node.get("type") == "array" and self.classify_node(path, node.get("items", {})) in {
            "open_json",
            "open_map",
        }:
            return "open_json_container"
        if not any(key in node for key in ("type", "properties", "items", "pattern", "format")):
            return "open_json"
        return "closed"


def load_allowlist(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = payload.get("entries", [])
    keyed = {}
    for entry in entries:
        if entry.get("spec_pointer"):
            entry["spec_pointer"] = normalize_pointer(entry["spec_pointer"])
        key = entry.get("finding") or entry["rust_field"]
        if key in keyed:
            raise ValueError(f"duplicate wire Value allowlist entry: {key}")
        keyed[key] = entry
    return keyed


def decision_for_classification(classification: str) -> str:
    return {
        "closed_discriminated": "closed",
        "independent": "independent",
        "open_json": "open",
        "polymorphic_boundary": "raw",
        "internal_or_fixture": "raw",
    }.get(classification, "unclassified")


def default_action(classification: str, category: str) -> str:
    if classification == "closed_discriminated":
        return "Migrate this production boundary to the authoritative SDK discriminated type and delete the raw pairing."
    if classification == "independent":
        return "Retain as explicitly documented discriminator-independent metadata."
    if classification == "open_json":
        return "Retain only at the exact schema-declared open JSON boundary."
    if classification == "polymorphic_boundary":
        return "Retain only as a named raw/validated boundary; decode to the authoritative SDK type before business use."
    if classification == "internal_or_fixture":
        return "Retain as non-wire internal data and prevent it from entering protocol authoring."
    return f"Adjudicate and migrate the {category} finding."


def default_test() -> str:
    return "python tools/wire_value_audit.py --check"


def default_lifecycle(classification: str) -> str:
    if classification == "closed_discriminated":
        return "pending_migration"
    if classification == "unclassified":
        return "pending_adjudication"
    return "retained_boundary"


def report(
    fields: list[PublicValueField],
    dynamic_findings: list[WeakTypingFinding],
    resolver: SchemaResolver,
    allowlist: dict[str, dict[str, Any]],
    repositories: list[str],
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for field in fields:
        allowed = allowlist.get(field.key)
        allowed_pointer = allowed.get("spec_pointer") if allowed else None
        shape, field_pointer = resolver.field_shape(
            field.spec_pointer or allowed_pointer, field.struct_name, field.field_name
        )
        classification = allowed.get("classification") if allowed else None
        classification = classification or "unclassified"
        authority = None
        if allowed:
            authority = allowed.get("authority") or allowed.get("spec_pointer")
        authority = authority or (field_pointer if shape != "unknown" else None) or field.rust_type
        entries.append(
            {
                "finding": field.key,
                "category": "public_value_field",
                "rust_field": field.key,
                "crate": field.crate,
                "file": field.file,
                "path": field.file,
                "line": field.line,
                "owner": field.struct_name,
                "owner_repository": field.repository or "<unresolved>",
                "symbol": f"{field.struct_name}.{field.field_name}",
                "field": field.field_name,
                "discriminator": field.discriminator,
                "data_field": field.field_name,
                "rust_type": field.rust_type,
                "spec_pointer": (
                    field_pointer
                    if field.spec_pointer is not None and shape != "unknown"
                    else allowed.get("spec_pointer")
                    if allowed is not None and "spec_pointer" in allowed
                    else field_pointer
                    if shape != "unknown"
                    else None
                ),
                "schema_shape": shape,
                "classification": classification,
                "lifecycle": allowed.get("lifecycle", default_lifecycle(classification)) if allowed else default_lifecycle(classification),
                "decision": (allowed.get("decision") or decision_for_classification(classification)) if allowed else decision_for_classification(classification),
                "authority": authority,
                "action": allowed.get("action", default_action(classification, "public_value_field")) if allowed else None,
                "test": allowed.get("test", default_test()) if allowed else None,
                "reason": allowed.get("reason") if allowed else None,
                "evidence": f"public {field.rust_type} field",
            }
        )
    for finding in dynamic_findings:
        allowed = allowlist.get(finding.key)
        classification = allowed.get("classification") if allowed else "unclassified"
        entries.append(
            {
                "finding": finding.key,
                "category": finding.category,
                "rust_field": None,
                "crate": None,
                "file": finding.path,
                "path": finding.path,
                "line": finding.line,
                "owner": finding.symbol,
                "owner_repository": finding.repository or "<unresolved>",
                "symbol": finding.symbol,
                "field": finding.data_field,
                "discriminator": finding.discriminator,
                "data_field": finding.data_field,
                "rust_type": None,
                "spec_pointer": allowed.get("spec_pointer") if allowed else None,
                "schema_shape": allowed.get("schema_shape", "unknown") if allowed else "unknown",
                "classification": classification,
                "lifecycle": allowed.get("lifecycle", default_lifecycle(classification)) if allowed else default_lifecycle(classification),
                "decision": (allowed.get("decision") or decision_for_classification(classification)) if allowed else decision_for_classification(classification),
                "authority": allowed.get("authority") if allowed else None,
                "action": allowed.get("action", default_action(classification, finding.category)) if allowed else None,
                "test": allowed.get("test", default_test()) if allowed else None,
                "reason": allowed.get("reason") if allowed else None,
                "evidence": finding.evidence,
            }
        )
    entries.sort(key=lambda entry: entry["finding"])
    classifications = Counter(entry["classification"] for entry in entries)
    lifecycles = Counter(entry["lifecycle"] for entry in entries)
    shapes = Counter(entry["schema_shape"] for entry in entries)
    crates = Counter(entry["crate"] for entry in entries if entry["crate"])
    categories = Counter(entry["category"] for entry in entries)
    decisions = Counter(entry["decision"] for entry in entries)
    owners = Counter(entry["owner_repository"] for entry in entries)
    return {
        "summary": {
            "total": len(entries),
            "scope": {
                "repositories": sorted(repositories),
                "excluded_path_components": sorted(SKIP_PATH_PARTS),
                "excluded_repositories": sorted(NON_PRODUCTION_REPOSITORIES),
                "excluded_test_source_names": [
                    "tests.rs",
                    "*_tests.rs",
                    "test_*.rs",
                ],
                "inline_cfg_test": "excluded",
                "rfc7807_rfc9457_problem_details": "excluded",
            },
            "by_crate": dict(sorted(crates.items())),
            "by_category": dict(sorted(categories.items())),
            "by_classification": dict(sorted(classifications.items())),
            "by_lifecycle": dict(sorted(lifecycles.items())),
            "by_decision": dict(sorted(decisions.items())),
            "by_owner_repository": dict(sorted(owners.items())),
            "by_schema_shape": dict(sorted(shapes.items())),
        },
        "entries": entries,
    }


def validate(
    report_payload: dict[str, Any],
    allowlist: dict[str, dict[str, Any]],
    resolver: SchemaResolver,
) -> list[str]:
    errors: list[str] = []
    current = {entry["finding"]: entry for entry in report_payload["entries"]}
    for key, entry in current.items():
        classification = entry["classification"]
        if classification == "unclassified":
            errors.append(f"unclassified public Value field: {key}")
            continue
        if (
            entry["category"] == "public_value_field"
            and classification == "open_json"
            and entry["schema_shape"] not in {
            "open_json",
            "open_json_container",
            "open_map",
            }
        ):
            errors.append(
                f"open_json allowlist entry does not resolve to an open schema: {key}"
            )
        if (
            entry["category"] == "public_value_field"
            and entry["field"] == "extra"
            and entry["schema_shape"] == "closed"
        ):
            errors.append(f"closed schema exposes a public flattened extra map: {key}")
        if (
            entry["category"] == "public_value_field"
            and classification == "open_json"
            and entry["schema_shape"] == "open_map"
            and "Map<" not in entry["rust_type"]
        ):
            errors.append(f"open object field must use a map-shaped Rust type: {key}")
        if (
            entry["category"] == "public_value_field"
            and classification == "open_json"
            and entry["schema_shape"] == "open_json_container"
            and not any(
                container in entry["rust_type"] for container in ("Vec<", "Map<")
            )
        ):
            errors.append(f"open JSON container field must preserve its container shape: {key}")
        if classification not in VALID_CLASSIFICATIONS:
            errors.append(f"invalid classification {classification!r}: {key}")
        if not entry.get("reason"):
            errors.append(f"allowlist entry has no reason: {key}")
        if classification in {"open_json", "polymorphic_boundary"} and not entry.get(
            "spec_pointer"
        ) and not entry.get("authority") and entry["category"] == "public_value_field":
            errors.append(f"wire allowlist entry has no Spec pointer: {key}")
        if entry.get("decision") not in {"closed", "open", "independent", "raw"}:
            errors.append(f"finding has no closed/open/independent/raw decision: {key}")
        if entry.get("lifecycle") not in {
            "pending_adjudication",
            "pending_migration",
            "retained_boundary",
        }:
            errors.append(f"finding has no valid lifecycle: {key}")
        for field_name in (
            "path",
            "symbol",
            "data_field",
            "authority",
            "owner_repository",
            "action",
            "test",
        ):
            if not entry.get(field_name):
                errors.append(f"finding has no {field_name}: {key}")
        if entry.get("owner_repository") == "<unresolved>":
            errors.append(f"finding has unresolved owner_repository: {key}")
        if entry.get("authority") and not resolvable_authority(resolver, entry["authority"]):
            errors.append(f"finding authority is an unresolvable Spec pointer: {key}")
        if classification == "closed_discriminated" and not entry.get("discriminator"):
            errors.append(f"closed_discriminated finding has no discriminator: {key}")
        pointer = entry.get("spec_pointer")
        if pointer:
            try:
                resolver.pointer_node(pointer)
            except (FileNotFoundError, KeyError, json.JSONDecodeError, TypeError):
                errors.append(f"allowlist entry has an invalid Spec pointer: {key}")
    scanned_repositories = set(report_payload["summary"]["scope"]["repositories"])
    for key, allowed in allowlist.items():
        if any(token in key for token in ("*", "?", "[", "]")):
            errors.append(f"broad/glob allowlist entry is forbidden: {key}")
        if any(name in allowed for name in ("directory", "path_prefix", "glob")):
            errors.append(f"directory/file-wide allowlist rule is forbidden: {key}")
    pending_closed = [
        entry
        for entry in current.values()
        if entry["classification"] == "closed_discriminated"
    ]
    if pending_closed:
        by_owner = Counter(entry["owner_repository"] for entry in pending_closed)
        summary = ", ".join(
            f"{owner}={count}" for owner, count in sorted(by_owner.items())
        )
        errors.append(
            f"closed_discriminated migration debt remains ({len(pending_closed)} findings: {summary})"
        )
    for key in sorted(set(allowlist) - set(current)):
        allowed = allowlist[key]
        owner_repository = allowed.get("owner_repository", ROOT.name)
        if owner_repository in scanned_repositories:
            errors.append(f"stale allowlist entry: {key}")
    return errors


def seed_open_allowlist(
    path: Path, report_payload: dict[str, Any], allowlist: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    merged = dict(allowlist)
    for entry in report_payload["entries"]:
        if (
            entry["category"] != "public_value_field"
            or entry["schema_shape"]
            not in {"open_json", "open_map", "open_json_container"}
            or entry["finding"] in merged
        ):
            continue
        merged[entry["finding"]] = {
            "rust_field": entry["rust_field"],
            "spec_pointer": entry["spec_pointer"],
            "classification": "open_json",
            "lifecycle": "retained_boundary",
            "decision": "open",
            "authority": entry["spec_pointer"],
            "owner_repository": entry["owner_repository"],
            "action": default_action("open_json", "public_value_field"),
            "test": default_test(),
            "reason": "The resolved Spec field explicitly permits unconstrained JSON at this exact boundary.",
        }
    payload = {"entries": [merged[key] for key in sorted(merged)]}
    with path.open("w", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    return merged


def authority_for_finding(entry: dict[str, Any]) -> str:
    fields = set(filter(None, (entry.get("discriminator") or "").split(",")))
    data_fields = set(filter(None, (entry.get("data_field") or "").split(",")))
    path = entry["path"].lower()
    if (
        entry["owner_repository"] == "coauth"
        and entry["symbol"] == "NotificationEventLog.audit_context"
    ):
        return "coauth_data::notification::NotificationEventLog audit_context contract"
    if "signal_kind" in fields:
        return "arkret_models_collaboration::SignalPlaintextProfile"
    if "key_backup" in path or "active_series" in path:
        return "arkret_models_crypto::KeyBackupActiveSeries signing typestate"
    if "kind" in fields and ("payload" in data_fields or "event" in path):
        return "arkret_wire::event_spec::EventSpec associated Payload"
    if entry["category"] == "public_value_field":
        return entry.get("spec_pointer") or entry.get("rust_type") or entry["symbol"]
    if fields:
        return f"arkret-spec closed union selected by {','.join(sorted(fields))}"
    return f"arkret-spec protocol schema owning {','.join(sorted(data_fields))}"


def is_external_adapter_finding(entry: dict[str, Any]) -> bool:
    path = entry["path"].lower()
    symbol = entry["symbol"].lower()
    adapter_tokens = (
        "apns",
        "email",
        "fcm",
        "oauth",
        "oidc",
        "provider",
        "webhook",
    )
    return entry["category"] == "json_authoring" and any(
        token in path or token in symbol for token in adapter_tokens
    )


AUTHORITY_POINTER_RE = re.compile(r"[A-Za-z0-9_.-]+\.schema\.json(?:#[^\s;,]*)?")


def resolvable_authority(resolver: SchemaResolver, authority: str) -> bool:
    """Every Spec pointer an authority names must resolve.

    An authority may combine a Rust type with one or more schema pointers; the
    non-pointer text is a name and is not checked.
    """
    for pointer in AUTHORITY_POINTER_RE.findall(authority):
        try:
            resolver.pointer_node(pointer)
        except (FileNotFoundError, KeyError, IndexError, ValueError, TypeError):
            return False
    return True


def refresh_allowlist(
    path: Path,
    report_payload: dict[str, Any],
    allowlist: dict[str, dict[str, Any]],
    resolver: SchemaResolver,
) -> dict[str, dict[str, Any]]:
    """Refresh exact-key adjudications during an explicit maintainer run."""
    current_keys = {entry["finding"] for entry in report_payload["entries"]}
    scanned_repositories = set(
        report_payload["summary"]["scope"]["repositories"]
    )
    merged = {
        key: value
        for key, value in allowlist.items()
        if key in current_keys
        or value.get("owner_repository", ROOT.name) not in scanned_repositories
    }
    for entry in report_payload["entries"]:
        key = entry["finding"]
        existing = merged.get(key)
        if existing is not None and (
            "finding" not in existing
            or existing.get("adjudication") == "manual"
        ):
            continue
        category = entry["category"]
        has_discriminator = bool(entry.get("discriminator"))
        data_fields = set(filter(None, (entry.get("data_field") or "").split(",")))
        has_shape_data = bool(data_fields.intersection(DATA_FIELDS))
        closed_pair_candidate = (
            category in {"paired_api", "closed_dispatch"}
            or (category == "json_authoring" and has_shape_data)
            or (
                category == "public_value_field"
                and entry.get("field") in DATA_FIELDS
            )
        )
        is_independent_audit_context = (
            entry["owner_repository"] == "coauth"
            and entry["symbol"] == "NotificationEventLog.audit_context"
        )
        if is_independent_audit_context:
            classification = "independent"
        elif (
            category == "public_value_field"
            and entry.get("schema_shape")
            in {"open_json", "open_json_container", "open_map"}
        ):
            # A resolved open schema is stronger evidence than a sibling field
            # merely named `kind`/`state`/`schema`; the raw value is not selected
            # by that discriminator.
            classification = "open_json"
        elif existing is not None and existing.get("classification") == "polymorphic_boundary":
            # Preserve exact, previously adjudicated raw ingress/persistence or
            # extension boundaries. The exact finding key still provides the
            # stale ratchet when the code disappears.
            classification = "polymorphic_boundary"
        elif is_external_adapter_finding(entry):
            classification = "polymorphic_boundary"
        elif has_discriminator and closed_pair_candidate:
            classification = "closed_discriminated"
        else:
            classification = "polymorphic_boundary"
        decision = decision_for_classification(classification)
        if classification == "independent":
            reason = (
                "Notification audit_context is documented supplementary audit annotation; NotificationEventKind "
                "does not select or constrain its shape."
            )
        elif classification == "closed_discriminated":
            reason = (
                "The discriminator and raw data remain independently representable at this exact production symbol; "
                "the authoritative SDK discriminated type must replace the pairing."
            )
        elif classification == "open_json":
            reason = (
                "The resolved Spec field explicitly permits unconstrained JSON at this exact boundary; "
                "a sibling discriminator does not select its shape."
            )
        elif is_external_adapter_finding(entry):
            reason = (
                "This exact JSON construction is an external provider/identity adapter payload, not an Arkret "
                "closed union; it remains confined to the named adapter boundary."
            )
        elif category == "json_authoring":
            reason = (
                "This exact production symbol hand-authors a protocol-shaped JSON object; it must serialize an "
                "authoritative SDK type or stay behind a named validated raw boundary."
            )
        elif category == "json_path_mutation":
            reason = (
                "This exact production symbol mutates a protocol field by string path outside the authoritative "
                "SDK serializer and is tracked until migrated."
            )
        else:
            reason = (
                "This exact public Value field is a raw polymorphic boundary and must be decoded to its "
                "authoritative type before protocol business logic."
            )
        merged[key] = {
            "finding": key,
            "classification": classification,
            "lifecycle": default_lifecycle(classification),
            "decision": decision,
            "authority": (
                "external provider/identity protocol owned by this adapter"
                if is_external_adapter_finding(entry)
                else authority_for_finding(entry)
            ),
            "owner_repository": entry["owner_repository"],
            "action": default_action(classification, category),
            "test": default_test(),
            "reason": reason,
        }
        if entry.get("spec_pointer") and entry.get("schema_shape") != "unknown":
            merged[key]["spec_pointer"] = entry["spec_pointer"]
        if existing is not None and existing.get("classification") == classification:
            # An unchanged adjudication keeps its recorded authority and
            # rationale; the generic defaults above only seed new or
            # reclassified findings, and must not overwrite an exact Spec
            # pointer with a Rust type name.
            if existing.get("reason"):
                merged[key]["reason"] = existing["reason"]
            authority = existing.get("authority")
            if authority and resolvable_authority(resolver, authority):
                merged[key]["authority"] = authority
    payload = {"entries": [merged[key] for key in sorted(merged)]}
    with path.open("w", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    return merged


def tracked_inventory(report_payload: dict[str, Any]) -> dict[str, Any]:
    """The committed inventory omits source line numbers.

    Findings are keyed by path, symbol and an evidence digest, so a line shift
    from an unrelated edit elsewhere in the file is not an inventory change.
    The printed report keeps the line for navigation.
    """
    return {
        "summary": report_payload["summary"],
        "entries": [
            {name: value for name, value in entry.items() if name != "line"}
            for entry in report_payload["entries"]
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, default=DEFAULT_SPEC_ROOT)
    parser.add_argument("--source-root", type=Path, default=WORKSPACE_ROOT)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--write-report", type=Path)
    parser.add_argument("--seed-open-allowlist", action="store_true")
    parser.add_argument("--refresh-inventory", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    repositories = [name for name, _ in repository_roots(args.source_root)]
    fields = scan_fields(args.source_root)
    dynamic_findings = scan_dynamic_findings(args.source_root)
    resolver = SchemaResolver(args.spec_root)
    allowlist = load_allowlist(args.allowlist)
    payload = report(fields, dynamic_findings, resolver, allowlist, repositories)
    if args.seed_open_allowlist:
        allowlist = seed_open_allowlist(args.allowlist, payload, allowlist)
        payload = report(fields, dynamic_findings, resolver, allowlist, repositories)
    if args.refresh_inventory:
        allowlist = refresh_allowlist(args.allowlist, payload, allowlist, resolver)
        payload = report(fields, dynamic_findings, resolver, allowlist, repositories)
        with args.inventory.open("w", encoding="utf-8", newline="\n") as inventory_file:
            inventory_file.write(
                json.dumps(tracked_inventory(payload), indent=2, ensure_ascii=False) + "\n"
            )
    rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if args.write_report:
        with args.write_report.open("w", encoding="utf-8", newline="\n") as report_file:
            report_file.write(rendered)
    else:
        print(rendered, end="")
    if args.check:
        errors = validate(payload, allowlist, resolver)
        if args.inventory.exists():
            tracked = json.loads(args.inventory.read_text(encoding="utf-8"))
            tracked_repositories = set(
                tracked.get("summary", {}).get("scope", {}).get("repositories", [])
            )
            current_repositories = set(repositories)
            current = tracked_inventory(payload)
            if current_repositories == tracked_repositories:
                if tracked != current:
                    errors.append(
                        "wire Value inventory drifted; regenerate tools/wire_value_inventory.json"
                    )
            else:
                tracked_entries = [
                    entry
                    for entry in tracked.get("entries", [])
                    if entry.get("owner_repository") in current_repositories
                ]
                if tracked_entries != current["entries"]:
                    errors.append(
                        "wire Value inventory drifted for the repositories available in this checkout"
                    )
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
