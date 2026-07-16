#!/usr/bin/env python3
"""Audit public Rust wire fields whose declared type contains JSON Value."""

from __future__ import annotations

import argparse
import json
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
DEFAULT_SPEC_ROOT = ROOT.parent / "arkret-spec" / "spec" / "v1" / "artifacts" / "schemas"
DEFAULT_ALLOWLIST = ROOT / "tools" / "wire_value_allowlist.json"
DEFAULT_INVENTORY = ROOT / "tools" / "wire_value_inventory.json"
VALUE_RE = re.compile(r"(?<![A-Za-z0-9_])(?:serde_json::)?Value(?![A-Za-z0-9_])")
STRUCT_RE = re.compile(r"\bpub\s+struct\s+([A-Za-z_][A-Za-z0-9_]*)[^;{]*\{")
FIELD_RE = re.compile(
    r"\bpub(?:\s*\([^)]*\))?\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)\Z",
    re.DOTALL,
)
POINTER_RE = re.compile(
    r"`([^`]*(?:spec/v1/artifacts/schemas/)?[A-Za-z0-9_.-]+\.schema\.json(?:#[^`]*)?)`"
)


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
    crate: str
    file: str
    line: int
    struct_name: str
    field_name: str
    rust_type: str
    spec_pointer: str | None

    @property
    def key(self) -> str:
        return f"{self.file}::{self.struct_name}.{self.field_name}"


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


def scan_file(path: Path, source_root: Path) -> list[PublicValueField]:
    source = path.read_text(encoding="utf-8")
    masked = mask_non_code(source)
    relative = path.relative_to(source_root).as_posix()
    crate = relative.split("/", 2)[1]
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
        for offset, raw_field in split_top_level_fields(body, masked_body):
            code = mask_non_code(raw_field).strip()
            field_match = FIELD_RE.search(code)
            if not field_match:
                continue
            field_name = field_match.group(1)
            rust_type = " ".join(field_match.group(2).split())
            if not VALUE_RE.search(rust_type):
                continue
            absolute_offset = opening + 1 + offset
            line = source.count("\n", 0, absolute_offset) + 1
            found.append(
                PublicValueField(
                    crate=crate,
                    file=relative,
                    line=line,
                    struct_name=struct_name,
                    field_name=field_name,
                    rust_type=rust_type,
                    spec_pointer=pointer,
                )
            )
    return found


def scan_fields(source_root: Path = ROOT) -> list[PublicValueField]:
    fields: list[PublicValueField] = []
    for path in sorted((source_root / "crates").glob("**/*.rs")):
        fields.extend(scan_file(path, source_root))
    return sorted(fields, key=lambda field: field.key)


class SchemaResolver:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.cache: dict[Path, Any] = {}
        self.def_index: dict[str, list[tuple[Path, str, Any]]] | None = None

    def load(self, path: Path) -> Any:
        resolved = path.resolve()
        if resolved not in self.cache:
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
            properties = owner.get("properties") if isinstance(owner, dict) else None
            if not isinstance(properties, dict) or field_name not in properties:
                if pointer and field_name == "extra" and isinstance(owner, dict):
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
    for entry in entries:
        if entry.get("spec_pointer"):
            entry["spec_pointer"] = normalize_pointer(entry["spec_pointer"])
    return {entry["rust_field"]: entry for entry in entries}


def report(fields: list[PublicValueField], resolver: SchemaResolver, allowlist: dict[str, dict[str, Any]]) -> dict[str, Any]:
    entries = []
    for field in fields:
        allowed = allowlist.get(field.key)
        allowed_pointer = allowed.get("spec_pointer") if allowed else None
        shape, field_pointer = resolver.field_shape(
            allowed_pointer or field.spec_pointer, field.struct_name, field.field_name
        )
        classification = allowed.get("classification") if allowed else None
        entries.append(
            {
                "rust_field": field.key,
                "crate": field.crate,
                "file": field.file,
                "line": field.line,
                "owner": field.struct_name,
                "field": field.field_name,
                "rust_type": field.rust_type,
                "spec_pointer": (
                    allowed.get("spec_pointer")
                    if allowed is not None and "spec_pointer" in allowed
                    else field_pointer or field.spec_pointer
                ),
                "schema_shape": shape,
                "classification": classification or "unclassified",
                "reason": allowed.get("reason") if allowed else None,
            }
        )
    classifications = Counter(entry["classification"] for entry in entries)
    shapes = Counter(entry["schema_shape"] for entry in entries)
    crates = Counter(entry["crate"] for entry in entries)
    return {
        "summary": {
            "total": len(entries),
            "by_crate": dict(sorted(crates.items())),
            "by_classification": dict(sorted(classifications.items())),
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
    current = {entry["rust_field"]: entry for entry in report_payload["entries"]}
    for key, entry in current.items():
        classification = entry["classification"]
        if classification == "unclassified":
            errors.append(f"unclassified public Value field: {key}")
            continue
        if classification == "open_json" and entry["schema_shape"] not in {
            "open_json",
            "open_json_container",
            "open_map",
        }:
            errors.append(
                f"open_json allowlist entry does not resolve to an open schema: {key}"
            )
        if entry["field"] == "extra" and entry["schema_shape"] == "closed":
            errors.append(f"closed schema exposes a public flattened extra map: {key}")
        if classification == "open_json" and entry["schema_shape"] == "open_map" and "Map<" not in entry["rust_type"]:
            errors.append(f"open object field must use a map-shaped Rust type: {key}")
        if classification == "open_json" and entry["schema_shape"] == "open_json_container" and not any(
            container in entry["rust_type"] for container in ("Vec<", "Map<")
        ):
            errors.append(f"open JSON container field must preserve its container shape: {key}")
        if classification not in {
            "open_json",
            "polymorphic_boundary",
            "internal_or_fixture",
        }:
            errors.append(f"invalid classification {classification!r}: {key}")
        if not entry.get("reason"):
            errors.append(f"allowlist entry has no reason: {key}")
        if classification in {"open_json", "polymorphic_boundary"} and not entry.get(
            "spec_pointer"
        ):
            errors.append(f"wire allowlist entry has no Spec pointer: {key}")
        pointer = entry.get("spec_pointer")
        if pointer:
            try:
                resolver.pointer_node(pointer)
            except (FileNotFoundError, KeyError, json.JSONDecodeError, TypeError):
                errors.append(f"allowlist entry has an invalid Spec pointer: {key}")
    for key in sorted(set(allowlist) - set(current)):
        errors.append(f"stale allowlist entry: {key}")
    return errors


def seed_open_allowlist(
    path: Path, report_payload: dict[str, Any], allowlist: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    merged = dict(allowlist)
    for entry in report_payload["entries"]:
        if entry["schema_shape"] not in {"open_json", "open_map", "open_json_container"} or entry["rust_field"] in merged:
            continue
        merged[entry["rust_field"]] = {
            "rust_field": entry["rust_field"],
            "spec_pointer": entry["spec_pointer"],
            "classification": "open_json",
            "reason": "The resolved Spec field explicitly permits unconstrained JSON at this exact boundary.",
        }
    payload = {"entries": [merged[key] for key in sorted(merged)]}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return merged


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, default=DEFAULT_SPEC_ROOT)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--write-report", type=Path)
    parser.add_argument("--seed-open-allowlist", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    fields = scan_fields(args.source_root)
    resolver = SchemaResolver(args.spec_root)
    allowlist = load_allowlist(args.allowlist)
    payload = report(fields, resolver, allowlist)
    if args.seed_open_allowlist:
        allowlist = seed_open_allowlist(args.allowlist, payload, allowlist)
        payload = report(fields, resolver, allowlist)
    rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if args.write_report:
        args.write_report.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    if args.check:
        errors = validate(payload, allowlist, resolver)
        if args.inventory.exists() and args.source_root.resolve() == ROOT.resolve():
            tracked = json.loads(args.inventory.read_text(encoding="utf-8"))
            if tracked != payload:
                errors.append(
                    "wire Value inventory drifted; regenerate tools/wire_value_inventory.json"
                )
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
