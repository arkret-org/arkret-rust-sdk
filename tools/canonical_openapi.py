"""Generate closed, offline OpenAPI components from exact normative schemas.

Only schema-valued keywords are traversed: defaults/examples and extension data
are never interpreted as schemas. Static references become local components;
unsupported dynamic/reference scopes fail generation rather than losing rules.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote, urldefrag, urljoin, urlsplit

SCHEMA_BASE = "https://arkret.org/v1/schemas/"
MAPS = {"$defs", "definitions", "properties", "patternProperties", "dependentSchemas"}
SINGLES = {
    "additionalProperties", "unevaluatedProperties", "propertyNames", "items",
    "contains", "not", "if", "then", "else", "unevaluatedItems", "contentSchema",
    "additionalItems",
}
ARRAYS = {"allOf", "anyOf", "oneOf", "prefixItems"}


def escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def children(node):
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if key in MAPS:
            if not isinstance(value, dict):
                raise ValueError(f"non-object schema map: {key}")
            for name, child in value.items():
                yield (key, name), child
        elif key in SINGLES:
            yield (key,), value
        elif key in ARRAYS:
            if not isinstance(value, list):
                raise ValueError(f"non-array schema applicator: {key}")
            for index, child in enumerate(value):
                yield (key, index), child


class CanonicalClosure:
    def __init__(self, schemas: Path):
        self.schemas = schemas.resolve()
        self.documents = {}
        self.inputs = {}
        self.pending = set()
        self.components = {}
        self.sources = {}

    def document(self, file):
        if file not in self.documents:
            if Path(file).name != file or not file.endswith(".json"):
                raise ValueError(f"schema path escapes canonical root: {file}")
            raw = (self.schemas / file).read_bytes()
            data = json.loads(raw)
            if data.get("$id") != SCHEMA_BASE + file:
                raise ValueError(f"canonical schema URI differs from its owning file: {file}")
            self.documents[file] = data
            self.inputs[file] = raw
        return self.documents[file]

    def reference_parts(self, owner, reference):
        if not isinstance(reference, str) or any(ord(c) <= 32 or ord(c) == 127 for c in reference):
            raise ValueError("schema reference contains raw URI whitespace/control")
        if "?" in reference.split("#", 1)[0]:
            raise ValueError("schema reference contains a query delimiter")
        if re.search(r"%(?![0-9a-fA-F]{2})", reference):
            raise ValueError("malformed schema reference percent escape")
        uri, fragment = urldefrag(urljoin(SCHEMA_BASE + owner, reference))
        parts = urlsplit(uri)
        if (parts.scheme != "https" or parts.netloc != "arkret.org" or parts.query
                or not parts.path.startswith("/v1/schemas/")):
            raise ValueError(f"unregistered external schema reference: {reference}")
        file = unquote(parts.path.removeprefix("/v1/schemas/"), errors="strict")
        self.document(file)
        fragment = unquote(fragment, errors="strict")
        return file, fragment

    def target(self, owner, reference):
        file, fragment = self.reference_parts(owner, reference)
        if fragment and not fragment.startswith("/"):
            matches = []
            # A pointer may explicitly activate a schema stored beneath an
            # otherwise unknown keyword. Index those targets too, without
            # interpreting arbitrary annotation/instance data as schemas.
            pending = {(file, "")}
            seen = set()
            while pending:
                target = min(pending)
                pending.remove(target)
                if target in seen:
                    continue
                seen.add(target)
                owner_file, pointer = target
                node = self.node(target)
                if not isinstance(node, dict):
                    continue
                if owner_file == file and node.get("$anchor") == fragment:
                    matches.append(pointer)
                if "$ref" in node:
                    ref_file, ref_pointer = self.reference_parts(owner_file, node["$ref"])
                    pending.add((ref_file, ""))
                    if ref_pointer.startswith("/"):
                        pending.add((ref_file, ref_pointer))
                for path, _ in children(node):
                    pending.add((owner_file, pointer + "".join("/" + escape(str(x)) for x in path)))
            if len(matches) != 1:
                raise ValueError(f"schema anchor must resolve exactly once: {reference}")
            fragment = matches[0]
        return file, fragment

    def node(self, target):
        file, pointer = target
        node = self.document(file)
        for token in pointer.split("/")[1:]:
            if re.search(r"~(?![01])", token):
                raise ValueError(f"invalid JSON pointer token: {pointer}")
            token = token.replace("~1", "/").replace("~0", "~")
            if isinstance(node, list):
                if not re.fullmatch(r"0|[1-9][0-9]*", token):
                    raise ValueError(f"invalid JSON pointer array index: {pointer}")
                if int(token) >= len(node):
                    raise ValueError(f"JSON pointer array index is out of bounds: {pointer}")
                node = node[int(token)]
            elif isinstance(node, dict):
                node = node[token]
            else:
                raise ValueError(f"JSON pointer traverses a non-container: {pointer}")
        if not isinstance(node, (dict, bool)):
            raise ValueError(f"reference does not target a schema: {target}")
        return node

    @staticmethod
    def name(target):
        return "arkret_v1_" + hashlib.sha256(("#".join(target)).encode()).hexdigest()

    def render(self, node, file, pointer):
        if isinstance(node, bool):
            return node
        if not isinstance(node, dict):
            raise ValueError(f"schema position is neither object nor boolean: {file}#{pointer}")
        if any(key in node for key in ("$dynamicRef", "$recursiveRef", "$dynamicAnchor")):
            raise ValueError(f"dynamic schema scope requires explicit support: {file}#{pointer}")
        if "$id" in node and (pointer or node["$id"] != SCHEMA_BASE + file):
            raise ValueError(f"embedded schema resource requires explicit support: {file}#{pointer}")
        output = {key: value for key, value in node.items() if key not in {"$id", "$anchor"}}
        if "$ref" in node:
            target = self.target(file, node["$ref"])
            self.node(target)
            self.pending.add(target)
            output["$ref"] = "#/components/schemas/" + self.name(target)
        for path, child in children(node):
            # Copy only the schema container being rewritten. Instance-valued
            # annotations are left byte-value-identical, including literal refs.
            cursor = output
            original = node
            for part in path[:-1]:
                if cursor[part] is original[part]:
                    cursor[part] = list(cursor[part]) if isinstance(cursor[part], list) else dict(cursor[part])
                cursor, original = cursor[part], original[part]
            cursor[path[-1]] = self.render(
                child, file, pointer + "".join("/" + escape(str(x)) for x in path)
            )
        return output

    def build(self, roots):
        root_names = {}
        for name, reference in roots.items():
            file, _, fragment = reference.partition("#")
            self.document(file)
            target = self.target(file, "#" + fragment)
            self.node(target)
            self.pending.add(target)
            root_names[name] = self.name(target)
        seen = set()
        while self.pending:
            target = min(self.pending)
            self.pending.remove(target)
            if target in seen:
                continue
            seen.add(target)
            name = self.name(target)
            self.components[name] = self.render(self.node(target), *target)
            self.sources[name] = SCHEMA_BASE + target[0] + "#" + target[1]
        return {
            "roots": root_names,
            "components": dict(sorted(self.components.items())),
            "sources": dict(sorted(self.sources.items())),
        }


def raw_rust_string(value):
    hashes = "#"
    while '"' + hashes in value:
        hashes += "#"
    return "r" + hashes + '"' + value + '"' + hashes


def generate_bundle(schemas: Path, bundle):
    closure = CanonicalClosure(schemas)
    data = closure.build(bundle["roots"])
    lines = ["//! @generated; do not edit.", "//! Generator: tools/generate-closed-models.py (canonical OpenAPI closure)."]
    for file, raw in sorted(closure.inputs.items()):
        lines += [f"//! Input: schemas/{file}", f"//! sha256={hashlib.sha256(raw).hexdigest()}"]
    lines += [
        "",
        "static SCHEMAS: std::sync::OnceLock<Vec<(String, salvo_oapi::schema::Schema)>> = std::sync::OnceLock::new();",
        "const SCHEMA_JSON: &str = " + raw_rust_string(json.dumps(data["components"], ensure_ascii=True, separators=(",", ":"))) + ";",
        "",
        "fn register(components: &mut salvo_oapi::Components, root: &str) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {",
        "    let schemas = SCHEMAS.get_or_init(|| crate::canonical_openapi::decode_components(SCHEMA_JSON));",
        "    crate::canonical_openapi::register_components(components, schemas);",
        "    salvo_oapi::Ref::from_schema_name(root).into()",
        "}",
    ]
    for rust_type, root in sorted(data["roots"].items()):
        if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", rust_type):
            raise ValueError(f"invalid canonical OpenAPI Rust type: {rust_type}")
        lines += [
            f"impl salvo_oapi::ToSchema for super::{rust_type} {{",
            "    fn to_schema(components: &mut salvo_oapi::Components) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {",
            f'        register(components, "{root}")',
            "    }",
            "}",
            f"impl salvo_oapi::ComposeSchema for super::{rust_type} {{",
            "    fn compose(components: &mut salvo_oapi::Components, _generics: Vec<salvo_oapi::RefOr<salvo_oapi::schema::Schema>>) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {",
            "        <Self as salvo_oapi::ToSchema>::to_schema(components)",
            "    }",
            "}",
        ]
    lines += [
        "#[cfg(test)]",
        "mod tests {",
        "    #[test]",
        "    fn every_generated_canonical_component_serializes_losslessly() {",
        "        let expected: serde_json::Value = serde_json::from_str(super::SCHEMA_JSON).unwrap();",
        "        let mut components = salvo_oapi::Components::default();",
        "        let schemas = crate::canonical_openapi::decode_components(super::SCHEMA_JSON);",
        "        crate::canonical_openapi::register_components(&mut components, &schemas);",
        "        assert_eq!(serde_json::to_value(components.schemas).unwrap(), expected);",
        "    }",
        "}",
    ]
    return "\n".join(lines) + "\n", sorted(closure.inputs), data
