#!/usr/bin/env python3
"""Generate selected production closed models from canonical schemas.

Bindings select Rust names/traits and external SDK types, never object members.
Schema defaults are annotations, not permission to insert signed wire members.
Domain constraints remain with the existing validate methods and schema gate.
Unsupported structural composition fails the whole generation transaction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TIMESTAMP = "time.schema.json#/$defs/timestamp"
HELPERS = "arkret_canonical::serde_helpers"


def normalize(pointer: str, owner: str = "") -> str:
    file, mark, fragment = pointer.partition("#")
    return (file.removeprefix("./") or owner.split("#")[0]) + (mark + fragment)


def rust_name(wire: str) -> str:
    name = "".join(part[:1].upper() + part[1:] for part in wire.split("_"))
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", name):
        raise ValueError(f"unsupported Rust variant: {wire}")
    return name


class Generator:
    def __init__(self, schemas: Path, bindings: dict):
        if bindings["version"] != 1:
            raise ValueError("unsupported bindings version")
        self.schemas = schemas
        self.bindings = bindings
        self.names = {
            row["schema"]: row["name"]
            for family in bindings["families"] for row in family["types"]
        }
        self.names.update(bindings["references"])
        self.inputs: dict[str, bytes] = {}

    def node(self, pointer: str) -> dict:
        file, _, fragment = pointer.partition("#")
        if Path(file).name != file:
            raise ValueError(f"schema path escapes root: {file}")
        raw = (self.schemas / file).read_bytes()
        self.inputs[file] = raw
        node = json.loads(raw)
        if node.get("source_of_truth") is False:
            raise ValueError(f"derived schema cannot own generated fields: {file}")
        for part in fragment.split("/")[1:]:
            node = node[part.replace("~1", "/").replace("~0", "~")]
        return node

    def rust_type(self, node: dict, pointer: str) -> tuple[str, bool]:
        if "$ref" in node:
            target = normalize(node["$ref"], pointer)
            if target == TIMESTAMP:
                self.node(target)
                return "chrono::DateTime<chrono::Utc>", True
            if target in self.names:
                return self.names[target], False
            raise ValueError(f"unbound schema reference: {target}")
        if pointer in self.names:
            return self.names[pointer], False
        if any(key in node for key in ("oneOf", "anyOf", "allOf", "not", "if", "enum", "const")):
            raise ValueError(f"unsupported field composition: {pointer}")
        kind = node.get("type")
        if kind == "string":
            return "String", False
        if kind == "boolean":
            return "bool", False
        if kind == "integer" and node.get("minimum", -1) >= 0:
            maximum = node.get("maximum", 2**64 - 1)
            if maximum > 2**64 - 1:
                raise ValueError(f"integer exceeds u64: {pointer}")
            return next(t for bound, t in ((255, "u8"), (65535, "u16"), (2**32-1, "u32"), (2**64-1, "u64")) if maximum <= bound), False
        if kind == "array":
            inner, _ = self.rust_type(node["items"], pointer + "/items")
            return f"Vec<{inner}>", False
        raise ValueError(f"unsupported field type: {pointer}: {kind}")

    def declaration(self, row: dict) -> str:
        pointer, name = row["schema"], row["name"]
        node = self.node(pointer)
        if any(key in node for key in ("anyOf", "allOf", "not", "if", "patternProperties", "dependentRequired", "dependentSchemas")):
            raise ValueError(f"unsupported object composition: {pointer}")
        traits = ["Clone", "Debug", "PartialEq", "Eq", "serde::Serialize", "serde::Deserialize"]
        if row.get("copy"):
            traits.insert(1, "Copy")
        if row.get("default") or row.get("default_variant"):
            traits.insert(2, "Default")
        lines = [f"/// Counterpart: `{pointer}`."]
        if row.get("openapi", True):
            lines.append('#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]')
        lines.append(f'#[derive({", ".join(traits)})]')
        if "oneOf" in node:
            lines += ['#[serde(untagged)]', f"pub enum {name} {{"]
            kinds = set()
            for branch in node["oneOf"]:
                if set(branch) != {"$ref"}:
                    raise ValueError(f"union branch must be a named reference: {pointer}")
                target = normalize(branch["$ref"], pointer)
                shape = self.node(target)
                kind = shape.get("properties", {}).get("kind", {}).get("const")
                if (shape.get("type") != "object" or shape.get("additionalProperties") is not False
                    or "kind" not in shape.get("required", []) or not isinstance(kind, str)
                    or kind in kinds or target not in self.names):
                    raise ValueError(f"union branches must have distinct required closed kind: {target}")
                kinds.add(kind)
                lines.append(f"    {rust_name(kind)}({self.names[target]}),")
            if not kinds:
                raise ValueError(f"empty union: {pointer}")
        elif "enum" in node:
            if node.get("type") != "string":
                raise ValueError(f"unsupported enum: {pointer}")
            lines += [f"pub enum {name} {{"]
            variants = set()
            for value in node["enum"]:
                variant = rust_name(value)
                if variant in variants:
                    raise ValueError(f"duplicate Rust variant: {variant}")
                variants.add(variant)
                if value == row.get("default_variant"):
                    lines.append("    #[default]")
                lines += [f"    #[serde(rename = {json.dumps(value)})]", f"    {variant},"]
            if row.get("default_variant") and row["default_variant"] not in node["enum"]:
                raise ValueError(f"default variant absent: {pointer}")
        else:
            if node.get("type") != "object" or node.get("additionalProperties") is not False:
                raise ValueError(f"not a closed object: {pointer}")
            properties = node.get("properties", {})
            required = set(node.get("required", []))
            if not required <= properties.keys():
                raise ValueError(f"required member has no property: {pointer}")
            lines += ['#[serde(deny_unknown_fields)]', f"pub struct {name} {{"]
            for field, shape in properties.items():
                if not re.fullmatch(r"[a-z][a-z0-9_]*", field) or field in {"type", "ref", "self", "mod"}:
                    raise ValueError(f"unsupported Rust field name: {field}")
                here = pointer + ("/properties/" if "#" in pointer else "#/properties/") + field
                rust_type, timestamp = self.rust_type(shape, here)
                if field not in required:
                    lines.append('    #[serde(default, skip_serializing_if = "Option::is_none",')
                    helper = "deserialize_non_null_optional_timestamp" if timestamp else "deserialize_non_null_optional"
                    lines.append(f'        deserialize_with = "{HELPERS}::{helper}")]')
                    if timestamp:
                        lines.append(f'    #[serde(serialize_with = "{HELPERS}::serialize_optional_canonical_timestamp")]')
                    rust_type = f"Option<{rust_type}>"
                elif timestamp:
                    lines.append(f'    #[serde(with = "{HELPERS}::canonical_timestamp")]')
                lines.append(f"    pub {field}: {rust_type},")
        return "\n".join(lines + ["}", ""])

    def generate(self) -> dict[str, str]:
        outputs = {}
        for family in self.bindings["families"]:
            self.inputs = {}
            contents = "\n".join(self.declaration(row) for row in family["types"])
            header = ["//! @generated; do not edit by hand.", "//! Generator: tools/generate-closed-models.py"]
            for path, raw in self.inputs.items():
                header.extend(["//!", f"//! Input: schemas/{path}", f"//! sha256={hashlib.sha256(raw).hexdigest()}"])
            binding_bytes = json.dumps(self.bindings, sort_keys=True, separators=(",", ":")).encode()
            header.extend(["//!", "//! Bindings: tools/closed-model-bindings.json", f"//! sha256={hashlib.sha256(binding_bytes).hexdigest()}"])
            outputs[family["output"]] = "\n".join(header) + "\n\n" + contents
        return outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    bindings = json.loads((ROOT / "closed-model-bindings.json").read_text(encoding="utf-8"))
    manifest = json.loads((ROOT / "spec-generation-manifest.json").read_text(encoding="utf-8"))
    declared = [path for entry in manifest["entries"] if entry["generator"] == "closed-models" for path in entry["outputs"]]
    selected = [family["output"] for family in bindings["families"]]
    if len(set(selected)) != len(selected) or sorted(selected) != sorted(declared):
        raise ValueError("closed model bindings and generation manifest output sets differ")
    outputs = Generator(args.artifacts_dir / "schemas", bindings).generate()
    for relative, contents in outputs.items():
        output = args.output_root / relative
        if not output.resolve().is_relative_to(args.output_root.resolve()):
            raise ValueError(f"output escapes root: {relative}")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(contents, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
