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
            if "rust" not in row
        }
        self.names.update(bindings["references"])
        self.local_aliases: dict[str, str] = {}
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
        def rebase(value):
            if isinstance(value, dict):
                return {key: normalize(child, file) if key == "$ref" else rebase(child)
                        for key, child in value.items()}
            return [rebase(child) for child in value] if isinstance(value, list) else value
        node = rebase(node)
        for part in fragment.split("/")[1:]:
            token = part.replace("~1", "/").replace("~0", "~")
            while isinstance(node, dict) and token not in node and "$ref" in node:
                node = self.node(node["$ref"])
            node = node[int(token)] if isinstance(node, list) else node[token]
        return node

    def nullable(self, node: dict, owner: str, seen=None) -> bool:
        seen = set() if seen is None else seen
        if isinstance(node, bool):
            return node
        kind = node.get("type")
        if kind is not None and kind != "null" and not (isinstance(kind, list) and "null" in kind):
            return False
        if "const" in node and node["const"] is not None:
            return False
        if "enum" in node and None not in node["enum"]:
            return False
        if "$ref" in node:
            target = normalize(node["$ref"], owner)
            if target in seen:
                raise ValueError(f"cyclic null applicability reference: {target}")
            if not self.nullable(self.node(target), target, seen | {target}):
                return False
        if "allOf" in node and not all(self.nullable(branch, owner, seen) for branch in node["allOf"]):
            return False
        if "anyOf" in node and not any(self.nullable(branch, owner, seen) for branch in node["anyOf"]):
            return False
        if "oneOf" in node and sum(self.nullable(branch, owner, seen) for branch in node["oneOf"]) != 1:
            return False
        if "not" in node and self.nullable(node["not"], owner, seen):
            return False
        if "if" in node:
            branch = "then" if self.nullable(node["if"], owner, seen) else "else"
            if branch in node and not self.nullable(node[branch], owner, seen):
                return False
        # Applicability-only keywords (properties, pattern, minimum, etc.) do
        # not reject null unless a type/enum/const/composition proves it.
        return True

    def representation(self, row: dict, node: dict) -> str:
        """Project schema-owned members using reviewed Rust representation hooks.

        The hooks carry types/traits/serde adapters, never membership or order.
        include! keeps private validators and public Rust paths at their owner.
        """
        pointer = row["schema"]
        seen = set()
        while "$ref" in node:
            target = node["$ref"]
            if target in seen:
                raise ValueError(f"cyclic object reference: {pointer}")
            seen.add(target)
            node = self.node(target)
        if (node.get("type") != "object" or node.get("additionalProperties") is not False
            or "patternProperties" in node):
            raise ValueError(f"representation requires closed named object members: {pointer}")
        rust = row["rust"]
        properties = node.get("properties", {})
        if set(properties) != set(rust["members"]):
            raise ValueError(f"Rust representation member set drifted: {pointer}")
        attributes = list(rust["attributes"])
        if any(attr.startswith("#[derive") and "Deserialize" in attr for attr in attributes) and not any("deny_unknown_fields" in attr for attr in attributes):
            attributes.append("#[serde(deny_unknown_fields)]")
        lines = [f"/// Counterpart: `{pointer}`.", *attributes, rust["signature"] + " {"]
        required = set(node.get("required", []))
        for wire, shape in properties.items():
            binding = rust["members"][wire]
            attributes = list(binding["attributes"])
            typ = binding["type"]
            for qualified, local in self.local_aliases.items():
                typ = re.sub(r"(?<![\w:])" + re.escape(qualified) + r"(?![\w:])", local, typ)
            if wire in required:
                if any("skip_serializing_if" in attr for attr in attributes):
                    raise ValueError(f"required member cannot be omitted by its Rust representation: {pointer}/{wire}")
                attributes = [re.sub(r'\bdefault(?:\s*=\s*"[^"]*")?\s*,?\s*', '', attr) for attr in attributes]
                attributes = [attr for attr in attributes if not re.fullmatch(r'#\[serde\(\s*\)\]', attr)]
                if typ.startswith("Option<") and not any("deserialize_with" in attr or re.search(r"\bwith\s*=", attr) for attr in attributes):
                    attributes.append(f'#[serde(deserialize_with = "{HELPERS}::deserialize_required_nullable")]')
            if typ.startswith("Option<") and wire not in required and not self.nullable(shape, pointer):
                for index, attr in enumerate(attributes):
                    if re.search(r'\bwith\s*=\s*"[^"]*::optional_canonical_timestamp"', attr):
                        attributes[index] = re.sub(
                            r'\bwith\s*=\s*"[^"]*::optional_canonical_timestamp"',
                            f'serialize_with = "{HELPERS}::serialize_optional_canonical_timestamp", deserialize_with = "{HELPERS}::deserialize_non_null_optional_timestamp"', attr)
            if (typ.startswith("Option<") and wire not in required and not self.nullable(shape, pointer)
                and not any("deserialize_with" in attr or re.search(r"\bwith\s*=", attr) for attr in attributes)):
                default = "" if any(re.search(r"\bdefault\b", attr) for attr in attributes) else "default, "
                attributes.append(f'#[serde({default}deserialize_with = "{HELPERS}::deserialize_non_null_optional")]')
                if not any("skip_serializing_if" in attr for attr in attributes):
                    attributes.append('#[serde(skip_serializing_if = "Option::is_none")]')
            lines.extend("    " + attr for attr in attributes)
            lines.append(f"    {binding['visibility']} {binding['name']}: {typ},")
        return "\n".join(lines + ["}", ""])

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
        if "rust" in row:
            return self.representation(row, node)
        if any(key in node for key in ("anyOf", "allOf", "not", "if", "patternProperties", "dependentRequired", "dependentSchemas")):
            raise ValueError(f"unsupported object composition: {pointer}")
        traits = ["Clone", "Debug", "PartialEq", "serde::Serialize", "serde::Deserialize"]
        if row.get("eq", True):
            traits.insert(3, "Eq")
        if row.get("copy"):
            traits.insert(1, "Copy")
        if row.get("default") or row.get("default_variant"):
            traits.insert(2, "Default")
        lines = [f"/// Counterpart: `{pointer}`."]
        if row.get("openapi", True):
            lines.append('#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]')
        lines.append(f'#[derive({", ".join(traits)})]')
        if row.get("expect_large_enum_variant"):
            lines.append('#[expect(clippy::large_enum_variant, reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy.")]')
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
        elif "enum" in node or "const" in node:
            values = node.get("enum", [node.get("const")])
            if node.get("type", "string") != "string" or not all(isinstance(value, str) for value in values):
                raise ValueError(f"unsupported enum: {pointer}")
            lines += [f"pub enum {name} {{"]
            variants = set()
            for value in values:
                variant = rust_name(value)
                if variant in variants:
                    raise ValueError(f"duplicate Rust variant: {variant}")
                variants.add(variant)
                if value == row.get("default_variant"):
                    lines.append("    #[default]")
                lines += [f"    #[serde(rename = {json.dumps(value)})]", f"    {variant},"]
            if row.get("default_variant") and row["default_variant"] not in values:
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
        qualified_names = self.names.copy()
        for family in self.bindings["families"]:
            self.inputs = {}
            self.names = qualified_names.copy()
            self.local_aliases = {}
            for row in family["types"]:
                qualified = self.names.get(row["schema"], "")
                if qualified.endswith("::" + row["name"]):
                    self.names[row["schema"]] = row["name"]
                    self.local_aliases[qualified] = row["name"]
            contents = "\n".join(self.declaration(row) for row in family["types"])
            header = ["//! @generated; do not edit by hand.", "//! Generator: tools/generate-closed-models.py"]
            for path, raw in self.inputs.items():
                header.extend(["//!", f"//! Input: schemas/{path}", f"//! sha256={hashlib.sha256(raw).hexdigest()}"])
            binding_bytes = json.dumps(self.bindings, sort_keys=True, separators=(",", ":")).encode()
            header.extend(["//!", "//! Bindings: tools/closed-model-bindings.json", f"//! sha256={hashlib.sha256(binding_bytes).hexdigest()}"])
            if family.get("inline"):
                header = [line.replace("//!", "//", 1) for line in header]
            outputs[family["output"]] = "\n".join(header) + "\n\n" + contents
        self.names = qualified_names
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
    registry = json.loads((ROOT / "schema_struct_registry.json").read_text(encoding="utf-8"))
    generated = {family["output"] + "::" + row["name"]: row["schema"] for family in bindings["families"] for row in family["types"]}
    retained = {row["rust_type"]: row for row in bindings["retained_models"]}
    expected = {row["rust_type"]: row["schema"] for row in registry["mappings"]}
    actual = {key: value for key, value in generated.items() if key in expected}
    if set(actual) & set(retained) or actual | {key: row["schema"] for key, row in retained.items()} != expected:
        raise ValueError("every schema mapping must have exactly one generated or reviewed retained owner")
    exempted = {row["rust_type"] for row in registry["exemptions"]}
    if {row["rust_type"] for row in bindings["retained_exemptions"]} != exempted:
        raise ValueError("every field-set exemption requires an explicit generation classification")
    for row in [*bindings["retained_models"], *bindings["retained_exemptions"]]:
        if row["category"] not in {"domain_semantics", "artifact_expression", "internal_implementation"} or len(row["reason"]) < 50:
            raise ValueError(f"unreviewed retained generation boundary: {row['rust_type']}")
    prefix_path = "crates/canonical/src/generated/binding_prefixes.rs"
    prefix_outputs = [path for entry in manifest["entries"] if entry["generator"] == "binding-prefixes" for path in entry["outputs"]]
    if prefix_outputs != [prefix_path]:
        raise ValueError("binding prefix generation manifest mismatch")
    raw = (args.artifacts_dir / "registry/proof-context-registry.json").read_bytes()
    lines = ["//! @generated; do not edit by hand.", "//! Input: registry/proof-context-registry.json", f"//! sha256={hashlib.sha256(raw).hexdigest()}", "", "pub struct DomainPrefix;", "", "impl DomainPrefix {"]
    for row in json.loads(raw)["domain_separations"]:
        if "prefix_bytes_hex" not in row:
            continue
        prefix = bytes.fromhex(row["prefix_bytes_hex"])
        name = re.sub(r"[^A-Za-z0-9]", "_", row["domain"]).upper()
        lines.append(f"    pub const {name}: &'static [u8] = &[{', '.join(str(byte) for byte in prefix)}];")
    outputs[prefix_path] = "\n".join(lines + ["}", ""])
    retired_path = "crates/wire/src/generated/rejected_profile_markers.rs"
    if [path for entry in manifest["entries"] if entry["generator"] == "rejected-profile-markers" for path in entry["outputs"]] != [retired_path]:
        raise ValueError("retired profile marker manifest mismatch")
    raw = (args.artifacts_dir / "registry/contract-registry.json").read_bytes()
    lines = ["//! @generated; do not edit by hand.", "//! Rejection markers only; these are never active or claimable profiles.", "//! Input: registry/contract-registry.json", f"//! sha256={hashlib.sha256(raw).hexdigest()}", "", "pub struct RejectedProfileId;", "", "impl RejectedProfileId {"]
    for row in json.loads(raw)["rejected_profile_markers"]:
        if row["behavior"] != "reject_without_activation_or_registration":
            raise ValueError("retired profiles must remain rejection-only")
        name = row["profile_id"].removeprefix("ak.profile.").replace(".", "_").upper()
        lines.append(f'    pub const {name}: &\'static str = {json.dumps(row["profile_id"])};')
    outputs[retired_path] = "\n".join(lines + ["}", ""])
    for relative, contents in outputs.items():
        output = args.output_root / relative
        if not output.resolve().is_relative_to(args.output_root.resolve()):
            raise ValueError(f"output escapes root: {relative}")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(contents, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
