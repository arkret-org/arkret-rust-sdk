#!/usr/bin/env python3
"""Compare generated wire types against the hand-written ones.

Byte equality is not the useful bar: the hand-written crate carries rustdoc,
builders, ``cfg_attr`` OpenAPI derives and hand-ordered attributes that no
generator should try to reproduce. The bar that matters is that both spellings
make serde do the same thing, so the comparison runs on the serde-level model
and sorts every difference into one of three buckets:

* ``generator-gap`` - the prototype could not express what the schema says.
* ``drift`` - the hand-written type and the Spec disagree about the wire shape.
* ``equivalent`` - both agree on the wire, only the Rust spelling differs.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rust_model  # noqa: E402
from generate import GeneratedType  # noqa: E402

DRIFT = "drift"
GAP = "generator-gap"
EQUIVALENT = "equivalent"


@dataclass
class Difference:
    rust_type: str
    pointer: str
    member: str | None
    bucket: str
    detail: str
    kind: str = ""


@dataclass
class Comparison:
    rust_type: str
    pointer: str
    identical: bool = False
    differences: list[Difference] = field(default_factory=list)


def _omission(attributes: list[str]) -> str | None:
    for attribute in attributes:
        match = re.search(r'skip_serializing_if\s*=\s*"([^"]+)"', attribute)
        if match:
            return match.group(1)
    return None


def _has_default(attributes: list[str]) -> bool:
    return any(re.search(r"\bdefault\b", attribute) for attribute in attributes)


def _with_helper(attributes: list[str]) -> str | None:
    for attribute in attributes:
        match = re.search(r'with\s*=\s*"([^"]+)"', attribute)
        if match:
            return match.group(1)
    return None


def _normalize_type(rust_type: str) -> str:
    text = re.sub(r"\s+", "", rust_type)
    text = text.replace("serde_json::Value", "Value")
    text = text.replace("BTreeSet<", "Vec<")  # ordering-only difference on the wire
    text = re.sub(r"\bcrate::", "", text)
    text = re.sub(r"\b[a-z_][a-z0-9_]*(?:::[a-z_][a-z0-9_]*)*::", "", text)
    return text


def _int_family(rust_type: str) -> str:
    return "int" if re.fullmatch(r"[ui](8|16|32|64|128|size)", rust_type) else rust_type


def _leaf_name(rust_type: str) -> str:
    text = rust_type
    while True:
        match = re.fullmatch(r"(?:Option|Vec|BTreeSet)<(.+)>", text)
        if not match:
            return text
        text = match.group(1)


def _enum_values(item: object) -> frozenset[str] | None:
    if isinstance(item, rust_model.RustType):
        if item.kind != "enum" or any(v.payload for v in item.variants):
            return None
        return frozenset(v.wire_name for v in item.variants)
    if isinstance(item, GeneratedType):
        if item.kind != "enum":
            return None
        payloads = [payload for _, payload, _ in item.variants]
        if any(not re.fullmatch(r"[a-z0-9_.+ -]*", p or "") for p in payloads):
            return None
        return frozenset(payloads)
    return None


def _member_shape(item: object) -> frozenset[tuple[str, bool]] | None:
    if isinstance(item, rust_model.RustType):
        if item.kind != "struct":
            return None
        return frozenset(
            (f.wire_name, f.optional)
            for f in item.fields
            if not f.skipped and not f.flatten
        )
    if isinstance(item, GeneratedType):
        if item.kind != "struct":
            return None
        return frozenset(
            (f.wire_name, f.rust_type.startswith("Option<"))
            for f in item.fields
            if f.wire_name
        )
    return None


def structurally_equal(left: object | None, right: object | None) -> bool:
    """Do two differently named types describe the same wire shape?

    The generator has to invent a name for every inline subschema; the crate
    already has a hand-picked one. Comparing shapes keeps that naming freedom
    out of the drift bucket.
    """
    if left is None or right is None:
        return False
    left_values, right_values = _enum_values(left), _enum_values(right)
    if left_values is not None and right_values is not None:
        return left_values == right_values
    left_members, right_members = _member_shape(left), _member_shape(right)
    if left_members is not None and right_members is not None:
        return left_members == right_members
    return False


INT_CAPACITY = {
    "u8": 255,
    "u16": 65535,
    "u32": 4294967295,
    "u64": 18446744073709551615,
    "i32": 2147483647,
    "i64": 9223372036854775807,
}
OPAQUE = {"String", "Value", "bool", "u8", "u16", "u32", "u64", "i32", "i64", "f64", "()"}


def _shape_delta(left: object | None, right: object | None) -> str | None:
    left_values, right_values = _enum_values(left), _enum_values(right)
    if left_values is not None and right_values is not None:
        return (
            f"rust-only={sorted(left_values - right_values)} "
            f"spec-only={sorted(right_values - left_values)}"
        )
    left_members, right_members = _member_shape(left), _member_shape(right)
    if left_members is not None and right_members is not None:
        left_names = {n for n, _ in left_members}
        right_names = {n for n, _ in right_members}
        optional_delta = sorted(
            n
            for n in left_names & right_names
            if dict(left_members)[n] != dict(right_members)[n]
        )
        return (
            f"rust-only={sorted(left_names - right_names)} "
            f"spec-only={sorted(right_names - left_names)} "
            f"optionality-differs={optional_delta}"
        )
    return None


def _classify_leaf_mismatch(
    left_type: str,
    right_type: str,
    left_leaf: str,
    right_leaf: str,
    hand_item: object | None,
    generated_item: object | None,
) -> tuple[str, str, str]:
    """Say why two leaf types differ, so the residue is actionable."""
    if right_leaf in OPAQUE and left_leaf not in OPAQUE:
        return (
            GAP,
            "missing-binding",
            f"the prototype has no binding for this schema node and fell back to "
            f"{right_type}; the crate uses {left_type}",
        )
    if left_leaf in OPAQUE and right_leaf not in OPAQUE:
        return (
            DRIFT,
            "weak-typing",
            f"the schema constrains this member ({right_type}) but the crate "
            f"carries it as {left_type}",
        )
    if isinstance(hand_item, rust_model.RustType) and hand_item.fields and all(
        f.flatten for f in hand_item.fields
    ):
        return (
            EQUIVALENT,
            "open-map-typed-as-map",
            f"{left_type} carries the whole object as a flattened map, so the "
            f"schema's named members round-trip untyped rather than being lost",
        )
    delta = _shape_delta(hand_item, generated_item)
    if delta:
        return (
            DRIFT,
            "shape-delta",
            f"{left_type} and the spec node disagree: {delta}",
        )
    return (
        GAP,
        "unsettled-type",
        f"type mismatch the prototype cannot settle: hand={left_type} generated={right_type}",
    )


def compare_struct(
    hand: rust_model.RustType,
    generated: GeneratedType,
    hand_types: dict[str, rust_model.RustType] | None = None,
    generated_types: dict[str, GeneratedType] | None = None,
) -> Comparison:
    hand_types = hand_types or {}
    generated_types = generated_types or {}
    result = Comparison(rust_type=hand.name, pointer=generated.pointer)
    hand_fields = {
        f.wire_name: f for f in hand.fields if not f.skipped and not f.flatten
    }
    hand_flatten = [f for f in hand.fields if f.flatten]
    generated_fields = {
        f.wire_name: f for f in generated.fields if f.wire_name
    }
    generated_flatten = [f for f in generated.fields if not f.wire_name]

    for name in sorted(set(generated_fields) - set(hand_fields)):
        result.differences.append(
            Difference(
                hand.name,
                generated.pointer,
                name,
                DRIFT,
                "spec declares this member; the hand-written type has no field for it",
            )
        )
    for name in sorted(set(hand_fields) - set(generated_fields)):
        result.differences.append(
            Difference(
                hand.name,
                generated.pointer,
                name,
                DRIFT,
                "hand-written field has no counterpart member in the spec node",
            )
        )

    for name in sorted(set(hand_fields) & set(generated_fields)):
        left = hand_fields[name]
        right = generated_fields[name]
        left_type = _normalize_type(left.rust_type)
        right_type = _normalize_type(right.rust_type)
        if left.optional != right.rust_type.startswith("Option<"):
            generated_container = right.rust_type.startswith(
                ("Vec<", "BTreeSet<", "BTreeMap<")
            )
            if (left.optional and generated_container) or (
                not left.optional
                and left_type.startswith(("Vec<", "BTreeSet<", "BTreeMap<"))
                and right.rust_type.startswith("Option<")
            ):
                # Both spell "may be absent"; they differ only in whether an
                # explicit JSON null is accepted on the way in.
                result.differences.append(
                    Difference(
                        hand.name,
                        generated.pointer,
                        name,
                        EQUIVALENT,
                        f"container optionality: hand={left.rust_type} "
                        f"generated={right.rust_type} (absence agrees, null handling differs)",
                        "container-optionality",
                    )
                )
            else:
                result.differences.append(
                    Difference(
                        hand.name,
                        generated.pointer,
                        name,
                        DRIFT,
                        f"optionality: hand={'Option<..>' if left.optional else 'required'} "
                        f"schema={'optional' if right.rust_type.startswith('Option<') else 'required'}",
                        "optionality",
                    )
                )
        elif left_type != right_type:
            bucket = EQUIVALENT
            kind = "type-spelling"
            detail = f"type spelling: hand={left.rust_type} generated={right.rust_type}"
            left_leaf = _leaf_name(left_type)
            right_leaf = _leaf_name(right_type)
            if _int_family(left_leaf) == "int" and _int_family(right_leaf) == "int":
                capacity = INT_CAPACITY.get(left_leaf)
                maximum = right.schema_maximum
                if maximum is not None and capacity is not None and capacity >= maximum:
                    bucket = EQUIVALENT
                    kind = "integer-width-covers"
                    detail = (
                        f"integer width: hand={left.rust_type} covers the declared "
                        f"maximum {maximum}; generated={right.rust_type} is only wider"
                    )
                elif maximum is not None and capacity is not None:
                    bucket = DRIFT
                    kind = "integer-too-narrow"
                    detail = (
                        f"integer width: hand={left.rust_type} cannot hold the declared "
                        f"maximum {maximum}"
                    )
                else:
                    bucket = EQUIVALENT
                    kind = "integer-width-unbounded"
                    detail = (
                        f"integer width: hand={left.rust_type} narrows an unbounded "
                        f"schema domain (generated={right.rust_type}); no declared maximum "
                        f"to check against"
                    )
            elif structurally_equal(
                hand_types.get(left_leaf), generated_types.get(right_leaf)
            ):
                kind = "anonymous-name"
                detail = (
                    f"same wire shape under a different name: hand={left.rust_type} "
                    f"generated={right.rust_type}"
                )
            elif left_leaf != right_leaf:
                bucket, kind, detail = _classify_leaf_mismatch(
                    left.rust_type,
                    right.rust_type,
                    left_leaf,
                    right_leaf,
                    hand_types.get(left_leaf),
                    generated_types.get(right_leaf),
                )
            result.differences.append(
                Difference(hand.name, generated.pointer, name, bucket, detail, kind)
            )

        hand_omission = left.skip_serializing_if
        generated_omission = _omission(right.attributes)
        if hand_omission != generated_omission:
            result.differences.append(
                Difference(
                    hand.name,
                    generated.pointer,
                    name,
                    EQUIVALENT,
                    f"omission rule: hand={hand_omission} generated={generated_omission}",
                )
            )
        if left.has_default != _has_default(right.attributes):
            # serde already fills a missing Option<T> with None, so the missing
            # attribute changes nothing there. On a bare container it does: the
            # field becomes mandatory on the wire.
            container = not left.optional and left_type.startswith(
                ("Vec<", "BTreeSet<", "BTreeMap<")
            )
            result.differences.append(
                Difference(
                    hand.name,
                    generated.pointer,
                    name,
                    DRIFT if (container and not left.has_default) else EQUIVALENT,
                    (
                        f"missing serde default on {left.rust_type}: the schema leaves this "
                        "member optional but the crate fails to deserialize when it is absent"
                        if (container and not left.has_default)
                        else f"serde default attribute: hand={left.has_default} "
                        f"generated={_has_default(right.attributes)} (no wire effect on Option)"
                    ),
                    "absent-default" if (container and not left.has_default) else "redundant-default",
                )
            )
        if (left.with_module or None) != _with_helper(right.attributes):
            result.differences.append(
                Difference(
                    hand.name,
                    generated.pointer,
                    name,
                    EQUIVALENT if left.with_module else GAP,
                    f"serde with: hand={left.with_module} generated={_with_helper(right.attributes)}",
                )
            )

    generated_denies = any("deny_unknown_fields" in a for a in generated.attributes)
    if hand.deny_unknown_fields != generated_denies:
        bucket = DRIFT if generated_denies else EQUIVALENT
        result.differences.append(
            Difference(
                hand.name,
                generated.pointer,
                None,
                bucket,
                f"deny_unknown_fields: hand={hand.deny_unknown_fields} spec={generated_denies}",
            )
        )
    if bool(hand_flatten) != bool(generated_flatten):
        result.differences.append(
            Difference(
                hand.name,
                generated.pointer,
                None,
                EQUIVALENT if hand_flatten else DRIFT,
                f"extension capture: hand={[f.name for f in hand_flatten]} "
                f"spec-open={bool(generated_flatten)}",
            )
        )
    result.identical = not result.differences
    return result


def compare_enum(hand: rust_model.RustType, generated: GeneratedType) -> Comparison:
    result = Comparison(rust_type=hand.name, pointer=generated.pointer)
    if any(v.payload for v in hand.variants) or any(
        payload and payload != ident for ident, payload, _ in generated.variants
    ):
        hand_names = {v.name for v in hand.variants}
        generated_names = {ident for ident, _, _ in generated.variants}
        if len(hand.variants) != len(generated.variants):
            result.differences.append(
                Difference(
                    hand.name,
                    generated.pointer,
                    None,
                    GAP,
                    f"data-carrying union arity: hand={len(hand.variants)} "
                    f"generated={len(generated.variants)} "
                    f"(hand={sorted(hand_names)} generated={sorted(generated_names)})",
                )
            )
        result.identical = not result.differences
        return result

    hand_values = {v.wire_name for v in hand.variants}
    generated_values = {payload for _, payload, _ in generated.variants}
    for value in sorted(generated_values - hand_values):
        result.differences.append(
            Difference(
                hand.name, generated.pointer, value, DRIFT,
                "spec enum value has no Rust variant",
            )
        )
    for value in sorted(hand_values - generated_values):
        result.differences.append(
            Difference(
                hand.name, generated.pointer, value, DRIFT,
                "Rust variant is not in the spec enum",
            )
        )
    result.identical = not result.differences
    return result


def compare(
    hand: rust_model.RustType,
    generated: GeneratedType,
    hand_types: dict[str, rust_model.RustType] | None = None,
    generated_types: dict[str, GeneratedType] | None = None,
) -> Comparison:
    if generated.kind == "struct" and hand.kind == "struct":
        return compare_struct(hand, generated, hand_types, generated_types)
    if generated.kind == "enum" and hand.kind == "enum":
        return compare_enum(hand, generated)
    return Comparison(
        rust_type=hand.name,
        pointer=generated.pointer,
        differences=[
            Difference(
                hand.name,
                generated.pointer,
                None,
                GAP,
                f"kind mismatch: hand={hand.kind} generated={generated.kind}",
            )
        ],
    )
