#!/usr/bin/env python3
"""Generate committed Rust registry surfaces from Arkret v1 artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


def load(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def variant(value: str, prefixes: tuple[str, ...] = ()) -> str:
    for prefix in prefixes:
        if value.startswith(prefix):
            value = value[len(prefix) :]
            break
    parts = re.split(r"[^A-Za-z0-9]+", value)
    result = "".join(part[:1].upper() + part[1:] for part in parts if part)
    if not result or result[0].isdigit():
        result = "Value" + result
    return result


def associated_name(value: str, prefixes: tuple[str, ...] = ()) -> str:
    for prefix in prefixes:
        if value.startswith(prefix):
            value = value[len(prefix) :]
            break
    return re.sub(r"[^A-Za-z0-9]+", "_", value).upper()


SCHEMA_ID_PREFIXES = ("ak.schema.", "ak.")
PROFILE_ID_PREFIXES = ("ak.profile.",)
REDUCER_PROFILE_PREFIXES = ("ak.reducer.",)
DID_FRESHNESS_PREFIXES = ("ak.did_freshness.",)
AUTHORITY_SOURCE_PREFIXES = ("ak.authority.",)


def rust_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def rustdoc_text(value: str) -> str:
    """Render registry prose as inert rustdoc text, never as an HTML tag."""
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def rust_option(value: Any) -> str:
    return "None" if value is None else f"Some({rust_string(str(value))})"


def rust_usize_option(value: Any) -> str:
    return "None" if value is None else f"Some({int(value)})"


def rust_slice(values: list[str] | None) -> str:
    return "&[" + ", ".join(rust_string(value) for value in (values or [])) + "]"


def event_kind_slice(values: list[str] | None) -> str:
    """Event-kind wire list rendered from the generated single-literal domain."""
    return (
        "&["
        + ", ".join(
            f"event_kind_str::{associated_name(value, ('ak.',))}"
            for value in (values or [])
        )
        + "]"
    )


def header(
    inputs: list[tuple[str, dict[str, Any], str]], counts: str
) -> list[str]:
    lines = [
        "//! @generated; do not edit by hand.",
        "//! Generator: tools/generate-registry-types.py",
    ]
    for relative, artifact, digest in inputs:
        version = artifact.get("version", "unversioned")
        lines.append(f"//! Input: {relative}; version={version}; sha256={digest}")
    lines.extend([f"//! Entries: {counts}", ""])
    return lines


def ensure_unique(
    rows: list[dict[str, Any]], key: str, prefixes: tuple[str, ...] = ()
) -> None:
    seen: dict[str, str] = {}
    for row in rows:
        value = str(row[key])
        name = variant(value, prefixes)
        if name in seen:
            raise ValueError(
                f"variant collision {name!r}: {seen[name]!r} and {value!r}"
            )
        seen[name] = value


def generate_digest_suite_codes(artifacts: Path) -> str:
    relative = "registry/digest-suite-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(
        (row for row in artifact["suites"] if row["status"] == "active"),
        key=lambda row: row["wire_code"],
    )
    ensure_unique(rows, "canonical_id")
    seen_codes: set[int] = set()
    for row in rows:
        code = int(row["wire_code"])
        if code in seen_codes:
            raise ValueError(f"duplicate active digest-suite wire_code: {code}")
        if code == 0 or code & 0xF0:
            raise ValueError(
                f"active v1 suite-tagged full-digest wire_code must have high nibble zero: 0x{code:02x}"
            )
        if int(row["digest_length_bytes"]) != 32:
            raise ValueError(
                f"active 33-byte token suite {row['canonical_id']!r} does not have a 32-byte digest"
            )
        seen_codes.add(code)

    lines = header([(relative, artifact, digest)], f"active={len(rows)}")
    lines.extend(
        [
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "#[repr(u8)]",
            "pub enum DigestSuiteCode {",
        ]
    )
    for row in rows:
        lines.append(f"    {variant(row['canonical_id'])} = 0x{int(row['wire_code']):02x},")
    lines.extend(["}", "", "impl DigestSuiteCode {"])
    lines.extend(
        [
            "    pub const fn as_u8(self) -> u8 { self as u8 }",
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['canonical_id'])} => {rust_string(row['canonical_id'])},"
        )
    lines.extend(["        }", "    }", ""])
    lines.extend(
        [
            "    pub const fn from_digest_suite(suite: arkret_canonical::DigestSuite) -> Self {",
            "        match suite {",
        ]
    )
    for row in rows:
        lines.append(
            f"            arkret_canonical::DigestSuite::{variant(row['canonical_id'])} => Self::{variant(row['canonical_id'])},"
        )
    lines.extend(["        }", "    }", ""])
    lines.extend(
        [
            "    pub const fn digest_suite(self) -> arkret_canonical::DigestSuite {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['canonical_id'])} => arkret_canonical::DigestSuite::{variant(row['canonical_id'])},"
        )
    lines.extend(["        }", "    }", "}", ""])
    lines.extend(
        [
            "impl TryFrom<u8> for DigestSuiteCode {",
            "    type Error = crate::IdentifierError;",
            "",
            "    fn try_from(value: u8) -> crate::Result<Self> {",
            "        match value {",
        ]
    )
    for row in rows:
        lines.append(
            f"            0x{int(row['wire_code']):02x} => Ok(Self::{variant(row['canonical_id'])}),"
        )
    lines.extend(
        [
            "            _ => Err(crate::IdentifierError::InvalidId(format!(",
            "                \"unsupported digest suite code: 0x{value:02x}\"",
            "            ))),",
            "        }",
            "    }",
            "}",
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_operations(artifacts: Path) -> str:
    relative = "registry/operation-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(artifact["operations"], key=lambda row: row["operation_id"])
    ensure_unique(rows, "operation_id", ("ak.",))
    lines = header([(relative, artifact, digest)], f"registered={len(rows)}")
    lines.extend(
        [
            "use serde::{Deserialize, Serialize};",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "#[repr(usize)]",
            "pub enum ServiceOperationId {",
        ]
    )
    for row in rows:
        lines.append(f"    {variant(row['operation_id'], ('ak.',))},")
    lines.extend(
        [
            "}",
            "",
            "pub const REGISTERED_SERVICE_OPERATION_IDS: &[&str] = &[",
        ]
    )
    for row in rows:
        lines.append(
            f"    ServiceOperationId::{associated_name(row['operation_id'], ('ak.',))},"
        )
    lines.extend(
        [
            "];",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub enum DurableEffectKind {",
            "    EventLog,",
            "    ActorPrivateEvent,",
            "    Branched,",
            "    None,",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub enum DurableEventTarget {",
            "    Static(&'static [&'static str]),",
            "    Dynamic(&'static str),",
            "    DynamicMany(&'static [&'static str]),",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct DurableEffectDescriptor {",
            "    pub kind: DurableEffectKind,",
            "    pub target: Option<DurableEventTarget>,",
            "    pub rationale: Option<&'static str>,",
            "    pub branch_contract_json: Option<&'static str>,",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct ServiceOperationDescriptor {",
            "    pub id: ServiceOperationId,",
            "    pub http_method: &'static str,",
            "    pub http_path: &'static str,",
            "    pub grpc: Option<&'static str>,",
            "    pub mq: Option<&'static str>,",
            "    pub body_class: Option<&'static str>,",
            "    pub max_canonical_body_bytes: Option<usize>,",
            "    pub success_shape_kind: &'static str,",
            "    pub idempotency_mechanism: Option<&'static str>,",
            "    pub retry_safe: Option<bool>,",
            "    pub request_schema_ref: Option<&'static str>,",
            "    pub response_schema_ref: Option<&'static str>,",
            "    pub uncertain_outcome: Option<&'static str>,",
            "    pub durable_effect: Option<DurableEffectDescriptor>,",
            "}",
            "",
            "impl ServiceOperationId {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in rows:
        lines.append(f"        Self::{variant(row['operation_id'], ('ak.',))},")
    lines.extend(
        [
            "    ];",
            "",
        ]
    )
    for row in rows:
        lines.append(
            f"    pub const {associated_name(row['operation_id'], ('ak.',))}: &'static str = "
            f"{rust_string(row['operation_id'])};"
        )
    lines.extend(
        [
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['operation_id'], ('ak.',))} => "
            f"Self::{associated_name(row['operation_id'], ('ak.',))},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{associated_name(row['operation_id'], ('ak.',))} => "
            f"Some(Self::{variant(row['operation_id'], ('ak.',))}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "",
            "    /// Resolve the one registered operation selected by an HTTP request.",
            "    /// Query parameters are excluded by callers; each path-template",
            "    /// placeholder matches exactly one non-empty URL path segment.",
            "    pub fn from_http_request(method: &str, path: &str) -> Option<Self> {",
            "        let specificity = SERVICE_OPERATION_DESCRIPTORS",
            "            .iter()",
            "            .filter(|descriptor| {",
            "                descriptor.http_method == method",
            "                    && http_path_template_matches(descriptor.http_path, path)",
            "            })",
            "            .map(|descriptor| descriptor.http_path.bytes().filter(|byte| *byte == b'{').count())",
            "            .min()?;",
            "        let mut matches = SERVICE_OPERATION_DESCRIPTORS.iter().filter(|descriptor| {",
            "            descriptor.http_method == method",
            "                && http_path_template_matches(descriptor.http_path, path)",
            "                && descriptor.http_path.bytes().filter(|byte| *byte == b'{').count() == specificity",
            "        });",
            "        let selected = matches.next()?.id;",
            "        matches.next().is_none().then_some(selected)",
            "    }",
            "",
            "    /// Check whether this exact versioned operation belongs to an HTTP",
            "    /// method/path family selected by `Arkret-Operation`.",
            "    pub fn matches_http_request(self, method: &str, path: &str) -> bool {",
            "        let descriptor = self.descriptor();",
            "        descriptor.http_method == method",
            "            && http_path_template_matches(descriptor.http_path, path)",
            "    }",
            "",
            "    pub fn descriptor(self) -> &'static ServiceOperationDescriptor {",
            "        &SERVICE_OPERATION_DESCRIPTORS[self as usize]",
            "    }",
            "}",
            "",
            "impl std::fmt::Display for ServiceOperationId {",
            "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {",
            "        f.write_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl Serialize for ServiceOperationId {",
            "    fn serialize<S: serde::Serializer>(",
            "        &self,",
            "        serializer: S,",
            "    ) -> Result<S::Ok, S::Error> {",
            "        serializer.serialize_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl<'de> Deserialize<'de> for ServiceOperationId {",
            "    fn deserialize<D: serde::Deserializer<'de>>(",
            "        deserializer: D,",
            "    ) -> Result<Self, D::Error> {",
            "        let raw = String::deserialize(deserializer)?;",
            "        Self::from_wire(&raw).ok_or_else(|| {",
            '            serde::de::Error::custom(format!("unknown service operation id: {raw}"))',
            "        })",
            "    }",
            "}",
            "",
            "pub const SERVICE_OPERATION_DESCRIPTORS: &[ServiceOperationDescriptor] = &[",
        ]
    )
    for row in rows:
        method, path = row["http"].split(" ", 1)
        uncertain = row.get("uncertain_outcome")
        if isinstance(uncertain, (dict, list)):
            uncertain = json.dumps(
                uncertain, separators=(",", ":"), sort_keys=True
            )
        retry = row.get("retry_safe")
        retry_expr = (
            "None" if retry is None else f"Some({str(bool(retry)).lower()})"
        )
        durable = row.get("durable_effect")
        durable_lines: list[str]
        if durable is None:
            durable_lines = ["        durable_effect: None,"]
        else:
            kind = durable.get("kind")
            if kind == "event_log":
                if "event_kinds" in durable:
                    target = (
                        "Some(DurableEventTarget::Static("
                        f"{rust_slice(durable['event_kinds'])}))"
                    )
                elif isinstance(durable.get("event_kind_source"), str):
                    target = (
                        "Some(DurableEventTarget::Dynamic("
                        f"{rust_string(durable['event_kind_source'])}))"
                    )
                elif (
                    isinstance(durable.get("event_kind_sources"), list)
                    and durable["event_kind_sources"]
                    and all(
                        isinstance(source, str) and source
                        for source in durable["event_kind_sources"]
                    )
                ):
                    target = (
                        "Some(DurableEventTarget::DynamicMany("
                        f"{rust_slice(durable['event_kind_sources'])}))"
                    )
                else:
                    raise ValueError(
                        f"{row['operation_id']} event_log durable effect needs a target"
                    )
                durable_expr = (
                    "Some(DurableEffectDescriptor { "
                    "kind: DurableEffectKind::EventLog, "
                    f"target: {target}, rationale: None, branch_contract_json: None }})"
                )
            elif kind == "actor_private_event":
                event_kind = durable.get("event_kind")
                if not isinstance(event_kind, str):
                    raise ValueError(
                        f"{row['operation_id']} actor_private_event needs event_kind"
                    )
                durable_expr = (
                    "Some(DurableEffectDescriptor { "
                    "kind: DurableEffectKind::ActorPrivateEvent, "
                    "target: Some(DurableEventTarget::Static("
                    f"{rust_slice([event_kind])})), rationale: None, "
                    "branch_contract_json: None })"
                )
            elif kind == "none":
                rationale = durable.get("rationale")
                if not isinstance(rationale, str) or not rationale:
                    raise ValueError(
                        f"{row['operation_id']} none durable effect needs rationale"
                    )
                durable_expr = (
                    "Some(DurableEffectDescriptor { "
                    "kind: DurableEffectKind::None, target: None, "
                    f"rationale: Some({rust_string(rationale)}), "
                    "branch_contract_json: None })"
                )
            elif kind == "branched":
                discriminator = durable.get("discriminator")
                branches = durable.get("effect_branches")
                if not isinstance(discriminator, dict) or not isinstance(branches, list):
                    raise ValueError(
                        f"{row['operation_id']} branched durable effect needs discriminator and effect_branches"
                    )
                branch_contract = json.dumps(
                    {
                        "discriminator": discriminator,
                        "effect_branches": branches,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                )
                durable_expr = (
                    "Some(DurableEffectDescriptor { "
                    "kind: DurableEffectKind::Branched, target: None, rationale: None, "
                    f"branch_contract_json: Some({rust_string(branch_contract)}) }})"
                )
            else:
                raise ValueError(
                    f"{row['operation_id']} has unsupported durable effect kind {kind!r}"
                )
            durable_lines = [f"        durable_effect: {durable_expr},"]
        lines.extend(
            [
                "    ServiceOperationDescriptor {",
                f"        id: ServiceOperationId::{variant(row['operation_id'], ('ak.',))},",
                f"        http_method: {rust_string(method)},",
                f"        http_path: {rust_string(path)},",
                f"        grpc: {rust_option(row.get('grpc'))},",
                f"        mq: {rust_option(row.get('mq'))},",
                f"        body_class: {rust_option(row.get('body_class'))},",
                "        max_canonical_body_bytes: "
                f"{rust_usize_option(row.get('max_canonical_body_bytes'))},",
                f"        success_shape_kind: {rust_string(row['success_shape_kind'])},",
                f"        idempotency_mechanism: {rust_option(row.get('idempotency_mechanism'))},",
                f"        retry_safe: {retry_expr},",
                f"        request_schema_ref: {rust_option(row.get('request_schema_ref'))},",
                f"        response_schema_ref: {rust_option(row.get('response_schema_ref'))},",
                f"        uncertain_outcome: {rust_option(uncertain)},",
                *durable_lines,
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "fn http_path_template_matches(template: &str, path: &str) -> bool {",
            "    let mut template_segments = template.split('/');",
            "    let mut path_segments = path.split('/');",
            "    loop {",
            "        match (template_segments.next(), path_segments.next()) {",
            "            (None, None) => return true,",
            "            (Some(expected), Some(actual)) => {",
            "                let placeholder = expected.starts_with('{')",
            "                    && expected.ends_with('}')",
            "                    && expected.len() > 2;",
            "                if (placeholder && actual.is_empty())",
            "                    || (!placeholder && expected != actual)",
            "                {",
            "                    return false;",
            "                }",
            "            }",
            "            _ => return false,",
            "        }",
            "    }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_capability_discovery(artifacts: Path) -> str:
    relative = "registry/contract-registry.json"
    artifact, digest = load(artifacts / relative)
    bundles = sorted(
        artifact["operation_registry"]["operation_bundles"],
        key=lambda row: row["operation_bundle_id"],
    )
    features = sorted(
        artifact["feature_registry"]["features"], key=lambda row: row["feature_id"]
    )
    ensure_unique(bundles, "operation_bundle_id", ("ak.operation_bundle.",))
    ensure_unique(features, "feature_id", ("ak.feature.",))
    lines = header(
        [(relative, artifact, digest)],
        f"operation_bundles={len(bundles)} features={len(features)}",
    )
    lines.extend(
        [
            "use crate::{BindingKind, ServiceKind, ServiceOperationId};",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "pub struct OperationBindingPair {",
            "    pub operation_id: ServiceOperationId,",
            "    pub binding_kind: BindingKind,",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct OperationBundleDescriptor {",
            "    pub operation_bundle_id: &'static str,",
            "    pub service_kind: ServiceKind,",
            "    pub members: &'static [OperationBindingPair],",
            "}",
            "",
            "impl OperationBundleDescriptor {",
            "    pub fn contains(&self, operation_id: ServiceOperationId, binding_kind: BindingKind) -> bool {",
            "        self.members.iter().any(|pair| pair.operation_id == operation_id && pair.binding_kind == binding_kind)",
            "    }",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub enum FeatureStatus { Active, Experimental, TestOnly }",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct FeatureDescriptor {",
            "    pub feature_id: &'static str,",
            "    pub status: FeatureStatus,",
            "    pub defined_in: &'static str,",
            "    pub service_kinds: &'static [ServiceKind],",
            "    pub required_operation_pairs: &'static [OperationBindingPair],",
            "    pub required_profiles: &'static [&'static str],",
            "    pub required_limits: &'static [&'static str],",
            "    pub semantic_guarantees: &'static [&'static str],",
            "    pub conflicts: &'static [&'static str],",
            "}",
            "",
            "pub const OPERATION_BUNDLES: &[OperationBundleDescriptor] = &[",
        ]
    )
    binding_variants = {
        "http_json": "BindingKind::HttpJson",
        "tus": "BindingKind::Tus",
        "websocket": "BindingKind::Websocket",
    }
    for bundle in bundles:
        lines.extend(
            [
                "    OperationBundleDescriptor {",
                f"        operation_bundle_id: {rust_string(bundle['operation_bundle_id'])},",
                f"        service_kind: ServiceKind::{variant(bundle['service_kind'])},",
                "        members: &[",
            ]
        )
        for member in bundle["members"]:
            binding = binding_variants.get(member["binding_kind"])
            if binding is None:
                raise ValueError(
                    f"unsupported operation bundle binding kind: {member['binding_kind']}"
                )
            lines.extend(
                [
                    "            OperationBindingPair {",
                    "                operation_id: "
                    f"ServiceOperationId::{variant(member['operation_id'], ('ak.',))},",
                    f"                binding_kind: {binding},",
                    "            },",
                ]
            )
        lines.extend(["        ],", "    },"])
    lines.extend(
        [
            "];",
            "",
            "pub fn operation_bundle_descriptor(operation_bundle_id: &str) -> Option<&'static OperationBundleDescriptor> {",
            "    OPERATION_BUNDLES.binary_search_by_key(&operation_bundle_id, |row| row.operation_bundle_id)",
            "        .ok().map(|index| &OPERATION_BUNDLES[index])",
            "}",
            "",
            "pub fn operation_bundles_for_service_kind(service_kind: ServiceKind) -> impl Iterator<Item = &'static OperationBundleDescriptor> {",
            "    OPERATION_BUNDLES.iter().filter(move |bundle| bundle.service_kind == service_kind)",
            "}",
            "",
            "pub fn role_describe_bundle_descriptor(service_kind: ServiceKind) -> Option<&'static OperationBundleDescriptor> {",
            "    operation_bundles_for_service_kind(service_kind).find(|bundle| bundle.operation_bundle_id.ends_with(\".describe.v1\"))",
            "}",
            "",
            "pub fn operation_binding_is_registered(operation_id: ServiceOperationId, binding_kind: BindingKind) -> bool {",
            "    OPERATION_BUNDLES.iter().any(|bundle| bundle.contains(operation_id, binding_kind))",
            "}",
            "",
            "pub const FEATURES: &[FeatureDescriptor] = &[",
        ]
    )
    status_variants = {
        "active": "FeatureStatus::Active",
        "experimental": "FeatureStatus::Experimental",
        "test_only": "FeatureStatus::TestOnly",
    }
    for feature in features:
        status = status_variants.get(feature["status"])
        if status is None:
            raise ValueError(f"unsupported feature status: {feature['status']}")
        service_kinds = "&[" + ", ".join(
            f"ServiceKind::{variant(kind)}" for kind in feature["service_kinds"]
        ) + "]"
        lines.extend(
            [
                "    FeatureDescriptor {",
                f"        feature_id: {rust_string(feature['feature_id'])},",
                f"        status: {status},",
                f"        defined_in: {rust_string(feature['defined_in'])},",
                f"        service_kinds: {service_kinds},",
                "        required_operation_pairs: &[",
            ]
        )
        for pair in feature["required_operation_pairs"]:
            binding = binding_variants.get(pair["binding_kind"])
            if binding is None:
                raise ValueError(f"unsupported feature binding kind: {pair['binding_kind']}")
            lines.extend(
                [
                    "            OperationBindingPair {",
                    "                operation_id: "
                    f"ServiceOperationId::{variant(pair['operation_id'], ('ak.',))},",
                    f"                binding_kind: {binding},",
                    "            },",
                ]
            )
        lines.extend(
            [
                "        ],",
                f"        required_profiles: {rust_slice(feature['required_profiles'])},",
                f"        required_limits: {rust_slice(feature['required_limits'])},",
                f"        semantic_guarantees: {rust_slice(feature['semantic_guarantees'])},",
                f"        conflicts: {rust_slice(feature['conflicts'])},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "pub fn feature_descriptor(feature_id: &str) -> Option<&'static FeatureDescriptor> {",
            "    FEATURES.binary_search_by_key(&feature_id, |row| row.feature_id)",
            "        .ok().map(|index| &FEATURES[index])",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_error_codes(artifacts: Path) -> str:
    relative = "registry/error-code-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(artifact["codes"], key=lambda row: row["code"])
    ensure_unique(rows, "code")
    contexts = sorted(
        {
            context
            for row in rows
            for context in row.get("http_status_by_context", {})
        }
    )
    lines = header([(relative, artifact, digest)], f"error_codes={len(rows)}")
    lines.extend(
        [
            "use serde::{Deserialize, Serialize};",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]",
            '#[serde(rename_all = "snake_case")]',
            "pub enum ErrorStatusContext {",
        ]
    )
    for context in contexts:
        lines.append(f"    {variant(context)},")
    lines.extend(
        [
            "}",
            "",
            "impl ErrorStatusContext {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for context in contexts:
        lines.append(f"        Self::{variant(context)},")
    lines.extend(
        [
            "    ];",
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for context in contexts:
        lines.append(
            f"            Self::{variant(context)} => {rust_string(context)},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "}",
            "",
            "impl std::fmt::Display for ErrorStatusContext {",
            "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {",
            "        f.write_str(self.as_str())",
            "    }",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]",
            '#[serde(rename_all = "snake_case")]',
            "#[repr(usize)]",
            "pub enum ErrorCode {",
        ]
    )
    for row in rows:
        lines.append(f"    {variant(row['code'])},")
    lines.extend(
        [
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct ErrorCodeDescriptor {",
            "    pub code: ErrorCode,",
            "    pub type_uri: &'static str,",
            "    pub title: &'static str,",
            "    pub http_status: u16,",
            "    pub http_status_by_context: &'static [(ErrorStatusContext, u16)],",
            "    pub scope: &'static str,",
            "    pub applies_to: &'static [&'static str],",
            "    pub description: &'static str,",
            "}",
            "",
            "impl ErrorCode {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in rows:
        lines.append(f"        Self::{variant(row['code'])},")
    lines.extend(
        [
            "    ];",
            "",
        ]
    )
    for row in rows:
        lines.append(
            f"    pub const {row['code'].upper()}: &'static str = "
            f"{rust_string(row['code'])};"
        )
    lines.extend(
        [
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['code'])} => "
            f"{rust_string(row['code'])},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in rows:
        lines.append(
            f"            {rust_string(row['code'])} => "
            f"Some(Self::{variant(row['code'])}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "",
            "    pub fn descriptor(self) -> &'static ErrorCodeDescriptor {",
            "        &ERROR_CODE_DESCRIPTORS[self as usize]",
            "    }",
            "",
            "    pub fn http_status(self) -> u16 {",
            "        self.descriptor().http_status",
            "    }",
            "",
            "    pub fn type_uri(self) -> &'static str {",
            "        self.descriptor().type_uri",
            "    }",
            "",
            "    pub fn title(self) -> &'static str {",
            "        self.descriptor().title",
            "    }",
            "",
            "    pub fn http_status_in(self, context: ErrorStatusContext) -> u16 {",
            "        let descriptor = self.descriptor();",
            "        descriptor",
            "            .http_status_by_context",
            "            .iter()",
            "            .find(|(entry, _)| *entry == context)",
            "            .map_or(descriptor.http_status, |(_, status)| *status)",
            "    }",
            "}",
            "",
            "impl std::fmt::Display for ErrorCode {",
            "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {",
            "        f.write_str(self.as_str())",
            "    }",
            "}",
            "",
            "pub const ERROR_CODE_DESCRIPTORS: &[ErrorCodeDescriptor] = &[",
        ]
    )
    for row in rows:
        by_context = "&["
        by_context += ", ".join(
            f"(ErrorStatusContext::{variant(context)}, {int(status)})"
            for context, status in sorted(
                row.get("http_status_by_context", {}).items()
            )
        )
        by_context += "]"
        lines.extend(
            [
                "    ErrorCodeDescriptor {",
                f"        code: ErrorCode::{variant(row['code'])},",
                f"        type_uri: {rust_string(row['type_uri'])},",
                f"        title: {rust_string(row['title'])},",
                f"        http_status: {int(row['http_status'])},",
                f"        http_status_by_context: {by_context},",
                f"        scope: {rust_string(row['scope'])},",
                f"        applies_to: {rust_slice(row.get('applies_to'))},",
                f"        description: {rust_string(row['description'])},",
                "    },",
            ]
        )
    lines.append("];")
    return "\n".join(lines) + "\n"


def generate_reason_codes(artifacts: Path) -> str:
    relative = "registry/error-code-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(artifact["reason_codes"], key=lambda row: row["code"])
    ensure_unique(rows, "code")
    lines = header([(relative, artifact, digest)], f"reason_codes={len(rows)}")
    lines.extend(
        [
            "use serde::{Deserialize, Deserializer, Serialize, Serializer};",
            "",
            "#[derive(Clone, Debug, PartialEq, Eq, Hash)]",
            "pub enum ReasonCode {",
        ]
    )
    for row in rows:
        lines.append(f"    {variant(row['code'])},")
    lines.extend(
        [
            "    Unknown(String),",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct ReasonCodeDescriptor {",
            "    pub code: &'static str,",
            "    pub applies_to: &'static [&'static str],",
            "    pub description: &'static str,",
            "}",
            "",
            "impl ReasonCode {",
        ]
    )
    for row in rows:
        lines.append(
            f"    pub const {row['code'].upper()}: &'static str = "
            f"{rust_string(row['code'])};"
        )
    lines.extend(
        [
            "",
            "    pub fn as_str(&self) -> &str {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['code'])} => "
            f"Self::{row['code'].upper()},"
        )
    lines.extend(
        [
            "            Self::Unknown(value) => value,",
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Self {",
            "        match value {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{row['code'].upper()} => "
            f"Self::{variant(row['code'])},"
        )
    lines.extend(
        [
            "            _ => Self::Unknown(value.to_owned()),",
            "        }",
            "    }",
            "",
            "    pub fn is_valid_wire(value: &str) -> bool {",
            "        let mut characters = value.chars();",
            "        matches!(characters.next(), Some('a'..='z'))",
            "            && value.len() <= 64",
            "            && characters.all(|character| {",
            "                character.is_ascii_lowercase()",
            "                    || character.is_ascii_digit()",
            "                    || character == '_'",
            "            })",
            "    }",
            "",
            "    pub fn descriptor(&self) -> Option<&'static ReasonCodeDescriptor> {",
            "        REASON_CODE_DESCRIPTORS",
            "            .iter()",
            "            .find(|row| row.code == self.as_str())",
            "    }",
            "}",
            "",
            "impl Serialize for ReasonCode {",
            "    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {",
            "        if !Self::is_valid_wire(self.as_str()) {",
            "            return Err(serde::ser::Error::custom(\"invalid reason code\"));",
            "        }",
            "        serializer.serialize_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl<'de> Deserialize<'de> for ReasonCode {",
            "    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {",
            "        let value = String::deserialize(deserializer)?;",
            "        if !Self::is_valid_wire(&value) {",
            "            return Err(serde::de::Error::custom(\"invalid reason code\"));",
            "        }",
            "        Ok(Self::from_wire(&value))",
            "    }",
            "}",
            "",
            '#[cfg(feature = "openapi")]',
            "impl salvo_oapi::ToSchema for ReasonCode {",
            "    fn to_schema(",
            "        _components: &mut salvo_oapi::Components,",
            "    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {",
            "        salvo_oapi::schema::Object::new()",
            "            .schema_type(salvo_oapi::schema::BasicType::String)",
            '            .pattern("^[a-z][a-z0-9_]{0,63}$")',
            "            .max_length(64)",
            "            .into()",
            "    }",
            "}",
            "",
            '#[cfg(feature = "openapi")]',
            "impl salvo_oapi::ComposeSchema for ReasonCode {",
            "    fn compose(",
            "        components: &mut salvo_oapi::Components,",
            "        generics: Vec<salvo_oapi::RefOr<salvo_oapi::schema::Schema>>,",
            "    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {",
            "        let _ = generics;",
            "        <Self as salvo_oapi::ToSchema>::to_schema(components)",
            "    }",
            "}",
            "",
            "pub const REASON_CODE_DESCRIPTORS: &[ReasonCodeDescriptor] = &[",
        ]
    )
    for row in rows:
        lines.extend(
            [
                "    ReasonCodeDescriptor {",
                f"        code: ReasonCode::{row['code'].upper()},",
                f"        applies_to: {rust_slice(row.get('applies_to'))},",
                f"        description: {rust_string(row['description'])},",
                "    },",
            ]
        )
    lines.append("];")
    return "\n".join(lines) + "\n"


def generate_service_kinds(artifacts: Path) -> str:
    relative = "registry/service-kind-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(
        (
            row
            for row in artifact["service_kinds"]
            if row["status"] == "active"
        ),
        key=lambda row: row["canonical_id"],
    )
    ensure_unique(rows, "canonical_id")
    lines = header([(relative, artifact, digest)], f"active={len(rows)}")
    lines.extend(
        [
            "use serde::{Deserialize, Serialize};",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]",
            '#[serde(rename_all = "snake_case")]',
            "#[repr(usize)]",
            '#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]',
            "pub enum ServiceKind {",
        ]
    )
    for row in rows:
        lines.append(f"    {variant(row['canonical_id'])},")
    lines.extend(
        [
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct ServiceKindDescriptor {",
            "    pub service_kind: ServiceKind,",
            "    pub valid_in: &'static [&'static str],",
            "    pub description: &'static str,",
            "}",
            "",
            "impl ServiceKind {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in rows:
        lines.append(f"        Self::{variant(row['canonical_id'])},")
    lines.extend(
        [
            "    ];",
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['canonical_id'])} => "
            f"{rust_string(row['canonical_id'])},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn descriptor(self) -> &'static ServiceKindDescriptor {",
            "        &SERVICE_KIND_DESCRIPTORS[self as usize]",
            "    }",
            "",
            "    pub fn valid_in(self, context: &str) -> bool {",
            "        self.descriptor().valid_in.contains(&context)",
            "    }",
            "}",
            "",
            "pub const SERVICE_KIND_DESCRIPTORS: &[ServiceKindDescriptor] = &[",
        ]
    )
    for row in rows:
        lines.extend(
            [
                "    ServiceKindDescriptor {",
                f"        service_kind: ServiceKind::{variant(row['canonical_id'])},",
                f"        valid_in: {rust_slice(row['valid_in'])},",
                f"        description: {rust_string(row['description'])},",
                "    },",
            ]
        )
    lines.append("];")
    return "\n".join(lines) + "\n"


def generate_relation_kinds(artifacts: Path) -> str:
    relative = "registry/relation-kind-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(
        artifact["relation_kinds"], key=lambda row: row["canonical_id"]
    )
    ensure_unique(rows, "canonical_id")
    lines = header([(relative, artifact, digest)], f"standard={len(rows)}")
    lines.extend(
        [
            "use serde::{Deserialize, Deserializer, Serialize, Serializer};",
            "",
            "#[derive(Clone, Debug, PartialEq, Eq, Hash)]",
            "pub enum RelationKind {",
        ]
    )
    for row in rows:
        lines.append(f"    {variant(row['canonical_id'])},")
    lines.extend(
        [
            "    Custom(String),",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub enum RelationTruthSourceClass {",
            "    Canonical,",
            "    DerivedProjection,",
            "    ShapeDependent,",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct RelationKindDescriptor {",
            "    pub canonical_id: &'static str,",
            "    pub default_cardinality: &'static str,",
            "    pub truth_source_class: RelationTruthSourceClass,",
            "    pub weak_semantic: bool,",
            "}",
            "",
            "impl RelationKind {",
            "    pub const STANDARD: &'static [Self] = &[",
        ]
    )
    for row in rows:
        lines.append(f"        Self::{variant(row['canonical_id'])},")
    lines.extend(
        [
            "    ];",
            "",
            "    pub fn as_str(&self) -> &str {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['canonical_id'])} => "
            f"{rust_string(row['canonical_id'])},"
        )
    lines.extend(
        [
            "            Self::Custom(value) => value,",
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Self {",
            "        match value {",
        ]
    )
    for row in rows:
        lines.append(
            f"            {rust_string(row['canonical_id'])} => "
            f"Self::{variant(row['canonical_id'])},"
        )
    lines.extend(
        [
            "            _ => Self::Custom(value.to_owned()),",
            "        }",
            "    }",
            "",
            "    pub fn descriptor(&self) -> Option<&'static RelationKindDescriptor> {",
            "        RELATION_KIND_DESCRIPTORS",
            "            .iter()",
            "            .find(|row| row.canonical_id == self.as_str())",
            "    }",
            "",
            "    pub fn is_standard(&self) -> bool {",
            "        self.descriptor().is_some()",
            "    }",
            "",
            "    pub fn is_structural(&self) -> bool {",
            "        self.descriptor().is_some_and(|row| !row.weak_semantic)",
            "    }",
            "}",
            "",
            "impl Serialize for RelationKind {",
            "    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {",
            "        serializer.serialize_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl<'de> Deserialize<'de> for RelationKind {",
            "    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {",
            "        Ok(Self::from_wire(&String::deserialize(deserializer)?))",
            "    }",
            "}",
            "",
            "pub const RELATION_KIND_DESCRIPTORS: &[RelationKindDescriptor] = &[",
        ]
    )
    for row in rows:
        lines.extend(
            [
                "    RelationKindDescriptor {",
                f"        canonical_id: {rust_string(row['canonical_id'])},",
                f"        default_cardinality: {rust_string(row['default_cardinality'])},",
                "        truth_source_class: "
                f"RelationTruthSourceClass::{variant(row['truth_source_class'])},",
                f"        weak_semantic: {str(bool(row['weak_semantic'])).lower()},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_security_strings(artifacts: Path) -> str:
    names = [
        "proof-context-registry.json",
        "exporter-label-registry.json",
        "digest-suite-registry.json",
        "signature-alg-registry.json",
        "hpke-suite-registry.json",
        "mls-ciphersuite-registry.json",
        "mls-extension-registry.json",
        "aead-profile-registry.json",
    ]
    loaded = [
        (f"registry/{name}", *load(artifacts / "registry" / name))
        for name in names
    ]
    proof = loaded[0][1]["contexts"]
    labels = loaded[1][1]["labels"]
    proof = sorted(proof, key=lambda row: row["context"])
    labels = sorted(labels, key=lambda row: row["label"])
    ensure_unique(proof, "context", ("ak.",))
    ensure_unique(labels, "label", ("ak.", "arkret-"))
    digests = loaded[2][1]["suites"]
    signatures = loaded[3][1]["algorithms"]
    hpke = loaded[4][1]["suites"]
    mls = loaded[5][1]["ciphersuites"]
    mls_extensions = loaded[6][1]["extensions"]
    domains = sorted(loaded[0][1]["domain_separations"], key=lambda row: row["domain"])
    aead_profiles = sorted(loaded[7][1]["profiles"], key=lambda row: row["canonical_id"])
    ensure_unique(domains, "domain", ("ak.",))
    ensure_unique(aead_profiles, "canonical_id", ("ak.aead.",))
    lines = header(
        loaded,
        f"proof_contexts={len(proof)}, exporter_labels={len(labels)}, "
        f"digest_suites={len(digests)}, signature_algorithms={len(signatures)}, "
        f"hpke_suites={len(hpke)}, mls_ciphersuites={len(mls)}, "
        f"mls_extensions={len(mls_extensions)}, domain_separations={len(domains)}, "
        f"aead_profiles={len(aead_profiles)}",
    )
    lines.extend(
        [
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "#[repr(usize)]",
            "pub enum ProofContextId {",
        ]
    )
    for row in proof:
        lines.append(f"    {variant(row['context'], ('ak.',))},")
    lines.extend(
        [
            "}",
            "",
            "impl ProofContextId {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in proof:
        lines.append(f"        Self::{variant(row['context'], ('ak.',))},")
    lines.extend(["    ];", ""])
    for row in proof:
        lines.append(
            f"    pub const {associated_name(row['context'], ('ak.',))}: &'static str = "
            f"{rust_string(row['context'])};"
        )
    lines.extend(
        [
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in proof:
        lines.append(
            f"            Self::{variant(row['context'], ('ak.',))} => "
            f"Self::{associated_name(row['context'], ('ak.',))},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in proof:
        lines.append(
            f"            Self::{associated_name(row['context'], ('ak.',))} => "
            f"Some(Self::{variant(row['context'], ('ak.',))}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "#[repr(usize)]",
            "pub enum DomainSeparationId {",
        ]
    )
    for row in domains:
        lines.append(f"    {variant(row['domain'], ('ak.',))},")
    lines.extend(
        [
            "}",
            "",
            "impl DomainSeparationId {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in domains:
        lines.append(f"        Self::{variant(row['domain'], ('ak.',))},")
    lines.extend(["    ];", ""])
    for row in domains:
        lines.append(
            f"    pub const {associated_name(row['domain'], ('ak.',))}: &'static str = "
            f"{rust_string(row['domain'])};"
        )
    lines.extend(
        [
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in domains:
        lines.append(
            f"            Self::{variant(row['domain'], ('ak.',))} => "
            f"Self::{associated_name(row['domain'], ('ak.',))},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in domains:
        lines.append(
            f"            Self::{associated_name(row['domain'], ('ak.',))} => "
            f"Some(Self::{variant(row['domain'], ('ak.',))}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "#[repr(usize)]",
            "pub enum AeadProfileId {",
        ]
    )
    for row in aead_profiles:
        lines.append(f"    {variant(row['canonical_id'], ('ak.aead.',))},")
    lines.extend(
        [
            "}",
            "",
            "impl AeadProfileId {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in aead_profiles:
        lines.append(f"        Self::{variant(row['canonical_id'], ('ak.aead.',))},")
    lines.extend(["    ];", ""])
    for row in aead_profiles:
        lines.append(
            f"    pub const {associated_name(row['canonical_id'], ('ak.aead.',))}: &'static str = "
            f"{rust_string(row['canonical_id'])};"
        )
    lines.extend(
        [
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in aead_profiles:
        lines.append(
            f"            Self::{variant(row['canonical_id'], ('ak.aead.',))} => "
            f"Self::{associated_name(row['canonical_id'], ('ak.aead.',))},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in aead_profiles:
        lines.append(
            f"            Self::{associated_name(row['canonical_id'], ('ak.aead.',))} => "
            f"Some(Self::{variant(row['canonical_id'], ('ak.aead.',))}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "#[repr(usize)]",
            "pub enum HpkeSuiteId {",
        ]
    )
    for row in sorted(hpke, key=lambda row: row["canonical_id"]):
        lines.append(f"    {variant(row['canonical_id'], ('ak.hpke_',))},")
    lines.extend(
        [
            "}",
            "",
            "impl HpkeSuiteId {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in sorted(hpke, key=lambda row: row["canonical_id"]):
        lines.append(f"        Self::{variant(row['canonical_id'], ('ak.hpke_',))},")
    lines.extend(["    ];", ""])
    for row in sorted(hpke, key=lambda row: row["canonical_id"]):
        lines.append(
            f"    pub const {associated_name(row['canonical_id'], ('ak.hpke_',))}: &'static str = "
            f"{rust_string(row['canonical_id'])};"
        )
    lines.extend(
        [
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in sorted(hpke, key=lambda row: row["canonical_id"]):
        lines.append(
            f"            Self::{variant(row['canonical_id'], ('ak.hpke_',))} => "
            f"Self::{associated_name(row['canonical_id'], ('ak.hpke_',))},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in sorted(hpke, key=lambda row: row["canonical_id"]):
        lines.append(
            f"            Self::{associated_name(row['canonical_id'], ('ak.hpke_',))} => "
            f"Some(Self::{variant(row['canonical_id'], ('ak.hpke_',))}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "#[repr(usize)]",
            "pub enum ExporterLabelId {",
        ]
    )
    for row in labels:
        lines.append(f"    {variant(row['label'], ('ak.', 'arkret-'))},")
    lines.extend(
        [
            "}",
            "",
            "impl ExporterLabelId {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in labels:
        lines.append(f"        Self::{variant(row['label'], ('ak.', 'arkret-'))},")
    lines.extend(["    ];", ""])
    for row in labels:
        lines.append(
            f"    pub const {associated_name(row['label'], ('ak.', 'arkret-'))}: &'static str = "
            f"{rust_string(row['label'])};"
        )
    lines.extend(
        [
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in labels:
        lines.append(
            f"            Self::{variant(row['label'], ('ak.', 'arkret-'))} => "
            f"Self::{associated_name(row['label'], ('ak.', 'arkret-'))},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in labels:
        lines.append(
            f"            Self::{associated_name(row['label'], ('ak.', 'arkret-'))} => "
            f"Some(Self::{variant(row['label'], ('ak.', 'arkret-'))}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct ProofContextDescriptor {",
            "    pub id: ProofContextId,",
            "    pub context: &'static str,",
            "    pub object_family: &'static str,",
            "    pub consumer_operation: Option<&'static str>,",
            "    pub binding_fields: &'static [&'static str],",
            "    pub schema_ref: &'static str,",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct ExporterLabelDescriptor {",
            "    pub id: ExporterLabelId,",
            "    pub label: &'static str,",
            "    pub primitive: Option<&'static str>,",
            "    pub context_fields: &'static [&'static str],",
            "    pub output_bytes: &'static str,",
            "    pub empty_context_forbidden: bool,",
            "    pub forbid_reuse_with: &'static [&'static str],",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct AlgorithmSuiteDescriptor {",
            "    pub canonical_id: &'static str,",
            "    pub status: &'static str,",
            "    pub role: &'static str,",
            "    pub profile_gate: Option<&'static str>,",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct MlsExtensionDescriptor {",
            "    pub name: &'static str,",
            "    pub codepoint: &'static str,",
            "    pub status: &'static str,",
            "    pub profile_id: &'static str,",
            "}",
            "",
            "pub const PROOF_CONTEXTS: &[ProofContextDescriptor] = &[",
        ]
    )
    for row in proof:
        lines.extend(
            [
                "    ProofContextDescriptor {",
                f"        id: ProofContextId::{variant(row['context'], ('ak.',))},",
                f"        context: {rust_string(row['context'])},",
                f"        object_family: {rust_string(row['object_family'])},",
                f"        consumer_operation: {rust_option(row.get('consumer_operation'))},",
                f"        binding_fields: {rust_slice(row['binding_fields'])},",
                f"        schema_ref: {rust_string(row['schema_ref'])},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "pub const EXPORTER_LABELS: &[ExporterLabelDescriptor] = &[",
        ]
    )
    for row in labels:
        lines.extend(
            [
                "    ExporterLabelDescriptor {",
                "        id: ExporterLabelId::"
                f"{variant(row['label'], ('ak.', 'arkret-'))},",
                f"        label: {rust_string(row['label'])},",
                f"        primitive: {rust_option(row.get('primitive'))},",
                f"        context_fields: {rust_slice(row['context_fields'])},",
                f"        output_bytes: {rust_string(str(row['output_bytes']))},",
                "        empty_context_forbidden: "
                f"{str(bool(row['empty_context_forbidden'])).lower()},",
                f"        forbid_reuse_with: {rust_slice(row['forbid_reuse_with'])},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "pub const DIGEST_SUITES: &[AlgorithmSuiteDescriptor] = &[",
        ]
    )
    for row in sorted(digests, key=lambda row: row["canonical_id"]):
        lines.extend(
            [
                "    AlgorithmSuiteDescriptor {",
                f"        canonical_id: {rust_string(row['canonical_id'])},",
                f"        status: {rust_string(row['status'])},",
                f"        role: {rust_string(row['role'])},",
                f"        profile_gate: {rust_option(row.get('profile_gate'))},",
                "    },",
            ]
        )
    lines.extend(["];", "", "pub const SIGNATURE_ALGORITHMS: &[AlgorithmSuiteDescriptor] = &["])
    for row in sorted(signatures, key=lambda row: row["canonical_id"]):
        lines.extend(
            [
                "    AlgorithmSuiteDescriptor {",
                f"        canonical_id: {rust_string(row['canonical_id'])},",
                f"        status: {rust_string(row['status'])},",
                f"        role: {rust_string(row['role'])},",
                f"        profile_gate: {rust_option(row.get('profile_gate'))},",
                "    },",
            ]
        )
    lines.extend(["];", "", "pub const HPKE_SUITES: &[AlgorithmSuiteDescriptor] = &["])
    for row in sorted(hpke, key=lambda row: row["canonical_id"]):
        lines.extend(
            [
                "    AlgorithmSuiteDescriptor {",
                f"        canonical_id: {rust_string(row['canonical_id'])},",
                f"        status: {rust_string(row['status'])},",
                f"        role: {rust_string(row['role'])},",
                f"        profile_gate: {rust_option(row.get('profile_gate'))},",
                "    },",
            ]
        )
    lines.extend(["];", "", "pub const MLS_CIPHERSUITES: &[AlgorithmSuiteDescriptor] = &["])
    for row in sorted(mls, key=lambda row: row["canonical_id"]):
        lines.extend(
            [
                "    AlgorithmSuiteDescriptor {",
                f"        canonical_id: {rust_string(row['canonical_id'])},",
                f"        status: {rust_string(row['status'])},",
                f"        role: {rust_string(row['role'])},",
                f"        profile_gate: {rust_option(row.get('profile_gate'))},",
                "    },",
            ]
        )
    lines.extend(["];", "", "pub const MLS_EXTENSIONS: &[MlsExtensionDescriptor] = &["])
    for row in sorted(mls_extensions, key=lambda row: row["name"]):
        lines.extend(
            [
                "    MlsExtensionDescriptor {",
                f"        name: {rust_string(row['name'])},",
                f"        codepoint: {rust_string(row['codepoint'])},",
                f"        status: {rust_string(row['status'])},",
                f"        profile_id: {rust_string(row['profile_id'])},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "pub fn proof_context(value: &str) -> Option<&'static ProofContextDescriptor> {",
            "    ProofContextId::from_wire(value).map(proof_context_descriptor)",
            "}",
            "",
            "pub const fn proof_context_descriptor(",
            "    id: ProofContextId,",
            ") -> &'static ProofContextDescriptor {",
            "    &PROOF_CONTEXTS[id as usize]",
            "}",
            "",
            "pub fn exporter_label(value: &str) -> Option<&'static ExporterLabelDescriptor> {",
            "    ExporterLabelId::from_wire(value).map(exporter_label_descriptor)",
            "}",
            "",
            "pub const fn exporter_label_descriptor(",
            "    id: ExporterLabelId,",
            ") -> &'static ExporterLabelDescriptor {",
            "    &EXPORTER_LABELS[id as usize]",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_capability_actions(artifacts: Path) -> str:
    relative = "registry/capability-action-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(artifact["actions"], key=lambda row: row["action"])
    ensure_unique(rows, "action", ("ak.",))
    lines = header([(relative, artifact, digest)], f"registered={len(rows)}")
    lines.extend(
        [
            "use serde::{Deserialize, Serialize};",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "#[repr(usize)]",
            "pub enum CapabilityActionId {",
        ]
    )
    for row in rows:
        lines.append(f"    {variant(row['action'], ('ak.',))},")
    lines.extend(
        [
            "}",
            "",
            "impl CapabilityActionId {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in rows:
        lines.append(f"        Self::{variant(row['action'], ('ak.',))},")
    lines.extend(["    ];", ""])
    for row in rows:
        lines.append(
            f"    pub const {associated_name(row['action'], ('ak.',))}: &'static str = "
            f"{rust_string(row['action'])};"
        )
    lines.extend(
        [
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['action'], ('ak.',))} => "
            f"Self::{associated_name(row['action'], ('ak.',))},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{associated_name(row['action'], ('ak.',))} => "
            f"Some(Self::{variant(row['action'], ('ak.',))}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "}",
            "",
            "impl std::fmt::Display for CapabilityActionId {",
            "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {",
            "        f.write_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl Serialize for CapabilityActionId {",
            "    fn serialize<S: serde::Serializer>(",
            "        &self,",
            "        serializer: S,",
            "    ) -> Result<S::Ok, S::Error> {",
            "        serializer.serialize_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl<'de> Deserialize<'de> for CapabilityActionId {",
            "    fn deserialize<D: serde::Deserializer<'de>>(",
            "        deserializer: D,",
            "    ) -> Result<Self, D::Error> {",
            "        let raw = String::deserialize(deserializer)?;",
            "        Self::from_wire(&raw).ok_or_else(|| {",
            '            serde::de::Error::custom(format!("unknown capability action id: {raw}"))',
            "        })",
            "    }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_schema_ids(artifacts: Path) -> str:
    relative = "registry/schema-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(artifact["schemas"], key=lambda row: row["schema_id"])
    ensure_unique(rows, "schema_id", SCHEMA_ID_PREFIXES)
    active = [row for row in rows if row.get("status", "active") == "active"]
    lines = header(
        [(relative, artifact, digest)],
        f"schema_ids={len(rows)}, active={len(active)}",
    )
    lines.extend(
        [
            "use serde::{Deserialize, Serialize};",
            "",
            "/// Registered `ak.schema.*` identifiers. Every schema-id literal the",
            "/// SDK ships is spelled exactly once, here; owning wire types alias the",
            "/// associated const as `Type::SCHEMA`.",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "#[repr(usize)]",
            "pub enum SchemaId {",
        ]
    )
    for row in rows:
        lines.append(f"    {variant(row['schema_id'], SCHEMA_ID_PREFIXES)},")
    lines.extend(
        [
            "}",
            "",
            "impl SchemaId {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in rows:
        lines.append(f"        Self::{variant(row['schema_id'], SCHEMA_ID_PREFIXES)},")
    lines.extend(
        [
            "    ];",
            "",
            "    /// Rows the registry declares `active`; excludes `candidate` rows.",
            "    pub const ACTIVE: &'static [Self] = &[",
        ]
    )
    for row in active:
        lines.append(f"        Self::{variant(row['schema_id'], SCHEMA_ID_PREFIXES)},")
    lines.extend(["    ];", ""])
    for row in rows:
        name = associated_name(row["schema_id"], SCHEMA_ID_PREFIXES)
        description = row.get("description")
        if description:
            lines.append(f"    /// {rustdoc_text(description)}")
        lines.append(
            f"    pub const {name}: &'static str = {rust_string(row['schema_id'])};"
        )
    lines.extend(
        [
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['schema_id'], SCHEMA_ID_PREFIXES)} => "
            f"Self::{associated_name(row['schema_id'], SCHEMA_ID_PREFIXES)},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    /// Path of the JSON Schema document backing this id, relative to",
            "    /// `spec/v1/artifacts/`.",
            "    pub const fn file(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['schema_id'], SCHEMA_ID_PREFIXES)} => "
            f"{rust_string(row['file'])},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{associated_name(row['schema_id'], SCHEMA_ID_PREFIXES)} => "
            f"Some(Self::{variant(row['schema_id'], SCHEMA_ID_PREFIXES)}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "}",
            "",
            "impl std::fmt::Display for SchemaId {",
            "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {",
            "        f.write_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl Serialize for SchemaId {",
            "    fn serialize<S: serde::Serializer>(",
            "        &self,",
            "        serializer: S,",
            "    ) -> Result<S::Ok, S::Error> {",
            "        serializer.serialize_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl<'de> Deserialize<'de> for SchemaId {",
            "    fn deserialize<D: serde::Deserializer<'de>>(",
            "        deserializer: D,",
            "    ) -> Result<Self, D::Error> {",
            "        let raw = String::deserialize(deserializer)?;",
            "        Self::from_wire(&raw)",
            '            .ok_or_else(|| serde::de::Error::custom(format!("unknown schema id: {raw}")))',
            "    }",
            "}",
            "",
            '#[cfg(feature = "openapi")]',
            "impl salvo_oapi::ToSchema for SchemaId {",
            "    fn to_schema(",
            "        _components: &mut salvo_oapi::Components,",
            "    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {",
            "        salvo_oapi::schema::Object::new()",
            "            .schema_type(salvo_oapi::schema::BasicType::String)",
            "            .enum_values(Self::ALL.iter().map(|value| value.as_str()))",
            "            .into()",
            "    }",
            "}",
            "",
            '#[cfg(feature = "openapi")]',
            "impl salvo_oapi::ComposeSchema for SchemaId {",
            "    fn compose(",
            "        components: &mut salvo_oapi::Components,",
            "        generics: Vec<salvo_oapi::RefOr<salvo_oapi::schema::Schema>>,",
            "    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {",
            "        let _ = generics;",
            "        <Self as salvo_oapi::ToSchema>::to_schema(components)",
            "    }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_closed_registry_types(artifacts: Path) -> str:
    files = [
        "track-name-registry.json",
        "binding-kind-registry.json",
        "authority-set-policy-registry.json",
    ]
    loaded = [
        (f"registry/{name}", *load(artifacts / "registry" / name))
        for name in files
    ]
    track_artifact, binding_artifact, authority_artifact = [
        item[1] for item in loaded
    ]
    tracks = sorted(
        (
            row
            for row in track_artifact["track_names"]
            if row.get("status", "active") == "active"
        ),
        key=lambda row: row["track_name"],
    )
    bindings = sorted(
        (
            row
            for row in binding_artifact["entries"]
            if row.get("status") in {"active", "candidate"}
        ),
        key=lambda row: row["kind"],
    )
    policies = authority_artifact["policies"]
    policy_kinds = sorted({row["policy_kind"] for row in policies})
    source_kinds = sorted({row["source_kind"] for row in policies})
    ensure_unique(tracks, "track_name")
    ensure_unique(bindings, "kind")
    lines = header(
        loaded,
        (
            f"track_names={len(tracks)}, binding_kinds={len(bindings)}, "
            f"authority_policy_kinds={len(policy_kinds)}, "
            f"authority_source_kinds={len(source_kinds)}"
        ),
    )

    def emit_string_enum(
        type_name: str, values: list[str], *, copy: bool = True
    ) -> list[str]:
        derives = "Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash"
        if copy:
            derives = "Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash"
        emitted = [
            "#[cfg_attr(feature = \"openapi\", derive(salvo_oapi::ToSchema))]",
            f"#[derive({derives}, Serialize, Deserialize)]",
            "#[serde(rename_all = \"snake_case\")]",
            f"pub enum {type_name} {{",
        ]
        emitted.extend(f"    {variant(value)}," for value in values)
        emitted.extend(
            [
                "}",
                "",
                f"impl {type_name} {{",
                "    pub const ALL: &'static [Self] = &[",
            ]
        )
        emitted.extend(f"        Self::{variant(value)}," for value in values)
        emitted.extend(
            [
                "    ];",
                "",
                "    pub const fn as_str(self) -> &'static str {",
                "        match self {",
            ]
        )
        emitted.extend(
            f"            Self::{variant(value)} => {rust_string(value)},"
            for value in values
        )
        emitted.extend(
            [
                "        }",
                "    }",
                "",
                "    pub fn from_wire(value: &str) -> Option<Self> {",
                "        match value {",
            ]
        )
        emitted.extend(
            f"            {rust_string(value)} => Some(Self::{variant(value)}),"
            for value in values
        )
        emitted.extend(
            [
                "            _ => None,",
                "        }",
                "    }",
                "}",
                "",
                f"impl std::fmt::Display for {type_name} {{",
                "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {",
                "        f.write_str((*self).as_str())",
                "    }",
                "}",
            ]
        )
        return emitted

    lines.extend(["use serde::{Deserialize, Serialize};", ""])
    lines.extend(emit_string_enum("TrackName", [row["track_name"] for row in tracks]))
    lines.append("")
    lines.extend(emit_string_enum("BindingKind", [row["kind"] for row in bindings]))
    lines.append("")
    lines.extend(emit_string_enum("AuthoritySetPolicyKind", policy_kinds))
    lines.append("")
    lines.extend(emit_string_enum("AuthoritySetSourceKind", source_kinds))
    return "\n".join(lines) + "\n"




def account_data_key_namespace(pattern: str) -> str:
    """Literal head of an Account Data key pattern, stripped of separators."""
    head = pattern.split("<", 1)[0]
    return head.rstrip(".:")


def generate_account_data_keys(artifacts: Path) -> str:
    relative = "registry/account-data-key-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(
        (
            row
            for row in artifact["account_data_key_patterns"]
            if row["status"] == "active"
        ),
        key=lambda row: row["key_pattern"],
    )
    namespaces = [
        {"key_pattern": row["key_pattern"], "namespace": account_data_key_namespace(row["key_pattern"])}
        for row in rows
    ]
    ensure_unique(namespaces, "namespace", ("ak.",))
    lines = header([(relative, artifact, digest)], f"account_data_keys={len(rows)}")
    lines.extend(
        [
            "use serde::{Deserialize, Serialize};",
            "",
            "/// Registered Account Data key namespaces. The registry rows are key",
            "/// *patterns*; this type carries the literal head of each pattern, which is",
            "/// the value clients and servers compare against and the only place the",
            "/// namespace literal is spelled.",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "#[repr(usize)]",
            "pub enum AccountDataKey {",
        ]
    )
    for row in namespaces:
        lines.append(f"    {variant(row['namespace'], ('ak.',))},")
    lines.extend(
        [
            "}",
            "",
            "impl AccountDataKey {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in namespaces:
        lines.append(f"        Self::{variant(row['namespace'], ('ak.',))},")
    lines.extend(["    ];", ""])
    for row, source in zip(namespaces, rows):
        description = source.get("description")
        if description:
            lines.append(f"    /// {rustdoc_text(description)}")
        lines.append(f"    /// Key pattern: `{source['key_pattern']}`.")
        lines.append(
            f"    pub const {associated_name(row['namespace'], ('ak.',))}: &'static str = "
            f"{rust_string(row['namespace'])};"
        )
    lines.extend(
        [
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in namespaces:
        lines.append(
            f"            Self::{variant(row['namespace'], ('ak.',))} => "
            f"Self::{associated_name(row['namespace'], ('ak.',))},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    /// Whether `value` is this key exactly, or a parameterized key inside",
            "    /// this namespace (`<namespace>:<...>` or `<namespace>.<...>`).",
            "    pub fn matches(self, value: &str) -> bool {",
            "        let namespace = self.as_str();",
            "        let Some(rest) = value.strip_prefix(namespace) else {",
            "            return false;",
            "        };",
            "        rest.is_empty()",
            "            || (matches!(rest.as_bytes().first(), Some(b':' | b'.')) && rest.len() > 1)",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in namespaces:
        lines.append(
            f"            Self::{associated_name(row['namespace'], ('ak.',))} => "
            f"Some(Self::{variant(row['namespace'], ('ak.',))}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "",
            "    /// Resolve a concrete Account Data key to its registered namespace.",
            "    pub fn for_key(value: &str) -> Option<Self> {",
            "        Self::ALL.iter().copied().find(|key| key.matches(value))",
            "    }",
            "}",
            "",
            "impl std::fmt::Display for AccountDataKey {",
            "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {",
            "        f.write_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl Serialize for AccountDataKey {",
            "    fn serialize<S: serde::Serializer>(",
            "        &self,",
            "        serializer: S,",
            "    ) -> Result<S::Ok, S::Error> {",
            "        serializer.serialize_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl<'de> Deserialize<'de> for AccountDataKey {",
            "    fn deserialize<D: serde::Deserializer<'de>>(",
            "        deserializer: D,",
            "    ) -> Result<Self, D::Error> {",
            "        let raw = String::deserialize(deserializer)?;",
            "        Self::from_wire(&raw).ok_or_else(|| {",
            '            serde::de::Error::custom(format!("unknown account data key: {raw}"))',
            "        })",
            "    }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_profile_ids(artifacts: Path) -> str:
    relative = "profiles/conformance-profiles.json"
    artifact, digest = load(artifacts / relative)
    declared_roles = artifact["profile_roles"]
    ids = sorted(declared_roles)
    rows = [{"profile_id": value, "role": declared_roles[value]} for value in ids]
    ensure_unique(rows, "profile_id", PROFILE_ID_PREFIXES)
    roles = {
        "client": "Client",
        "server": "Server",
        "gateway": "Gateway",
        "directory": "Directory",
        "admin": "Admin",
        "interop": "Interop",
    }
    for row in rows:
        if row["role"] not in roles:
            raise ValueError(
                f"profile {row['profile_id']} has unsupported role {row['role']!r}; "
                f"allowed: {', '.join(sorted(roles))}"
            )
    # `profile_roles` is the only view this generator reads, so an id that the
    # artifact body declares without a role entry would silently be missing
    # from the enum. Compare against a regex pass over the raw artifact.
    body_ids = set(
        re.findall(
            r"ak\.profile\.[A-Za-z0-9_.-]+\.v[0-9]+",
            (artifacts / relative).read_text(encoding="utf-8"),
        )
    )
    unroled = sorted(body_ids - set(ids))
    if unroled:
        raise ValueError(
            "profile ids present in the artifact body without a profile_roles "
            f"entry: {', '.join(unroled)}"
        )
    lines = header([(relative, artifact, digest)], f"profile_ids={len(rows)}")
    lines.extend(
        [
            "use serde::{Deserialize, Serialize};",
            "",
            "/// Declared conformance profile identifiers. Every `ak.profile.*` literal",
            "/// the SDK ships is spelled exactly once, here.",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "#[repr(usize)]",
            "pub enum ProfileId {",
        ]
    )
    for row in rows:
        lines.append(f"    {variant(row['profile_id'], PROFILE_ID_PREFIXES)},")
    lines.extend(
        [
            "}",
            "",
            "/// Spec-layer `profile_roles` partition: every declared profile id",
            "/// belongs to exactly one of these roles. SDK manifests, client-side",
            "/// feature negotiation, and conformance loaders MUST consult",
            "/// [`ProfileId::role`] before claiming a profile as locally implemented.",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "pub enum ProfileRole {",
        ]
    )
    for name in roles.values():
        lines.append(f"    {name},")
    lines.extend(
        [
            "}",
            "",
            "impl ProfileRole {",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for wire_value, name in roles.items():
        lines.append(f"            Self::{name} => {rust_string(wire_value)},")
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for wire_value, name in roles.items():
        lines.append(f"            {rust_string(wire_value)} => Some(Self::{name}),")
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "}",
            "",
            "impl ProfileId {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in rows:
        lines.append(f"        Self::{variant(row['profile_id'], PROFILE_ID_PREFIXES)},")
    lines.extend(["    ];", ""])
    for row in rows:
        lines.append(
            f"    pub const {associated_name(row['profile_id'], PROFILE_ID_PREFIXES)}: "
            f"&'static str = {rust_string(row['profile_id'])};"
        )
    lines.extend(
        [
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['profile_id'], PROFILE_ID_PREFIXES)} => "
            f"Self::{associated_name(row['profile_id'], PROFILE_ID_PREFIXES)},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    /// Spec-declared role of this profile, mirroring",
            "    /// `conformance-profiles.json#/profile_roles`.",
            "    pub const fn role(self) -> ProfileRole {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['profile_id'], PROFILE_ID_PREFIXES)} => "
            f"ProfileRole::{roles[row['role']]},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    /// Every profile whose spec role is `role`, in declaration order.",
            "    pub fn with_role(role: ProfileRole) -> impl Iterator<Item = Self> {",
            "        Self::ALL.iter().copied().filter(move |id| id.role() == role)",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{associated_name(row['profile_id'], PROFILE_ID_PREFIXES)} => "
            f"Some(Self::{variant(row['profile_id'], PROFILE_ID_PREFIXES)}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "}",
            "",
            "impl std::fmt::Display for ProfileId {",
            "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {",
            "        f.write_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl Serialize for ProfileId {",
            "    fn serialize<S: serde::Serializer>(",
            "        &self,",
            "        serializer: S,",
            "    ) -> Result<S::Ok, S::Error> {",
            "        serializer.serialize_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl<'de> Deserialize<'de> for ProfileId {",
            "    fn deserialize<D: serde::Deserializer<'de>>(",
            "        deserializer: D,",
            "    ) -> Result<Self, D::Error> {",
            "        let raw = String::deserialize(deserializer)?;",
            "        Self::from_wire(&raw)",
            '            .ok_or_else(|| serde::de::Error::custom(format!("unknown profile id: {raw}")))',
            "    }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_reducer_profiles(artifacts: Path) -> str:
    relative = "registry/reducer-profile-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(
        (row for row in artifact["profiles"] if row["status"] == "active"),
        key=lambda row: row["profile_id"],
    )
    ensure_unique(rows, "profile_id", REDUCER_PROFILE_PREFIXES)
    active = {row["profile_id"] for row in rows}
    if len(active) != len(rows):
        raise ValueError("duplicate active reducer profile id")
    for row in rows:
        if not re.fullmatch(
            r"ak\.reducer(?:\.[a-z0-9][a-z0-9_.-]*)?\.v[0-9]+", row["profile_id"]
        ):
            raise ValueError(f"invalid reducer profile id: {row['profile_id']}")
    edges = sorted(
        (row["profile_id"], target)
        for row in rows
        for target in row.get("upgrade_edges") or []
    )
    for source, target in edges:
        if target not in active:
            raise ValueError(
                f"reducer profile {source} has an upgrade edge to unknown or "
                f"inactive profile {target}"
            )
    lines = header(
        [(relative, artifact, digest)],
        f"reducer_profiles={len(rows)}, upgrade_edges={len(edges)}",
    )
    lines.extend(
        [
            "/// Active Realm reducer profiles. A Realm selects exactly one through",
            "/// its reducer-profile singleton control cell; ordinary Events and",
            "/// federation service bindings do not declare one.",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "pub enum ReducerProfileId {",
        ]
    )
    for row in rows:
        lines.append(f"    {variant(row['profile_id'], REDUCER_PROFILE_PREFIXES)},")
    lines.extend(
        [
            "}",
            "",
            "impl ReducerProfileId {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in rows:
        lines.append(f"        Self::{variant(row['profile_id'], REDUCER_PROFILE_PREFIXES)},")
    lines.extend(["    ];", ""])
    for row in rows:
        lines.append(
            f"    pub const {associated_name(row['profile_id'], REDUCER_PROFILE_PREFIXES)}: "
            f"&'static str = {rust_string(row['profile_id'])};"
        )
    lines.extend(
        [
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['profile_id'], REDUCER_PROFILE_PREFIXES)} => "
            f"Self::{associated_name(row['profile_id'], REDUCER_PROFILE_PREFIXES)},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{associated_name(row['profile_id'], REDUCER_PROFILE_PREFIXES)} => "
            f"Some(Self::{variant(row['profile_id'], REDUCER_PROFILE_PREFIXES)}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "",
            "    /// Whether this profile registers a direct upgrade to `target`.",
            "    /// An upgrade the source does not declare is never valid.",
            "    pub fn can_upgrade_to(self, target: Self) -> bool {",
            "        REDUCER_PROFILE_UPGRADE_EDGES.contains(&(self, target))",
            "    }",
            "}",
            "",
            "/// Directed reducer-profile upgrades registered by the source profile.",
            "pub const REDUCER_PROFILE_UPGRADE_EDGES: "
            "&[(ReducerProfileId, ReducerProfileId)] = &[",
        ]
    )
    for source, target in edges:
        lines.append(
            f"    (ReducerProfileId::{variant(source, REDUCER_PROFILE_PREFIXES)}, "
            f"ReducerProfileId::{variant(target, REDUCER_PROFILE_PREFIXES)}),"
        )
    lines.extend(
        [
            "];",
            "",
            "/// Whether `value` names an active Realm reducer profile.",
            "pub fn is_reducer_profile_id(value: &str) -> bool {",
            "    ReducerProfileId::from_wire(value).is_some()",
            "}",
            "",
            "/// Whether `source` registers a direct upgrade to `target`. Ids that are",
            "/// unknown or no longer active never upgrade.",
            "pub fn can_upgrade_reducer_profile(source: &str, target: &str) -> bool {",
            "    match (",
            "        ReducerProfileId::from_wire(source),",
            "        ReducerProfileId::from_wire(target),",
            "    ) {",
            "        (Some(source), Some(target)) => source.can_upgrade_to(target),",
            "        _ => false,",
            "    }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_registry_descriptors(artifacts: Path) -> str:
    files = [
        "id-kind-registry.json",
        "capability-action-registry.json",
        "schema-registry.json",
        "account-data-key-registry.json",
    ]
    loaded = [
        (f"registry/{name}", *load(artifacts / "registry" / name))
        for name in files
    ]
    (
        id_artifact,
        capability_artifact,
        schema_artifact,
        account_artifact,
    ) = [item[1] for item in loaded]
    ids = sorted(
        (
            row
            for row in id_artifact["id_kinds"]
            if row["status"] == "active"
        ),
        key=lambda row: row["kind"],
    )
    special = sorted(
        (
            row
            for row in id_artifact["special_forms"]
            if row["status"] in {"active", "profile_extension"}
        ),
        key=lambda row: row["kind"],
    )
    actions = sorted(
        capability_artifact["actions"], key=lambda row: row["action"]
    )
    schemas = sorted(
        (
            row
            for row in schema_artifact["schemas"]
            if row.get("status", "active") == "active"
        ),
        key=lambda row: row["schema_id"],
    )
    patterns = sorted(
        (
            row
            for row in account_artifact["account_data_key_patterns"]
            if row["status"] == "active"
        ),
        key=lambda row: row["key_pattern"],
    )
    counts = (
        f"id_kinds={len(ids)}, special_forms={len(special)}, "
        f"actions={len(actions)}, schemas={len(schemas)}, "
        f"account_data_patterns={len(patterns)}"
    )
    lines = header(loaded, counts)
    lines.extend(
        [
            "use arkret_wire::{CapabilityActionId, SchemaId, event_kind_str};",
            "use serde::{Deserialize, Serialize};",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct IdKindDescriptor {",
            "    pub kind: &'static str,",
            "    pub category: &'static str,",
            "    pub wire_form: &'static str,",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct SpecialFormIdKindDescriptor {",
            "    pub kind: &'static str,",
            "    pub wire_form: &'static str,",
            "    /// Registered regular expression the wire form's payload (everything",
            "    /// after the `ak:<kind>:` prefix) must match.",
            "    pub payload_pattern: &'static str,",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]",
            "#[serde(rename_all = \"snake_case\")]",
            "pub enum CapabilityRiskTier {",
            "    Low,",
            "    Medium,",
            "    High,",
            "}",
            "",
            "impl CapabilityRiskTier {",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
            "            Self::Low => \"low\",",
            "            Self::Medium => \"medium\",",
            "            Self::High => \"high\",",
            "        }",
            "    }",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct CapabilityActionDescriptor {",
            "    pub action: CapabilityActionId,",
            "    pub category: &'static str,",
            "    pub risk_tier: CapabilityRiskTier,",
            "    pub required_constraints: &'static [&'static str],",
            "    pub target_event_kinds: &'static [&'static str],",
            "    pub grant_authority_actions: &'static [&'static str],",
            "    pub profile: Option<&'static str>,",
            "    pub root_control_only: bool,",
            "    pub subject_only: bool,",
            "    pub reducer_only: bool,",
            "    pub event_mapping_kind: &'static str,",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct SchemaDescriptor {",
            "    pub schema_id: &'static str,",
            "    pub file: &'static str,",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct AccountDataPatternDescriptor {",
            "    pub key_pattern: &'static str,",
            "    pub scope: &'static str,",
            "    pub storage: &'static str,",
            "    pub plaintext_schema: Option<&'static str>,",
            "    pub writer_authorities: &'static [&'static str],",
            "    pub holder_self_operations: &'static [&'static str],",
            "    pub write_event_kinds: &'static [&'static str],",
            "    pub deletion_mode: &'static str,",
            "}",
            "",
            "pub const REGISTERED_ID_KINDS: &[IdKindDescriptor] = &[",
        ]
    )
    for row in ids:
        lines.extend(
            [
                "    IdKindDescriptor {",
                f"        kind: {rust_string(row['kind'])},",
                f"        category: {rust_string(row['category'])},",
                f"        wire_form: {rust_string(row['wire_form'])},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "pub const REGISTERED_SPECIAL_FORM_ID_KINDS: &[SpecialFormIdKindDescriptor] = &[",
        ]
    )
    for row in special:
        lines.extend(
            [
                "    SpecialFormIdKindDescriptor {",
                f"        kind: {rust_string(row['kind'])},",
                f"        wire_form: {rust_string(row['wire_form'])},",
                f"        payload_pattern: {rust_string(row['payload_pattern'])},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "pub const REGISTERED_CAPABILITY_ACTIONS: &[CapabilityActionDescriptor] = &[",
        ]
    )
    for row in actions:
        lines.extend(
            [
                "    CapabilityActionDescriptor {",
                f"        action: CapabilityActionId::{variant(row['action'], ('ak.',))},",
                f"        category: {rust_string(row['category'])},",
                f"        risk_tier: CapabilityRiskTier::{variant(row['risk_tier'])},",
                f"        required_constraints: {rust_slice(row['required_constraints'])},",
                f"        target_event_kinds: {event_kind_slice(row['target_event_kinds'])},",
                f"        grant_authority_actions: {rust_slice(row.get('grant_authority_actions') or [])},",
                f"        profile: {rust_option(row.get('profile'))},",
                f"        root_control_only: {str(bool(row.get('root_control_only'))).lower()},",
                f"        subject_only: {str(bool(row.get('subject_only'))).lower()},",
                f"        reducer_only: {str(bool(row.get('reducer_only'))).lower()},",
                f"        event_mapping_kind: {rust_string(row['event_mapping_kind'])},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "pub const REGISTERED_SCHEMA_IDS: &[SchemaDescriptor] = &[",
        ]
    )
    for row in schemas:
        lines.extend(
            [
                "    SchemaDescriptor {",
                f"        schema_id: SchemaId::{associated_name(row['schema_id'], SCHEMA_ID_PREFIXES)},",
                f"        file: {rust_string(row['file'])},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "pub const REGISTERED_ACCOUNT_DATA_PATTERNS: &[AccountDataPatternDescriptor] = &[",
        ]
    )
    for row in patterns:
        lines.extend(
            [
                "    AccountDataPatternDescriptor {",
                f"        key_pattern: {rust_string(row['key_pattern'])},",
                f"        scope: {rust_string(row['scope'])},",
                f"        storage: {rust_string(row['storage'])},",
                f"        plaintext_schema: {rust_option(row.get('plaintext_schema'))},",
                f"        writer_authorities: {rust_slice(row['writer_authorities'])},",
                f"        holder_self_operations: {rust_slice(row['holder_self_operations'])},",
                f"        write_event_kinds: {event_kind_slice(row['write_event_kinds'])},",
                f"        deletion_mode: {rust_string(row['deletion_mode'])},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "pub fn capability_action(",
            "    value: &str,",
            ") -> Option<&'static CapabilityActionDescriptor> {",
            "    CapabilityActionId::from_wire(value).map(capability_action_descriptor)",
            "}",
            "",
            "pub const fn capability_action_descriptor(",
            "    id: CapabilityActionId,",
            ") -> &'static CapabilityActionDescriptor {",
            "    &REGISTERED_CAPABILITY_ACTIONS[id as usize]",
            "}",
            "",
            "pub fn account_data_pattern(",
            "    value: &str,",
            ") -> Option<&'static AccountDataPatternDescriptor> {",
            "    REGISTERED_ACCOUNT_DATA_PATTERNS",
            "        .iter()",
            "        .find(|row| account_data_pattern_matches(row.key_pattern, value))",
            "}",
            "",
            "fn account_data_pattern_matches(pattern: &str, value: &str) -> bool {",
            "    let mut pattern_rest = pattern;",
            "    let mut value_rest = value;",
            "    while let Some(open) = pattern_rest.find('<') {",
            "        let literal = &pattern_rest[..open];",
            "        if !value_rest.starts_with(literal) {",
            "            return false;",
            "        }",
            "        value_rest = &value_rest[literal.len()..];",
            "        let Some(close_offset) = pattern_rest[open + 1..].find('>') else {",
            "            return false;",
            "        };",
            "        let after = open + close_offset + 2;",
            "        pattern_rest = &pattern_rest[after..];",
            "        if let Some(next_open) = pattern_rest.find('<') {",
            "            let separator = &pattern_rest[..next_open];",
            "            let Some(separator_at) = value_rest.find(separator) else {",
            "                return false;",
            "            };",
            "            if separator_at == 0 {",
            "                return false;",
            "            }",
            "            value_rest = &value_rest[separator_at..];",
            "        } else {",
            "            return !value_rest.is_empty() && pattern_rest.is_empty();",
            "        }",
            "    }",
            "    pattern_rest == value_rest",
            "}",
            "",
            "pub fn schema(value: &str) -> Option<&'static SchemaDescriptor> {",
            "    REGISTERED_SCHEMA_IDS",
            "        .iter()",
            "        .find(|row| row.schema_id == value)",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_did_freshness_profiles(artifacts: Path) -> str:
    relative = "registry/did-freshness-profile-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(artifact["profiles"], key=lambda row: row["freshness_profile_id"])
    ensure_unique(rows, "freshness_profile_id", DID_FRESHNESS_PREFIXES)
    tiers = {"low": "Low", "medium": "Medium", "high": "High"}
    lines = header([(relative, artifact, digest)], f"registered={len(rows)}")
    lines.extend(
        [
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "pub enum DidFreshnessProfileId {",
        ]
    )
    for row in rows:
        lines.append(f"    {variant(row['freshness_profile_id'], DID_FRESHNESS_PREFIXES)},")
    lines.extend(
        [
            "}",
            "",
            "/// Registered risk tier of a freshness profile. Fixed by registration:",
            "/// a deployment declares only the numeric windows.",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "pub enum DidFreshnessRiskTier {",
            "    Low,",
            "    Medium,",
            "    High,",
            "}",
            "",
            "impl DidFreshnessProfileId {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in rows:
        lines.append(
            f"        Self::{variant(row['freshness_profile_id'], DID_FRESHNESS_PREFIXES)},"
        )
    lines.extend(["    ];", ""])
    for row in rows:
        lines.append(
            f"    pub const {associated_name(row['freshness_profile_id'], DID_FRESHNESS_PREFIXES)}: "
            f"&'static str = {rust_string(row['freshness_profile_id'])};"
        )
    lines.extend(["", "    pub const fn as_str(self) -> &'static str {", "        match self {"])
    for row in rows:
        lines.append(
            f"            Self::{variant(row['freshness_profile_id'], DID_FRESHNESS_PREFIXES)} => "
            f"Self::{associated_name(row['freshness_profile_id'], DID_FRESHNESS_PREFIXES)},"
        )
    lines.extend(["        }", "    }", "", "    pub const fn risk_tier(self) -> DidFreshnessRiskTier {", "        match self {"])
    for row in rows:
        lines.append(
            f"            Self::{variant(row['freshness_profile_id'], DID_FRESHNESS_PREFIXES)} => "
            f"DidFreshnessRiskTier::{tiers[row['risk_tier']]},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    /// §5.4: an unknown id resolves to the strictest tier, never to",
            '    /// "any cached binding will do".',
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{associated_name(row['freshness_profile_id'], DID_FRESHNESS_PREFIXES)} => "
            f"Some(Self::{variant(row['freshness_profile_id'], DID_FRESHNESS_PREFIXES)}),"
        )
    lines.extend(["            _ => None,", "        }", "    }", "}"])
    return "\n".join(lines) + "\n"



def generate_authority_sources(artifacts: Path) -> str:
    relative = "registry/authority-source-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(artifact["sources"], key=lambda row: row["authority_source_id"])
    ensure_unique(rows, "authority_source_id", AUTHORITY_SOURCE_PREFIXES)
    lines = header([(relative, artifact, digest)], f"registered={len(rows)}")
    lines.extend(
        [
            "use serde::{Deserialize, Serialize};",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
            "pub enum AuthoritySourceId {",
        ]
    )
    for row in rows:
        lines.append(
            f"    {variant(row['authority_source_id'], AUTHORITY_SOURCE_PREFIXES)},"
        )
    lines.extend(
        [
            "}",
            "",
            "impl AuthoritySourceId {",
            "    pub const ALL: &'static [Self] = &[",
        ]
    )
    for row in rows:
        lines.append(
            f"        Self::{variant(row['authority_source_id'], AUTHORITY_SOURCE_PREFIXES)},"
        )
    lines.extend(["    ];", ""])
    for row in rows:
        lines.append(
            f"    pub const {associated_name(row['authority_source_id'], AUTHORITY_SOURCE_PREFIXES)}: "
            f"&'static str = {rust_string(row['authority_source_id'])};"
        )
    lines.extend(
        [
            "",
            "    pub const fn as_str(self) -> &'static str {",
            "        match self {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{variant(row['authority_source_id'], AUTHORITY_SOURCE_PREFIXES)} => "
            f"Self::{associated_name(row['authority_source_id'], AUTHORITY_SOURCE_PREFIXES)},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn from_wire(value: &str) -> Option<Self> {",
            "        match value {",
        ]
    )
    for row in rows:
        lines.append(
            f"            Self::{associated_name(row['authority_source_id'], AUTHORITY_SOURCE_PREFIXES)} => "
            f"Some(Self::{variant(row['authority_source_id'], AUTHORITY_SOURCE_PREFIXES)}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "}",
            "",
            "impl std::fmt::Display for AuthoritySourceId {",
            "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {",
            "        f.write_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl Serialize for AuthoritySourceId {",
            "    fn serialize<S: serde::Serializer>(",
            "        &self,",
            "        serializer: S,",
            "    ) -> Result<S::Ok, S::Error> {",
            "        serializer.serialize_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl<'de> Deserialize<'de> for AuthoritySourceId {",
            "    fn deserialize<D: serde::Deserializer<'de>>(",
            "        deserializer: D,",
            "    ) -> Result<Self, D::Error> {",
            "        let raw = String::deserialize(deserializer)?;",
            "        Self::from_wire(&raw).ok_or_else(|| {",
            '            serde::de::Error::custom(format!("unknown authority source id: {raw}"))',
            "        })",
            "    }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_simple_string_enum(
    *,
    relative: str,
    artifact: dict[str, Any],
    digest: str,
    rows: list[dict[str, Any]],
    key: str,
    prefixes: tuple[str, ...],
    enum_name: str,
    counts: str,
    repr_usize: bool = False,
) -> str:
    """Generate the shared closed wire-id enum surface used by simple registries."""
    ensure_unique(rows, key, prefixes)
    lines = header([(relative, artifact, digest)], counts)
    lines.append("#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]")
    if repr_usize:
        lines.append("#[repr(usize)]")
    lines.append(f"pub enum {enum_name} {{")
    for row in rows:
        lines.append(f"    {variant(row[key], prefixes)},")
    lines.extend(["}", "", f"impl {enum_name} {{", "    pub const ALL: &'static [Self] = &["])
    for row in rows:
        lines.append(f"        Self::{variant(row[key], prefixes)},")
    lines.extend(["    ];", ""])
    for row in rows:
        lines.append(
            f"    pub const {associated_name(row[key], prefixes)}: &'static str = "
            f"{rust_string(row[key])};"
        )
    lines.extend(["", "    pub const fn as_str(self) -> &'static str {", "        match self {"])
    for row in rows:
        lines.append(
            f"            Self::{variant(row[key], prefixes)} => "
            f"Self::{associated_name(row[key], prefixes)},"
        )
    lines.extend(["        }", "    }", "", "    pub fn from_wire(value: &str) -> Option<Self> {", "        match value {"])
    for row in rows:
        lines.append(
            f"            Self::{associated_name(row[key], prefixes)} => "
            f"Some(Self::{variant(row[key], prefixes)}),"
        )
    lines.extend(["            _ => None,", "        }", "    }", "}"])
    return "\n".join(lines) + "\n"


def generate_service_contract_ids(artifacts: Path) -> str:
    relative = "registry/contract-registry.json"
    data, digest = load(artifacts / relative)
    rows = sorted(data.get("service_contracts", []), key=lambda row: row["contract_id"])
    return generate_simple_string_enum(
        relative=relative,
        artifact=data,
        digest=digest,
        rows=rows,
        key="contract_id",
        prefixes=("ak.",),
        enum_name="ServiceContractId",
        counts=f"service_contracts={len(rows)}",
        repr_usize=True,
    )


def generate_device_message_kinds(artifacts: Path) -> str:
    relative = "schemas/device-message.schema.json"
    data, digest = load(artifacts / relative)
    rows = [
        {"kind": value}
        for value in sorted(data["$defs"]["actor_private_update_kind"]["enum"])
    ]
    return generate_simple_string_enum(
        relative=relative,
        artifact=data,
        digest=digest,
        rows=rows,
        key="kind",
        prefixes=("ak.",),
        enum_name="ActorPrivateUpdateKind",
        counts=f"actor_private_update_kinds={len(rows)}",
    )


def generate_authority_set_ids(artifacts: Path) -> str:
    relative = "registry/authority-set-policy-registry.json"
    data, digest = load(artifacts / relative)
    rows = sorted(data["policies"], key=lambda row: row["authority_set_id"])
    return generate_simple_string_enum(
        relative=relative,
        artifact=data,
        digest=digest,
        rows=rows,
        key="authority_set_id",
        prefixes=("ak.authority_set.",),
        enum_name="AuthoritySetId",
        counts=f"authority_sets={len(rows)}",
    )


def generate_history_store_limits(artifacts: Path) -> str:
    relative = "registry/history-recovery-scalability-registry.json"
    data, digest = load(artifacts / relative)
    store = data["history_store"]
    numeric = sorted(
        (name, value)
        for name, value in store.items()
        if isinstance(value, int) and not isinstance(value, bool)
    )
    fields = [
        (name, "i64" if name.endswith("_seconds") else "usize", value)
        for name, value in numeric
    ]
    lines = header([(relative, data, digest)], f"history_store_limits={len(fields)}")
    lines.extend([
        "/// Machine-readable `history_store` section of",
        "/// `registry/history-recovery-scalability-registry.json`, the single source",
        "/// of truth for the device-local history-only store quotas.",
        "///",
        f"/// Material dedupe rule: {rustdoc_text(store['material_dedupe_rule'])}",
        "///",
        f"/// Material quota rule: {rustdoc_text(store['material_quota_rule'])}",
        "///",
        f"/// Material eviction rule: {rustdoc_text(store['material_eviction_rule'])}",
        "///",
        f"/// Origin attribution rule: {rustdoc_text(store['origin_attribution_rule'])}",
        "///",
        f"/// Event candidate binding rule: {rustdoc_text(store['event_candidate_binding_rule'])}",
        "///",
        f"/// `candidate_digest` preimage: {rustdoc_text(store['candidate_digest'])}.",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
        "pub struct HistoryStoreLimits {",
    ])
    for name, rust_type, _ in fields:
        lines.append(f"    pub {name}: {rust_type},")
    lines.extend(["}", "", "/// The registered `history_store` limits.", "pub const HISTORY_STORE_LIMITS: HistoryStoreLimits = HistoryStoreLimits {"])
    for name, _, value in fields:
        lines.append(f"    {name}: {value},")
    lines.extend(["};"])
    return "\n".join(lines) + "\n"


def generate_redactable_fields(artifacts: Path) -> str:
    relative = "registry/redactable-field-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(
        artifact["redactable_fields"],
        key=lambda row: (row["object_kind"], row["path"]),
    )
    paths = sorted({row["path"] for row in rows})
    lines = header(
        [(relative, artifact, digest)],
        f"redactable_fields={len(rows)}, distinct_paths={len(paths)}",
    )
    lines.extend(
        [
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct RedactableFieldDescriptor {",
            "    pub object_kind: &'static str,",
            "    pub path: &'static str,",
            "    pub paired_path: &'static str,",
            "    pub non_terminal_clear_op: &'static str,",
            "    pub terminal_clear_event_kinds: &'static [&'static str],",
            "}",
            "",
            "/// Registered redactable content-carrier slots",
            "/// (`event-and-patch.md` section 4.2.4).",
            "pub const REDACTABLE_FIELDS: &[RedactableFieldDescriptor] = &[",
        ]
    )
    for row in rows:
        lines.extend(
            [
                "    RedactableFieldDescriptor {",
                f"        object_kind: {rust_string(row['object_kind'])},",
                f"        path: {rust_string(row['path'])},",
                f"        paired_path: {rust_string(row['paired_path'])},",
                "        non_terminal_clear_op: "
                f"{rust_string(row['non_terminal_clear_op'])},",
                "        terminal_clear_event_kinds: "
                f"{rust_slice(row['terminal_clear_event_kinds'])},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "/// Distinct slot paths a patch `$op=\"unset\"` must never address.",
            "/// Realm-defined `redactable: true` fields are declared by their own",
            "/// Realm schema and are enforced separately.",
            "pub const REDACTABLE_FIELD_PATHS: &[&str] = &[",
        ]
    )
    for path in paths:
        lines.append(f"    {rust_string(path)},")
    lines.append("];")
    return "\n".join(lines) + "\n"


def generate_reducer_managed_paths(artifacts: Path) -> str:
    relative = "registry/reducer-managed-path-registry.json"
    artifact, digest = load(artifacts / relative)
    universal = sorted(
        artifact["universal_forbidden_patch_paths"], key=lambda row: row["path"]
    )
    objects = sorted(artifact["objects"], key=lambda row: row["object_kind"])
    any_object_paths = sorted(
        {row["path"] for row in universal}
        | {
            entry["path"]
            for row in objects
            for entry in row["forbidden_patch_paths"]
        }
    )
    lines = header(
        [(relative, artifact, digest)],
        f"universal_paths={len(universal)}, object_kinds={len(objects)}, "
        f"any_object_paths={len(any_object_paths)}",
    )
    lines.extend(
        [
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct ReducerManagedPathDescriptor {",
            "    pub path: &'static str,",
            "    pub basis: &'static str,",
            "    pub reason_code: &'static str,",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct ReducerManagedObjectPathDescriptor {",
            "    pub path: &'static str,",
            "    pub basis: &'static str,",
            "    pub reason_code: &'static str,",
            "    pub schema_enforced: bool,",
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct ReducerManagedObjectDescriptor {",
            "    pub object_kind: &'static str,",
            "    pub forbidden_paths: &'static [ReducerManagedObjectPathDescriptor],",
            "    pub universal_exemptions: &'static [&'static str],",
            "}",
            "",
            "/// General minimum set of `event-and-patch.md` section 4.2.5: the patch",
            "/// paths every patch-bearing object kind forbids unless it declares an",
            "/// explicit exemption.",
            "pub const REDUCER_MANAGED_UNIVERSAL_PATHS: "
            "&[ReducerManagedPathDescriptor] = &[",
        ]
    )
    for row in universal:
        lines.extend(
            [
                "    ReducerManagedPathDescriptor {",
                f"        path: {rust_string(row['path'])},",
                f"        basis: {rust_string(row['basis'])},",
                f"        reason_code: {rust_string(row['reason_code'])},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "/// Per-object-kind additions and exemptions. An object kind absent from",
            "/// this table has no patch surface registered in the spec.",
            "pub const REDUCER_MANAGED_OBJECTS: &[ReducerManagedObjectDescriptor] = &[",
        ]
    )
    for row in objects:
        lines.extend(
            [
                "    ReducerManagedObjectDescriptor {",
                f"        object_kind: {rust_string(row['object_kind'])},",
            ]
        )
        entries = sorted(row["forbidden_patch_paths"], key=lambda item: item["path"])
        if entries:
            lines.append("        forbidden_paths: &[")
            for entry in entries:
                lines.extend(
                    [
                        "            ReducerManagedObjectPathDescriptor {",
                        f"                path: {rust_string(entry['path'])},",
                        f"                basis: {rust_string(entry['basis'])},",
                        f"                reason_code: {rust_string(entry['reason_code'])},",
                        "                schema_enforced: "
                        f"{'true' if entry['schema_enforced'] else 'false'},",
                        "            },",
                    ]
                )
            lines.append("        ],")
        else:
            lines.append("        forbidden_paths: &[],")
        exemptions = sorted(entry["path"] for entry in row["universal_exemptions"])
        lines.extend(
            [
                f"        universal_exemptions: {rust_slice(exemptions)},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "/// Conservative object-agnostic superset: every path forbidden on at",
            "/// least one object kind, with no exemption applied. Only for callers",
            "/// that cannot name the object kind; a caller that can name it MUST use",
            "/// the per-object table instead, because applying this superset to a",
            "/// View rejects the `state` patch that `views.md` section 3.1 requires.",
            "pub const REDUCER_MANAGED_ANY_OBJECT_PATCH_PATHS: &[&str] = &[",
        ]
    )
    for path in any_object_paths:
        lines.append(f"    {rust_string(path)},")
    lines.append("];")
    return "\n".join(lines) + "\n"


GENERATORS = {
    "crates/identifiers/src/generated/digest_suite_codes.rs": generate_digest_suite_codes,
    "crates/wire/src/error_codes/error_code.rs": generate_error_codes,
    "crates/wire/src/error_codes/reason_code.rs": generate_reason_codes,
    "crates/wire/src/generated/operation_ids.rs": generate_operations,
    "crates/wire/src/generated/capability_discovery.rs": generate_capability_discovery,
    "crates/wire/src/generated/schema_ids.rs": generate_schema_ids,
    "crates/wire/src/generated/closed_registry_types.rs": (
        generate_closed_registry_types
    ),
    "crates/wire/src/generated/profile_ids.rs": generate_profile_ids,
    "crates/wire/src/generated/reducer_profiles.rs": generate_reducer_profiles,
    "crates/wire/src/generated/account_data_keys.rs": (
        generate_account_data_keys
    ),
    "crates/wire/src/generated/service_kinds.rs": generate_service_kinds,
    "crates/wire/src/generated/relation_kinds.rs": generate_relation_kinds,
    "crates/wire/src/generated/security_strings.rs": (
        generate_security_strings
    ),
    "crates/wire/src/generated/service_contract_ids.rs": generate_service_contract_ids,
    "crates/wire/src/generated/device_message_kinds.rs": generate_device_message_kinds,
    "crates/wire/src/generated/authority_set_ids.rs": generate_authority_set_ids,
    "crates/wire/src/generated/capability_actions.rs": (
        generate_capability_actions
    ),
    "crates/wire/src/generated/did_freshness_profiles.rs": (
        generate_did_freshness_profiles
    ),
    "crates/wire/src/generated/authority_sources.rs": generate_authority_sources,
    "crates/wire/src/generated/history_store_limits.rs": (
        generate_history_store_limits
    ),
    "crates/wire/src/generated/redactable_fields.rs": generate_redactable_fields,
    "crates/wire/src/generated/reducer_managed_paths.rs": (
        generate_reducer_managed_paths
    ),
    "crates/schema/src/generated/registry_descriptors.rs": (
        generate_registry_descriptors
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    for relative, generator in GENERATORS.items():
        output = args.output_root / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            generator(args.artifacts_dir),
            encoding="utf-8",
            newline="\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
