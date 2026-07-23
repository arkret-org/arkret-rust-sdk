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


def rust_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def rust_option(value: Any) -> str:
    return "None" if value is None else f"Some({rust_string(str(value))})"


def rust_slice(values: list[str] | None) -> str:
    return "&[" + ", ".join(rust_string(value) for value in (values or [])) + "]"


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
        lines.append(f"    {rust_string(row['operation_id'])},")
    lines.extend(
        [
            "];",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct ServiceOperationDescriptor {",
            "    pub id: ServiceOperationId,",
            "    pub http_method: &'static str,",
            "    pub http_path: &'static str,",
            "    pub grpc: Option<&'static str>,",
            "    pub mq: Option<&'static str>,",
            "    pub success_shape_kind: &'static str,",
            "    pub idempotency_mechanism: Option<&'static str>,",
            "    pub retry_safe: Option<bool>,",
            "    pub request_schema_ref: Option<&'static str>,",
            "    pub response_schema_ref: Option<&'static str>,",
            "    pub uncertain_outcome: Option<&'static str>,",
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
            f"{rust_string(row['operation_id'])},"
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
            f"            {rust_string(row['operation_id'])} => "
            f"Some(Self::{variant(row['operation_id'], ('ak.',))}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
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
        lines.extend(
            [
                "    ServiceOperationDescriptor {",
                f"        id: ServiceOperationId::{variant(row['operation_id'], ('ak.',))},",
                f"        http_method: {rust_string(method)},",
                f"        http_path: {rust_string(path)},",
                f"        grpc: {rust_option(row.get('grpc'))},",
                f"        mq: {rust_option(row.get('mq'))},",
                f"        success_shape_kind: {rust_string(row['success_shape_kind'])},",
                f"        idempotency_mechanism: {rust_option(row.get('idempotency_mechanism'))},",
                f"        retry_safe: {retry_expr},",
                f"        request_schema_ref: {rust_option(row.get('request_schema_ref'))},",
                f"        response_schema_ref: {rust_option(row.get('response_schema_ref'))},",
                f"        uncertain_outcome: {rust_option(uncertain)},",
                "    },",
            ]
        )
    lines.append("];")
    return "\n".join(lines) + "\n"


def generate_error_codes(artifacts: Path) -> str:
    relative = "registry/error-code-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(artifact["codes"], key=lambda row: row["code"])
    ensure_unique(rows, "code")
    lines = header([(relative, artifact, digest)], f"error_codes={len(rows)}")
    lines.extend(
        [
            "use serde::{Deserialize, Serialize};",
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
            "    pub http_status: u16,",
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
        lines.extend(
            [
                "    ErrorCodeDescriptor {",
                f"        code: ErrorCode::{variant(row['code'])},",
                f"        http_status: {int(row['http_status'])},",
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
            f"{rust_string(row['code'])},"
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
            f"            {rust_string(row['code'])} => "
            f"Self::{variant(row['code'])},"
        )
    lines.extend(
        [
            "            _ => Self::Unknown(value.to_owned()),",
            "        }",
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
            "        serializer.serialize_str(self.as_str())",
            "    }",
            "}",
            "",
            "impl<'de> Deserialize<'de> for ReasonCode {",
            "    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {",
            "        Ok(Self::from_wire(&String::deserialize(deserializer)?))",
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
                f"        code: {rust_string(row['code'])},",
                f"        applies_to: {rust_slice(row['applies_to'])},",
                f"        description: {rust_string(row['description'])},",
                "    },",
            ]
        )
    lines.append("];")
    return "\n".join(lines) + "\n"


def generate_service_types(artifacts: Path) -> str:
    relative = "registry/service-type-registry.json"
    artifact, digest = load(artifacts / relative)
    rows = sorted(
        (
            row
            for row in artifact["service_types"]
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
            "pub enum ServiceType {",
        ]
    )
    for row in rows:
        lines.append(f"    {variant(row['canonical_id'])},")
    lines.extend(
        [
            "}",
            "",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct ServiceTypeDescriptor {",
            "    pub service_type: ServiceType,",
            "    pub valid_in: &'static [&'static str],",
            "    pub description: &'static str,",
            "}",
            "",
            "impl ServiceType {",
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
            "    pub fn descriptor(self) -> &'static ServiceTypeDescriptor {",
            "        &SERVICE_TYPE_DESCRIPTORS[self as usize]",
            "    }",
            "",
            "    pub fn valid_in(self, context: &str) -> bool {",
            "        self.descriptor().valid_in.contains(&context)",
            "    }",
            "}",
            "",
            "pub const SERVICE_TYPE_DESCRIPTORS: &[ServiceTypeDescriptor] = &[",
        ]
    )
    for row in rows:
        lines.extend(
            [
                "    ServiceTypeDescriptor {",
                f"        service_type: ServiceType::{variant(row['canonical_id'])},",
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
            "",
            "pub type StandardRelationKindMetadata = RelationKindDescriptor;",
            "pub const STANDARD_RELATION_KIND_METADATA: &[StandardRelationKindMetadata] =",
            "    RELATION_KIND_DESCRIPTORS;",
            "",
            "pub fn standard_relation_kind_metadata(",
            "    relation_kind: &str,",
            ") -> Option<&'static StandardRelationKindMetadata> {",
            "    RELATION_KIND_DESCRIPTORS",
            "        .iter()",
            "        .find(|row| row.canonical_id == relation_kind)",
            "}",
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
    lines = header(
        loaded,
        f"proof_contexts={len(proof)}, exporter_labels={len(labels)}, "
        f"digest_suites={len(digests)}, signature_algorithms={len(signatures)}, "
        f"hpke_suites={len(hpke)}, mls_ciphersuites={len(mls)}, "
        f"mls_extensions={len(mls_extensions)}",
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
            f"{rust_string(row['context'])},"
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
            f"            {rust_string(row['context'])} => "
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
            f"{rust_string(row['label'])},"
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
            f"            {rust_string(row['label'])} => "
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
            "    pub output_length: &'static str,",
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
                f"        output_length: {rust_string(str(row['output_length']))},",
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
            f"{rust_string(row['action'])},"
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
            f"            {rust_string(row['action'])} => "
            f"Some(Self::{variant(row['action'], ('ak.',))}),"
        )
    lines.extend(
        [
            "            _ => None,",
            "        }",
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
        "account-data-type-registry.json",
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
            for row in account_artifact["account_data_types"]
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
            "use arkret_wire::CapabilityActionId;",
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
            "    pub profile: Option<&'static str>,",
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
            "    pub write_event_kinds: &'static [&'static str],",
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
                f"        target_event_kinds: {rust_slice(row['target_event_kinds'])},",
                f"        profile: {rust_option(row.get('profile'))},",
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
                f"        schema_id: {rust_string(row['schema_id'])},",
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
                f"        write_event_kinds: {rust_slice(row['write_event_kinds'])},",
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
            "    CapabilityActionId::from_wire(value)",
            "        .map(|id| &REGISTERED_CAPABILITY_ACTIONS[id as usize])",
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


GENERATORS = {
    "crates/wire/src/error_codes/error_code.rs": generate_error_codes,
    "crates/wire/src/error_codes/reason_code.rs": generate_reason_codes,
    "crates/wire/src/generated/operation_ids.rs": generate_operations,
    "crates/wire/src/generated/service_types.rs": generate_service_types,
    "crates/wire/src/generated/relation_kinds.rs": generate_relation_kinds,
    "crates/wire/src/generated/security_strings.rs": (
        generate_security_strings
    ),
    "crates/wire/src/generated/capability_actions.rs": (
        generate_capability_actions
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
