#!/usr/bin/env python3
"""Generate the typed, clean-break conformance profile registry."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


def rust_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def rust_slice(values: list[str]) -> str:
    return "&[" + ", ".join(rust_string(value) for value in sorted(set(values))) + "]"


def associated_name(value: str, prefix: str = "") -> str:
    if prefix:
        if not value.startswith(prefix):
            raise ValueError(f"{value!r} does not start with {prefix!r}")
        value = value[len(prefix) :]
    return re.sub(r"[^A-Za-z0-9]+", "_", value).upper()


def event_kind_ref(value: str, registered_event_kinds: set[str]) -> str:
    if value in registered_event_kinds:
        return f"event_kind_str::{associated_name(value, 'ak.')}"
    if value.startswith("wire_scope:"):
        return rust_string(value)
    raise ValueError(f"profile requirement references unregistered event kind: {value!r}")


def event_kind_slice(values: list[str], registered_event_kinds: set[str]) -> str:
    return (
        "&["
        + ", ".join(
            event_kind_ref(value, registered_event_kinds)
            for value in sorted(set(values))
        )
        + "]"
    )


def variant(value: str, prefix: str = "") -> str:
    if prefix:
        if not value.startswith(prefix):
            raise ValueError(f"{value!r} does not start with {prefix!r}")
        value = value[len(prefix) :]
    parts = [part for part in re.split(r"[^A-Za-z0-9]+", value) if part]
    return "".join(part[:1].upper() + part[1:] for part in parts)


def operation_requirement(row: dict[str, str]) -> str:
    direction = {"provide": "Provide", "consume": "Consume"}.get(row["direction"])
    binding = {
        "http_json": "HttpJson",
        "websocket": "Websocket",
        "tus": "Tus",
    }.get(row["binding_kind"])
    if direction is None or binding is None:
        raise ValueError(f"unsupported operation requirement: {row!r}")
    operation = variant(row["operation_id"], "ak.")
    return (
        "ProfileOperationRequirement { "
        f"direction: ProfileOperationDirection::{direction}, "
        f"operation_id: ServiceOperationId::{operation}, "
        f"binding_kind: BindingKind::{binding} "
        "}"
    )


def phase(value: str) -> str:
    names = {
        "build": "Build",
        "conformance": "Conformance",
        "startup_claim_guard": "StartupClaimGuard",
        "peer_eligibility": "PeerEligibility",
        "runtime_negotiation": "RuntimeNegotiation",
        "runtime_admission": "RuntimeAdmission",
    }
    try:
        return f"ProfileEnforcementPhase::{names[value]}"
    except KeyError as error:
        raise ValueError(f"unsupported profile enforcement phase: {value}") from error


def non_event_rule(row: dict[str, Any], registered_event_kinds: set[str]) -> str:
    string_fields = [
        "issuer_action",
        "grantable_action",
        "required_registration_event_kind",
        "required_claimed_profile",
        "required_constraint_kind",
        "required_constraint_subkind",
        "subject_binding",
        "scope_binding",
        "epoch_binding",
        "requested_action_binding",
    ]
    fields = [
        f"{name}: "
        + (
            event_kind_ref(str(row[name]), registered_event_kinds)
            if name == "required_registration_event_kind"
            else rust_string(str(row[name]))
        )
        for name in string_fields
    ]
    fields.insert(
        1,
        "issuer_owner_authority_allowed: "
        + str(bool(row["issuer_owner_authority_allowed"])).lower(),
    )
    return "NonEventGrantAuthorityRule { " + ", ".join(fields) + " }"


def generate(artifact_path: Path, event_kind_registry_path: Path | None = None) -> str:
    raw = artifact_path.read_bytes()
    artifact = json.loads(raw)
    if event_kind_registry_path is None:
        event_kind_registry_path = (
            artifact_path.parent.parent / "registry" / "contract-registry.json"
        )
    event_kind_raw = event_kind_registry_path.read_bytes()
    contract_registry = json.loads(event_kind_raw)
    event_kind_registry = contract_registry.get("event_kind_registry")
    if not isinstance(event_kind_registry, dict):
        raise ValueError("contract registry lacks event_kind_registry")
    registered_event_kinds = {
        str(row["event_kind"])
        for row in event_kind_registry.get("event_kinds", [])
        if row.get("status") == "active"
    }
    if not registered_event_kinds:
        raise ValueError("event-kind registry has no active event kinds")
    requirements = artifact.get("profile_requirements")
    if not isinstance(requirements, dict):
        raise ValueError("conformance profile artifact lacks profile_requirements")
    digest = hashlib.sha256(raw).hexdigest()
    lines = [
        "//! Generated typed conformance profile requirements.",
        "//!",
        "//! @generated by tools/generate-sdk-profile-requirements.py; do not edit.",
        f"//! Input version: {artifact['version']}; sha256={digest}; requirements={len(requirements)}.",
        "//! Event kinds input version: "
        f"{event_kind_registry['version']}; sha256={hashlib.sha256(event_kind_raw).hexdigest()}; "
        f"registered={len(registered_event_kinds)}.",
        "",
        "use std::collections::BTreeMap;",
        "use std::sync::LazyLock;",
        "",
        "use crate::{BindingKind, ServiceOperationId, event_kind_str};",
        "",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
        "pub enum ProfileOperationDirection { Provide, Consume }",
        "",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
        "pub enum ProfileEnforcementPhase {",
        "    Build, Conformance, StartupClaimGuard, PeerEligibility,",
        "    RuntimeNegotiation, RuntimeAdmission,",
        "}",
        "",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]",
        "pub struct ProfileOperationRequirement {",
        "    pub direction: ProfileOperationDirection,",
        "    pub operation_id: ServiceOperationId,",
        "    pub binding_kind: BindingKind,",
        "}",
        "",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
        "pub struct NonEventGrantAuthorityRule {",
        "    pub issuer_action: &'static str,",
        "    pub issuer_owner_authority_allowed: bool,",
        "    pub grantable_action: &'static str,",
        "    pub required_registration_event_kind: &'static str,",
        "    pub required_claimed_profile: &'static str,",
        "    pub required_constraint_kind: &'static str,",
        "    pub required_constraint_subkind: &'static str,",
        "    pub subject_binding: &'static str,",
        "    pub scope_binding: &'static str,",
        "    pub epoch_binding: &'static str,",
        "    pub requested_action_binding: &'static str,",
        "}",
        "",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
        "pub struct ProfileRequirements {",
        "    pub profile_id: &'static str,",
        "    pub inherits: &'static [&'static str],",
        "    pub enforcement_phases: &'static [ProfileEnforcementPhase],",
        "    pub operation_requirements: &'static [ProfileOperationRequirement],",
        "    pub required_event_kinds: &'static [&'static str],",
        "    pub required_schemas: &'static [&'static str],",
        "    pub rejected_event_kinds: &'static [&'static str],",
        "    pub required_fixtures: &'static [&'static str],",
        "    pub required_capability_actions: &'static [&'static str],",
        "    pub required_features: &'static [&'static str],",
        "    pub required_constraint_kinds: &'static [&'static str],",
        "    pub non_event_grant_authority_rules: &'static [NonEventGrantAuthorityRule],",
        "}",
        "",
        "impl ProfileRequirements {",
        "    pub fn provide_requirements(&self) -> impl Iterator<Item = &ProfileOperationRequirement> {",
        "        self.operation_requirements.iter().filter(|row| row.direction == ProfileOperationDirection::Provide)",
        "    }",
        "    pub fn consume_requirements(&self) -> impl Iterator<Item = &ProfileOperationRequirement> {",
        "        self.operation_requirements.iter().filter(|row| row.direction == ProfileOperationDirection::Consume)",
        "    }",
        "}",
        "",
        "pub static PROFILE_REQUIREMENTS: LazyLock<BTreeMap<&'static str, ProfileRequirements>> =",
        "    LazyLock::new(|| {",
        "        let mut map = BTreeMap::new();",
    ]
    for profile_id in sorted(requirements):
        row = requirements[profile_id]
        features = list(row.get("required_features", []))
        constraints = list(row.get("required_constraint_kinds", []))
        constraints.extend(row.get("required_constraint_subkinds", []))
        ops = ", ".join(operation_requirement(item) for item in row["operation_requirements"])
        phases = ", ".join(phase(item) for item in row["enforcement_phases"])
        rules = ", ".join(
            non_event_rule(item, registered_event_kinds)
            for item in row.get("non_event_grant_authority_rules", [])
        )
        lines.extend(
            [
                f"        map.insert({rust_string(profile_id)}, ProfileRequirements {{",
                f"            profile_id: {rust_string(profile_id)},",
                f"            inherits: {rust_slice(row.get('inherits', []))},",
                f"            enforcement_phases: &[{phases}],",
                f"            operation_requirements: &[{ops}],",
                "            required_event_kinds: "
                f"{event_kind_slice(row.get('required_event_kinds', []), registered_event_kinds)},",
                f"            required_schemas: {rust_slice(row.get('required_schemas', []))},",
                "            rejected_event_kinds: "
                f"{event_kind_slice(row.get('rejected_event_kinds', []), registered_event_kinds)},",
                f"            required_fixtures: {rust_slice(row.get('required_fixtures', []))},",
                "            required_capability_actions: "
                f"{rust_slice(row.get('required_capability_actions', []))},",
                f"            required_features: {rust_slice(features)},",
                f"            required_constraint_kinds: {rust_slice(constraints)},",
                f"            non_event_grant_authority_rules: &[{rules}],",
                "        });",
            ]
        )
    lines.extend(
        [
            "        map",
            "    });",
            "",
            "pub fn known_profile_ids() -> Vec<&'static str> {",
            "    PROFILE_REQUIREMENTS.keys().copied().collect()",
            "}",
            "",
            "pub fn requirements_for(profile_id: &str) -> Option<&'static ProfileRequirements> {",
            "    PROFILE_REQUIREMENTS.get(profile_id)",
            "}",
            "",
            "pub fn non_event_grant_authority_rule(",
            "    profile_id: &str, grantable_action: &str,",
            ") -> Option<&'static NonEventGrantAuthorityRule> {",
            "    requirements_for(profile_id)?.non_event_grant_authority_rules.iter()",
            "        .find(|rule| rule.grantable_action == grantable_action)",
            "}",
            "",
            "#[derive(Clone, Debug, PartialEq, Eq)]",
            "pub enum ProfileRequirementsError { UnknownProfile { profile_id: String } }",
            "",
            "impl std::fmt::Display for ProfileRequirementsError {",
            "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {",
            "        match self { Self::UnknownProfile { profile_id } =>",
            "            write!(f, \"unknown conformance profile: {profile_id}\") }",
            "    }",
            "}",
            "impl std::error::Error for ProfileRequirementsError {}",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.artifacts_dir / "profiles" / "conformance-profiles.json"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    event_kind_registry = args.artifacts_dir / "registry" / "contract-registry.json"
    args.output.write_text(
        generate(source, event_kind_registry), encoding="utf-8", newline="\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
