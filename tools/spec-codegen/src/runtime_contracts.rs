use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{Result, bail};

use crate::model::{RealmBootstrapProfile, SpecInputs};
use crate::render::{
    associated_name, event_kind_slice, header, option_string, rust_string, string_slice, variant,
};

pub struct GeneratedOutput {
    pub relative_path: PathBuf,
    pub contents: String,
}

pub fn generate(inputs: &SpecInputs) -> Result<Vec<GeneratedOutput>> {
    validate(inputs)?;
    Ok(vec![
        GeneratedOutput {
            relative_path: "crates/identifiers/src/generated/protocol_time_tolerances.rs".into(),
            contents: generate_protocol_time_tolerances(inputs)?,
        },
        GeneratedOutput {
            relative_path: "crates/schema/src/generated/registry_descriptors.rs".into(),
            contents: generate_registry_descriptors(inputs),
        },
        GeneratedOutput {
            relative_path: "crates/schema/src/generated/runtime_contracts.rs".into(),
            contents: generate_runtime_contracts(inputs),
        },
        GeneratedOutput {
            relative_path: "crates/schema/src/generated/event_runtime_contracts.rs".into(),
            contents: generate_event_runtime_contracts(inputs)?,
        },
    ])
}

fn generate_protocol_time_tolerances(inputs: &SpecInputs) -> Result<String> {
    let registry = &inputs.contracts.protocol_time_tolerance_registry;
    let mut tolerance_ids = BTreeSet::new();
    let mut tolerance_names = BTreeSet::new();
    for tolerance in &registry.tolerances {
        if !tolerance_ids.insert(tolerance.tolerance_id.as_str()) {
            bail!("duplicate protocol time tolerance id {}", tolerance.tolerance_id);
        }
        if !tolerance_names.insert(tolerance.name.as_str()) {
            bail!("duplicate protocol time tolerance name {}", tolerance.name);
        }
        if tolerance.unit != "milliseconds" || tolerance.value < 0 {
            bail!(
                "protocol time tolerance {} must be a non-negative millisecond value",
                tolerance.tolerance_id
            );
        }
    }
    let mut scenario_ids = BTreeSet::new();
    for scenario in &registry.scenarios {
        if !scenario_ids.insert(scenario.scenario_id.as_str()) {
            bail!("duplicate protocol time tolerance scenario {}", scenario.scenario_id);
        }
        if !tolerance_ids.contains(scenario.tolerance_id.as_str()) {
            bail!(
                "protocol time tolerance scenario {} references unknown tolerance {}",
                scenario.scenario_id,
                scenario.tolerance_id
            );
        }
        if !matches!(
            scenario.direction.as_str(),
            "future_only" | "symmetric_not_before_and_expiry"
        ) {
            bail!(
                "protocol time tolerance scenario {} uses unsupported direction {}",
                scenario.scenario_id,
                scenario.direction
            );
        }
    }

    let mut output = header(
        &[&inputs.contracts_source],
        &format!(
            "protocol_time_tolerances={}, protocol_time_tolerance_scenarios={}",
            registry.tolerances.len(),
            registry.scenarios.len()
        ),
    );
    output.push_str(
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n\
pub enum ProtocolTimeToleranceDirection {\n\
    FutureOnly,\n\
    SymmetricNotBeforeAndExpiry,\n\
}\n\n\
#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n\
pub struct ProtocolTimeToleranceDescriptor {\n\
    pub tolerance_id: &'static str,\n\
    pub name: &'static str,\n\
    pub value_ms: i64,\n\
}\n\n\
#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n\
pub struct ProtocolTimeToleranceScenarioDescriptor {\n\
    pub scenario_id: &'static str,\n\
    pub tolerance_id: &'static str,\n\
    pub direction: ProtocolTimeToleranceDirection,\n\
    pub comparison: &'static str,\n\
}\n\n",
    );

    for tolerance in &registry.tolerances {
        writeln!(
            output,
            "pub const {}: i64 = {};",
            associated_name(&tolerance.name, &[]),
            tolerance.value
        )
        .expect("write to String");
    }
    output.push_str("\npub const PROTOCOL_TIME_TOLERANCES: &[ProtocolTimeToleranceDescriptor] = &[\n");
    for tolerance in &registry.tolerances {
        writeln!(
            output,
            "    ProtocolTimeToleranceDescriptor {{ tolerance_id: {}, name: {}, value_ms: {} }},",
            rust_string(&tolerance.tolerance_id),
            rust_string(&tolerance.name),
            associated_name(&tolerance.name, &[])
        )
        .expect("write to String");
    }
    output.push_str("];\n\npub const PROTOCOL_TIME_TOLERANCE_SCENARIOS: &[ProtocolTimeToleranceScenarioDescriptor] = &[\n");
    for scenario in &registry.scenarios {
        writeln!(
            output,
            "    ProtocolTimeToleranceScenarioDescriptor {{ scenario_id: {}, tolerance_id: {}, direction: ProtocolTimeToleranceDirection::{}, comparison: {} }},",
            rust_string(&scenario.scenario_id),
            rust_string(&scenario.tolerance_id),
            variant(&scenario.direction, &[]),
            rust_string(&scenario.comparison)
        )
        .expect("write to String");
    }
    output.push_str("];\n\npub fn protocol_time_tolerance(value: &str) -> Option<&'static ProtocolTimeToleranceDescriptor> {\n    PROTOCOL_TIME_TOLERANCES.iter().find(|row| row.tolerance_id == value)\n}\n\npub fn protocol_time_tolerance_scenario(value: &str) -> Option<&'static ProtocolTimeToleranceScenarioDescriptor> {\n    PROTOCOL_TIME_TOLERANCE_SCENARIOS.iter().find(|row| row.scenario_id == value)\n}\n");
    Ok(output)
}

fn validate(inputs: &SpecInputs) -> Result<()> {
    let operations = inputs
        .operations
        .operations
        .iter()
        .map(|row| row.operation_id.as_str())
        .collect::<BTreeSet<_>>();
    for (owner, values) in inputs
        .agent_runtime
        .capability_sets
        .iter()
        .flat_map(|(name, rule)| {
            [
                (
                    format!("capability_sets.{name}.activation_operations"),
                    &rule.activation_operations,
                ),
                (
                    format!("capability_sets.{name}.mandatory_operations"),
                    &rule.mandatory_operations,
                ),
            ]
        })
        .chain(
            inputs
                .agent_runtime
                .feature_additions
                .iter()
                .map(|(name, values)| (format!("feature_additions.{name}"), values)),
        )
    {
        for value in values {
            if !operations.contains(value.as_str()) {
                bail!("{owner} references unknown operation {value}");
            }
        }
    }
    for (name, rule) in &inputs.agent_runtime.capability_sets {
        if rule.selection_rule != "any_activation_operation_present_in_immutable_provision_actions"
        {
            bail!("capability_sets.{name} uses unsupported selection_rule");
        }
        let activation = rule.activation_operations.iter().collect::<BTreeSet<_>>();
        if activation.len() != rule.activation_operations.len() {
            bail!("capability_sets.{name} repeats an activation operation");
        }
        if rule
            .mandatory_operations
            .iter()
            .any(|operation| !activation.contains(operation))
        {
            bail!("capability_sets.{name} mandatory operations are not activation operations");
        }
    }
    for group in &inputs.operations.surface_groups {
        for value in &group.operations {
            if !operations.contains(value.as_str()) {
                bail!(
                    "operation surface {} references unknown operation {value}",
                    group.surface
                );
            }
        }
    }
    let session_policy = &inputs
        .operations
        .high_security_session_authentication_policy;
    if session_policy.applies_to_operation_id_prefix != "ak.self." {
        bail!("high-security session policy must apply to ak.self.* operations");
    }
    for value in &session_policy.unauthenticated_public_projection_operations {
        if !operations.contains(value.as_str()) {
            bail!("high-security session policy references unknown operation {value}");
        }
        if !value.starts_with(&session_policy.applies_to_operation_id_prefix) {
            bail!("high-security session policy exception is outside its prefix: {value}");
        }
    }
    if inputs.deployment_probes.probes.len() != 1
        || inputs.deployment_probes.probes[0].probe_id
            != "deployment_probe.tls.pq_hybrid_x25519mlkem768.v1"
    {
        bail!("deployment probe registry does not contain the one closed Arkret v1 TLS probe");
    }

    let event_kinds = inputs
        .event_kinds
        .event_kinds
        .iter()
        .map(|row| row.event_kind.as_str())
        .collect::<BTreeSet<_>>();
    for (owner, profile) in bootstrap_profiles(inputs) {
        let mut conditions = BTreeSet::new();
        for slot in &profile.ordered_slots {
            if !event_kinds.contains(slot.event_kind.as_str()) {
                bail!(
                    "realm_bootstrap_registry.{owner} references unknown event kind {}",
                    slot.event_kind
                );
            }
            if slot.extra.keys().any(|key| key != "expected_revision") {
                bail!("realm_bootstrap_registry.{owner} contains an unsupported slot field");
            }
            if let Some(expected_revision) = slot.extra.get("expected_revision") {
                if !expected_revision.is_null() {
                    bail!(
                        "realm_bootstrap_registry.{owner} supports only expected_revision=null"
                    );
                }
            }
            if let Some(condition) = &slot.condition
                && !conditions.insert(condition)
            {
                bail!("realm_bootstrap_registry.{owner} repeats condition {condition}");
            }
        }
    }
    let id_kinds = inputs
        .id_kinds
        .id_kinds
        .iter()
        .filter(|row| row.status == "active")
        .map(|row| row.kind.as_str())
        .collect::<BTreeSet<_>>();
    for event in &inputs.event_kinds.event_kinds {
        if event.status != "active" {
            continue;
        }
        let derived_id_kinds = event
            .id_kind
            .iter()
            .chain(event.id_kinds.iter())
            .collect::<Vec<_>>();
        if event.id_source.as_deref() == Some("event_derived") && derived_id_kinds.is_empty() {
            bail!(
                "{} declares event_derived without an id kind",
                event.event_kind
            );
        }
        for id_kind in derived_id_kinds {
            if !id_kinds.contains(id_kind.as_str()) {
                bail!("{} references unknown id kind {id_kind}", event.event_kind);
            }
        }
    }
    Ok(())
}

fn bootstrap_profiles(inputs: &SpecInputs) -> [(&'static str, &RealmBootstrapProfile); 2] {
    [
        (
            "ordinary_collaboration",
            &inputs
                .contracts
                .realm_bootstrap_registry
                .ordinary_collaboration,
        ),
        (
            "direct_conversation",
            &inputs
                .contracts
                .realm_bootstrap_registry
                .direct_conversation,
        ),
    ]
}

fn generate_registry_descriptors(inputs: &SpecInputs) -> String {
    let mut ids = inputs
        .id_kinds
        .id_kinds
        .iter()
        .filter(|row| row.status == "active")
        .collect::<Vec<_>>();
    ids.sort_by_key(|row| &row.kind);
    let mut special = inputs
        .id_kinds
        .special_forms
        .iter()
        .filter(|row| matches!(row.status.as_str(), "active" | "profile_extension"))
        .collect::<Vec<_>>();
    special.sort_by_key(|row| &row.kind);
    let mut actions = inputs.capability_actions.actions.iter().collect::<Vec<_>>();
    actions.sort_by_key(|row| &row.action);
    let mut schemas = inputs
        .schemas
        .schemas
        .iter()
        .filter(|row| row.status == "active")
        .collect::<Vec<_>>();
    schemas.sort_by_key(|row| &row.schema_id);
    let mut patterns = inputs
        .account_data
        .account_data_key_patterns
        .iter()
        .filter(|row| row.status == "active")
        .collect::<Vec<_>>();
    patterns.sort_by_key(|row| &row.key_pattern);

    let mut output = header(
        &[
            &inputs.id_kinds_source,
            &inputs.capability_actions_source,
            &inputs.schemas_source,
            &inputs.account_data_source,
        ],
        &format!(
            "id_kinds={}, special_forms={}, actions={}, schemas={}, account_data_patterns={}",
            ids.len(),
            special.len(),
            actions.len(),
            schemas.len(),
            patterns.len()
        ),
    );
    output.push_str(
        r#"use arkret_wire::{CapabilityActionId, SchemaId, event_kind_str};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdKindDescriptor {
    pub kind: &'static str,
    pub category: &'static str,
    pub wire_form: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpecialFormIdKindDescriptor {
    pub kind: &'static str,
    pub wire_form: &'static str,
    pub payload_pattern: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityRiskTier { Low, Medium, High }

impl CapabilityRiskTier {
    pub const fn as_str(self) -> &'static str {
        match self { Self::Low => "low", Self::Medium => "medium", Self::High => "high" }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityActionDescriptor {
    pub action: CapabilityActionId,
    pub category: &'static str,
    pub risk_tier: CapabilityRiskTier,
    pub required_constraints: &'static [&'static str],
    pub required_evaluator_checks: &'static [&'static str],
    pub target_event_kinds: &'static [&'static str],
    pub grant_authority_actions: &'static [&'static str],
    pub profile: Option<&'static str>,
    pub root_control_only: bool,
    pub subject_only: bool,
    pub event_mapping_kind: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaDescriptor { pub schema_id: &'static str, pub file: &'static str }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountDataPatternDescriptor {
    pub key_pattern: &'static str,
    pub scope: &'static str,
    pub storage: &'static str,
    pub plaintext_schema: Option<&'static str>,
    pub writer_authorities: &'static [&'static str],
    pub holder_self_operations: &'static [&'static str],
    pub write_event_kinds: &'static [&'static str],
    pub deletion_mode: &'static str,
}

pub const REGISTERED_ID_KINDS: &[IdKindDescriptor] = &[
"#,
    );
    for row in ids {
        writeln!(
            output,
            "    IdKindDescriptor {{ kind: {}, category: {}, wire_form: {} }},",
            rust_string(&row.kind),
            rust_string(&row.category),
            rust_string(&row.wire_form)
        )
        .expect("write to String");
    }
    output.push_str(
        "];\n\npub const REGISTERED_SPECIAL_FORM_ID_KINDS: &[SpecialFormIdKindDescriptor] = &[\n",
    );
    for row in special {
        writeln!(
            output,
            "    SpecialFormIdKindDescriptor {{ kind: {}, wire_form: {}, payload_pattern: {} }},",
            rust_string(&row.kind),
            rust_string(&row.wire_form),
            rust_string(&row.payload_pattern)
        )
        .expect("write to String");
    }
    output.push_str(
        "];\n\npub const REGISTERED_CAPABILITY_ACTIONS: &[CapabilityActionDescriptor] = &[\n",
    );
    for row in actions {
        writeln!(
            output,
            "    CapabilityActionDescriptor {{ action: CapabilityActionId::{}, category: {}, risk_tier: CapabilityRiskTier::{}, required_constraints: {}, required_evaluator_checks: {}, target_event_kinds: {}, grant_authority_actions: {}, profile: {}, root_control_only: {}, subject_only: {}, event_mapping_kind: {} }},",
            variant(&row.action, &["ak."]),
            rust_string(&row.category),
            variant(&row.risk_tier, &[]),
            string_slice(&row.required_constraints),
            string_slice(&row.required_evaluator_checks),
            event_kind_slice(&row.target_event_kinds),
            string_slice(&row.grant_authority_actions),
            option_string(row.profile.as_deref()),
            row.root_control_only,
            row.subject_only,
            rust_string(&row.event_mapping_kind),
        )
        .expect("write to String");
    }
    output.push_str("];\n\npub const REGISTERED_SCHEMA_IDS: &[SchemaDescriptor] = &[\n");
    for row in schemas {
        writeln!(
            output,
            "    SchemaDescriptor {{ schema_id: SchemaId::{}, file: {} }},",
            associated_name(&row.schema_id, &["ak.schema.", "ak."]),
            rust_string(&row.file)
        )
        .expect("write to String");
    }
    output.push_str(
        "];\n\npub const REGISTERED_ACCOUNT_DATA_PATTERNS: &[AccountDataPatternDescriptor] = &[\n",
    );
    for row in patterns {
        writeln!(
            output,
            "    AccountDataPatternDescriptor {{ key_pattern: {}, scope: {}, storage: {}, plaintext_schema: {}, writer_authorities: {}, holder_self_operations: {}, write_event_kinds: {}, deletion_mode: {} }},",
            rust_string(&row.key_pattern),
            rust_string(&row.scope),
            rust_string(&row.storage),
            option_string(row.plaintext_schema.as_deref()),
            string_slice(&row.writer_authorities),
            string_slice(&row.holder_self_operations),
            event_kind_slice(&row.write_event_kinds),
            rust_string(&row.deletion_mode),
        )
        .expect("write to String");
    }
    output.push_str(
        r#"];

pub fn capability_action(value: &str) -> Option<&'static CapabilityActionDescriptor> {
    CapabilityActionId::from_wire(value).map(capability_action_descriptor)
}

pub const fn capability_action_descriptor(id: CapabilityActionId) -> &'static CapabilityActionDescriptor {
    &REGISTERED_CAPABILITY_ACTIONS[id as usize]
}

pub fn capability_actions_for_event_kind(event_kind: &str) -> impl Iterator<Item = &'static CapabilityActionDescriptor> {
    REGISTERED_CAPABILITY_ACTIONS.iter().filter(move |row| row.target_event_kinds.contains(&event_kind))
}

pub fn account_data_pattern(value: &str) -> Option<&'static AccountDataPatternDescriptor> {
    REGISTERED_ACCOUNT_DATA_PATTERNS.iter().find(|row| account_data_pattern_matches(row.key_pattern, value))
}

fn account_data_pattern_matches(pattern: &str, value: &str) -> bool {
    let mut pattern_rest = pattern;
    let mut value_rest = value;
    while let Some(open) = pattern_rest.find('<') {
        let literal = &pattern_rest[..open];
        if !value_rest.starts_with(literal) { return false; }
        value_rest = &value_rest[literal.len()..];
        let Some(close_offset) = pattern_rest[open + 1..].find('>') else { return false; };
        let after = open + close_offset + 2;
        pattern_rest = &pattern_rest[after..];
        if let Some(next_open) = pattern_rest.find('<') {
            let separator = &pattern_rest[..next_open];
            let Some(separator_at) = value_rest.find(separator) else { return false; };
            if separator_at == 0 { return false; }
            value_rest = &value_rest[separator_at..];
        } else {
            return !value_rest.is_empty() && pattern_rest.is_empty();
        }
    }
    pattern_rest == value_rest
}

pub fn schema(value: &str) -> Option<&'static SchemaDescriptor> {
    REGISTERED_SCHEMA_IDS.iter().find(|row| row.schema_id == value)
}
"#,
    );
    output
}

fn generate_runtime_contracts(inputs: &SpecInputs) -> String {
    let mut output = header(
        &[
            &inputs.agent_runtime_source,
            &inputs.contracts_source,
            &inputs.operations_source,
            &inputs.event_kinds_source,
            &inputs.schemas_source,
            &inputs.id_kinds_source,
            &inputs.deployment_probes_source,
        ],
        &format!(
            "capability_sets={}, layers={}, feature_additions={}, bootstrap_profiles=2, operation_surface_groups={}",
            inputs.agent_runtime.capability_sets.len(),
            inputs.agent_runtime.layers.len(),
            inputs.agent_runtime.feature_additions.len(),
            inputs.operations.surface_groups.len(),
        ),
    );
    output.push_str(
        "use arkret_wire::{ServiceOperationId, event_kind_str};\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]\npub enum AgentRuntimeCapability {\n",
    );
    for name in inputs.agent_runtime.capability_sets.keys() {
        writeln!(output, "    {},", variant(name, &[])).expect("write to String");
    }
    output.push_str(
        r#"}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentRuntimeCapabilitySelectionRule {
    AnyActivationOperationPresentInImmutableProvisionActions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentRuntimeCapabilityDescriptor {
    pub capability: AgentRuntimeCapability,
    pub selection_rule: AgentRuntimeCapabilitySelectionRule,
    pub activation_operations: &'static [ServiceOperationId],
    pub mandatory_operations: &'static [ServiceOperationId],
}

pub const AGENT_RUNTIME_CAPABILITIES: &[AgentRuntimeCapabilityDescriptor] = &[
"#,
    );
    for (name, rule) in &inputs.agent_runtime.capability_sets {
        writeln!(
            output,
            "    AgentRuntimeCapabilityDescriptor {{ capability: AgentRuntimeCapability::{}, selection_rule: AgentRuntimeCapabilitySelectionRule::{}, activation_operations: &[{}], mandatory_operations: &[{}] }},",
            variant(name, &[]),
            variant(&rule.selection_rule, &[]),
            rule.activation_operations
                .iter()
                .map(|value| format!("ServiceOperationId::{}", variant(value, &["ak."])))
                .collect::<Vec<_>>()
                .join(", "),
            rule.mandatory_operations
                .iter()
                .map(|value| format!("ServiceOperationId::{}", variant(value, &["ak."])))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .expect("write to String");
    }
    output.push_str("];\n\npub const fn agent_runtime_capability_descriptor(capability: AgentRuntimeCapability) -> &'static AgentRuntimeCapabilityDescriptor {\n    match capability {\n");
    for (index, name) in inputs.agent_runtime.capability_sets.keys().enumerate() {
        writeln!(
            output,
            "        AgentRuntimeCapability::{} => &AGENT_RUNTIME_CAPABILITIES[{index}],",
            variant(name, &[])
        )
        .expect("write to String");
    }
    output.push_str("    }\n}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]\npub enum AgentRuntimeScopeLayer {\n");
    for row in &inputs.agent_runtime.layers {
        writeln!(output, "    {},", variant(&row.layer, &[])).expect("write to String");
    }
    output.push_str(
        r#"}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentRuntimeScopeLayerDescriptor {
    pub layer: AgentRuntimeScopeLayer,
    pub missing_reason: &'static str,
    pub recovery: &'static str,
}

pub const AGENT_RUNTIME_SCOPE_LAYERS: &[AgentRuntimeScopeLayerDescriptor] = &[
"#,
    );
    for row in &inputs.agent_runtime.layers {
        writeln!(
            output,
            "    AgentRuntimeScopeLayerDescriptor {{ layer: AgentRuntimeScopeLayer::{}, missing_reason: {}, recovery: {} }},",
            variant(&row.layer, &[]), rust_string(&row.missing_reason), rust_string(&row.recovery)
        )
        .expect("write to String");
    }
    output.push_str("];\n\npub const fn agent_runtime_scope_layer_descriptor(layer: AgentRuntimeScopeLayer) -> &'static AgentRuntimeScopeLayerDescriptor {\n    match layer {\n");
    for (index, row) in inputs.agent_runtime.layers.iter().enumerate() {
        writeln!(
            output,
            "        AgentRuntimeScopeLayer::{} => &AGENT_RUNTIME_SCOPE_LAYERS[{index}],",
            variant(&row.layer, &[])
        )
        .expect("write to String");
    }
    output.push_str("    }\n}\n\n#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]\npub enum AgentRuntimeFeature {\n");
    for name in inputs.agent_runtime.feature_additions.keys() {
        writeln!(output, "    {},", variant(name, &[])).expect("write to String");
    }
    output.push_str(
        "}\n\npub const AGENT_RUNTIME_FEATURE_OPERATIONS: &[&[ServiceOperationId]] = &[\n",
    );
    for values in inputs.agent_runtime.feature_additions.values() {
        writeln!(
            output,
            "    &[{}],",
            values
                .iter()
                .map(|value| format!("ServiceOperationId::{}", variant(value, &["ak."])))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .expect("write to String");
    }
    output.push_str("];\n\npub const fn agent_runtime_feature_operations(feature: AgentRuntimeFeature) -> &'static [ServiceOperationId] {\n    match feature {\n");
    for (index, name) in inputs.agent_runtime.feature_additions.keys().enumerate() {
        writeln!(
            output,
            "        AgentRuntimeFeature::{} => AGENT_RUNTIME_FEATURE_OPERATIONS[{index}],",
            variant(name, &[])
        )
        .expect("write to String");
    }
    output.push_str(
        r#"    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealmBootstrapProfile { OrdinaryCollaboration, DirectConversation }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealmBootstrapPresence { Required, Optional, Conditional }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealmBootstrapIdSource { EventDerived }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealmBootstrapCondition {
"#,
    );
    let conditions = bootstrap_profiles(inputs)
        .into_iter()
        .flat_map(|(_, profile)| profile.ordered_slots.iter())
        .filter_map(|slot| slot.condition.as_deref())
        .collect::<BTreeSet<_>>();
    for condition in conditions {
        writeln!(output, "    {},", variant(condition, &[])).expect("write to String");
    }
    output.push_str(
        r#"}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealmBootstrapExpectedRevision { Null }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealmBootstrapSlotDescriptor {
    pub event_kind: &'static str,
    pub presence: RealmBootstrapPresence,
    pub id_source: Option<RealmBootstrapIdSource>,
    pub condition: Option<RealmBootstrapCondition>,
    pub expected_revision: Option<RealmBootstrapExpectedRevision>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealmBootstrapProfileDescriptor {
    pub profile: RealmBootstrapProfile,
    pub atomic: bool,
    pub all_or_nothing: bool,
    pub genesis_confirms_complete_unit: bool,
    pub ordered_slots: &'static [RealmBootstrapSlotDescriptor],
}

"#,
    );
    for (name, profile) in bootstrap_profiles(inputs) {
        writeln!(
            output,
            "const {}_BOOTSTRAP_SLOTS: &[RealmBootstrapSlotDescriptor] = &[",
            associated_name(name, &[])
        )
        .expect("write to String");
        for slot in &profile.ordered_slots {
            let id_source = slot.id_source.as_ref().map_or_else(
                || "None".to_owned(),
                |value| format!("Some(RealmBootstrapIdSource::{})", variant(value, &[])),
            );
            let condition = slot.condition.as_ref().map_or_else(
                || "None".to_owned(),
                |value| format!("Some(RealmBootstrapCondition::{})", variant(value, &[])),
            );
            let expected_revision = if slot.extra.contains_key("expected_revision") {
                "Some(RealmBootstrapExpectedRevision::Null)"
            } else {
                "None"
            };
            writeln!(
                output,
                "    RealmBootstrapSlotDescriptor {{ event_kind: event_kind_str::{}, presence: RealmBootstrapPresence::{}, id_source: {id_source}, condition: {condition}, expected_revision: {expected_revision} }},",
                associated_name(&slot.event_kind, &["ak."]), variant(&slot.presence, &[])
            )
            .expect("write to String");
        }
        output.push_str("];\n\n");
    }
    output
        .push_str("pub const REALM_BOOTSTRAP_PROFILES: &[RealmBootstrapProfileDescriptor] = &[\n");
    for (name, profile) in bootstrap_profiles(inputs) {
        writeln!(
            output,
            "    RealmBootstrapProfileDescriptor {{ profile: RealmBootstrapProfile::{}, atomic: {}, all_or_nothing: {}, genesis_confirms_complete_unit: {}, ordered_slots: {}_BOOTSTRAP_SLOTS }},",
            variant(name, &[]), profile.atomic, profile.all_or_nothing,
            profile.genesis_confirms_complete_unit, associated_name(name, &[])
        )
        .expect("write to String");
    }
    let first_contact = &inputs.contracts.realm_bootstrap_registry.first_contact;
    writeln!(
        output,
        r#"];

pub const fn realm_bootstrap_profile_descriptor(profile: RealmBootstrapProfile) -> &'static RealmBootstrapProfileDescriptor {{
    match profile {{
        RealmBootstrapProfile::OrdinaryCollaboration => &REALM_BOOTSTRAP_PROFILES[0],
        RealmBootstrapProfile::DirectConversation => &REALM_BOOTSTRAP_PROFILES[1],
    }}
}}

pub fn realm_bootstrap_slot_for_condition(
    profile: RealmBootstrapProfile,
    condition: RealmBootstrapCondition,
) -> Option<&'static RealmBootstrapSlotDescriptor> {{
    realm_bootstrap_profile_descriptor(profile)
        .ordered_slots
        .iter()
        .find(|slot| slot.condition == Some(condition))
}}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealmBootstrapFirstContactDescriptor {{
    pub require_create_derived_realm_id: bool,
    pub require_complete_genesis_state_commitment: bool,
    pub fail_closed_until_complete: bool,
}}

pub const REALM_BOOTSTRAP_FIRST_CONTACT: RealmBootstrapFirstContactDescriptor = RealmBootstrapFirstContactDescriptor {{
    require_create_derived_realm_id: {},
    require_complete_genesis_state_commitment: {},
    fail_closed_until_complete: {},
}};"#,
        first_contact.require_create_derived_realm_id,
        first_contact.require_complete_genesis_state_commitment,
        first_contact.fail_closed_until_complete,
    )
    .expect("write to String");
    output.push_str(
        r#"

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationSurfaceGroupDescriptor {
    pub surface: &'static str,
    pub surface_class: &'static str,
    pub profile: Option<&'static str>,
    pub operations: &'static [ServiceOperationId],
}

pub const REGISTERED_OPERATION_SURFACE_GROUPS: &[OperationSurfaceGroupDescriptor] = &[
"#,
    );
    for group in &inputs.operations.surface_groups {
        writeln!(
            output,
            "    OperationSurfaceGroupDescriptor {{ surface: {}, surface_class: {}, profile: {}, operations: &[{}] }},",
            rust_string(&group.surface),
            rust_string(&group.surface_class),
            option_string(group.profile.as_deref()),
            group.operations
                .iter()
                .map(|operation| format!("ServiceOperationId::{}", variant(operation, &["ak."])))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .expect("write to String");
    }
    let session_policy = &inputs
        .operations
        .high_security_session_authentication_policy;
    writeln!(
        output,
        r#"];

pub const HIGH_SECURITY_SESSION_OPERATION_PREFIX: &str = {};
pub const UNAUTHENTICATED_PUBLIC_PROJECTION_OPERATIONS: &[ServiceOperationId] = &[{}];

pub const EVENT_KIND_REGISTRY_VERSION: &str = {};
pub const SCHEMA_REGISTRY_VERSION: &str = {};
pub const OPERATION_REGISTRY_VERSION: &str = {};
pub const ID_KIND_REGISTRY_VERSION: &str = {};
pub const PQ_HYBRID_TLS_REQUIRED_GROUP: &str = {};"#,
        rust_string(&session_policy.applies_to_operation_id_prefix),
        session_policy
            .unauthenticated_public_projection_operations
            .iter()
            .map(|operation| format!("ServiceOperationId::{}", variant(operation, &["ak."])))
            .collect::<Vec<_>>()
            .join(", "),
        rust_string(&inputs.event_kinds_source.version),
        rust_string(&inputs.schemas_source.version),
        rust_string(&inputs.operations_source.version),
        rust_string(&inputs.id_kinds_source.version),
        rust_string(&inputs.deployment_probes.probes[0].tls.required_named_group),
    )
    .expect("write to String");
    output
}

fn generate_event_runtime_contracts(inputs: &SpecInputs) -> Result<String> {
    let mut events = inputs
        .event_kinds
        .event_kinds
        .iter()
        .filter(|event| event.status == "active")
        .collect::<Vec<_>>();
    events.sort_by_key(|event| &event.event_kind);
    let mut output = header(
        &[&inputs.event_kinds_source, &inputs.id_kinds_source],
        &format!("active_events={}", events.len()),
    );
    writeln!(output, "use arkret_wire::event_kind_str;").expect("write to String");
    output.push_str(
        r#"
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventIdSource { EventDerived }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRuntimeContractDescriptor {
    pub event_kind: &'static str,
    pub id_source: Option<EventIdSource>,
    pub derived_id_kinds: &'static [&'static str],
}

"#,
    );
    output.push_str("pub const EVENT_RUNTIME_CONTRACTS: &[EventRuntimeContractDescriptor] = &[\n");
    for event in events {
        let mut derived_id_kinds = event.id_kind.iter().cloned().collect::<Vec<_>>();
        derived_id_kinds.extend(event.id_kinds.iter().cloned());
        let id_source = if event.id_source.as_deref() == Some("event_derived") {
            "Some(EventIdSource::EventDerived)"
        } else {
            "None"
        };
        writeln!(
            output,
            "    EventRuntimeContractDescriptor {{ event_kind: event_kind_str::{}, id_source: {id_source}, derived_id_kinds: {} }},",
            associated_name(&event.event_kind, &["ak."]),
            string_slice(&derived_id_kinds),
        )
        .expect("write to String");
    }
    output.push_str(
        r#"];

pub fn event_runtime_contract(event_kind: &str) -> Option<&'static EventRuntimeContractDescriptor> {
    EVENT_RUNTIME_CONTRACTS
        .binary_search_by_key(&event_kind, |descriptor| descriptor.event_kind)
        .ok()
        .map(|index| &EVENT_RUNTIME_CONTRACTS[index])
}
"#,
    );
    Ok(output)
}
