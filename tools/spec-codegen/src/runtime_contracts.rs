use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde_json::Value;

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
            if slot.extra.keys().any(|key| key != "head_eq") {
                bail!("realm_bootstrap_registry.{owner} contains an unsupported slot field");
            }
            if let Some(head_eq) = slot.extra.get("head_eq") {
                if !head_eq.is_null() {
                    bail!("realm_bootstrap_registry.{owner} supports only head_eq=null");
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
        for requirement in &event.pre_state_requirements {
            if !matches!(
                requirement.predicate.kind.as_str(),
                PRE_STATE_PRESENT | PRE_STATE_EQUALS_PAYLOAD | PRE_STATE_MATCHES_PAYLOAD
            ) {
                bail!(
                    "{} uses unsupported pre-state predicate {}",
                    event.event_kind,
                    requirement.predicate.kind
                );
            }
            if matches!(
                requirement.predicate.kind.as_str(),
                PRE_STATE_EQUALS_PAYLOAD | PRE_STATE_MATCHES_PAYLOAD
            ) && requirement.predicate.payload_field.is_none()
            {
                bail!(
                    "{} omits payload_field for {}",
                    event.event_kind,
                    requirement.predicate.kind
                );
            }
            if let Some(condition) = &requirement.condition {
                validate_pre_state_condition(&event.event_kind, condition)?;
            }
        }
    }
    Ok(())
}

/// The closed stored-field predicates of `zh/models/event-and-patch.md`
/// section 2.4.2. `stored_field_matches_payload` is the weakest of the three:
/// it holds when the stored field and the payload field are both absent, or
/// both present and byte-identical. That closes both directions at once for a
/// payload field that is optional on the wire, so a forged value cannot enter
/// a branch that belongs to another object class and an omitted value cannot
/// skip a registered write.
const PRE_STATE_PRESENT: &str = "stored_field_present";
const PRE_STATE_EQUALS_PAYLOAD: &str = "stored_field_equals_payload";
const PRE_STATE_MATCHES_PAYLOAD: &str = "stored_field_matches_payload";

/// Validate one `pre_state_requirements[].condition` against the closed
/// payload-condition grammar it shares verbatim with `cell_writes[].condition`.
///
/// The condition decides whether the requirement is evaluated at all, so an
/// unknown operator, a missing member or a source path that is not an explicit
/// `payload.<path>` fails the generation run instead of being dropped: a
/// silently ignored condition turns a conditional requirement into an
/// unconditional one and rejects Events the registry admits.
fn validate_pre_state_condition(event_kind: &str, condition: &Value) -> Result<()> {
    let object = condition
        .as_object()
        .with_context(|| format!("{event_kind} pre-state condition is not an object"))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .with_context(|| format!("{event_kind} pre-state condition omits kind"))?;
    let members: &[&str] = match kind {
        "field_present" | "field_absent" => &["kind", "field"],
        "field_equals" => &["kind", "field", "const"],
        "any_field_present" => &["kind", "fields"],
        other => bail!("{event_kind} uses unsupported pre-state condition {other}"),
    };
    for member in object.keys() {
        if !members.contains(&member.as_str()) {
            bail!("{event_kind} pre-state condition {kind} carries unsupported member {member}");
        }
    }
    for member in members {
        if !object.contains_key(*member) {
            bail!("{event_kind} pre-state condition {kind} omits {member}");
        }
    }
    if let Some(field) = object.get("field") {
        require_payload_path(event_kind, kind, field)?;
    }
    if let Some(fields) = object.get("fields") {
        let fields = fields.as_array().with_context(|| {
            format!("{event_kind} pre-state condition {kind} fields is not an array")
        })?;
        if fields.len() < 2 {
            bail!("{event_kind} pre-state condition {kind} needs at least two fields");
        }
        for field in fields {
            require_payload_path(event_kind, kind, field)?;
        }
    }
    if let Some(constant) = object.get("const")
        && !matches!(
            constant,
            Value::String(_) | Value::Number(_) | Value::Bool(_)
        )
    {
        bail!("{event_kind} pre-state condition {kind} const is not a scalar");
    }
    Ok(())
}

fn require_payload_path(event_kind: &str, kind: &str, field: &Value) -> Result<()> {
    let path = field.as_str().with_context(|| {
        format!("{event_kind} pre-state condition {kind} field is not a string")
    })?;
    if !path.starts_with("payload.") || path.ends_with('.') {
        bail!(
            "{event_kind} pre-state condition {kind} field {path} is not an explicit payload path"
        );
    }
    Ok(())
}

/// Render a registry rule node as the closed `arkret_wire::EventCellRule` AST.
///
/// The pre-state condition grammar is the cell-write condition grammar, so it
/// travels in the same parse-free AST and is evaluated by the same code rather
/// than being duplicated into a second closed enum that could drift from it.
fn cell_rule_expression(value: &Value, is_operator: bool) -> Result<String> {
    if is_operator {
        let operator = value
            .as_str()
            .context("a cell rule kind must be a string operator")?;
        return Ok(format!(
            "EventCellRule::Operator(EventCellRuleOperator::{})",
            variant(operator, &[])
        ));
    }
    Ok(match value {
        Value::Null => "EventCellRule::Null".to_owned(),
        Value::Bool(value) => format!("EventCellRule::Bool({value})"),
        Value::Number(number) => {
            let value = number
                .as_i64()
                .context("a cell rule number must fit in an i64")?;
            format!("EventCellRule::Integer({value})")
        }
        Value::String(value) => format!("EventCellRule::String({})", rust_string(value)),
        Value::Array(items) => {
            let items = items
                .iter()
                .map(|item| cell_rule_expression(item, false))
                .collect::<Result<Vec<_>>>()?;
            format!("EventCellRule::Array(&[{}])", items.join(", "))
        }
        Value::Object(fields) => {
            let fields = fields
                .iter()
                .map(|(key, value)| {
                    Ok(format!(
                        "EventCellRuleField {{ key: EventCellRuleKey::{}, value: {} }}",
                        variant(key, &[]),
                        cell_rule_expression(value, key == "kind")?
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            format!("EventCellRule::Object(&[{}])", fields.join(", "))
        }
    })
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
    pub reducer_only: bool,
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
            "    CapabilityActionDescriptor {{ action: CapabilityActionId::{}, category: {}, risk_tier: CapabilityRiskTier::{}, required_constraints: {}, required_evaluator_checks: {}, target_event_kinds: {}, grant_authority_actions: {}, profile: {}, root_control_only: {}, subject_only: {}, reducer_only: {}, event_mapping_kind: {} }},",
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
            row.reducer_only,
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
pub enum RealmBootstrapHeadEq { Null }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealmBootstrapSlotDescriptor {
    pub event_kind: &'static str,
    pub presence: RealmBootstrapPresence,
    pub id_source: Option<RealmBootstrapIdSource>,
    pub condition: Option<RealmBootstrapCondition>,
    pub head_eq: Option<RealmBootstrapHeadEq>,
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
            let head_eq = if slot.extra.contains_key("head_eq") {
                "Some(RealmBootstrapHeadEq::Null)"
            } else {
                "None"
            };
            writeln!(
                output,
                "    RealmBootstrapSlotDescriptor {{ event_kind: event_kind_str::{}, presence: RealmBootstrapPresence::{}, id_source: {id_source}, condition: {condition}, head_eq: {head_eq} }},",
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
    let requirement_count = events
        .iter()
        .map(|event| event.pre_state_requirements.len())
        .sum::<usize>();
    let mut output = header(
        &[&inputs.event_kinds_source, &inputs.id_kinds_source],
        &format!(
            "active_events={}, pre_state_requirements={requirement_count}",
            events.len()
        ),
    );
    // A conditional requirement carries the registry's own rule AST, so the
    // vocabulary types are imported only when the registry actually declares a
    // condition. Importing them unconditionally would leave the generated file
    // with unused imports on a registry that declares none.
    let conditional = events
        .iter()
        .flat_map(|event| event.pre_state_requirements.iter())
        .any(|requirement| requirement.condition.is_some());
    let rule_imports = if conditional {
        "CellFamilyId, EventCellRule, EventCellRuleField, EventCellRuleKey, EventCellRuleOperator, event_kind_str"
    } else {
        "CellFamilyId, EventCellRule, event_kind_str"
    };
    writeln!(output, "use arkret_wire::{{{rule_imports}}};").expect("write to String");
    output.push_str(
        r#"
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventIdSource { EventDerived }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventPreStatePredicateKind { StoredFieldPresent, StoredFieldEqualsPayload, StoredFieldMatchesPayload }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventPreStateRequirementDescriptor {
    pub cell_family: CellFamilyId,
    pub subject_field: &'static str,
    pub condition: Option<EventCellRule>,
    pub predicate: EventPreStatePredicateKind,
    pub stored_field: &'static str,
    pub payload_field: Option<&'static str>,
    pub failure_code: &'static str,
    pub failure_reason_code: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRuntimeContractDescriptor {
    pub event_kind: &'static str,
    pub reducer_input: bool,
    pub id_source: Option<EventIdSource>,
    pub derived_id_kinds: &'static [&'static str],
    pub pre_state_requirements: &'static [EventPreStateRequirementDescriptor],
}

"#,
    );
    for event in &events {
        if event.pre_state_requirements.is_empty() {
            continue;
        }
        writeln!(
            output,
            "const {}_PRE_STATE_REQUIREMENTS: &[EventPreStateRequirementDescriptor] = &[",
            associated_name(&event.event_kind, &["ak."])
        )
        .expect("write to String");
        for requirement in &event.pre_state_requirements {
            let condition = match &requirement.condition {
                None => "None".to_owned(),
                Some(condition) => format!("Some({})", cell_rule_expression(condition, false)?),
            };
            writeln!(
                output,
                "    EventPreStateRequirementDescriptor {{ cell_family: CellFamilyId::{}, subject_field: {}, condition: {condition}, predicate: EventPreStatePredicateKind::{}, stored_field: {}, payload_field: {}, failure_code: {}, failure_reason_code: {} }},",
                variant(&requirement.cell_family, &["ak.component."]),
                rust_string(&requirement.subject.field),
                variant(&requirement.predicate.kind, &[]),
                rust_string(&requirement.predicate.field),
                option_string(requirement.predicate.payload_field.as_deref()),
                rust_string(&requirement.failure.code),
                rust_string(&requirement.failure.reason_code),
            )
            .expect("write to String");
        }
        output.push_str("];\n\n");
    }
    output.push_str("pub const EVENT_RUNTIME_CONTRACTS: &[EventRuntimeContractDescriptor] = &[\n");
    for event in events {
        let mut derived_id_kinds = event.id_kind.iter().cloned().collect::<Vec<_>>();
        derived_id_kinds.extend(event.id_kinds.iter().cloned());
        let id_source = if event.id_source.as_deref() == Some("event_derived") {
            "Some(EventIdSource::EventDerived)"
        } else {
            "None"
        };
        let requirements = if event.pre_state_requirements.is_empty() {
            "&[]".to_owned()
        } else {
            format!(
                "{}_PRE_STATE_REQUIREMENTS",
                associated_name(&event.event_kind, &["ak."])
            )
        };
        writeln!(
            output,
            "    EventRuntimeContractDescriptor {{ event_kind: event_kind_str::{}, reducer_input: {}, id_source: {id_source}, derived_id_kinds: {}, pre_state_requirements: {requirements} }},",
            associated_name(&event.event_kind, &["ak."]),
            event.reducer_input,
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
