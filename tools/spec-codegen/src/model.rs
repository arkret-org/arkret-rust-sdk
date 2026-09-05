use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct LoadedArtifact {
    pub relative_path: &'static str,
    pub version: String,
    pub digest: String,
}

impl LoadedArtifact {
    pub(crate) fn read<T: DeserializeOwned>(
        artifacts_dir: &Path,
        relative_path: &'static str,
    ) -> Result<(Self, T)> {
        let path = artifacts_dir.join(relative_path);
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
        let version = value
            .get("version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unversioned")
            .to_owned();
        let typed =
            serde_json::from_value(value).with_context(|| format!("decode {}", path.display()))?;
        Ok((
            Self {
                relative_path,
                version,
                digest: hex::encode(Sha256::digest(bytes)),
            },
            typed,
        ))
    }
}

#[derive(Debug)]
pub struct SpecInputs {
    pub id_kinds_source: LoadedArtifact,
    pub id_kinds: IdKindRegistry,
    pub capability_actions_source: LoadedArtifact,
    pub capability_actions: CapabilityActionRegistry,
    pub schemas_source: LoadedArtifact,
    pub schemas: SchemaRegistry,
    pub account_data_source: LoadedArtifact,
    pub account_data: AccountDataRegistry,
    pub agent_runtime_source: LoadedArtifact,
    pub agent_runtime: AgentRuntimeRegistry,
    pub contracts_source: LoadedArtifact,
    pub contracts: ContractRegistry,
    pub operations_source: LoadedArtifact,
    pub operations: OperationRegistry,
    pub event_kinds_source: LoadedArtifact,
    pub event_kinds: EventKindRegistry,
    pub deployment_probes_source: LoadedArtifact,
    pub deployment_probes: DeploymentProbeRegistry,
}

impl SpecInputs {
    pub fn load(artifacts_dir: &Path) -> Result<Self> {
        let (id_kinds_source, id_kinds) =
            LoadedArtifact::read(artifacts_dir, "registry/id-kind-registry.json")?;
        let (capability_actions_source, capability_actions) =
            LoadedArtifact::read(artifacts_dir, "registry/capability-action-registry.json")?;
        let (schemas_source, schemas) =
            LoadedArtifact::read(artifacts_dir, "registry/schema-registry.json")?;
        let (account_data_source, account_data) =
            LoadedArtifact::read(artifacts_dir, "registry/account-data-key-registry.json")?;
        let (agent_runtime_source, agent_runtime) =
            LoadedArtifact::read(artifacts_dir, "registry/agent-runtime-scope-registry.json")?;
        let (contracts_source, contracts) =
            LoadedArtifact::read(artifacts_dir, "registry/contract-registry.json")?;
        let (operations_source, operations) =
            LoadedArtifact::read(artifacts_dir, "registry/operation-registry.json")?;
        let (event_kinds_source, event_kinds) =
            LoadedArtifact::read(artifacts_dir, "registry/event-kind-registry.json")?;
        let (deployment_probes_source, deployment_probes) =
            LoadedArtifact::read(artifacts_dir, "deployment-probes.json")?;
        Ok(Self {
            id_kinds_source,
            id_kinds,
            capability_actions_source,
            capability_actions,
            schemas_source,
            schemas,
            account_data_source,
            account_data,
            agent_runtime_source,
            agent_runtime,
            contracts_source,
            contracts,
            operations_source,
            operations,
            event_kinds_source,
            event_kinds,
            deployment_probes_source,
            deployment_probes,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct IdKindRegistry {
    pub id_kinds: Vec<IdKind>,
    pub special_forms: Vec<SpecialIdForm>,
}

#[derive(Debug, Deserialize)]
pub struct IdKind {
    pub kind: String,
    pub category: String,
    pub wire_form: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct SpecialIdForm {
    pub kind: String,
    pub wire_form: String,
    pub payload_pattern: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct CapabilityActionRegistry {
    pub actions: Vec<CapabilityAction>,
}

#[derive(Debug, Deserialize)]
pub struct CapabilityAction {
    pub action: String,
    pub category: String,
    pub risk_tier: String,
    #[serde(default)]
    pub required_constraints: Vec<String>,
    #[serde(default)]
    pub required_evaluator_checks: Vec<String>,
    #[serde(default)]
    pub target_event_kinds: Vec<String>,
    #[serde(default)]
    pub grant_authority_actions: Vec<String>,
    pub profile: Option<String>,
    #[serde(default)]
    pub root_control_only: bool,
    #[serde(default)]
    pub subject_only: bool,
    #[serde(default)]
    pub reducer_only: bool,
    pub event_mapping_kind: String,
}

#[derive(Debug, Deserialize)]
pub struct SchemaRegistry {
    pub schemas: Vec<SchemaRegistration>,
}

#[derive(Debug, Deserialize)]
pub struct SchemaRegistration {
    pub schema_id: String,
    pub file: String,
    #[serde(default = "active_status")]
    pub status: String,
}

fn active_status() -> String {
    "active".to_owned()
}

#[derive(Debug, Deserialize)]
pub struct AccountDataRegistry {
    pub account_data_key_patterns: Vec<AccountDataPattern>,
}

#[derive(Debug, Deserialize)]
pub struct AccountDataPattern {
    pub key_pattern: String,
    pub scope: String,
    pub storage: String,
    pub plaintext_schema: Option<String>,
    pub writer_authorities: Vec<String>,
    pub holder_self_operations: Vec<String>,
    pub write_event_kinds: Vec<String>,
    pub deletion_mode: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct AgentRuntimeRegistry {
    pub layers: Vec<AgentRuntimeLayer>,
    pub capability_sets: BTreeMap<String, AgentCapabilitySet>,
    pub feature_additions: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct AgentRuntimeLayer {
    pub layer: String,
    pub missing_reason: String,
    pub recovery: String,
}

#[derive(Debug, Deserialize)]
pub struct AgentCapabilitySet {
    pub selection_rule: String,
    pub activation_operations: Vec<String>,
    pub mandatory_operations: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ContractRegistry {
    pub realm_bootstrap_registry: RealmBootstrapRegistry,
    pub event_kind_registry: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct RealmBootstrapRegistry {
    pub ordinary_collaboration: RealmBootstrapProfile,
    pub direct_conversation: RealmBootstrapProfile,
    pub first_contact: RealmBootstrapFirstContact,
}

#[derive(Debug, Deserialize)]
pub struct RealmBootstrapProfile {
    pub atomic: bool,
    pub all_or_nothing: bool,
    pub genesis_seal_covers_complete_unit: bool,
    pub ordered_slots: Vec<RealmBootstrapSlot>,
}

#[derive(Debug, Deserialize)]
pub struct RealmBootstrapSlot {
    pub event_kind: String,
    pub presence: String,
    pub id_source: Option<String>,
    pub condition: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct RealmBootstrapFirstContact {
    pub require_create_derived_realm_id: bool,
    pub require_complete_genesis_state_commitment: bool,
    pub fail_closed_until_complete: bool,
}

#[derive(Debug, Deserialize)]
pub struct OperationRegistry {
    pub operations: Vec<OperationRegistration>,
    pub surface_groups: Vec<OperationSurfaceGroup>,
    pub high_security_session_authentication_policy: HighSecuritySessionAuthenticationPolicy,
}

#[derive(Debug, Deserialize)]
pub struct OperationRegistration {
    pub operation_id: String,
}

#[derive(Debug, Deserialize)]
pub struct HighSecuritySessionAuthenticationPolicy {
    pub applies_to_operation_id_prefix: String,
    pub unauthenticated_public_projection_operations: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct OperationSurfaceGroup {
    pub surface: String,
    pub surface_class: String,
    pub profile: Option<String>,
    pub operations: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct EventKindRegistry {
    pub event_kinds: Vec<EventKindRegistration>,
}

#[derive(Debug, Deserialize)]
pub struct EventKindRegistration {
    pub event_kind: String,
    pub status: String,
    #[serde(default)]
    pub reducer_input: bool,
    pub id_source: Option<String>,
    pub id_kind: Option<String>,
    #[serde(default)]
    pub id_kinds: Vec<String>,
    #[serde(default)]
    pub pre_state_requirements: Vec<EventPreStateRequirement>,
    pub cell_family: Option<String>,
    #[serde(default)]
    pub cell_writes: Vec<EventCellWrite>,
}

#[derive(Debug, Deserialize)]
pub struct EventCellWrite {
    pub cell_family: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EventPreStateRequirement {
    pub cell_family: String,
    pub subject: EventPreStateSubject,
    /// Optional payload condition drawn from the same closed grammar as
    /// `cell_writes[].condition`. A requirement whose condition does not hold
    /// is not evaluated at all, so the raw AST is carried through verbatim
    /// rather than flattened into a codegen-private shape.
    pub condition: Option<serde_json::Value>,
    pub predicate: EventPreStatePredicate,
    pub failure: EventPreStateFailure,
}

#[derive(Debug, Deserialize)]
pub struct EventPreStateSubject {
    pub field: String,
}

#[derive(Debug, Deserialize)]
pub struct EventPreStatePredicate {
    pub kind: String,
    pub field: String,
    pub payload_field: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EventPreStateFailure {
    pub code: String,
    pub reason_code: String,
}

#[derive(Debug, Deserialize)]
pub struct DeploymentProbeRegistry {
    pub probes: Vec<DeploymentProbe>,
}

#[derive(Debug, Deserialize)]
pub struct DeploymentProbe {
    pub probe_id: String,
    pub tls: DeploymentProbeTls,
}

#[derive(Debug, Deserialize)]
pub struct DeploymentProbeTls {
    pub required_named_group: String,
}
