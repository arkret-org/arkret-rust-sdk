use std::sync::OnceLock;

use arkret_wire::generated::{EVENT_KIND_DESCRIPTORS, SERVICE_OPERATION_DESCRIPTORS};

use super::*;
use crate::generated::{
    CapabilityRiskTier, REGISTERED_ID_KINDS, REGISTERED_SCHEMA_IDS,
    REGISTERED_SPECIAL_FORM_ID_KINDS,
};
use crate::{
    INVITE_DELIVERY_REQUEST_SCHEMA, INVITE_RECEIVE_POLICY_SCHEMA, PRINCIPAL_LOCATOR_SCHEMA,
    PROFILE_ATTESTED_AUDIT_E2EE, PROFILE_DIRECTORY_SERVICE, PROFILE_DISCLOSED_AUDIT_E2EE,
};

const EMBEDDED_ARTIFACTS_SENTINEL: &str = "<embedded-spec-artifacts>";
#[cfg(feature = "embedded-artifacts")]
const EMBEDDED_SPEC_ARTIFACTS_JSON: &str = include_str!("embedded_artifacts.json");
#[cfg(not(feature = "embedded-artifacts"))]
const EMBEDDED_SPEC_ARTIFACTS_JSON: &str = "{}";

static EMBEDDED_SPEC_ARTIFACTS: OnceLock<std::result::Result<BTreeMap<String, Value>, String>> =
    OnceLock::new();
static EMBEDDED_CAPABILITY_ACTIONS: OnceLock<
    std::result::Result<BTreeMap<String, ParsedCapabilityActionDescriptor>, String>,
> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpecArtifactBundle {
    pub schema_registry: Value,
    pub event_kind_registry: Value,
    pub operation_registry: Value,
    #[serde(default)]
    pub operation_clause_registry: Value,
    pub id_kind_registry: Value,
    #[serde(default)]
    pub capability_action_registry: Value,
    #[serde(default)]
    pub conformance_profiles: Value,
    #[serde(skip)]
    pub artifacts_dir: Option<PathBuf>,
}

/// Profile requirement slice loaded from
/// `profiles/conformance-profiles.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRequirement {
    pub profile_id: String,
    #[serde(default)]
    pub inherits: Vec<String>,
    #[serde(default)]
    pub required_endpoints: Vec<String>,
    #[serde(default)]
    pub required_event_kinds: Vec<String>,
    #[serde(default)]
    pub required_schemas: Vec<String>,
    #[serde(default)]
    pub rejected_event_kinds: Vec<String>,
    #[serde(default)]
    pub required_fixtures: Vec<String>,
    #[serde(default)]
    pub required_capability_actions: Vec<String>,
    #[serde(default)]
    pub required_features: Vec<String>,
    #[serde(default)]
    pub required_cell_namespaces: Vec<String>,
    #[serde(default)]
    pub required_cells: Vec<String>,
    #[serde(default)]
    pub required_constraint_kinds: Vec<String>,
}

/// Criticality level a receiver applies when it does not recognise an event's
/// `component_type` / `component_version`.
///
/// Sourced verbatim from the spec event-kind-registry. Per-event overrides via
/// `Event.requirements.critical_extensions` still take precedence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    /// Receivers MUST fail closed (`schema_violation`, `soft_fail`, or
    /// `quarantine` depending on context) when the component is unknown.
    Required,
    /// Receivers MAY warn and ignore the event when the component is unknown.
    Optional,
    /// Receivers MUST silently drop the event when the component is unknown.
    Ignore,
}

/// Component metadata for a single state event kind, as declared by the spec
/// event-kind-registry.
///
/// Returned by [`SpecArtifactBundle::component`]. Multiple event kinds MAY
/// share a `component_type` (e.g. `ak.capability.grant` and
/// `ak.capability.revoke`) — the alias entry will set
/// `component_slot_alias_of` to the canonical kind that owns the slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentDescriptor {
    pub event_kind: String,
    pub component_type: String,
    pub component_version: u64,
    pub criticality: Criticality,
    /// Canonical event kind whose cell this kind aliases, when set. Aliasing
    /// kinds share the same `(component_type, component_version)` as the
    /// canonical kind and resolve to the same cell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_slot_alias_of: Option<String>,
}

/// Machine-readable descriptor for one capability action registry entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedCapabilityActionDescriptor {
    pub action: String,
    pub category: String,
    pub risk_tier: CapabilityRiskTier,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_constraints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_evaluator_checks: Vec<String>,
    pub target_event_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub event_mapping_kind: String,
}

impl SpecArtifactBundle {
    pub fn load(artifacts_dir: impl AsRef<Path>) -> Result<Self> {
        let requested_dir = artifacts_dir.as_ref();
        let (artifacts_dir, registry_dir) = if requested_dir.ends_with("registry") {
            let artifacts_dir = requested_dir
                .parent()
                .unwrap_or(requested_dir)
                .to_path_buf();
            (artifacts_dir, requested_dir.to_path_buf())
        } else {
            (requested_dir.to_path_buf(), requested_dir.join("registry"))
        };
        Ok(Self {
            schema_registry: read_json_artifact(&registry_dir.join("schema-registry.json"))?,
            event_kind_registry: read_json_artifact(
                &registry_dir.join("event-kind-registry.json"),
            )?,
            operation_registry: read_json_artifact(&registry_dir.join("operation-registry.json"))?,
            operation_clause_registry: read_json_artifact(
                &registry_dir.join("operation-clause-registry.json"),
            )?,
            id_kind_registry: read_json_artifact(&registry_dir.join("id-kind-registry.json"))?,
            capability_action_registry: read_json_artifact(
                &registry_dir.join("capability-action-registry.json"),
            )?,
            conformance_profiles: read_json_artifact(
                &artifacts_dir
                    .join("profiles")
                    .join("conformance-profiles.json"),
            )?,
            artifacts_dir: Some(artifacts_dir),
        })
    }

    pub fn load_embedded() -> Result<Self> {
        Ok(Self {
            schema_registry: read_embedded_json_artifact("registry/schema-registry.json")?,
            event_kind_registry: read_embedded_json_artifact("registry/event-kind-registry.json")?,
            operation_registry: read_embedded_json_artifact("registry/operation-registry.json")?,
            operation_clause_registry: read_embedded_json_artifact(
                "registry/operation-clause-registry.json",
            )?,
            id_kind_registry: read_embedded_json_artifact("registry/id-kind-registry.json")?,
            capability_action_registry: read_embedded_json_artifact(
                "registry/capability-action-registry.json",
            )?,
            conformance_profiles: read_embedded_json_artifact(
                "profiles/conformance-profiles.json",
            )?,
            artifacts_dir: Some(PathBuf::from(EMBEDDED_ARTIFACTS_SENTINEL)),
        })
    }

    pub fn drift_report(&self) -> ArtifactDriftReport {
        let registered_schema_ids: Vec<&str> = REGISTERED_SCHEMA_IDS
            .iter()
            .map(|descriptor| descriptor.schema_id)
            .collect();
        let registered_event_kinds: Vec<&str> = EVENT_KIND_DESCRIPTORS
            .iter()
            .map(|descriptor| descriptor.kind)
            .collect();
        let registered_operations: Vec<&str> = SERVICE_OPERATION_DESCRIPTORS
            .iter()
            .map(|descriptor| descriptor.id.as_str())
            .collect();
        let registered_id_kinds: Vec<&str> = REGISTERED_ID_KINDS
            .iter()
            .map(|descriptor| descriptor.kind)
            .collect();
        let registered_special_forms: Vec<&str> = REGISTERED_SPECIAL_FORM_ID_KINDS
            .iter()
            .map(|descriptor| descriptor.kind)
            .collect();
        ArtifactDriftReport {
            checked_files: vec![
                "registry/schema-registry.json".to_owned(),
                "registry/event-kind-registry.json".to_owned(),
                "registry/operation-registry.json".to_owned(),
                "registry/operation-clause-registry.json".to_owned(),
                "registry/id-kind-registry.json".to_owned(),
                "registry/capability-action-registry.json".to_owned(),
                "profiles/conformance-profiles.json".to_owned(),
            ],
            missing_schemas: missing_registry_values(
                &self.schema_registry,
                "schemas",
                "schema_id",
                &registered_schema_ids,
            ),
            missing_event_kinds: missing_registry_values(
                &self.event_kind_registry,
                "event_kinds",
                "event_kind",
                &registered_event_kinds,
            ),
            missing_operations: missing_registry_values(
                &self.operation_registry,
                "operations",
                "operation_id",
                &registered_operations,
            ),
            missing_id_kinds: missing_registry_values(
                &self.id_kind_registry,
                "id_kinds",
                "kind",
                &registered_id_kinds,
            ),
            missing_special_form_id_kinds: missing_registry_values(
                &self.id_kind_registry,
                "special_forms",
                "kind",
                &registered_special_forms,
            ),
            missing_profiles: self.missing_profile_values(SUPPORTED_PROFILE_IDS),
            profile_requirement_issues: self.profile_requirement_drift(),
            missing_payload_validators: self.payload_validator_drift(),
            unlisted_schemas: unlisted_active_registry_values(
                &self.schema_registry,
                "schemas",
                "schema_id",
                SUPPORTED_SCHEMA_IDS,
            ),
            unlisted_event_kinds: unlisted_active_registry_values(
                &self.event_kind_registry,
                "event_kinds",
                "event_kind",
                SUPPORTED_EVENT_KINDS,
            ),
            unlisted_operations: unlisted_active_registry_values(
                &self.operation_registry,
                "operations",
                "operation_id",
                SUPPORTED_SERVICE_OPERATIONS,
            ),
            unlisted_id_kinds: unlisted_active_registry_values(
                &self.id_kind_registry,
                "id_kinds",
                "kind",
                SUPPORTED_ID_KINDS,
            ),
            unlisted_special_form_id_kinds: unlisted_active_registry_values(
                &self.id_kind_registry,
                "special_forms",
                "kind",
                SUPPORTED_SPECIAL_FORM_ID_KINDS,
            ),
        }
    }

    fn payload_validator_drift(&self) -> Vec<String> {
        let Some(artifacts_dir) = &self.artifacts_dir else {
            return Vec::new();
        };
        let catalog = if artifacts_dir == Path::new(EMBEDDED_ARTIFACTS_SENTINEL) {
            event_payload_validator_catalog_from_embedded_spec_artifacts()
        } else {
            event_payload_validator_catalog_from_spec_artifacts(artifacts_dir)
        };
        let catalog = match catalog {
            Ok(catalog) => catalog,
            Err(error) => return vec![format!("catalog_error: {error}")],
        };
        catalog.missing_payload_validators_for(active_standard_durable_event_kinds(
            &self.event_kind_registry,
        ))
    }

    /// Return every `ak.profile.*.vN` ID referenced by the conformance profile
    /// artifact, including profile requirement keys and optional-extension refs.
    pub fn profile_ids(&self) -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        collect_profile_ids(&self.conformance_profiles, &mut ids);
        ids
    }

    /// Return the machine-readable requirements for one profile ID.
    pub fn profile_requirement(&self, profile_id: &str) -> Result<Option<ProfileRequirement>> {
        let Some(requirements) = self
            .conformance_profiles
            .get("profile_requirements")
            .and_then(Value::as_object)
        else {
            return Ok(None);
        };
        let Some(entry) = requirements.get(profile_id) else {
            return Ok(None);
        };
        Ok(Some(ProfileRequirement {
            profile_id: profile_id.to_owned(),
            inherits: optional_string_array(entry, "inherits", profile_id)?,
            required_endpoints: optional_string_array(entry, "required_endpoints", profile_id)?,
            required_event_kinds: optional_string_array(entry, "required_event_kinds", profile_id)?,
            required_schemas: optional_string_array(entry, "required_schemas", profile_id)?,
            rejected_event_kinds: optional_string_array(entry, "rejected_event_kinds", profile_id)?,
            required_fixtures: optional_string_array(entry, "required_fixtures", profile_id)?,
            required_capability_actions: optional_string_array(
                entry,
                "required_capability_actions",
                profile_id,
            )?,
            required_features: optional_string_array(entry, "required_features", profile_id)?,
            required_cell_namespaces: optional_string_array(
                entry,
                "required_cell_namespaces",
                profile_id,
            )?,
            required_cells: optional_string_array(entry, "required_cells", profile_id)?,
            required_constraint_kinds: profile_required_constraint_kinds(entry, profile_id)?,
        }))
    }

    fn missing_profile_values(&self, expected: &[&str]) -> Vec<String> {
        let profiles = self.profile_ids();
        expected
            .iter()
            .filter(|profile| !profiles.contains(**profile))
            .map(|profile| (*profile).to_owned())
            .collect()
    }

    fn profile_requirement_drift(&self) -> Vec<String> {
        let operation_ids = SERVICE_OPERATION_DESCRIPTORS
            .iter()
            .map(|descriptor| descriptor.id.as_str())
            .collect();
        let event_kinds = EVENT_KIND_DESCRIPTORS
            .iter()
            .map(|descriptor| descriptor.kind)
            .collect();
        let schema_ids = REGISTERED_SCHEMA_IDS
            .iter()
            .map(|descriptor| descriptor.schema_id)
            .collect();
        let mut issues = Vec::new();
        let Some(requirements) = self
            .conformance_profiles
            .get("profile_requirements")
            .and_then(Value::as_object)
        else {
            return issues;
        };
        for profile_id in requirements.keys() {
            let requirement = match self.profile_requirement(profile_id) {
                Ok(Some(requirement)) => requirement,
                Ok(None) => continue,
                Err(error) => {
                    issues.push(format!(
                        "{profile_id}: profile requirement parse error: {error}"
                    ));
                    continue;
                }
            };
            profile_requirement_missing_values(
                &mut issues,
                profile_id,
                "required_endpoint",
                &requirement.required_endpoints,
                &operation_ids,
                "REGISTERED_OPERATION_IDS",
            );
            profile_requirement_missing_values(
                &mut issues,
                profile_id,
                "required_event_kind",
                &requirement.required_event_kinds,
                &event_kinds,
                "REGISTERED_EVENT_KINDS",
            );
            profile_requirement_missing_values(
                &mut issues,
                profile_id,
                "required_schema",
                &requirement.required_schemas,
                &schema_ids,
                "REGISTERED_SCHEMA_IDS",
            );
        }
        issues
    }

    /// Look up the [`ComponentDescriptor`] for a state event kind.
    ///
    /// Returns `Ok(None)` when the kind is not registered, `Err` when the
    /// registry entry is malformed (missing `cell_family` or a `.vN` suffix).
    pub fn component(&self, event_kind: &str) -> Result<Option<ComponentDescriptor>> {
        let Some(entry) = registry_entry(
            &self.event_kind_registry,
            "event_kinds",
            "event_kind",
            event_kind,
        ) else {
            return Ok(None);
        };
        // Current v1 registry cell metadata is keyed by `cell_family`; old
        // component_* artifact shapes are rejected as drift.
        let component_type = entry
            .get("cell_family")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "event kind {event_kind} missing cell_family in registry"
                ))
            })?
            .to_owned();
        let component_version = component_type
            .rsplit_once(".v")
            .and_then(|(_, suffix)| suffix.parse::<u64>().ok())
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "event kind {event_kind} cell_family missing .vN version suffix"
                ))
            })?;
        let criticality = Criticality::Required;
        // Alias owner is the first registry entry with the same cell identity.
        let component_slot_alias_of = entry.get("cell_subject").and_then(|cell_subject| {
            let canonical_owner = self.event_kind_registry["event_kinds"]
                .as_array()
                .and_then(|entries| {
                    entries.iter().find_map(|other| {
                        let other_kind = other.get("event_kind").and_then(Value::as_str)?;
                        let other_family = other.get("cell_family").and_then(Value::as_str)?;
                        if other_family != component_type {
                            return None;
                        }
                        if other.get("cell_subject") != Some(cell_subject) {
                            return None;
                        }
                        Some(other_kind.to_owned())
                    })
                })?;
            if canonical_owner == event_kind {
                None
            } else {
                Some(canonical_owner)
            }
        });
        Ok(Some(ComponentDescriptor {
            event_kind: event_kind.to_owned(),
            component_type,
            component_version,
            criticality,
            component_slot_alias_of,
        }))
    }

    /// Look up a capability action descriptor from the loaded spec artifact.
    ///
    /// Returns `Ok(None)` for actions absent from the registry. The caller can
    /// then apply the spec's fail-closed default for unknown actions.
    pub fn capability_action(
        &self,
        action: &str,
    ) -> Result<Option<ParsedCapabilityActionDescriptor>> {
        capability_action_from_registry(&self.capability_action_registry, action)
    }
}

/// Two-way drift between the SDK's declared spec coverage (`SUPPORTED_*`)
/// and the spec's registry/profile artifacts.
///
/// `missing_*` lists entries the SDK declares coverage for that the spec no
/// longer ships. These are hard errors and are surfaced by [`Self::validate`].
/// `profile_requirement_issues` lists profile requirement references that point
/// at operation/schema/event constants missing from the SDK-declared coverage.
/// `unlisted_*` lists entries the spec ships that the SDK has not yet declared
/// coverage for. These are hard errors because the SDK tracks the active v1
/// registry surface.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDriftReport {
    pub checked_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_schemas: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_event_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_operations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_id_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_special_form_id_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile_requirement_issues: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_payload_validators: Vec<String>,
    /// Active spec-side entries the SDK has not declared coverage for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlisted_schemas: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlisted_event_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlisted_operations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlisted_id_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlisted_special_form_id_kinds: Vec<String>,
}

impl ArtifactDriftReport {
    pub fn validate(&self) -> Result<()> {
        if self.missing_schemas.is_empty()
            && self.missing_event_kinds.is_empty()
            && self.missing_operations.is_empty()
            && self.missing_id_kinds.is_empty()
            && self.missing_special_form_id_kinds.is_empty()
            && self.missing_profiles.is_empty()
            && self.profile_requirement_issues.is_empty()
            && self.missing_payload_validators.is_empty()
            && !self.has_unlisted()
        {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "spec artifact drift detected: schemas={:?} events={:?} operations={:?} ids={:?} special_forms={:?} profiles={:?} profile_requirements={:?} payload_validators={:?} unlisted_schemas={:?} unlisted_events={:?} unlisted_operations={:?} unlisted_ids={:?} unlisted_special_forms={:?}",
                self.missing_schemas,
                self.missing_event_kinds,
                self.missing_operations,
                self.missing_id_kinds,
                self.missing_special_form_id_kinds,
                self.missing_profiles,
                self.profile_requirement_issues,
                self.missing_payload_validators,
                self.unlisted_schemas,
                self.unlisted_event_kinds,
                self.unlisted_operations,
                self.unlisted_id_kinds,
                self.unlisted_special_form_id_kinds
            )))
        }
    }

    /// True when the spec ships active entries the SDK does not declare.
    pub fn has_unlisted(&self) -> bool {
        !self.unlisted_schemas.is_empty()
            || !self.unlisted_event_kinds.is_empty()
            || !self.unlisted_operations.is_empty()
            || !self.unlisted_id_kinds.is_empty()
            || !self.unlisted_special_form_id_kinds.is_empty()
    }
}

/// SDK-declared coverage of spec artifacts.
///
/// These constants enumerate the schemas, event kinds, service operations
/// profile IDs and typed-ID kinds the SDK recognises from the v1 spec artifacts.
/// [`SpecArtifactBundle::drift_report`] cross-checks them against the live
/// registry and produces:
///
/// * `missing_*` (hard error) - the SDK declares coverage for an entry the spec no longer ships.
///   Surfaced by [`ArtifactDriftReport::validate`]; bring the constant in line with the spec when
///   this fires.
/// * `unlisted_*` (hard error) - the spec ships an active entry the SDK has not declared coverage
///   for.
///
/// Update this constant whenever the SDK adds typed support for a new
/// schema; the drift report will then enforce that the spec still ships it.
pub const SUPPORTED_SCHEMA_IDS: &[&str] = &[
    "ak.schema.account_data_encrypted_value.v1",
    "ak.schema.agent_requested_scope_disclosure.v1",
    "ak.schema.device_reanchor.v1",
    "ak.schema.mls_governance_proof_bundle.v1",
    // Realm/Space schemas: `ak.schema.realm.v1` is the security-boundary
    // schema; `ak.schema.space.v1` is the product container schema.
    "ak.schema.realm.v1",
    REALM_JOIN_CANDIDATE_SCHEMA,
    "ak.schema.actor_profile.v1",
    "ak.schema.accountability_grant.v1",
    "ak.schema.message.v1",
    "ak.schema.content_block_poll.v1",
    "ak.schema.morph.v1",
    "ak.schema.morph.customer_risk.v1",
    "ak.schema.morph.customer_risk.ext.v1",
    "ak.schema.relation.v1",
    "ak.schema.policy.v1",
    "ak.schema.invite.v1",
    PRINCIPAL_LOCATOR_SCHEMA,
    INVITE_DELIVERY_REQUEST_SCHEMA,
    INVITE_RECEIVE_POLICY_SCHEMA,
    "ak.schema.availability_receipt.v1",
    "ak.schema.event_batch_receipt.v1",
    "ak.schema.patch.v1",
    "ak.schema.range_completeness_attestation.v1",
    "ak.schema.ice_config_response.v1",
    "ak.schema.device_message.v1",
    "ak.schema.blob.v1",
    "ak.schema.media_metadata.v1",
    "ak.schema.key_backup.v1",
    "ak.schema.notification.v1",
    "ak.schema.read_cursor.v1",
    "ak.schema.read_receipt.v1",
    "ak.schema.did_key_log_entry.v1",
    "ak.schema.did_continuity_proof.v1",
    "ak.schema.identity_receipt.v1",
    "ak.schema.identity_link.v1",
    "ak.schema.handle_claim.v1",
    "ak.schema.member_delivery_binding_candidate.v1",
    // R3.1 spec-sync (arkret-spec @ 7157ee8, 2026-05-27).
    "ak.schema.member_identity.v1",
    // R3.2 spec-sync (arkret-spec @ b56cab1, 2026-05-28).
    "ak.schema.list_handles_for_subject_response.v1",
    "ak.schema.grant_constraint.v1",
    "ak.schema.resource_selector.v1",
    "ak.schema.mimi_interop.v1",
    "ak.schema.moderation_report.v1",
    "ak.schema.moderation_queue_item.v1",
    "ak.schema.applet.v1",
    "ak.schema.agent_selector_claim.v1",
    "ak.schema.audit_ryw_receipt.v1",
    "ak.schema.erasure_receipt.v1",
    "ak.schema.erasure_verification_stub.v1",
    PERSONAL_PRODUCTIVITY_SCHEMA,
    DRAFT_SYNC_SCHEMA,
    CALENDAR_EVENT_SCHEMA,
    DISAPPEARING_MESSAGES_SCHEMA,
    SEARCH_SERVICE_SCHEMA,
    "ak.schema.cross_signing_publish.v1",
    "ak.schema.cross_signing_reset.v1",
    "ak.schema.inclusion_list.v1",
    "ak.schema.seal_transparency.v1",
    // Round R2/R3 (2026-05-20) — broadcast ephemeral envelope, moderation
    // appeal payloads, structured attestation evidence.
    "ak.schema.ephemeral_envelope.v1",
    "ak.schema.moderation_appeal.v1",
    "ak.schema.attestation_evidence.v1",
    // AKP-0007 (spec b7d35be) — Circle primitive schema.
    "ak.schema.circle.v1",
    // Key-backup hardening (B-C, spec head 37ce729) — recovery policy and
    // recovery receipt schemas.
    "ak.schema.recovery_policy.v1",
    "ak.schema.recovery_receipt.v1",
    "ak.schema.recovery_session.v1",
    "ak.schema.service_describe.v1",
    EVENT_SCHEMA,
    EVENT_PAYLOAD_SCHEMA,
    STRAND_SCHEMA,
    SPACE_SCHEMA,
    ANCHOR_SCHEMA,
    BOTTOM_SCHEMA,
    SNAPSHOT_SCHEMA,
    CAPABILITY_SCHEMA,
    CURSOR_SCHEMA,
    ENCRYPTED_ENVELOPE_SCHEMA,
    ACCOUNT_SUBSCRIBE_FRAME_SCHEMA,
    VIEW_SCHEMA,
    // Spec-sync (schema-registry.json) — service-operation DTO schemas and
    // newer feature schemas the registry ships that the SDK had not yet
    // declared coverage for.
    "ak.schema.account_operations.v1",
    "ak.schema.account_data_operations.v1",
    "ak.schema.agent_pairing_bootstrap.v1",
    "ak.schema.agent_operations.v1",
    "ak.schema.applet_edge_operations.v1",
    "ak.schema.applet_ghost_operations.v1",
    "ak.schema.applet_install_operations.v1",
    "ak.schema.applet_install_plan.v1",
    "ak.schema.applet_package.v1",
    "ak.schema.applet_registration_epoch_transcript.v1",
    "ak.schema.applet_widget_declaration.v1",
    "ak.schema.authz_operations.v1",
    "ak.schema.blob_operations.v1",
    "ak.schema.call_recording_artifact.v1",
    "ak.schema.circle_operations.v1",
    "ak.schema.common_ids.v1",
    "ak.schema.consent_operations.v1",
    "ak.schema.contact_operations.v1",
    "ak.schema.delivery_binding_stale.v1",
    "ak.schema.directory_operations.v1",
    "ak.schema.file_transfer.v1",
    "ak.schema.key_backup_active_series.v1",
    "ak.schema.key_backup_plaintext.v1",
    "ak.schema.key_backup_unlock_proof.v1",
    "ak.schema.keypackage_operations.v1",
    "ak.schema.keys_operations.v1",
    "ak.schema.media_operations.v1",
    "ak.schema.mimi_operations.v1",
    "ak.schema.peer_contact_delivery_request.v1",
    "ak.schema.pin.v1",
    "ak.schema.push_operations.v1",
    "ak.schema.query.v1",
    "ak.schema.read_cursor_operations.v1",
    "ak.schema.realm_link_operations.v1",
    "ak.schema.realm_organization_operations.v1",
    "ak.schema.realm_policy_server_operations.v1",
    "ak.schema.realm_read_operations.v1",
    "ak.schema.rsvp.v1",
    "ak.schema.service_operation_dtos.v1",
    "ak.schema.sdk_conformance_claim.v1",
    "ak.schema.key_transparency.v1",
];

/// Active event kinds the SDK recognises from the spec registry.
/// Every registered event kind has a generated typed representation and
/// descriptor-backed validation in this SDK.
pub const SUPPORTED_EVENT_KINDS: &[&str] =
    arkret_wire::generated::REGISTERED_EVENT_KIND_WIRE_VALUES;

/// Every registered service operation has generated route and metadata support.
pub const SUPPORTED_SERVICE_OPERATIONS: &[&str] =
    arkret_wire::generated::REGISTERED_SERVICE_OPERATION_IDS;

/// Profile IDs that still appear as hand-written SDK constants or service
/// requirement fixtures and are therefore hard-checked against the profile
/// artifact.
pub const SUPPORTED_PROFILE_IDS: &[&str] = &[
    PROFILE_DIRECTORY_SERVICE,
    PROFILE_ATTESTED_AUDIT_E2EE,
    PROFILE_DISCLOSED_AUDIT_E2EE,
];

pub const SUPPORTED_ID_KINDS: &[&str] = &[
    "actor_profile",
    "announce",
    "appeal",
    "applet",
    "attestation",
    "backup",
    "batch",
    "blob",
    "block",
    "call",
    "capability",
    "consent",
    "strand",
    "chunk",
    "claim",
    "device",
    "device_message",
    "event",
    "filter",
    "frame",
    "franking_proof",
    "grant",
    "invite",
    "key_event",
    "message",
    "morph",
    "notification",
    "read_cursor",
    "policy",
    "presentation",
    "receipt",
    "relation",
    "report",
    "realm",
    "moderation_queue_item",
    "request",
    "snapshot",
    "space",
    "subscription",
    "transaction",
    "view",
    // Spec-sync (id-kind-registry.json) — typed id kinds the registry ships
    // that the SDK had not yet declared. audit_* back the audit release session
    // model; recovery_session/backup_series back key-backup recovery;
    // rtc_participant backs realtime call participants; circle backs AKP-0007.
    "audit_binding",
    "audit_release",
    "audit_session",
    "backup_series",
    "circle",
    "recovery_session",
    "rtc_participant",
];

/// Special-form id kinds (non-UUIDv7) the SDK declares coverage for from
/// the spec id-kind-registry `special_forms` array. Round R2/R3 (2026-05-20)
/// adds `trust_domain` (`ak:trust_domain:<scope>`). These are validated
/// separately from `SUPPORTED_ID_KINDS` because the spec lists them
/// under `special_forms`, not `id_kinds`.
pub const SUPPORTED_SPECIAL_FORM_ID_KINDS: &[&str] = &[
    "seal",
    "blob",
    "cell",
    "cursor",
    "mls",
    "pseudonym",
    "plan",
    "service_registration_receipt",
    "trust_domain",
];

pub fn default_spec_artifacts_dir() -> Option<PathBuf> {
    if let Ok(artifacts_dir) = std::env::var("ARKRET_SPEC_ARTIFACTS") {
        return Some(PathBuf::from(artifacts_dir));
    }
    None
}

fn default_spec_artifact_bundle() -> Result<SpecArtifactBundle> {
    if let Some(artifacts_dir) = default_spec_artifacts_dir() {
        SpecArtifactBundle::load(artifacts_dir)
    } else {
        SpecArtifactBundle::load_embedded()
    }
}

pub fn artifact_drift_report_from_default_location() -> Result<Option<ArtifactDriftReport>> {
    Ok(Some(default_spec_artifact_bundle()?.drift_report()))
}

pub fn schema_registry_from_spec_artifacts(
    artifacts_dir: impl AsRef<Path>,
) -> Result<ProtocolSchemaRegistry> {
    let artifacts_dir = artifacts_dir.as_ref();
    let bundle = SpecArtifactBundle::load(artifacts_dir)?;
    let mut registry = ProtocolSchemaRegistry::new();
    let schemas = bundle
        .schema_registry
        .get("schemas")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Protocol("schema registry missing schemas".to_owned()))?;
    for entry in schemas {
        let schema_id = entry
            .get("schema_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Protocol("schema registry entry missing schema_id".to_owned()))?;
        let file = entry
            .get("file")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Protocol(format!("schema artifact {schema_id} has no file")))?;
        let schema_path = artifacts_dir.join(file);
        let schema = read_json_artifact(&schema_path)?;
        registry.register(schema_id, schema);
    }
    Ok(registry)
}

pub fn schema_registry_from_embedded_spec_artifacts() -> Result<ProtocolSchemaRegistry> {
    let bundle = SpecArtifactBundle::load_embedded()?;
    let mut registry = ProtocolSchemaRegistry::new();
    let schemas = bundle
        .schema_registry
        .get("schemas")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Protocol("schema registry missing schemas".to_owned()))?;
    for entry in schemas {
        let schema_id = entry
            .get("schema_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Protocol("schema registry entry missing schema_id".to_owned()))?;
        let file = entry
            .get("file")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Protocol(format!("schema artifact {schema_id} has no file")))?;
        let schema = read_embedded_json_artifact(file)?;
        registry.register(schema_id, schema);
    }
    Ok(registry)
}

fn active_standard_durable_event_kinds(registry: &Value) -> Vec<&str> {
    let Some(entries) = registry.get("event_kinds").and_then(Value::as_array) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter(|entry| entry.get("status").and_then(Value::as_str) == Some("active"))
        .filter(|entry| entry.get("wire_scope").and_then(Value::as_str) == Some("durable_event"))
        .filter_map(|entry| entry.get("event_kind").and_then(Value::as_str))
        .filter(|event_kind| events::is_standard_event_kind(event_kind))
        .collect()
}

pub fn schema_registry_from_default_spec_artifacts() -> Result<Option<ProtocolSchemaRegistry>> {
    if let Some(artifacts_dir) = default_spec_artifacts_dir() {
        Ok(Some(schema_registry_from_spec_artifacts(artifacts_dir)?))
    } else {
        Ok(Some(schema_registry_from_embedded_spec_artifacts()?))
    }
}

/// Look up a capability action descriptor from the embedded spec artifact.
///
/// This is the runtime-friendly path for services that need to fail closed on
/// unknown or unsupported capability actions without reading `arkret-spec` from
/// the local filesystem.
pub fn embedded_capability_action(
    action: &str,
) -> Result<Option<&'static ParsedCapabilityActionDescriptor>> {
    match EMBEDDED_CAPABILITY_ACTIONS.get_or_init(|| {
        let artifacts = embedded_spec_artifacts().map_err(|error| error.to_string())?;
        let registry = artifacts
            .get("registry/capability-action-registry.json")
            .ok_or_else(|| {
                "embedded spec artifact registry/capability-action-registry.json is missing"
                    .to_owned()
            })?;
        capability_actions_from_registry(registry).map_err(|error| error.to_string())
    }) {
        Ok(actions) => Ok(actions.get(action)),
        Err(error) => Err(Error::Protocol(error.clone())),
    }
}

fn capability_action_from_registry(
    registry: &Value,
    action: &str,
) -> Result<Option<ParsedCapabilityActionDescriptor>> {
    let Some(entry) = registry_entry(registry, "actions", "action", action) else {
        return Ok(None);
    };
    Ok(Some(capability_action_from_entry(entry, action)?))
}

fn capability_actions_from_registry(
    registry: &Value,
) -> Result<BTreeMap<String, ParsedCapabilityActionDescriptor>> {
    let entries = registry
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Protocol("capability action registry missing actions".to_owned()))?;
    let mut actions = BTreeMap::new();
    for entry in entries {
        let action = required_registry_string(entry, "action", "capability action")?;
        let descriptor = capability_action_from_entry(entry, action)?;
        actions.insert(action.to_owned(), descriptor);
    }
    Ok(actions)
}

fn capability_action_from_entry(
    entry: &Value,
    action: &str,
) -> Result<ParsedCapabilityActionDescriptor> {
    let action_field = required_registry_string(entry, "action", action)?;
    if action_field != action {
        return Err(Error::Protocol(format!(
            "capability action registry lookup for {action} returned {action_field}"
        )));
    }
    let risk_tier = match required_registry_string(entry, "risk_tier", action)? {
        "low" => CapabilityRiskTier::Low,
        "medium" => CapabilityRiskTier::Medium,
        "high" => CapabilityRiskTier::High,
        other => {
            return Err(Error::Protocol(format!(
                "capability action {action} has unknown risk_tier {other:?}"
            )));
        }
    };
    let profile = match entry.get("profile") {
        Some(Value::String(profile)) => Some(profile.clone()),
        Some(Value::Null) | None => None,
        Some(_) => {
            return Err(Error::Protocol(format!(
                "capability action {action} field profile must be string or null"
            )));
        }
    };
    Ok(ParsedCapabilityActionDescriptor {
        action: action.to_owned(),
        category: required_registry_string(entry, "category", action)?.to_owned(),
        risk_tier,
        required_constraints: registry_string_array(entry, "required_constraints", action)?,
        required_evaluator_checks: registry_string_array(
            entry,
            "required_evaluator_checks",
            action,
        )?,
        target_event_kinds: registry_string_array(entry, "target_event_kinds", action)?,
        profile,
        event_mapping_kind: required_registry_string(entry, "event_mapping_kind", action)?
            .to_owned(),
    })
}

fn required_registry_string<'a>(entry: &'a Value, field: &str, label: &str) -> Result<&'a str> {
    entry.get(field).and_then(Value::as_str).ok_or_else(|| {
        Error::Protocol(format!(
            "registry entry {label} field {field} must be a string"
        ))
    })
}

fn registry_string_array(entry: &Value, field: &str, label: &str) -> Result<Vec<String>> {
    let Some(raw) = entry.get(field) else {
        return Ok(Vec::new());
    };
    let array = raw.as_array().ok_or_else(|| {
        Error::Protocol(format!(
            "registry entry {label} field {field} must be an array"
        ))
    })?;
    array
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                Error::Protocol(format!(
                    "registry entry {label} field {field} contains a non-string"
                ))
            })
        })
        .collect()
}

fn collect_profile_ids(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::String(text) if is_profile_id(text) => {
            out.insert(text.clone());
        }
        Value::Array(values) => {
            for value in values {
                collect_profile_ids(value, out);
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                if is_profile_id(key) {
                    out.insert(key.clone());
                }
                collect_profile_ids(value, out);
            }
        }
        _ => {}
    }
}

fn is_profile_id(value: &str) -> bool {
    value.starts_with("ak.profile.") && value.rsplit_once(".v").is_some()
}

fn optional_string_array(value: &Value, field: &str, profile_id: &str) -> Result<Vec<String>> {
    let Some(raw) = value.get(field) else {
        return Ok(Vec::new());
    };
    let array = raw.as_array().ok_or_else(|| {
        Error::Protocol(format!(
            "profile {profile_id} field {field} must be an array"
        ))
    })?;
    let mut out = Vec::with_capacity(array.len());
    for item in array {
        let text = item.as_str().ok_or_else(|| {
            Error::Protocol(format!(
                "profile {profile_id} field {field} contains a non-string"
            ))
        })?;
        out.push(text.to_owned());
    }
    Ok(out)
}

fn profile_required_constraint_kinds(value: &Value, profile_id: &str) -> Result<Vec<String>> {
    let mut out = optional_string_array(value, "required_constraint_kinds", profile_id)?;
    out.extend(optional_string_array(
        value,
        "required_constraint_types",
        profile_id,
    )?);
    out.extend(optional_string_array(
        value,
        "required_constraint_subtypes",
        profile_id,
    )?);
    out.sort();
    out.dedup();
    Ok(out)
}

fn profile_requirement_missing_values(
    issues: &mut Vec<String>,
    profile_id: &str,
    requirement_field: &str,
    required: &[String],
    declared: &BTreeSet<&str>,
    declared_label: &str,
) {
    for value in required {
        if !declared.contains(value.as_str()) {
            issues.push(format!(
                "{profile_id}: {requirement_field} {value} missing from {declared_label}"
            ));
        }
    }
}

fn read_json_artifact(path: &Path) -> Result<Value> {
    let text = fs::read_to_string(path)
        .map_err(|error| Error::Protocol(format!("failed to read {}: {error}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|error| Error::Protocol(format!("failed to parse {}: {error}", path.display())))
}

fn embedded_spec_artifacts() -> Result<&'static BTreeMap<String, Value>> {
    match EMBEDDED_SPEC_ARTIFACTS.get_or_init(|| {
        serde_json::from_str(EMBEDDED_SPEC_ARTIFACTS_JSON)
            .map_err(|error| format!("failed to parse embedded spec artifacts: {error}"))
    }) {
        Ok(artifacts) => Ok(artifacts),
        Err(error) => Err(Error::Protocol(error.clone())),
    }
}

pub(super) fn read_embedded_json_artifact(path: &str) -> Result<Value> {
    embedded_spec_artifacts()?
        .get(path)
        .cloned()
        .ok_or_else(|| Error::Protocol(format!("embedded spec artifact {path} is missing")))
}

pub fn embedded_json_artifact(path: &str) -> Result<Value> {
    read_embedded_json_artifact(path)
}

#[doc(hidden)]
pub fn embedded_spec_artifact_paths() -> Result<Vec<String>> {
    Ok(embedded_spec_artifacts()?.keys().cloned().collect())
}

/// Canonical error code strings declared in the embedded
/// `error-code-registry.json` snapshot, in registry order.
pub fn embedded_error_code_codes() -> Result<Vec<String>> {
    let registry = read_embedded_json_artifact("registry/error-code-registry.json")?;
    let codes = registry
        .get("codes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Error::Protocol("embedded error-code-registry.json missing codes array".to_owned())
        })?;
    codes
        .iter()
        .map(|entry| {
            entry
                .get("code")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    Error::Protocol(
                        "embedded error-code-registry.json code entry missing code".to_owned(),
                    )
                })
        })
        .collect()
}

/// Canonical subordinate reason-code strings declared in the embedded
/// `error-code-registry.json` snapshot, in registry order.
pub fn embedded_error_code_reason_codes() -> Result<Vec<String>> {
    let registry = read_embedded_json_artifact("registry/error-code-registry.json")?;
    let codes = registry
        .get("reason_codes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Error::Protocol(
                "embedded error-code-registry.json missing reason_codes array".to_owned(),
            )
        })?;
    codes
        .iter()
        .map(|entry| {
            entry
                .get("code")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    Error::Protocol(
                        "embedded error-code-registry.json reason entry missing code".to_owned(),
                    )
                })
        })
        .collect()
}

/// The union of every error identifier declared in the embedded
/// `error-code-registry.json` snapshot — both the top-level `codes`
/// (canonical error codes) and the `reason_codes` (sub-reasons).
///
/// The spec registry splits identifiers across two arrays: canonical error
/// codes carry an `http_status` and live under `codes`, while finer-grained
/// sub-reasons carry `applies_to` and live under `reason_codes`. Some curated
/// `REASON_*` constants (e.g. the Reaction and direct-conversation sub-reasons)
/// are registered by the spec under `codes` rather than `reason_codes`, so the
/// cross-check in [`crate::error`] resolves against this union to avoid false
/// drift on the array a given identifier happens to be filed under.
pub fn embedded_error_code_identifiers() -> Result<BTreeSet<String>> {
    let registry = read_embedded_json_artifact("registry/error-code-registry.json")?;
    let mut identifiers = BTreeSet::new();
    for array_field in ["codes", "reason_codes"] {
        if let Some(entries) = registry.get(array_field).and_then(Value::as_array) {
            identifiers.extend(
                entries
                    .iter()
                    .filter_map(|entry| entry.get("code").and_then(Value::as_str))
                    .map(str::to_owned),
            );
        }
    }
    if identifiers.is_empty() {
        return Err(Error::Protocol(
            "embedded error-code-registry.json declared no codes or reason_codes".to_owned(),
        ));
    }
    Ok(identifiers)
}

fn missing_registry_values(
    registry: &Value,
    array_field: &str,
    key_field: &str,
    expected: &[&str],
) -> Vec<String> {
    expected
        .iter()
        .filter(|value| registry_entry(registry, array_field, key_field, value).is_none())
        .map(|value| (*value).to_owned())
        .collect()
}

/// Inverse of [`missing_registry_values`]: list active registry entries the
/// SDK has not declared coverage for. Filters on `status == "active"` so the
/// strict drift report doesn't flag inactive/profile-extension entries.
fn unlisted_active_registry_values(
    registry: &Value,
    array_field: &str,
    key_field: &str,
    declared: &[&str],
) -> Vec<String> {
    let declared_set: BTreeSet<&str> = declared.iter().copied().collect();
    let Some(entries) = registry.get(array_field).and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries {
        if entry
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("active")
            != "active"
        {
            continue;
        }
        let Some(key) = entry.get(key_field).and_then(Value::as_str) else {
            continue;
        };
        if !declared_set.contains(key) {
            out.push(key.to_owned());
        }
    }
    out.sort();
    out
}

pub(super) fn registry_entry<'a>(
    registry: &'a Value,
    array_field: &str,
    key_field: &str,
    expected_key: &str,
) -> Option<&'a Value> {
    registry[array_field]
        .as_array()?
        .iter()
        .find(|entry| entry[key_field].as_str() == Some(expected_key))
}

#[cfg(test)]
mod tests {
    use arkret_wire::{ErrorCode, REASON_CODE_DESCRIPTORS};

    use super::*;

    fn local_spec_artifacts_dir() -> Option<PathBuf> {
        if let Some(dir) = default_spec_artifacts_dir() {
            return Some(dir);
        }
        let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("arkret-spec")
            .join("spec")
            .join("v1")
            .join("artifacts");
        candidate.is_dir().then_some(candidate)
    }

    fn collect_json_artifact_paths(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
        let entries = fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", dir.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|error| {
                    panic!("failed to read entry in {}: {error}", dir.display())
                })
                .path();
            if path.is_dir() {
                collect_json_artifact_paths(root, &path, out);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or_else(|error| {
                        panic!(
                            "failed to strip {} from {}: {error}",
                            root.display(),
                            path.display()
                        )
                    })
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel);
            }
        }
    }

    fn generated_error_codes() -> Vec<String> {
        ErrorCode::ALL
            .iter()
            .map(|code| code.as_str().to_owned())
            .collect()
    }

    fn live_registry_codes(field: &str) -> Option<Vec<String>> {
        let artifacts_dir = local_spec_artifacts_dir()?;
        let registry_path = artifacts_dir
            .join("registry")
            .join("error-code-registry.json");
        let text = fs::read_to_string(&registry_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", registry_path.display()));
        let registry: Value = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", registry_path.display()));
        Some(
            registry
                .get(field)
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("live error-code-registry missing {field}"))
                .iter()
                .map(|entry| {
                    entry
                        .get("code")
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| panic!("live {field} entry missing code"))
                        .to_owned()
                })
                .collect(),
        )
    }

    #[cfg(feature = "embedded-artifacts")]
    #[test]
    fn generated_error_codes_match_embedded_registry() {
        let mut embedded = embedded_error_code_codes().expect("embedded error codes must load");
        let mut generated = generated_error_codes();
        embedded.sort_unstable();
        generated.sort_unstable();
        assert_eq!(generated, embedded);
    }

    #[test]
    fn generated_error_codes_match_live_registry_when_available() {
        let Some(mut live) = live_registry_codes("codes") else {
            return;
        };
        let mut generated = generated_error_codes();
        live.sort_unstable();
        generated.sort_unstable();
        assert_eq!(generated, live);
    }

    #[cfg(feature = "embedded-artifacts")]
    #[test]
    fn generated_reason_codes_match_embedded_registry() {
        let mut embedded =
            embedded_error_code_reason_codes().expect("embedded reason codes must load");
        let mut generated: Vec<String> = REASON_CODE_DESCRIPTORS
            .iter()
            .map(|descriptor| descriptor.code.to_owned())
            .collect();
        embedded.sort_unstable();
        generated.sort_unstable();
        assert_eq!(generated, embedded);
    }

    #[test]
    fn generated_reason_codes_match_live_registry_when_available() {
        let Some(mut live) = live_registry_codes("reason_codes") else {
            return;
        };
        let mut generated: Vec<String> = REASON_CODE_DESCRIPTORS
            .iter()
            .map(|descriptor| descriptor.code.to_owned())
            .collect();
        live.sort_unstable();
        generated.sort_unstable();
        assert_eq!(generated, live);
    }

    #[test]
    fn embedded_spec_artifacts_match_live_spec_when_available() {
        let Some(artifacts_dir) = local_spec_artifacts_dir() else {
            if std::env::var("ARKRET_REQUIRE_SPEC").as_deref() == Ok("1") {
                panic!(
                    "ARKRET_REQUIRE_SPEC=1 but no spec artifacts directory was found; \
                     set ARKRET_SPEC_ARTIFACTS or provide a ../arkret-spec co-checkout"
                );
            }
            return;
        };
        let embedded: BTreeSet<String> = embedded_spec_artifact_paths()
            .expect("embedded artifacts must load")
            .into_iter()
            .collect();
        let mut live = BTreeSet::new();
        collect_json_artifact_paths(&artifacts_dir, &artifacts_dir, &mut live);

        assert_eq!(embedded, live, "embedded spec artifact path set drifted");
        for path in live {
            let live_path = artifacts_dir.join(&path);
            let live_text = fs::read_to_string(&live_path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", live_path.display()));
            let live_value: Value = serde_json::from_str(&live_text)
                .unwrap_or_else(|error| panic!("failed to parse {}: {error}", live_path.display()));
            let embedded_value = embedded_json_artifact(&path)
                .unwrap_or_else(|error| panic!("embedded artifact {path} failed to load: {error}"));
            assert_eq!(embedded_value, live_value, "artifact {path} drifted");
        }
    }

    #[test]
    fn component_descriptor_resolves_canonical_and_alias_kinds() {
        let bundle = SpecArtifactBundle::load_embedded().unwrap();
        let canonical = bundle
            .component("ak.capability.grant")
            .unwrap()
            .expect("ak.capability.grant should be registered");
        assert_eq!(canonical.criticality, Criticality::Required);
        assert!(canonical.component_type.starts_with("ak.component."));
        assert!(canonical.component_version >= 1);
        assert!(canonical.component_slot_alias_of.is_none());

        let alias = bundle
            .component("ak.capability.revoke")
            .unwrap()
            .expect("ak.capability.revoke should be registered");
        assert_eq!(
            alias.component_slot_alias_of.as_deref(),
            Some("ak.capability.grant"),
            "ak.capability.revoke should slot-alias ak.capability.grant"
        );
        assert_eq!(alias.component_type, canonical.component_type);
        assert_eq!(alias.component_version, canonical.component_version);
        assert!(bundle.component("ak.bogus.kind").unwrap().is_none());
    }

    #[test]
    fn embedded_capability_action_reads_core_write_surface() {
        let message = embedded_capability_action("ak.message.create")
            .expect("embedded registry should parse")
            .expect("message create should be registered");
        assert_eq!(message.risk_tier, CapabilityRiskTier::Medium);
        assert_eq!(message.profile, None);
        assert_eq!(message.target_event_kinds, vec!["ak.message.create"]);

        let policy = embedded_capability_action("ak.policy.manage")
            .expect("embedded registry should parse")
            .expect("policy manage should be registered");
        assert_eq!(policy.risk_tier, CapabilityRiskTier::High);
        assert_eq!(policy.event_mapping_kind, "aggregate_admin");
    }

    #[test]
    fn embedded_capability_action_exposes_candidate_profile_gate() {
        let action = embedded_capability_action("ak.realm.join.review")
            .expect("embedded registry should parse")
            .expect("candidate action should be registered");
        assert_eq!(
            action.profile.as_deref(),
            Some("ak.profile.candidate.join_policy.v1")
        );
        assert_eq!(action.risk_tier, CapabilityRiskTier::Medium);
    }

    #[test]
    fn embedded_capability_action_returns_none_for_unknown_action() {
        assert!(
            embedded_capability_action("member.application.create")
                .expect("embedded registry should parse")
                .is_none()
        );
    }
}
