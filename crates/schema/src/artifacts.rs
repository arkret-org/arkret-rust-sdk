use std::sync::OnceLock;

use arkret_wire::ProfileId;
use arkret_wire::generated::{EVENT_KIND_DESCRIPTORS, SERVICE_OPERATION_DESCRIPTORS};

use super::*;
use crate::generated::{
    CapabilityRiskTier, REGISTERED_ID_KINDS, REGISTERED_SCHEMA_IDS,
    REGISTERED_SPECIAL_FORM_ID_KINDS,
};

const EMBEDDED_ARTIFACTS_SENTINEL: &str = "<embedded-spec-artifacts>";
/// The registry `status` that marks an entry part of the v1 surface the SDK
/// must cover. Registries that omit the field are read as active.
const ACTIVE_STATUS: &str = "active";
#[cfg(any(feature = "embedded-artifacts", test))]
const EMBEDDED_SPEC_ARTIFACTS_JSON: &str = include_str!("embedded_artifacts.json");
#[cfg(not(any(feature = "embedded-artifacts", test)))]
const EMBEDDED_SPEC_ARTIFACTS_JSON: &str = "{}";
#[cfg(any(feature = "embedded-artifacts", test))]
const EMBEDDED_OPENAPI_YAML: &str = include_str!("embedded_openapi.yaml");
#[cfg(not(any(feature = "embedded-artifacts", test)))]
const EMBEDDED_OPENAPI_YAML: &str = "";

static EMBEDDED_SPEC_ARTIFACTS: OnceLock<std::result::Result<BTreeMap<String, Value>, String>> =
    OnceLock::new();
static EMBEDDED_CAPABILITY_ACTIONS: OnceLock<
    std::result::Result<BTreeMap<String, ParsedCapabilityActionDescriptor>, String>,
> = OnceLock::new();
static EMBEDDED_CAPABILITY_ACTIONS_BY_EVENT_KIND: OnceLock<
    std::result::Result<BTreeMap<String, Vec<String>>, String>,
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
    pub enforcement_phases: Vec<String>,
    #[serde(default)]
    pub operation_requirements: Vec<ArtifactOperationRequirement>,
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
    /// Registered runtime features required from `ServiceDescribe`.
    #[serde(default)]
    pub required_features: Vec<String>,
    #[serde(default)]
    pub required_cell_namespaces: Vec<String>,
    #[serde(default)]
    pub required_cells: Vec<String>,
    #[serde(default)]
    pub required_constraint_kinds: Vec<String>,
    #[serde(default)]
    pub non_event_grant_authority_rules: Vec<ParsedNonEventGrantAuthorityRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactOperationRequirement {
    pub direction: String,
    pub operation_id: String,
    pub binding_kind: String,
}

/// Closed machine rule authorizing one non-event capability grant surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedNonEventGrantAuthorityRule {
    pub issuer_action: String,
    pub grantable_action: String,
    pub required_registration_event_kind: String,
    pub required_claimed_profile: String,
    pub required_constraint_kind: String,
    pub required_constraint_subkind: String,
    pub subject_binding: String,
    pub scope_binding: String,
    pub epoch_binding: String,
    pub requested_action_binding: String,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant_authority_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub root_control_only: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub subject_only: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reducer_only: bool,
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
                &registered_schema_ids,
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
            enforcement_phases: optional_string_array(entry, "enforcement_phases", profile_id)?,
            operation_requirements: optional_typed_array(
                entry,
                "operation_requirements",
                profile_id,
            )?,
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
            non_event_grant_authority_rules: optional_typed_array(
                entry,
                "non_event_grant_authority_rules",
                profile_id,
            )?,
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

    /// Cross-check every profile requirement against the SDK's generated
    /// constants, pairing the profile's own status with the status of the
    /// registry entry it references.
    ///
    /// The generated constants track the **active** registry surface, so a flat
    /// comparison mis-reports the one legitimate v1 case:
    /// `ak.profile.candidate.join_policy.v1` is itself a `candidate` profile and
    /// requires `ak.schema.join_policy_operations.v1`, the schema registry's only
    /// `candidate` row. Nothing drifts there — the SDK is right not to generate a
    /// candidate schema, and a candidate profile is right to require one.
    ///
    /// Pairing keeps every other case a hard error, and splits apart two the flat
    /// comparison reported with one message:
    ///
    /// * the reference resolves to no registry entry at all — a dangling requirement;
    /// * an **active** profile requires a non-active entry — a spec-side status inversion,
    ///   previously indistinguishable from an SDK generation gap.
    fn profile_requirement_drift(&self) -> Vec<String> {
        let operations = RequirementSurface {
            requirement_field: "required_endpoint",
            declared: SERVICE_OPERATION_DESCRIPTORS
                .iter()
                .map(|descriptor| descriptor.id.as_str())
                .collect(),
            declared_label: "REGISTERED_OPERATION_IDS",
            registry: &self.operation_registry,
            array_field: "operations",
            key_field: "operation_id",
        };
        let event_kinds = RequirementSurface {
            requirement_field: "required_event_kind",
            declared: EVENT_KIND_DESCRIPTORS
                .iter()
                .map(|descriptor| descriptor.kind)
                .collect(),
            declared_label: "REGISTERED_EVENT_KINDS",
            registry: &self.event_kind_registry,
            array_field: "event_kinds",
            key_field: "event_kind",
        };
        let schemas = RequirementSurface {
            requirement_field: "required_schema",
            declared: REGISTERED_SCHEMA_IDS
                .iter()
                .map(|descriptor| descriptor.schema_id)
                .collect(),
            declared_label: "REGISTERED_SCHEMA_IDS",
            registry: &self.schema_registry,
            array_field: "schemas",
            key_field: "schema_id",
        };

        let mut issues = Vec::new();
        let Some(requirements) = self
            .conformance_profiles
            .get("profile_requirements")
            .and_then(Value::as_object)
        else {
            return issues;
        };
        for (profile_id, entry) in requirements {
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
            let profile_status = entry
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or(ACTIVE_STATUS);
            let operation_ids = requirement
                .operation_requirements
                .iter()
                .map(|row| row.operation_id.clone())
                .collect::<Vec<_>>();
            operations.check(&mut issues, profile_id, profile_status, &operation_ids);
            event_kinds.check(
                &mut issues,
                profile_id,
                profile_status,
                &requirement.required_event_kinds,
            );
            schemas.check(
                &mut issues,
                profile_id,
                profile_status,
                &requirement.required_schemas,
            );
        }
        issues
    }

    /// Look up the [`ComponentDescriptor`] for a state event kind.
    ///
    /// Returns `Ok(None)` when the kind is not registered, `Err` when the
    /// registry entry does not identify one component slot or its cell family
    /// lacks a `.vN` suffix.
    pub fn component(&self, event_kind: &str) -> Result<Option<ComponentDescriptor>> {
        let Some(entry) = registry_entry(
            &self.event_kind_registry,
            "event_kinds",
            "event_kind",
            event_kind,
        ) else {
            return Ok(None);
        };
        // A single-write kind owns one component slot. Registry rows carry
        // that identity in `cell_writes[0]`.
        let (component_type, cell_subject) = component_cell_identity(entry).ok_or_else(|| {
            SchemaError::Protocol(format!(
                "event kind {event_kind} does not declare one unambiguous component slot"
            ))
        })?;
        let component_type = component_type.to_owned();
        let component_version = component_type
            .rsplit_once(".v")
            .and_then(|(_, suffix)| suffix.parse::<u64>().ok())
            .ok_or_else(|| {
                SchemaError::Protocol(format!(
                    "event kind {event_kind} cell_family missing .vN version suffix"
                ))
            })?;
        let criticality = Criticality::Required;
        // Alias owner is the first registry entry for the same component
        // family. Genesis and mutation events intentionally resolve the same
        // typed subject through different signed sources (for example,
        // envelope.event_id vs payload.grant_id), so the source path is not
        // part of the component-slot identity.
        let component_slot_alias_of = cell_subject.and_then(|_| {
            let canonical_owner = self.event_kind_registry["event_kinds"]
                .as_array()
                .and_then(|entries| {
                    entries.iter().find_map(|other| {
                        let other_kind = other.get("event_kind").and_then(Value::as_str)?;
                        let (other_family, _) = component_cell_identity(other)?;
                        (other_family == component_type).then(|| other_kind.to_owned())
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
            Err(SchemaError::Protocol(format!(
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

/// SDK-declared coverage of non-schema spec artifacts.
///
/// Schema coverage is generated as [`REGISTERED_SCHEMA_IDS`] and is checked in
/// both directions by [`SpecArtifactBundle::drift_report`]. The remaining
/// constants enumerate event kinds, service operations, profile IDs and
/// typed-ID kinds the SDK recognises from the v1 spec artifacts. The report
/// produces:
///
/// * `missing_*` (hard error) - the SDK declares coverage for an entry the spec no longer ships.
///   Surfaced by [`ArtifactDriftReport::validate`]; bring the constant in line with the spec when
///   this fires.
/// * `unlisted_*` (hard error) - the spec ships an active entry the SDK has not declared coverage
///   for.
///
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
    ProfileId::DIRECTORY_SERVICE_V1,
    ProfileId::ATTESTED_AUDIT_E2EE_V1,
    ProfileId::DISCLOSED_AUDIT_E2EE_V1,
];

/// Typed `ak:<kind>:<uuid>` id kinds the SDK ships a Rust type for.
///
/// This list is not free-form: `crates/schema/tests/id_kind_coverage.rs`
/// pins it to the identifiers crate's UUID and Event-token declarations in both
/// directions, so an entry here means a real newtype exists and a missing
/// entry fails the build rather than silently narrowing spec coverage.
/// `drift_report` then checks the same set against the live
/// `id-kind-registry.json`.
pub const SUPPORTED_ID_KINDS: &[&str] = &[
    "account_status_record",
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
    "session_grant",
    "scheduled_send",
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
    // 2026-08-01: recovered by the first real run of `spec_drift_report`.
    // `arkret-identifiers` has shipped typed newtypes for all five since
    // before this list was last touched; only the hand-copied list lagged.
    // The id_kind_coverage test now makes this class of gap unrepresentable.
    "authorization_lease",
    "invite_locator",
    "message_stream",
    "sidecar",
];

/// Special-form id kinds (non-UUIDv7) the SDK ships a Rust type for, from the
/// spec id-kind-registry `special_forms` array. Validated separately from
/// [`SUPPORTED_ID_KINDS`] because the spec lists them under `special_forms`,
/// not `id_kinds`.
///
/// Like [`SUPPORTED_ID_KINDS`], this list is not free-form:
/// `crates/schema/tests/id_kind_coverage.rs` pins it to
/// [`arkret_identifiers::DECLARED_SPECIAL_FORM_ID_KINDS`] in both directions.
/// Until that gate existed the list claimed four kinds with no type behind them
/// — `mls` and `pseudonym` (both `profile_extension`, validated by the E2EE
/// profile), `plan` and `service_registration_receipt` (both active, and now
/// implemented by `PlanId` / `ServiceRegistrationReceiptId`).
pub const SUPPORTED_SPECIAL_FORM_ID_KINDS: &[&str] = &[
    "blob",
    "cell",
    "cursor",
    "plan",
    "seal",
    "service_registration_receipt",
    "trust_domain",
];

pub fn default_spec_artifacts_dir() -> Option<PathBuf> {
    if let Ok(artifacts_dir) = std::env::var("ARKRET_SPEC_ARTIFACTS") {
        return Some(PathBuf::from(artifacts_dir));
    }
    None
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
        .ok_or_else(|| SchemaError::Protocol("schema registry missing schemas".to_owned()))?;
    for entry in schemas {
        let schema_id = entry
            .get("schema_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SchemaError::Protocol("schema registry entry missing schema_id".to_owned())
            })?;
        let file = entry.get("file").and_then(Value::as_str).ok_or_else(|| {
            SchemaError::Protocol(format!("schema artifact {schema_id} has no file"))
        })?;
        let schema_path = artifacts_dir.join(file);
        let schema = read_json_artifact(&schema_path)?;
        if let Some(fragment) = entry.get("fragment").and_then(Value::as_str) {
            registry.register_fragment(schema_id, schema, fragment)?;
        } else {
            registry.register(schema_id, schema);
        }
    }
    register_schema_documents_from_dir(&mut registry, &artifacts_dir.join("schemas"))?;
    Ok(registry)
}

pub fn schema_registry_from_embedded_spec_artifacts() -> Result<ProtocolSchemaRegistry> {
    let bundle = SpecArtifactBundle::load_embedded()?;
    let mut registry = ProtocolSchemaRegistry::new();
    let schemas = bundle
        .schema_registry
        .get("schemas")
        .and_then(Value::as_array)
        .ok_or_else(|| SchemaError::Protocol("schema registry missing schemas".to_owned()))?;
    for entry in schemas {
        let schema_id = entry
            .get("schema_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SchemaError::Protocol("schema registry entry missing schema_id".to_owned())
            })?;
        let file = entry.get("file").and_then(Value::as_str).ok_or_else(|| {
            SchemaError::Protocol(format!("schema artifact {schema_id} has no file"))
        })?;
        let schema = read_embedded_json_artifact(file)?;
        if let Some(fragment) = entry.get("fragment").and_then(Value::as_str) {
            registry.register_fragment(schema_id, schema, fragment)?;
        } else {
            registry.register(schema_id, schema);
        }
    }
    for (path, schema) in embedded_spec_artifacts()? {
        if path.starts_with("schemas/") && path.ends_with(".json") && schema.get("$id").is_some() {
            registry.register_reference_document(schema.clone())?;
        }
    }
    Ok(registry)
}

fn register_schema_documents_from_dir(
    registry: &mut ProtocolSchemaRegistry,
    directory: &Path,
) -> Result<()> {
    let entries = fs::read_dir(directory).map_err(|error| {
        SchemaError::Protocol(format!(
            "failed to read schema artifact directory {}: {error}",
            directory.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            SchemaError::Protocol(format!(
                "failed to read schema artifact entry in {}: {error}",
                directory.display()
            ))
        })?;
        let path = entry.path();
        if path.is_dir() {
            register_schema_documents_from_dir(registry, &path)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            let schema = read_json_artifact(&path)?;
            if schema.get("$id").is_some() {
                registry.register_reference_document(schema)?;
            }
        }
    }
    Ok(())
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
        Err(error) => Err(SchemaError::Protocol(error.clone())),
    }
}

/// The capability actions whose `target_event_kinds` cover `event_kind`.
///
/// Event kinds and capability actions are two distinct namespaces: an Event
/// names what happened, a capability action names what an actor is authorized
/// to do. Some strings coincide (`ak.message.create`), most do not
/// (`ak.realm.policy_server` is governed by `ak.policy.manage`). A caller that
/// holds an Event and needs the authorization question has to go through this
/// registry-derived mapping rather than passing the kind straight to a
/// capability check.
///
/// The returned slice is sorted and may name several actions; any one of them
/// authorizes the Event.
pub fn embedded_capability_actions_for_event_kind(event_kind: &str) -> Result<&'static [String]> {
    const EMPTY: &[String] = &[];
    match EMBEDDED_CAPABILITY_ACTIONS_BY_EVENT_KIND.get_or_init(|| {
        let actions = match EMBEDDED_CAPABILITY_ACTIONS.get_or_init(|| {
            let artifacts = embedded_spec_artifacts().map_err(|error| error.to_string())?;
            let registry = artifacts
                .get("registry/capability-action-registry.json")
                .ok_or_else(|| {
                    "embedded spec artifact registry/capability-action-registry.json is missing"
                        .to_owned()
                })?;
            capability_actions_from_registry(registry).map_err(|error| error.to_string())
        }) {
            Ok(actions) => actions,
            Err(error) => return Err(error.clone()),
        };
        let mut by_kind: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (action, descriptor) in actions {
            for kind in &descriptor.target_event_kinds {
                by_kind
                    .entry(kind.clone())
                    .or_default()
                    .push(action.clone());
            }
        }
        for actions in by_kind.values_mut() {
            actions.sort();
        }
        Ok(by_kind)
    }) {
        Ok(by_kind) => Ok(by_kind.get(event_kind).map_or(EMPTY, Vec::as_slice)),
        Err(error) => Err(SchemaError::Protocol(error.clone())),
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
        .ok_or_else(|| {
            SchemaError::Protocol("capability action registry missing actions".to_owned())
        })?;
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
        return Err(SchemaError::Protocol(format!(
            "capability action registry lookup for {action} returned {action_field}"
        )));
    }
    let risk_tier = match required_registry_string(entry, "risk_tier", action)? {
        "low" => CapabilityRiskTier::Low,
        "medium" => CapabilityRiskTier::Medium,
        "high" => CapabilityRiskTier::High,
        other => {
            return Err(SchemaError::Protocol(format!(
                "capability action {action} has unknown risk_tier {other:?}"
            )));
        }
    };
    let profile = match entry.get("profile") {
        Some(Value::String(profile)) => Some(profile.clone()),
        Some(Value::Null) | None => None,
        Some(_) => {
            return Err(SchemaError::Protocol(format!(
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
        grant_authority_actions: registry_string_array(entry, "grant_authority_actions", action)?,
        profile,
        root_control_only: registry_flag(entry, "root_control_only", action)?,
        subject_only: registry_flag(entry, "subject_only", action)?,
        reducer_only: registry_flag(entry, "reducer_only", action)?,
        event_mapping_kind: required_registry_string(entry, "event_mapping_kind", action)?
            .to_owned(),
    })
}

fn registry_flag(entry: &Value, field: &str, label: &str) -> Result<bool> {
    match entry.get(field) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(SchemaError::Protocol(format!(
            "capability action {label} field {field} must be a boolean"
        ))),
    }
}

fn required_registry_string<'a>(entry: &'a Value, field: &str, label: &str) -> Result<&'a str> {
    entry.get(field).and_then(Value::as_str).ok_or_else(|| {
        SchemaError::Protocol(format!(
            "registry entry {label} field {field} must be a string"
        ))
    })
}

fn registry_string_array(entry: &Value, field: &str, label: &str) -> Result<Vec<String>> {
    let Some(raw) = entry.get(field) else {
        return Ok(Vec::new());
    };
    let array = raw.as_array().ok_or_else(|| {
        SchemaError::Protocol(format!(
            "registry entry {label} field {field} must be an array"
        ))
    })?;
    array
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                SchemaError::Protocol(format!(
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
        SchemaError::Protocol(format!(
            "profile {profile_id} field {field} must be an array"
        ))
    })?;
    let mut out = Vec::with_capacity(array.len());
    for item in array {
        let text = item.as_str().ok_or_else(|| {
            SchemaError::Protocol(format!(
                "profile {profile_id} field {field} contains a non-string"
            ))
        })?;
        out.push(text.to_owned());
    }
    Ok(out)
}

fn optional_typed_array<T>(value: &Value, field: &str, profile_id: &str) -> Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let Some(raw) = value.get(field) else {
        return Ok(Vec::new());
    };
    serde_json::from_value(raw.clone()).map_err(|error| {
        SchemaError::Protocol(format!(
            "profile {profile_id} field {field} has an invalid shape: {error}"
        ))
    })
}

fn profile_required_constraint_kinds(value: &Value, profile_id: &str) -> Result<Vec<String>> {
    let mut out = optional_string_array(value, "required_constraint_kinds", profile_id)?;
    out.extend(optional_string_array(
        value,
        "required_constraint_subkinds",
        profile_id,
    )?);
    out.sort();
    out.dedup();
    Ok(out)
}

/// One SDK-declared surface a profile requirement can reference, paired with
/// the spec registry that surface is generated from.
///
/// Carrying the registry alongside the generated constant is what lets
/// [`SpecArtifactBundle::profile_requirement_drift`] tell a dangling reference
/// apart from an entry the SDK correctly did not generate.
struct RequirementSurface<'a> {
    requirement_field: &'a str,
    declared: BTreeSet<&'a str>,
    declared_label: &'a str,
    registry: &'a Value,
    array_field: &'a str,
    key_field: &'a str,
}

impl RequirementSurface<'_> {
    fn check(
        &self,
        issues: &mut Vec<String>,
        profile_id: &str,
        profile_status: &str,
        required: &[String],
    ) {
        let Self {
            requirement_field,
            declared_label,
            array_field,
            ..
        } = self;
        for value in required {
            if self.declared.contains(value.as_str()) {
                continue;
            }
            match registry_entry_status(self.registry, self.array_field, self.key_field, value) {
                None => issues.push(format!(
                    "{profile_id}: {requirement_field} {value} missing from {declared_label} and \
                     absent from the spec {array_field} registry"
                )),
                Some(ACTIVE_STATUS) => issues.push(format!(
                    "{profile_id}: {requirement_field} {value} is active in the spec registry but \
                     missing from {declared_label}"
                )),
                Some(status) if profile_status == ACTIVE_STATUS => issues.push(format!(
                    "{profile_id}: active profile requires {requirement_field} {value}, which the \
                     spec registry marks {status}"
                )),
                // A non-active profile requiring a non-active registry entry:
                // the SDK generates the active surface only, so the absence from
                // `declared_label` is the correct outcome, not drift.
                Some(_) => {}
            }
        }
    }
}

/// The status of one registry entry, or `None` when the registry ships no such
/// entry at all.
///
/// Registries that omit `status` — the operation registry does throughout, and
/// so do a large minority of schema registry rows — read as active, matching
/// [`unlisted_active_registry_values`].
fn registry_entry_status<'a>(
    registry: &'a Value,
    array_field: &str,
    key_field: &str,
    expected_key: &str,
) -> Option<&'a str> {
    registry_entry(registry, array_field, key_field, expected_key).map(|entry| {
        entry
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or(ACTIVE_STATUS)
    })
}

fn read_json_artifact(path: &Path) -> Result<Value> {
    let text = fs::read_to_string(path).map_err(|error| {
        SchemaError::Protocol(format!("failed to read {}: {error}", path.display()))
    })?;
    serde_json::from_str(&text).map_err(|error| {
        SchemaError::Protocol(format!("failed to parse {}: {error}", path.display()))
    })
}

fn embedded_spec_artifacts() -> Result<&'static BTreeMap<String, Value>> {
    match EMBEDDED_SPEC_ARTIFACTS.get_or_init(|| {
        serde_json::from_str(EMBEDDED_SPEC_ARTIFACTS_JSON)
            .map_err(|error| format!("failed to parse embedded spec artifacts: {error}"))
    }) {
        Ok(artifacts) => Ok(artifacts),
        Err(error) => Err(SchemaError::Protocol(error.clone())),
    }
}

pub(super) fn read_embedded_json_artifact(path: &str) -> Result<Value> {
    embedded_spec_artifacts()?
        .get(path)
        .cloned()
        .ok_or_else(|| SchemaError::Protocol(format!("embedded spec artifact {path} is missing")))
}

pub fn embedded_json_artifact(path: &str) -> Result<Value> {
    read_embedded_json_artifact(path)
}

/// Return whether the named Realm bootstrap slot explicitly registers a
/// genesis `head_eq null` precondition.
///
/// Bootstrap validators consume this machine contract instead of growing a
/// second hard-coded exception list in each SDK/service implementation.
pub fn realm_bootstrap_genesis_head_eq_registered(profile: &str, condition: &str) -> Result<bool> {
    let registry = read_embedded_json_artifact("registry/contract-registry.json")?;
    let slots = registry
        .pointer(&format!(
            "/realm_bootstrap_registry/{profile}/ordered_slots"
        ))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SchemaError::Protocol(format!(
                "Realm bootstrap profile {profile} has no ordered_slots registry"
            ))
        })?;
    let matching = slots
        .iter()
        .filter(|slot| slot.get("condition").and_then(Value::as_str) == Some(condition))
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(SchemaError::Protocol(format!(
            "Realm bootstrap condition {profile}/{condition} is not unique"
        )));
    }
    Ok(matches!(matching[0].get("head_eq"), Some(Value::Null)))
}

/// Return the canonical OpenAPI YAML copied from the spec artifact pipeline.
pub fn embedded_openapi_yaml() -> Result<&'static str> {
    if EMBEDDED_OPENAPI_YAML.is_empty() {
        return Err(SchemaError::Protocol(
            "embedded OpenAPI artifact is unavailable; enable the embedded-artifacts feature"
                .to_owned(),
        ));
    }
    Ok(EMBEDDED_OPENAPI_YAML)
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
/// cross-check in `crate::error` resolves against this union to avoid false
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
        return Err(SchemaError::Protocol(
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
            .unwrap_or(ACTIVE_STATUS)
            != ACTIVE_STATUS
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

fn component_cell_identity(entry: &Value) -> Option<(&str, Option<&Value>)> {
    let writes = entry.get("cell_writes")?.as_array()?;
    if writes.len() != 1 {
        return None;
    }
    let write = &writes[0];
    Some((
        write.get("cell_family")?.as_str()?,
        write.get("cell_subject"),
    ))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "embedded-artifacts")]
    use arkret_wire::ErrorStatusContext;
    use arkret_wire::{ErrorCode, REASON_CODE_DESCRIPTORS};

    use super::*;

    #[test]
    fn active_registry_entries_missing_from_generated_coverage_fail_closed() {
        let registry = serde_json::json!({
            "schemas": [
                {"schema_id": "ak.schema.covered.v1", "status": "active"},
                {"schema_id": "ak.schema.injected.v1", "status": "active"},
                {"schema_id": "ak.schema.future.v1", "status": "candidate"}
            ]
        });

        assert_eq!(
            unlisted_active_registry_values(
                &registry,
                "schemas",
                "schema_id",
                &["ak.schema.covered.v1"],
            ),
            vec!["ak.schema.injected.v1"]
        );
    }

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
    fn embedded_registry_codes(field: &str) -> Vec<String> {
        let registry = read_embedded_json_artifact("registry/error-code-registry.json")
            .expect("embedded error-code-registry must load");
        registry
            .get(field)
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("embedded error-code-registry missing {field}"))
            .iter()
            .map(|entry| {
                entry
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("embedded {field} entry missing code"))
                    .to_owned()
            })
            .collect()
    }

    #[cfg(feature = "embedded-artifacts")]
    #[test]
    fn generated_error_codes_match_embedded_registry() {
        let mut embedded = embedded_registry_codes("codes");
        let mut generated = generated_error_codes();
        embedded.sort_unstable();
        generated.sort_unstable();
        assert_eq!(generated, embedded);
    }

    #[cfg(feature = "embedded-artifacts")]
    #[test]
    fn generated_error_code_context_statuses_match_embedded_registry() {
        let registry = read_embedded_json_artifact("registry/error-code-registry.json")
            .expect("embedded error-code-registry must load");
        let entries = registry
            .get("codes")
            .and_then(Value::as_array)
            .expect("embedded error-code-registry missing codes");
        let mut contexts_seen = 0usize;
        for entry in entries {
            let wire = entry
                .get("code")
                .and_then(Value::as_str)
                .expect("registry code entry missing code");
            let code = ErrorCode::from_wire(wire)
                .unwrap_or_else(|| panic!("generated table missing error code {wire}"));
            let expected = entry
                .get("http_status_by_context")
                .and_then(Value::as_object);
            let generated = code.descriptor().http_status_by_context;
            let Some(expected) = expected else {
                assert!(
                    generated.is_empty(),
                    "{wire} carries context statuses the registry does not declare"
                );
                continue;
            };
            assert_eq!(
                generated.len(),
                expected.len(),
                "{wire} context status count drifted from the registry"
            );
            for (context, status) in generated {
                let declared = expected
                    .get(context.as_str())
                    .and_then(Value::as_u64)
                    .unwrap_or_else(|| panic!("{wire} registry missing context {context}"));
                assert_eq!(u64::from(*status), declared, "{wire} context {context}");
                assert_eq!(
                    code.http_status_in(*context),
                    *status,
                    "{wire} lookup disagrees with its descriptor for {context}"
                );
                contexts_seen += 1;
            }
            for context in ErrorStatusContext::ALL {
                if expected.contains_key(context.as_str()) {
                    continue;
                }
                assert_eq!(
                    code.http_status_in(*context),
                    code.http_status(),
                    "{wire} must fall back to its default status for {context}"
                );
            }
        }
        assert!(
            contexts_seen > 0,
            "registry declares no context-specific statuses; generator coverage is untested"
        );
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
        let mut embedded = embedded_registry_codes("reason_codes");
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
        let embedded: BTreeSet<String> = embedded_spec_artifacts()
            .expect("embedded artifacts must load")
            .keys()
            .cloned()
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

    #[cfg(feature = "embedded-artifacts")]
    #[test]
    fn embedded_openapi_matches_live_spec_when_available() {
        let embedded = embedded_openapi_yaml().expect("embedded OpenAPI must load");
        // 3.2 since the Events read operations moved to RFC 10008 QUERY, which
        // earlier OpenAPI versions cannot express.
        assert!(embedded.starts_with(
            "openapi: 3.2.0
"
        ));
        assert!(embedded.contains("\npaths:\n"));

        let Some(artifacts_dir) = local_spec_artifacts_dir() else {
            return;
        };
        let live_path = artifacts_dir
            .join("openapi")
            .join("arkret-service-api.openapi.yaml");
        let live = fs::read_to_string(&live_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", live_path.display()));
        assert_eq!(
            embedded.replace("\r\n", "\n"),
            live.replace("\r\n", "\n"),
            "embedded OpenAPI artifact drifted"
        );
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
    fn embedded_capability_actions_for_event_kind_inverts_target_event_kinds() {
        // A kind whose string coincides with its governing action.
        assert!(
            embedded_capability_actions_for_event_kind("ak.message.create")
                .expect("embedded registry should parse")
                .contains(&"ak.message.create".to_owned())
        );

        // A kind whose governing actions are named differently: this is the
        // case a caller holding only an Event kind cannot guess.
        let policy_server = embedded_capability_actions_for_event_kind("ak.realm.policy_server")
            .expect("embedded registry should parse");
        assert!(
            policy_server.contains(&"ak.policy.manage".to_owned()),
            "ak.realm.policy_server must map to ak.policy.manage, got {policy_server:?}"
        );
        assert!(
            policy_server.windows(2).all(|pair| pair[0] <= pair[1]),
            "candidates must be sorted: {policy_server:?}"
        );

        // An unregistered kind yields no candidates rather than an error, so
        // the caller can fall back to its own fail-closed verdict.
        assert!(
            embedded_capability_actions_for_event_kind("ak.not.a.registered.kind")
                .expect("embedded registry should parse")
                .is_empty()
        );
    }

    #[test]
    fn live_applet_bridge_profile_parses_non_event_grant_authority_rule_when_available() {
        let Some(artifacts_dir) = local_spec_artifacts_dir() else {
            return;
        };
        let bundle = SpecArtifactBundle::load(artifacts_dir).unwrap();
        let requirement = bundle
            .profile_requirement("ak.profile.applet_bridge.v1")
            .unwrap()
            .expect("applet bridge profile must exist");
        assert_eq!(requirement.non_event_grant_authority_rules.len(), 1);
        let rule = &requirement.non_event_grant_authority_rules[0];
        assert_eq!(rule.issuer_action, "ak.realm.admin");
        assert_eq!(rule.grantable_action, "ak.applet.ghost.provision");
        assert_eq!(
            rule.epoch_binding,
            "constraint.registration_epoch_exact_registration"
        );
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
