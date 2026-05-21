use super::*;
use crate::events::STANDARD_EVENT_KINDS;
use crate::{
    BUILT_IN_OPERATION_KINDS, PROFILE_ATTESTED_AUDIT_E2EE, PROFILE_DIRECTORY_SERVICE,
    PROFILE_DISCLOSED_AUDIT_E2EE,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpecArtifactBundle {
    pub schema_registry: Value,
    pub event_kind_registry: Value,
    pub operation_registry: Value,
    pub id_kind_registry: Value,
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
/// share a `component_type` (e.g. `cx.capability.grant` and
/// `cx.capability.revoke`) — the alias entry will set
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

impl SpecArtifactBundle {
    pub fn load(artifacts_dir: impl AsRef<Path>) -> Result<Self> {
        let requested_dir = artifacts_dir.as_ref();
        let (artifacts_dir, registry_dir) = if requested_dir.ends_with("registry") {
            let artifacts_dir = requested_dir.parent().unwrap_or(requested_dir).to_path_buf();
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
            id_kind_registry: read_json_artifact(&registry_dir.join("id-kind-registry.json"))?,
            conformance_profiles: read_json_artifact(
                &artifacts_dir.join("profiles").join("conformance-profiles.json"),
            )?,
            artifacts_dir: Some(artifacts_dir),
        })
    }

    pub fn drift_report(&self) -> ArtifactDriftReport {
        ArtifactDriftReport {
            checked_files: vec![
                "registry/schema-registry.json".to_owned(),
                "registry/event-kind-registry.json".to_owned(),
                "registry/operation-registry.json".to_owned(),
                "registry/id-kind-registry.json".to_owned(),
                "profiles/conformance-profiles.json".to_owned(),
            ],
            missing_schemas: missing_registry_values(
                &self.schema_registry,
                "schemas",
                "schema_id",
                ARTIFACT_BACKED_SCHEMA_IDS,
            ),
            missing_event_kinds: missing_registry_values(
                &self.event_kind_registry,
                "event_kinds",
                "event_kind",
                ARTIFACT_BACKED_EVENT_KINDS,
            ),
            missing_operations: missing_registry_values(
                &self.operation_registry,
                "operations",
                "operation_id",
                ARTIFACT_BACKED_SERVICE_OPERATIONS,
            ),
            missing_id_kinds: missing_registry_values(
                &self.id_kind_registry,
                "id_kinds",
                "kind",
                ARTIFACT_BACKED_ID_KINDS,
            ),
            missing_profiles: self.missing_profile_values(ARTIFACT_BACKED_PROFILE_IDS),
            profile_requirement_issues: self.profile_requirement_drift(),
            missing_payload_validators: self.payload_validator_drift(),
            unlisted_event_kinds: unlisted_active_registry_values(
                &self.event_kind_registry,
                "event_kinds",
                "event_kind",
                ARTIFACT_BACKED_EVENT_KINDS,
            ),
        }
    }

    fn payload_validator_drift(&self) -> Vec<String> {
        let Some(artifacts_dir) = &self.artifacts_dir else {
            return Vec::new();
        };
        let catalog = match event_payload_validator_catalog_from_spec_artifacts(artifacts_dir) {
            Ok(catalog) => catalog,
            Err(error) => return vec![format!("catalog_error: {error}")],
        };
        catalog.missing_payload_validators_for(active_standard_durable_event_kinds(
            &self.event_kind_registry,
        ))
    }

    /// Return every `cx.profile.*.vN` ID referenced by the conformance profile
    /// artifact, including profile requirement keys and optional-extension refs.
    pub fn profile_ids(&self) -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        collect_profile_ids(&self.conformance_profiles, &mut ids);
        ids
    }

    /// Return the machine-readable requirements for one profile ID.
    pub fn profile_requirement(&self, profile_id: &str) -> Result<Option<ProfileRequirement>> {
        let Some(requirements) =
            self.conformance_profiles.get("profile_requirements").and_then(Value::as_object)
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
        let operation_ids = ARTIFACT_BACKED_SERVICE_OPERATIONS.iter().copied().collect();
        let event_kinds = ARTIFACT_BACKED_EVENT_KINDS.iter().copied().collect();
        let schema_ids = ARTIFACT_BACKED_SCHEMA_IDS.iter().copied().collect();
        let mut issues = Vec::new();
        for profile_id in ARTIFACT_BACKED_PROFILE_IDS {
            let requirement = match self.profile_requirement(profile_id) {
                Ok(Some(requirement)) => requirement,
                Ok(None) => continue,
                Err(error) => {
                    issues.push(format!("{profile_id}: profile requirement parse error: {error}"));
                    continue;
                }
            };
            profile_requirement_missing_values(
                &mut issues,
                profile_id,
                "required_endpoint",
                &requirement.required_endpoints,
                &operation_ids,
                "ARTIFACT_BACKED_SERVICE_OPERATIONS",
            );
            profile_requirement_missing_values(
                &mut issues,
                profile_id,
                "required_event_kind",
                &requirement.required_event_kinds,
                &event_kinds,
                "ARTIFACT_BACKED_EVENT_KINDS",
            );
            profile_requirement_missing_values(
                &mut issues,
                profile_id,
                "required_schema",
                &requirement.required_schemas,
                &schema_ids,
                "ARTIFACT_BACKED_SCHEMA_IDS",
            );
        }
        issues
    }

    /// Look up the [`ComponentDescriptor`] for a state event kind.
    ///
    /// Returns `Ok(None)` when the kind is not registered, `Err` when the
    /// registry entry is malformed (missing `component_type`, non-integer
    /// version, unknown criticality value).
    pub fn component(&self, event_kind: &str) -> Result<Option<ComponentDescriptor>> {
        let Some(entry) =
            registry_entry(&self.event_kind_registry, "event_kinds", "event_kind", event_kind)
        else {
            return Ok(None);
        };
        // Spec migrated from `component_type`/`component_version`/`criticality`
        // (pre-c1717da shape) to `cell_family` (cell model). Read whichever the
        // spec ships; derive `component_version` from the `.vN` suffix and
        // default `criticality` to `Required` when only the cell-family form is
        // present (the spec asserts these reducer-input cells MUST be honored
        // by readers, equivalent to old `Required`).
        let component_type = entry
            .get("component_type")
            .and_then(Value::as_str)
            .or_else(|| entry.get("cell_family").and_then(Value::as_str))
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "event kind {event_kind} missing component_type / cell_family in registry"
                ))
            })?
            .to_owned();
        let component_version = entry
            .get("component_version")
            .and_then(Value::as_u64)
            .or_else(|| {
                // Parse version suffix `.vN` from cell_family
                component_type.rsplit_once(".v").and_then(|(_, suffix)| suffix.parse::<u64>().ok())
            })
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "event kind {event_kind} missing or non-integer component_version"
                ))
            })?;
        let criticality = match entry.get("criticality").and_then(Value::as_str) {
            Some("required") => Criticality::Required,
            Some("optional") => Criticality::Optional,
            Some("ignore") => Criticality::Ignore,
            Some(other) => {
                return Err(Error::Protocol(format!(
                    "event kind {event_kind} has unknown criticality {other:?}"
                )));
            }
            // Cell-family-only entries default to Required (reducer_input=true
            // implies the cell is part of canonical state).
            None => Criticality::Required,
        };
        // Slot-alias resolution: prefer the explicit `component_slot_alias_of`
        // field (pre-c1717da spec shape). When absent, find the FIRST event
        // in registry order that ships the same `(cell_family, cell_subject)`
        // — that's the canonical slot owner. If the current event is itself
        // that owner, return None; otherwise return the canonical owner's
        // event_kind. Cell-model alias example: `cx.capability.revoke` shares
        // `cx.component.capability.grant.v1` with `cx.capability.grant`, so
        // revoke slot-aliases to grant.
        let component_slot_alias_of = entry
            .get("component_slot_alias_of")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                let cell_subject = entry.get("cell_subject");
                let canonical_owner =
                    self.event_kind_registry["event_kinds"].as_array().and_then(|entries| {
                        entries.iter().find_map(|other| {
                            let other_kind = other.get("event_kind").and_then(Value::as_str)?;
                            let other_family = other.get("cell_family").and_then(Value::as_str)?;
                            if other_family != component_type {
                                return None;
                            }
                            if other.get("cell_subject") != cell_subject {
                                return None;
                            }
                            Some(other_kind.to_owned())
                        })
                    })?;
                if canonical_owner == event_kind { None } else { Some(canonical_owner) }
            });
        Ok(Some(ComponentDescriptor {
            event_kind: event_kind.to_owned(),
            component_type,
            component_version,
            criticality,
            component_slot_alias_of,
        }))
    }
}

/// Two-way drift between the SDK's declared spec coverage (`ARTIFACT_BACKED_*`)
/// and the spec's registry/profile artifacts.
///
/// `missing_*` lists entries the SDK declares coverage for that the spec no
/// longer ships — these are hard errors and are surfaced by [`Self::validate`].
/// `profile_requirement_issues` lists profile requirement references that point
/// at operation/schema/event constants missing from the SDK-declared coverage.
/// `unlisted_*` lists entries the spec ships that the SDK has not yet declared
/// coverage for — these are soft signals (the SDK may legitimately not cover
/// every spec extension yet) and are inspected via [`Self::has_unlisted`].
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
    pub missing_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile_requirement_issues: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_payload_validators: Vec<String>,
    /// Spec-side entries the SDK has not yet declared coverage for, scoped to
    /// the same families covered by `ARTIFACT_BACKED_*`. Filtered to active
    /// entries to avoid noise from inactive/profile-extension items.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlisted_event_kinds: Vec<String>,
}

impl ArtifactDriftReport {
    pub fn validate(&self) -> Result<()> {
        if self.missing_schemas.is_empty()
            && self.missing_event_kinds.is_empty()
            && self.missing_operations.is_empty()
            && self.missing_id_kinds.is_empty()
            && self.missing_profiles.is_empty()
            && self.profile_requirement_issues.is_empty()
            && self.missing_payload_validators.is_empty()
        {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "spec artifact drift detected: schemas={:?} events={:?} operations={:?} ids={:?} profiles={:?} profile_requirements={:?} payload_validators={:?}",
                self.missing_schemas,
                self.missing_event_kinds,
                self.missing_operations,
                self.missing_id_kinds,
                self.missing_profiles,
                self.profile_requirement_issues,
                self.missing_payload_validators
            )))
        }
    }

    /// True when the spec ships active entries the SDK does not yet declare
    /// coverage for. Soft signal — useful for "next round of work" reports.
    pub fn has_unlisted(&self) -> bool {
        !self.unlisted_event_kinds.is_empty()
    }
}

/// SDK-declared coverage of spec artifacts.
///
/// These constants enumerate the schemas, event kinds, service operations
/// profile IDs and typed-ID kinds the SDK recognises from the v1 spec artifacts.
/// [`SpecArtifactBundle::drift_report`] cross-checks them against the live
/// registry and produces:
///
/// * `missing_*` (hard error) — the SDK declares coverage for an entry the
///   spec no longer ships. Surfaced by [`ArtifactDriftReport::validate`];
///   bring the constant in line with the spec when this fires.
/// * `unlisted_event_kinds` (soft signal) — the spec ships an active event
///   kind the SDK has not declared coverage for.
///
/// Update this constant whenever the SDK adds typed support for a new
/// schema; the drift report will then enforce that the spec still ships it.
pub const ARTIFACT_BACKED_SCHEMA_IDS: &[&str] = &[
    "cx.schema.agent_task.v1",
    "cx.schema.content.mention_redirect.v1",
    "cx.schema.content.import_attestation.v1",
    "cx.schema.content.source_export_policy_attestation.v1",
    // Realm/Space inversion (spec 59ac1d4): `cx.schema.realm.v1` is the new
    // security-boundary schema. `cx.schema.space.v1` is now the container
    // schema (former `cx.schema.place.v1` is removed).
    "cx.schema.realm.v1",
    "cx.schema.space.v1",
    "cx.schema.actor_profile.v1",
    "cx.schema.message.v1",
    "cx.schema.morph.v1",
    "cx.schema.morph.customer_risk.v1",
    "cx.schema.relation.v1",
    "cx.schema.policy.v1",
    "cx.schema.invite.v1",
    "cx.schema.event_batch_receipt.v1",
    "cx.schema.patch.v1",
    "cx.schema.range_completeness_attestation.v1",
    "cx.schema.ice_config_response.v1",
    "cx.schema.device_message.v1",
    "cx.schema.blob.v1",
    "cx.schema.media_metadata.v1",
    "cx.schema.key_backup.v1",
    "cx.schema.notification.v1",
    "cx.schema.read_marker.v1",
    "cx.schema.read_receipt.v1",
    "cx.schema.did_key_log_entry.v1",
    "cx.schema.did_continuity_proof.v1",
    "cx.schema.identity_receipt.v1",
    "cx.schema.identity_link.v1",
    "cx.schema.handle_claim.v1",
    "cx.schema.member_delivery_binding_candidate.v1",
    "cx.schema.grant_constraint.v1",
    "cx.schema.resource_selector.v1",
    "cx.schema.mimi_interop.v1",
    "cx.schema.moderation_report.v1",
    "cx.schema.moderation_queue_item.v1",
    "cx.schema.applet.v1",
    "cx.schema.agent.v1",
    "cx.schema.audit_ryw_receipt.v1",
    "cx.schema.erasure_receipt.v1",
    "cx.schema.cross_signing_publish.v1",
    "cx.schema.cross_signing_reset.v1",
    // Round R2/R3 (2026-05-20) — broadcast ephemeral envelope, moderation
    // appeal payloads, structured attestation evidence.
    "cx.schema.ephemeral_envelope.v1",
    "cx.schema.moderation_appeal.v1",
    "cx.schema.attestation_evidence.v1",
    EVENT_SCHEMA,
    EVENT_PAYLOAD_SCHEMA,
    FLOW_SCHEMA,
    PLACE_SCHEMA,
    ANCHOR_SCHEMA,
    AGENT_AUTHORITY_SCHEMA,
    BOTTOM_SCHEMA,
    SNAPSHOT_SCHEMA,
    CAPABILITY_SCHEMA,
    CURSOR_SCHEMA,
    ENCRYPTED_PAYLOAD_SCHEMA,
    ACCOUNT_SUBSCRIBE_FRAME_SCHEMA,
    VIEW_SCHEMA,
];

/// Active event kinds the SDK recognises from the spec registry.
pub const ARTIFACT_BACKED_EVENT_KINDS: &[&str] = STANDARD_EVENT_KINDS;

pub const ARTIFACT_BACKED_SERVICE_OPERATIONS: &[&str] = BUILT_IN_OPERATION_KINDS;

/// Profile IDs that still appear as hand-written SDK constants or service
/// requirement fixtures and are therefore hard-checked against the profile
/// artifact.
pub const ARTIFACT_BACKED_PROFILE_IDS: &[&str] =
    &[PROFILE_DIRECTORY_SERVICE, PROFILE_ATTESTED_AUDIT_E2EE, PROFILE_DISCLOSED_AUDIT_E2EE];

pub const ARTIFACT_BACKED_ID_KINDS: &[&str] = &[
    "actor_profile",
    "agent_session",
    "appeal",
    "applet",
    "attestation",
    "backup",
    "batch",
    "blob",
    "block",
    "call",
    "capability",
    "flow",
    "chunk",
    "claim",
    "device",
    "devmsg",
    "event",
    "filter",
    "frame",
    "frank",
    "grant",
    "invite",
    "keyevt",
    "message",
    "morph",
    "notif",
    "policy",
    "presentation",
    "receipt",
    "relation",
    "report",
    "modq",
    "req",
    "snapshot",
    "place",
    "space",
    "txn",
    "view",
];

/// Special-form id kinds (non-UUIDv7) the SDK declares coverage for from
/// the spec id-kind-registry `special_forms` array. Round R2/R3 (2026-05-20)
/// adds `trust_domain` (`cx:trust_domain:<scope>`). These are validated
/// separately from `ARTIFACT_BACKED_ID_KINDS` because the spec lists them
/// under `special_forms`, not `id_kinds`.
pub const ARTIFACT_BACKED_SPECIAL_FORM_ID_KINDS: &[&str] =
    &["anchor", "blob", "cell", "cursor", "mls", "pseudonym", "trust_domain"];

pub fn default_spec_artifacts_dir() -> Option<PathBuf> {
    if let Ok(artifacts_dir) = std::env::var("CONTRIX_SPEC_ARTIFACTS") {
        return Some(PathBuf::from(artifacts_dir));
    }
    let spec_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("contrix-spec");
    let artifacts_dir = spec_root.join("spec").join("v1").join("artifacts");
    artifacts_dir.join("registry").join("schema-registry.json").exists().then_some(artifacts_dir)
}

pub fn artifact_drift_report_from_default_location() -> Result<Option<ArtifactDriftReport>> {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return Ok(None);
    };
    Ok(Some(SpecArtifactBundle::load(artifacts_dir)?.drift_report()))
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

fn active_standard_durable_event_kinds(registry: &Value) -> Vec<&str> {
    let Some(entries) = registry.get("event_kinds").and_then(Value::as_array) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter(|entry| entry.get("status").and_then(Value::as_str) == Some("active"))
        .filter(|entry| entry.get("wire_scope").and_then(Value::as_str) == Some("durable_event"))
        .filter_map(|entry| entry.get("event_kind").and_then(Value::as_str))
        .filter(|event_kind| crate::events::is_standard_event_kind(event_kind))
        .collect()
}

pub fn schema_registry_from_default_spec_artifacts() -> Result<Option<ProtocolSchemaRegistry>> {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return Ok(None);
    };
    Ok(Some(schema_registry_from_spec_artifacts(artifacts_dir)?))
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
    value.starts_with("cx.profile.") && value.rsplit_once(".v").is_some()
}

fn optional_string_array(value: &Value, field: &str, profile_id: &str) -> Result<Vec<String>> {
    let Some(raw) = value.get(field) else {
        return Ok(Vec::new());
    };
    let array = raw.as_array().ok_or_else(|| {
        Error::Protocol(format!("profile {profile_id} field {field} must be an array"))
    })?;
    let mut out = Vec::with_capacity(array.len());
    for item in array {
        let text = item.as_str().ok_or_else(|| {
            Error::Protocol(format!("profile {profile_id} field {field} contains a non-string"))
        })?;
        out.push(text.to_owned());
    }
    Ok(out)
}

fn profile_required_constraint_kinds(value: &Value, profile_id: &str) -> Result<Vec<String>> {
    let mut out = optional_string_array(value, "required_constraint_kinds", profile_id)?;
    out.extend(optional_string_array(value, "required_constraint_types", profile_id)?);
    out.extend(optional_string_array(value, "required_constraint_subtypes", profile_id)?);
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
/// soft drift report doesn't flag inactive/profile-extension entries that the
/// SDK is intentionally not modelling.
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
        if entry.get("status").and_then(Value::as_str) != Some("active") {
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
