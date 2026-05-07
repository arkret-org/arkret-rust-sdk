//! Schema registry and compatibility contracts.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use contrix_core::{
    CAPABILITY_SCHEMA, CLIENT_SYNC_RESPONSE_SCHEMA, COMMIT_SCHEMA, CURSOR_SCHEMA,
    ENCRYPTED_PAYLOAD_SCHEMA, ENTITY_SCHEMA, EVENT_SCHEMA, Error, FLOW_SCHEMA,
    GeneratedSchemaValidator, OPERATION_SCHEMA, ProtocolSchemaRegistry, Result,
    SCHEMA_COMPATIBILITY_PROFILE, SchemaCompatibilityEntry, SchemaCompatibilityTable, VIEW_SCHEMA,
    schema_version_compatibility_table,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use contrix_core::{
    GeneratedSchemaField, GeneratedSchemaValueType, ProtocolSchemaRegistry as Registry,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCatalogEntry {
    pub schema_id: String,
    pub current_version: String,
    pub compatible_since: String,
    pub migration_required: bool,
    pub generated_validator: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCatalogReport {
    pub profile: String,
    pub entries: Vec<SchemaCatalogEntry>,
    pub missing_compatibility: Vec<String>,
}

impl SchemaCatalogReport {
    pub fn validate(&self) -> Result<()> {
        if self.profile != SCHEMA_COMPATIBILITY_PROFILE {
            return Err(Error::Protocol("schema catalog profile mismatch".to_owned()));
        }
        if !self.missing_compatibility.is_empty() {
            return Err(Error::Protocol(format!(
                "schemas missing compatibility entries: {:?}",
                self.missing_compatibility
            )));
        }
        Ok(())
    }
}

pub fn schema_catalog() -> SchemaCatalogReport {
    let registry = ProtocolSchemaRegistry::default();
    let compatibility = schema_version_compatibility_table();
    let compatibility_by_id = compatibility
        .entries
        .iter()
        .map(|entry| (entry.schema_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut entries = Vec::new();
    let mut missing_compatibility = Vec::new();
    for schema_id in registry.schema_ids() {
        match compatibility_by_id.get(schema_id) {
            Some(entry) => entries.push(catalog_entry(&registry, entry)),
            None => missing_compatibility.push(schema_id.to_owned()),
        }
    }
    entries.sort_by(|left, right| left.schema_id.cmp(&right.schema_id));
    SchemaCatalogReport { profile: compatibility.profile, entries, missing_compatibility }
}

fn catalog_entry(
    registry: &ProtocolSchemaRegistry,
    compatibility: &SchemaCompatibilityEntry,
) -> SchemaCatalogEntry {
    SchemaCatalogEntry {
        schema_id: compatibility.schema_id.clone(),
        current_version: compatibility.current_version.clone(),
        compatible_since: compatibility.compatible_since.clone(),
        migration_required: compatibility.migration_required,
        generated_validator: registry.generated_validator(&compatibility.schema_id).is_ok(),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SchemaValidationVector {
    pub name: String,
    pub schema_id: String,
    pub input: Value,
    pub expected_valid: bool,
}

pub fn built_in_schema_vectors() -> Vec<SchemaValidationVector> {
    vec![
        SchemaValidationVector {
            name: "operation envelope minimal valid".to_owned(),
            schema_id: OPERATION_SCHEMA.to_owned(),
            input: json!({
                "operation_id": "cx:operation:01",
                "space_id": "cx:space:01",
                "actor_id": "did:web:alice.example",
                "kind": "cx.message.create",
                "causal": {},
                "content": {"body": "hello"}
            }),
            expected_valid: true,
        },
        SchemaValidationVector {
            name: "operation envelope missing content".to_owned(),
            schema_id: OPERATION_SCHEMA.to_owned(),
            input: json!({
                "operation_id": "cx:operation:01",
                "space_id": "cx:space:01",
                "actor_id": "did:web:alice.example",
                "kind": "cx.message.create",
                "causal": {}
            }),
            expected_valid: false,
        },
        SchemaValidationVector {
            name: "flow minimal valid".to_owned(),
            schema_id: FLOW_SCHEMA.to_owned(),
            input: json!({
                "schema": "cx.schema.flow.v1",
                "id": "cx:flow:01js0fb000000000000000000",
                "type": "flow",
                "space_id": "cx:space:01js0ke000000000000000000",
                "title": "Payment refactor",
                "flow_kind": "discussion",
                "created_by": "did:web:alice.example",
                "created_at": "2026-05-02T00:00:00Z"
            }),
            expected_valid: true,
        },
        SchemaValidationVector {
            name: "event envelope minimal valid".to_owned(),
            schema_id: EVENT_SCHEMA.to_owned(),
            input: json!({
                "event_id": "cx:event:01js0ke000000000000000001",
                "kind": "cx.message.create",
                "space_id": "cx:space:01js0ke000000000000000000",
                "space_version": "1",
                "actor_id": "did:web:alice.example",
                "actor_seq": 1,
                "created_at": "2026-05-02T00:00:00Z",
                "hlc": "01970e589d21-0000-a13f9c2e",
                "prev_refs": [],
                "auth_refs": [],
                "content": {"body": "hello"},
                "proofs": [{
                    "kind": "detached_jws",
                    "alg": "EdDSA",
                    "verification_method": "did:web:alice.example#key-1",
                    "payload_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "created_at": "2026-05-02T00:00:00Z",
                    "jws": "a..b"
                }]
            }),
            expected_valid: true,
        },
        SchemaValidationVector {
            name: "event envelope rejects untrusted security extension".to_owned(),
            schema_id: EVENT_SCHEMA.to_owned(),
            input: json!({
                "event_id": "cx:event:01js0ke000000000000000001",
                "space_id": "cx:space:01js0ke000000000000000000",
                "actor_id": "did:web:alice.example",
                "actor_seq": 1,
                "kind": "cx.message.create",
                "space_version": "1",
                "created_at": "2026-05-02T00:00:00Z",
                "hlc": "01970e589d21-0000-a13f9c2e",
                "prev_refs": [],
                "auth_refs": [],
                "content": {},
                "proofs": [{
                    "kind": "detached_jws",
                    "alg": "EdDSA",
                    "verification_method": "did:web:alice.example#key-1",
                    "payload_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "created_at": "2026-05-02T00:00:00Z",
                    "jws": "a..b"
                }],
                "x-security": {"override": true}
            }),
            expected_valid: false,
        },
    ]
}

pub fn validate_schema_vectors(vectors: &[SchemaValidationVector]) -> Result<()> {
    let registry = ProtocolSchemaRegistry::default();
    for vector in vectors {
        let valid = registry.validate_value(&vector.schema_id, &vector.input).is_ok();
        if valid != vector.expected_valid {
            return Err(Error::Protocol(format!(
                "schema vector '{}' expected valid={} got valid={valid}",
                vector.name, vector.expected_valid
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPayloadSchemaRule {
    pub event_kind: String,
    pub payload_schema_id: String,
    pub required_fields: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPayloadValidatorCatalog {
    pub rules: BTreeMap<String, EventPayloadSchemaRule>,
}

impl EventPayloadValidatorCatalog {
    pub fn validate_payload(&self, event_kind: &str, payload: &Value) -> Result<()> {
        let Some(rule) = self.rules.get(event_kind) else {
            return Ok(());
        };
        let object = payload.as_object().ok_or_else(|| {
            Error::Protocol(format!("event kind '{event_kind}' payload must be a JSON object"))
        })?;
        for field in &rule.required_fields {
            if !object.contains_key(field) {
                return Err(Error::Protocol(format!(
                    "event kind '{event_kind}' payload requires field '{field}'"
                )));
            }
        }
        Ok(())
    }
}

pub fn event_payload_validator_catalog() -> EventPayloadValidatorCatalog {
    let rules = [
        ("cx.flow.create", FLOW_SCHEMA, &["flow_id", "title", "flow_kind"][..]),
        ("cx.flow.update", FLOW_SCHEMA, &["flow_id", "title"][..]),
        ("cx.flow.archive", FLOW_SCHEMA, &["flow_id"][..]),
        ("cx.flow.restore", FLOW_SCHEMA, &["flow_id"][..]),
        ("cx.flow.move", FLOW_SCHEMA, &["flow_id", "parent_id"][..]),
        ("cx.flow.reorder", FLOW_SCHEMA, &["flow_id", "rank"][..]),
        ("cx.flow.convert", FLOW_SCHEMA, &["flow_id", "target_kind"][..]),
        ("cx.flow.branch.member", FLOW_SCHEMA, &["flow_id", "branch_id", "member_id"][..]),
        (
            "cx.flow.branch.history_visibility",
            FLOW_SCHEMA,
            &["flow_id", "branch_id", "history_visibility"][..],
        ),
        (
            "cx.flow.branch.policy_components",
            FLOW_SCHEMA,
            &["flow_id", "branch_id", "policy_components"][..],
        ),
        ("cx.message.create", EVENT_SCHEMA, &["body"][..]),
        ("cx.member.state", EVENT_SCHEMA, &["principal_id", "membership"][..]),
        ("cx.list.reorder", EVENT_SCHEMA, &["board_id", "list_id", "rank"][..]),
        ("cx.capability.grant", CAPABILITY_SCHEMA, &["capability_id", "subject", "resource"][..]),
    ]
    .into_iter()
    .map(|(event_kind, payload_schema_id, required_fields)| {
        (
            event_kind.to_owned(),
            EventPayloadSchemaRule {
                event_kind: event_kind.to_owned(),
                payload_schema_id: payload_schema_id.to_owned(),
                required_fields: required_fields.iter().map(|field| (*field).to_owned()).collect(),
            },
        )
    })
    .collect();
    EventPayloadValidatorCatalog { rules }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaBreakingChange {
    RemovedSchema,
    NewRequiredField,
    TypeNarrowed,
    AdditionalPropertiesClosed,
    SecurityExtensionTrustWidened,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaEvolutionPlan {
    pub from_version: String,
    pub to_version: String,
    pub affected_schemas: Vec<String>,
    pub breaking_changes: BTreeSet<SchemaBreakingChange>,
}

impl SchemaEvolutionPlan {
    pub fn validate_release_candidate(&self) -> Result<()> {
        if self.from_version.trim().is_empty() || self.to_version.trim().is_empty() {
            return Err(Error::Protocol("schema evolution versions must be present".to_owned()));
        }
        if self.affected_schemas.is_empty() {
            return Err(Error::Protocol("schema evolution must name affected schemas".to_owned()));
        }
        if !self.breaking_changes.is_empty() {
            return Err(Error::Protocol(format!(
                "schema evolution contains breaking changes: {:?}",
                self.breaking_changes
            )));
        }
        Ok(())
    }
}

pub fn generated_validators() -> Result<BTreeMap<String, GeneratedSchemaValidator>> {
    let registry = ProtocolSchemaRegistry::default();
    registry
        .schema_ids()
        .map(|schema_id| Ok((schema_id.to_owned(), registry.generated_validator(schema_id)?)))
        .collect()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpecArtifactBundle {
    pub schema_registry: Value,
    pub event_kind_registry: Value,
    pub operation_registry: Value,
    pub id_kind_registry: Value,
}

impl SpecArtifactBundle {
    pub fn load(artifacts_dir: impl AsRef<Path>) -> Result<Self> {
        let artifacts_dir = artifacts_dir.as_ref();
        let registry_dir = if artifacts_dir.ends_with("registry") {
            artifacts_dir.to_path_buf()
        } else {
            artifacts_dir.join("registry")
        };
        Ok(Self {
            schema_registry: read_json_artifact(&registry_dir.join("schema-registry.json"))?,
            event_kind_registry: read_json_artifact(
                &registry_dir.join("event-kind-registry.json"),
            )?,
            operation_registry: read_json_artifact(&registry_dir.join("operation-registry.json"))?,
            id_kind_registry: read_json_artifact(&registry_dir.join("id-kind-registry.json"))?,
        })
    }

    pub fn drift_report(&self) -> ArtifactDriftReport {
        ArtifactDriftReport {
            checked_files: vec![
                "registry/schema-registry.json".to_owned(),
                "registry/event-kind-registry.json".to_owned(),
                "registry/operation-registry.json".to_owned(),
                "registry/id-kind-registry.json".to_owned(),
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
            unlisted_event_kinds: unlisted_active_registry_values(
                &self.event_kind_registry,
                "event_kinds",
                "event_kind",
                ARTIFACT_BACKED_EVENT_KINDS,
            ),
        }
    }
}

/// Two-way drift between the SDK's declared spec coverage (`ARTIFACT_BACKED_*`)
/// and the spec's registry artifacts.
///
/// `missing_*` lists entries the SDK declares coverage for that the spec no
/// longer ships — these are hard errors and are surfaced by [`Self::validate`].
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
    /// Spec-side entries the SDK has not yet declared coverage for, scoped to
    /// the same families covered by `ARTIFACT_BACKED_*`. Filtered to active
    /// entries to avoid noise from deprecated/profile-extension items.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlisted_event_kinds: Vec<String>,
}

impl ArtifactDriftReport {
    pub fn validate(&self) -> Result<()> {
        if self.missing_schemas.is_empty()
            && self.missing_event_kinds.is_empty()
            && self.missing_operations.is_empty()
            && self.missing_id_kinds.is_empty()
        {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "spec artifact drift detected: schemas={:?} events={:?} operations={:?} ids={:?}",
                self.missing_schemas,
                self.missing_event_kinds,
                self.missing_operations,
                self.missing_id_kinds
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
/// and typed-ID kinds the SDK actively consumes from the v1 spec registry.
/// They are *not* a mirror of the entire spec — only the surfaces the SDK
/// has typed support for. [`SpecArtifactBundle::drift_report`] cross-checks
/// them against the live registry and produces:
///
/// * `missing_*` (hard error) — the SDK declares coverage for an entry the
///   spec no longer ships. Surfaced by [`ArtifactDriftReport::validate`];
///   bring the constant in line with the spec when this fires.
/// * `unlisted_event_kinds` (soft signal) — the spec ships an active event
///   kind the SDK has not declared coverage for. A pointer at next-round
///   work, not a CI failure.
///
/// Update this constant whenever the SDK adds typed support for a new
/// schema; the drift report will then enforce that the spec still ships it.
pub const ARTIFACT_BACKED_SCHEMA_IDS: &[&str] = &[
    EVENT_SCHEMA,
    FLOW_SCHEMA,
    CAPABILITY_SCHEMA,
    CURSOR_SCHEMA,
    ENCRYPTED_PAYLOAD_SCHEMA,
    CLIENT_SYNC_RESPONSE_SCHEMA,
    VIEW_SCHEMA,
];

/// Event kinds the SDK has typed reducer / projection support for. See
/// [`ARTIFACT_BACKED_SCHEMA_IDS`] for the full coverage-declaration model.
pub const ARTIFACT_BACKED_EVENT_KINDS: &[&str] = &[
    "cx.flow.create",
    "cx.flow.update",
    "cx.flow.archive",
    "cx.flow.restore",
    "cx.flow.move",
    "cx.flow.reorder",
    "cx.flow.branch.member",
    "cx.flow.branch.history_visibility",
    "cx.flow.branch.policy_components",
    "cx.message.create",
    "cx.member.state",
    "cx.capability.grant",
];

pub const ARTIFACT_BACKED_SERVICE_OPERATIONS: &[&str] = &[
    "cx.events.submit",
    "cx.events.get",
    "cx.events.batch_get",
    "cx.events.frontier",
    "cx.sync.client_sync",
    "cx.server.describe",
];

pub const ARTIFACT_BACKED_ID_KINDS: &[&str] = &["event", "space", "flow"];

pub fn default_spec_artifacts_dir() -> Option<PathBuf> {
    if let Ok(artifacts_dir) = std::env::var("CONTRIX_SPEC_ARTIFACTS") {
        return Some(PathBuf::from(artifacts_dir));
    }
    let spec_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("contrix-spec");
    // Prefer the v1 layout introduced when the spec repo reorganised its
    // artifacts under spec/v1/. Fall back to the legacy flat path.
    let candidates =
        [spec_root.join("spec").join("v1").join("artifacts"), spec_root.join("artifacts")];
    candidates.into_iter().find(|dir| dir.join("registry").join("schema-registry.json").exists())
}

pub fn artifact_drift_report_from_default_location() -> Result<Option<ArtifactDriftReport>> {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return Ok(None);
    };
    Ok(Some(SpecArtifactBundle::load(artifacts_dir)?.drift_report()))
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
/// soft drift report doesn't flag deprecated/profile-extension entries that
/// the SDK is intentionally not modelling.
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

fn registry_entry<'a>(
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

pub mod protocol {
    pub use contrix_core::{
        CAPABILITY_SCHEMA, CLIENT_SYNC_RESPONSE_SCHEMA, COMMIT_SCHEMA, CURSOR_SCHEMA,
        ENCRYPTED_PAYLOAD_SCHEMA, ENTITY_SCHEMA, EVENT_SCHEMA, FLOW_SCHEMA, GeneratedSchemaField,
        GeneratedSchemaValidator, GeneratedSchemaValueType, OPERATION_SCHEMA,
        ProtocolSchemaRegistry, SCHEMA_COMPATIBILITY_PROFILE, SchemaCompatibilityEntry,
        SchemaCompatibilityTable, VIEW_SCHEMA, schema_version_compatibility_table,
    };
}

pub const CORE_SCHEMA_IDS: &[&str] = &[
    CURSOR_SCHEMA,
    FLOW_SCHEMA,
    ENTITY_SCHEMA,
    VIEW_SCHEMA,
    EVENT_SCHEMA,
    OPERATION_SCHEMA,
    COMMIT_SCHEMA,
    CAPABILITY_SCHEMA,
    ENCRYPTED_PAYLOAD_SCHEMA,
    CLIENT_SYNC_RESPONSE_SCHEMA,
];

pub fn compatibility_table() -> SchemaCompatibilityTable {
    schema_version_compatibility_table()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_catalog_has_compatibility_for_all_registered_schemas() {
        let catalog = schema_catalog();
        catalog.validate().unwrap();
        assert!(catalog.entries.iter().any(|entry| entry.schema_id == OPERATION_SCHEMA));
    }

    #[test]
    fn schema_vectors_include_negative_security_extension_case() {
        validate_schema_vectors(&built_in_schema_vectors()).unwrap();
    }

    #[test]
    fn event_payload_catalog_validates_known_payload_fields() {
        let catalog = event_payload_validator_catalog();
        catalog
            .validate_payload(
                "cx.flow.move",
                &json!({
                    "flow_id": "cx:flow:01",
                    "parent_id": "cx:space:01"
                }),
            )
            .unwrap();
        assert!(matches!(
            catalog.validate_payload("cx.flow.move", &json!({"parent_id": "cx:space:01"})),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn generated_validators_cover_core_schema_ids() {
        let validators = generated_validators().unwrap();
        for schema_id in CORE_SCHEMA_IDS {
            assert!(validators.contains_key(*schema_id), "{schema_id}");
        }
    }

    #[test]
    fn spec_artifact_registry_covers_key_local_schema_and_event_contracts() {
        let Some(artifacts_dir) = default_spec_artifacts_dir() else {
            return;
        };
        let bundle = SpecArtifactBundle::load(artifacts_dir).unwrap();
        bundle.drift_report().validate().unwrap();

        let schemas = bundle.schema_registry["schemas"].as_array().expect("schemas array");
        let schema_ids = schemas
            .iter()
            .filter_map(|schema| schema["schema_id"].as_str())
            .collect::<BTreeSet<_>>();
        for schema_id in ARTIFACT_BACKED_SCHEMA_IDS {
            assert!(schema_ids.contains(*schema_id), "missing schema artifact for {schema_id}");
        }
        let event_schema = schemas
            .iter()
            .find(|schema| schema["schema_id"] == EVENT_SCHEMA)
            .expect("event envelope schema registry entry");
        assert_eq!(event_schema["file"].as_str(), Some("schemas/event-envelope.schema.json"));

        for event_kind in ARTIFACT_BACKED_EVENT_KINDS {
            let entry = registry_entry(
                &bundle.event_kind_registry,
                "event_kinds",
                "event_kind",
                event_kind,
            )
            .unwrap_or_else(|| panic!("missing event kind {event_kind}"));
            assert_eq!(entry["status"].as_str(), Some("active"), "{event_kind}");
            assert_eq!(entry["wire_scope"].as_str(), Some("durable_event"), "{event_kind}");
        }

        for operation_id in ARTIFACT_BACKED_SERVICE_OPERATIONS {
            assert!(
                registry_entry(
                    &bundle.operation_registry,
                    "operations",
                    "operation_id",
                    operation_id
                )
                .is_some(),
                "missing service operation {operation_id}"
            );
        }

        for (kind, wire_form) in
            [("event", "cx:event:<ulid>"), ("space", "cx:space:<ulid>"), ("flow", "cx:flow:<ulid>")]
        {
            let entry = registry_entry(&bundle.id_kind_registry, "id_kinds", "kind", kind)
                .unwrap_or_else(|| panic!("missing id kind {kind}"));
            assert_eq!(entry["wire_form"].as_str(), Some(wire_form), "{kind}");
        }
    }

    #[test]
    fn evolution_plan_rejects_breaking_release_candidate() {
        let mut breaking_changes = BTreeSet::new();
        breaking_changes.insert(SchemaBreakingChange::NewRequiredField);
        let plan = SchemaEvolutionPlan {
            from_version: "0.1.0".to_owned(),
            to_version: "0.2.0".to_owned(),
            affected_schemas: vec![OPERATION_SCHEMA.to_owned()],
            breaking_changes,
        };
        assert!(matches!(plan.validate_release_candidate(), Err(Error::Protocol(_))));
    }
}
