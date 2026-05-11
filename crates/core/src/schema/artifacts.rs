use super::*;
use crate::events::STANDARD_EVENT_KINDS;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpecArtifactBundle {
    pub schema_registry: Value,
    pub event_kind_registry: Value,
    pub operation_registry: Value,
    pub id_kind_registry: Value,
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
/// and typed-ID kinds the SDK recognises from the v1 spec registry.
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
    EVENT_SCHEMA,
    FLOW_SCHEMA,
    PLACE_SCHEMA,
    CAPABILITY_SCHEMA,
    CURSOR_SCHEMA,
    ENCRYPTED_PAYLOAD_SCHEMA,
    CLIENT_SYNC_RESPONSE_SCHEMA,
    VIEW_SCHEMA,
];

/// Active event kinds the SDK recognises from the spec registry.
pub const ARTIFACT_BACKED_EVENT_KINDS: &[&str] = STANDARD_EVENT_KINDS;

pub const ARTIFACT_BACKED_SERVICE_OPERATIONS: &[&str] = &[
    "cx.events.submit",
    "cx.events.get",
    "cx.events.batch_get",
    "cx.events.frontier",
    "cx.events.query",
    "cx.events.subscribe",
    // C17 wire-break (spec 2026-05-08): cx.sync.client_sync → cx.sync.account.
    "cx.sync.account",
    "cx.server.describe",
];

pub const ARTIFACT_BACKED_ID_KINDS: &[&str] =
    &["event", "space", "flow", "place", "morph", "message"];

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
