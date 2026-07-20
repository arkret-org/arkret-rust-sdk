use std::sync::OnceLock;

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPayloadSchemaRule {
    pub event_kind: String,
    pub payload_schema_id: String,
    pub required_fields: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EventPayloadValidatorCatalog {
    pub rules: BTreeMap<String, EventPayloadSchemaRule>,
    #[serde(default, skip)]
    registry: ProtocolSchemaRegistry,
}

impl EventPayloadValidatorCatalog {
    pub fn has_payload_validator(&self, event_kind: &str) -> bool {
        self.rules.contains_key(event_kind)
    }

    pub fn validate_payload(&self, event_kind: &str, payload: &Value) -> Result<()> {
        let warnings = self.validate_payload_with_warnings(event_kind, payload)?;
        for warning in warnings {
            tracing::warn!(
                event_kind = %event_kind,
                warning = %warning,
                "event payload validation warning"
            );
        }
        Ok(())
    }

    pub fn validate_payload_with_warnings(
        &self,
        event_kind: &str,
        payload: &Value,
    ) -> Result<Vec<String>> {
        let Some(rule) = self.rules.get(event_kind) else {
            return Err(Error::Protocol(format!(
                "event kind '{event_kind}' has no payload validator"
            )));
        };
        validate_required_payload_fields(event_kind, payload, &rule.required_fields)?;
        let mut warnings = Vec::new();
        warnings.extend(
            self.registry
                .validate_value_with_warnings(&rule.payload_schema_id, payload)
                .map_err(|error| {
                    Error::Protocol(format!(
                        "event kind '{event_kind}' payload violates {}: {error}",
                        rule.payload_schema_id
                    ))
                })?,
        );
        Ok(warnings)
    }

    pub fn missing_payload_validators_for<'a>(
        &self,
        event_kinds: impl IntoIterator<Item = &'a str>,
    ) -> Vec<String> {
        event_kinds
            .into_iter()
            .filter(|event_kind| !self.has_payload_validator(event_kind))
            .map(str::to_owned)
            .collect()
    }
}

fn validate_required_payload_fields(
    event_kind: &str,
    payload: &Value,
    required_fields: &[String],
) -> Result<()> {
    let object = payload.as_object().ok_or_else(|| {
        Error::Protocol(format!(
            "event kind '{event_kind}' payload must be a JSON object"
        ))
    })?;
    for field in required_fields {
        if !object.contains_key(field) {
            return Err(Error::Protocol(format!(
                "event kind '{event_kind}' payload requires field '{field}'"
            )));
        }
    }
    Ok(())
}

static DEFAULT_EVENT_PAYLOAD_VALIDATOR_CATALOG: OnceLock<
    std::result::Result<EventPayloadValidatorCatalog, String>,
> = OnceLock::new();

pub fn event_payload_validator_catalog() -> Result<EventPayloadValidatorCatalog> {
    match DEFAULT_EVENT_PAYLOAD_VALIDATOR_CATALOG.get_or_init(|| {
        build_default_event_payload_validator_catalog().map_err(|err| err.to_string())
    }) {
        Ok(catalog) => Ok(catalog.clone()),
        Err(error) => Err(Error::Protocol(error.clone())),
    }
}

fn build_default_event_payload_validator_catalog() -> Result<EventPayloadValidatorCatalog> {
    if let Some(artifacts_dir) = default_spec_artifacts_dir() {
        event_payload_validator_catalog_from_spec_artifacts(artifacts_dir)
    } else {
        event_payload_validator_catalog_from_embedded_spec_artifacts()
    }
}

pub fn event_payload_validator_catalog_from_spec_artifacts(
    artifacts_dir: impl AsRef<Path>,
) -> Result<EventPayloadValidatorCatalog> {
    let artifacts_dir = artifacts_dir.as_ref();
    let bundle = SpecArtifactBundle::load(artifacts_dir)?;
    let registry = schema_registry_from_spec_artifacts(artifacts_dir)?;
    event_payload_validator_catalog_from_bundle(&bundle, registry)
}

pub fn event_payload_validator_catalog_from_embedded_spec_artifacts()
-> Result<EventPayloadValidatorCatalog> {
    let bundle = SpecArtifactBundle::load_embedded()?;
    let registry = schema_registry_from_embedded_spec_artifacts()?;
    event_payload_validator_catalog_from_bundle(&bundle, registry)
}

fn event_payload_validator_catalog_from_bundle(
    bundle: &SpecArtifactBundle,
    registry: ProtocolSchemaRegistry,
) -> Result<EventPayloadValidatorCatalog> {
    let event_payload_schema = registry
        .schema(EVENT_PAYLOAD_SCHEMA)
        .ok_or_else(|| Error::Protocol("missing event payload schema artifact".to_owned()))?;
    let entries = bundle
        .event_kind_registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Protocol("event kind registry missing event_kinds".to_owned()))?;

    let mut rules = BTreeMap::new();
    for entry in entries {
        if entry.get("status").and_then(Value::as_str) != Some("active") {
            continue;
        }
        let Some(event_kind) = entry.get("event_kind").and_then(Value::as_str) else {
            continue;
        };
        if !events::is_standard_event_kind(event_kind) {
            continue;
        }
        let Some(payload_schema_id) = payload_schema_ref_for_event_entry(
            entry,
            event_payload_schema,
            &bundle.schema_registry,
        ) else {
            continue;
        };
        let required_fields =
            required_fields_for_event_kind(event_kind, &registry, &payload_schema_id);
        rules.insert(
            event_kind.to_owned(),
            EventPayloadSchemaRule {
                event_kind: event_kind.to_owned(),
                payload_schema_id,
                required_fields,
            },
        );
    }
    Ok(EventPayloadValidatorCatalog { rules, registry })
}

pub(super) fn payload_schema_ref_for_event_entry(
    entry: &Value,
    event_payload_schema: &Value,
    schema_registry: &Value,
) -> Option<String> {
    if let Some(schema_id) = entry.get("payload_schema").and_then(Value::as_str) {
        return Some(schema_id.to_owned());
    }
    if let Some(schema_ref) = entry.get("payload_schema_ref").and_then(Value::as_str) {
        let (file, fragment) = schema_ref
            .split_once('#')
            .map_or((schema_ref, None), |(file, fragment)| {
                (file, Some(fragment))
            });
        let schema_id = schema_registry
            .get("schemas")
            .and_then(Value::as_array)?
            .iter()
            .find(|schema| schema.get("file").and_then(Value::as_str) == Some(file))?
            .get("schema_id")
            .and_then(Value::as_str)?;
        return Some(match fragment {
            Some(fragment) => format!("{schema_id}#{fragment}"),
            None => schema_id.to_owned(),
        });
    }
    let event_kind = entry.get("event_kind").and_then(Value::as_str)?;
    let def_name = payload_def_name_for_event_kind(event_kind, event_payload_schema)?;
    Some(format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/{def_name}"))
}

fn payload_def_name_for_event_kind(
    event_kind: &str,
    event_payload_schema: &Value,
) -> Option<String> {
    let defs = event_payload_schema
        .get("$defs")
        .and_then(Value::as_object)?;
    for candidate in payload_def_candidates(event_kind) {
        if defs.contains_key(&candidate) {
            return Some(candidate);
        }
    }
    if generic_standard_payload_fallback_allowed(event_kind)
        && defs.contains_key("generic_standard_payload")
    {
        Some("generic_standard_payload".to_owned())
    } else {
        None
    }
}

fn generic_standard_payload_fallback_allowed(event_kind: &str) -> bool {
    matches!(
        event_kind,
        "ak.attestation.range_completeness"
            | "ak.audit.erasure_receipt"
            | "ak.circle.archive"
            | "ak.circle.restore"
            | "ak.circle.tombstone"
            | "ak.circle.update"
            | "ak.did.proof"
            | "ak.key.verification.accept"
            | "ak.key.verification.cancel"
            | "ak.key.verification.done"
            | "ak.key.verification.key"
            | "ak.key.verification.mac"
            | "ak.key.verification.ready"
            | "ak.key.verification.request"
            | "ak.key.verification.start"
            | "ak.moderation.appeal.close"
            | "ak.moderation.appeal.decision"
            | "ak.moderation.appeal.review"
            | "ak.moderation.appeal.submit"
            | "ak.presence"
            | "ak.realm.asset_privacy_policy"
            | "ak.realm.delivery_binding_policy"
            | "ak.realm.media_service"
            | "ak.realm.moderation_policy"
            | "ak.realm.plaintext_visible_services"
            | "ak.realm.policy"
            | "ak.realm.policy_components"
            | "ak.realm.policy_server"
            | "ak.realm.preview_policy"
            | "ak.realm.schema"
            | "ak.realm.upgrade"
            | "ak.realm_key.request"
            | "ak.receipt.read"
            | "ak.secret.request"
            | "ak.secret.send"
            | "ak.self.agent.deactivate"
            | "ak.self.agent.pause"
            | "ak.self.agent.resume"
            | "ak.self.moderation.report"
            | "ak.typing"
    )
}

fn payload_def_candidates(event_kind: &str) -> Vec<String> {
    let suffix = event_kind.strip_prefix("ak.").unwrap_or(event_kind);
    let exact = format!("{}_payload", suffix.replace('.', "_"));
    let parts = suffix.split('.').collect::<Vec<_>>();
    let mut candidates = Vec::new();
    match parts.as_slice() {
        ["space", "archive" | "restore"] => {
            candidates.push("space_state_transition_payload".to_owned());
        }
        ["space", "tombstone"] => candidates.push("space_object_tombstone_payload".to_owned()),
        _ => {}
    }
    candidates.push(exact);
    match parts.as_slice() {
        ["space", "create"] => candidates.push("space_create_payload".to_owned()),
        ["space", "child"] => candidates.push("space_child_payload".to_owned()),
        ["space", "parent"] => candidates.push("space_parent_payload".to_owned()),
        ["realm", "inheritance_policy"] => {
            candidates.push("realm_inheritance_policy_payload".to_owned());
        }
        ["realm", "history_visibility"] => {
            candidates.push("history_visibility_payload".to_owned());
        }
        ["realm", "history_sharing_policy"] => {
            candidates.push("history_sharing_policy_payload".to_owned());
        }
        ["realm", "read_receipt_policy"] => {
            candidates.push("read_receipt_policy_payload".to_owned());
        }
        ["realm", "disappearing_policy"] => {
            candidates.push("realm_disappearing_policy_payload".to_owned());
        }
        ["realm", "search_policy"] => {
            candidates.push("realm_search_policy_payload".to_owned());
        }
        ["space", "freeze"] => candidates.push("space_freeze_payload".to_owned()),
        ["space", "destroy"] => candidates.push("space_destroy_payload".to_owned()),
        ["space", "update"] => candidates.push("space_patch_payload".to_owned()),
        ["realm", "update"] => candidates.push("object_patch_payload".to_owned()),
        ["strand", "create"] => candidates.push("strand_create_payload".to_owned()),
        ["strand", "move"] => candidates.push("strand_move_payload".to_owned()),
        ["strand", "reorder"] => candidates.push("strand_reorder_payload".to_owned()),
        ["strand", "update"] => candidates.push("strand_patch_payload".to_owned()),
        ["strand", "archive" | "restore"] => {
            candidates.push("object_lifecycle_payload".to_owned());
        }
        ["strand", "track", "enable" | "disable" | "set_primary"] => {
            candidates.push("state_payload".to_owned());
        }
        ["strand", "track" | "tracks", "update"] => {
            candidates.push("generic_standard_payload".to_owned());
        }
        ["message", "create"] => candidates.push("message_create_payload".to_owned()),
        ["message", "revise"] => candidates.push("message_revise_payload".to_owned()),
        ["message", "redact"] | ["redaction"] => {
            candidates.push("message_redact_payload".to_owned());
        }
        ["reaction", "add" | "remove"] => candidates.push("reaction_payload".to_owned()),
        ["rsvp", "set"] => candidates.push("rsvp_set_payload".to_owned()),
        ["pin", "add"] => candidates.push("pin_add_payload".to_owned()),
        ["pin", "remove"] => candidates.push("pin_remove_payload".to_owned()),
        ["pin", "reorder"] => candidates.push("pin_reorder_payload".to_owned()),
        ["member", "state"] => candidates.push("membership_payload".to_owned()),
        ["morph", "create"] => candidates.push("morph_create_payload".to_owned()),
        ["morph", "update"] => candidates.push("morph_update_payload".to_owned()),
        ["morph", "archive" | "restore"] => {
            candidates.push("object_lifecycle_payload".to_owned());
        }
        ["relation", "create"] => candidates.push("relation_create_payload".to_owned()),
        ["relation", "update"] => candidates.push("relation_update_payload".to_owned()),
        ["relation", "delete"] => candidates.push("object_lifecycle_payload".to_owned()),
        ["container", "move_item"] => candidates.push("container_move_item_payload".to_owned()),
        ["container", "rebalance"] => candidates.push("container_rebalance_payload".to_owned()),
        ["view", "create" | "update" | "reconcile"] => candidates.push("view_payload".to_owned()),
        // Applet interop-session events resolve through the `exact`
        // candidate above, which the spec event-payload schema defines
        // directly. No family override is needed.
        // `ak.applet.registration` resolves through the `exact` candidate above
        // (`applet_registration_payload`, defined directly in the spec
        // event-payload schema) — it MUST NOT fall back to the generic shape.
        // Only `ak.applet.discovery` (no dedicated def) uses the generic body.
        ["applet", "discovery"] => {
            candidates.push("generic_standard_payload".to_owned());
        }
        ["capability", "grant" | "delegate" | "derived"] => {
            candidates.push("capability_grant_payload".to_owned());
        }
        ["capability", "revoke"] => candidates.push("capability_revoke_payload".to_owned()),
        ["session", "grant"] => candidates.push("session_grant_payload".to_owned()),
        ["consent", "grant"] => candidates.push("consent_grant_payload".to_owned()),
        ["consent", "revoke"] => candidates.push("consent_revoke_payload".to_owned()),
        ["device", "authorize"] => candidates.push("device_authorize_payload".to_owned()),
        ["device", "revoke"] => candidates.push("device_revoke_payload".to_owned()),
        ["device", "authorized"] => candidates.push("device_authorized_payload".to_owned()),
        ["device", "revoked"] => candidates.push("device_revoked_payload".to_owned()),
        ["device", "list_update"] => candidates.push("device_list_update_payload".to_owned()),
        ["cross_signing", "publish"] => candidates.push("cross_signing_publish_payload".to_owned()),
        ["cross_signing", "reset"] => candidates.push("cross_signing_reset_payload".to_owned()),
        ["mls", "proposal"] => candidates.push("mls_proposal_payload".to_owned()),
        ["mls", "genesis"] => candidates.push("mls_genesis_payload".to_owned()),
        ["mls", "commit"] => candidates.push("mls_commit_payload".to_owned()),
        ["mls", "commit_failed"] => candidates.push("mls_commit_failed_payload".to_owned()),
        ["mls", "welcome"] => candidates.push("mls_welcome_payload".to_owned()),
        ["mls", "keypackage"] => candidates.push("mls_keypackage_payload".to_owned()),
        ["realm_key", "share"] => candidates.push("realm_key_share_payload".to_owned()),
        ["realm_key", "withheld"] => candidates.push("realm_key_withheld_payload".to_owned()),
        ["realm_key", "share_audit"] => candidates.push("realm_key_share_audit_payload".to_owned()),
        ["moderation", "report"] => candidates.push("moderation_report_payload".to_owned()),
        ["audit", "accessed" | "ryw_receipt"] => candidates.push("audit_payload".to_owned()),
        ["call", "signal"] => candidates.push("call_payload".to_owned()),
        ["invite", ..] => candidates.push("invite_payload".to_owned()),
        ["profile", "update" | "realm_override"] => {
            candidates.push("object_patch_payload".to_owned());
        }
        ["space", ..]
        | ["organization", ..]
        | ["actor", ..]
        | ["handle", ..]
        | ["identity", ..]
        | ["schema", ..]
        | ["policy", ..]
        | ["account", ..]
        | ["profile", ..]
        | ["applet", ..]
        | ["mimi", ..]
        | ["sovereign", ..] => candidates.push("state_payload".to_owned()),
        _ => {}
    }
    candidates.dedup();
    candidates
}

fn required_fields_for_schema_ref(
    registry: &ProtocolSchemaRegistry,
    schema_ref: &str,
) -> Option<Vec<String>> {
    let schema = registry.schema(schema_ref)?;
    Some(
        schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
    )
}

fn required_fields_for_event_kind(
    event_kind: &str,
    registry: &ProtocolSchemaRegistry,
    schema_ref: &str,
) -> Vec<String> {
    let mut required_fields =
        required_fields_for_schema_ref(registry, schema_ref).unwrap_or_default();
    if event_kind == events::EventKind::INVITE_CREATE {
        for field in [
            "invite_id",
            "invitee",
            "invite_delivery_target",
            "introduction_evidence_digest",
            "expires_at",
        ] {
            if !required_fields.iter().any(|existing| existing == field) {
                required_fields.push(field.to_owned());
            }
        }
    }
    required_fields
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
            return Err(Error::Protocol(
                "schema evolution versions must be present".to_owned(),
            ));
        }
        if self.affected_schemas.is_empty() {
            return Err(Error::Protocol(
                "schema evolution must name affected schemas".to_owned(),
            ));
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
    let registry = schema_registry_from_default_spec_artifacts()?
        .unwrap_or_else(ProtocolSchemaRegistry::default);
    registry
        .schema_ids()
        .map(|schema_id| {
            Ok((
                schema_id.to_owned(),
                registry.generated_validator(schema_id)?,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Active standard event kinds whose content shape is validated by a
    /// dedicated sibling operation / content schema rather than an
    /// `event-payload.schema.json#/$defs/*` entry, so the SDK event-payload
    /// catalog legitimately carries no validator rule for them:
    ///
    /// - `ak.relation.tombstone` — `relation.schema.json`
    /// - `ak.moderation.franking_proof` — `moderation-report.schema.json`
    /// - `ak.read_cursor.advance` — `read-cursor-operations.schema.json` (actor-private,
    ///   `reducer_input:false`)
    ///
    /// Any *new* active standard kind that neither resolves to an event-payload
    /// def nor is added here MUST make [`catalog_covers_every_active_standard_kind`]
    /// fail closed, forcing an explicit wiring decision.
    const KINDS_WITHOUT_EVENT_PAYLOAD_VALIDATOR: &[&str] = &[
        "ak.moderation.franking_proof",
        "ak.read_cursor.advance",
        "ak.relation.tombstone",
    ];

    /// D6 fail-closed guard: every active standard event kind in the spec
    /// registry either resolves to an explicit payload validator (via
    /// [`payload_def_candidates`] or an explicit `payload_schema`) or appears in
    /// the documented [`KINDS_WITHOUT_EVENT_PAYLOAD_VALIDATOR`] exception list.
    /// A newly registered kind that is silently missed by the manual candidate
    /// table trips this assertion instead of drifting into an unvalidated
    /// payload surface.
    #[test]
    fn catalog_covers_every_active_standard_kind() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        let bundle = SpecArtifactBundle::load_embedded().unwrap();
        let entries = bundle
            .event_kind_registry
            .get("event_kinds")
            .and_then(Value::as_array)
            .unwrap();

        let mut missing = BTreeSet::new();
        for entry in entries {
            if entry.get("status").and_then(Value::as_str) != Some("active") {
                continue;
            }
            let Some(event_kind) = entry.get("event_kind").and_then(Value::as_str) else {
                continue;
            };
            if !events::is_standard_event_kind(event_kind) {
                continue;
            }
            if !catalog.has_payload_validator(event_kind) {
                missing.insert(event_kind.to_owned());
            }
        }

        let expected: BTreeSet<String> = KINDS_WITHOUT_EVENT_PAYLOAD_VALIDATOR
            .iter()
            .map(|k| (*k).to_owned())
            .collect();

        assert_eq!(
            missing, expected,
            "active standard kinds without a payload validator drifted from the documented \
             exception set; wire the new kind into payload_def_candidates or add it to \
             KINDS_WITHOUT_EVENT_PAYLOAD_VALIDATOR with a rationale"
        );
    }

    /// F-04 full-assertion guard (part 1): active standard kinds whose payload
    /// the manual [`payload_def_candidates`] table intentionally resolves to the
    /// loose `generic_standard_payload` shape — either through the explicit
    /// [`generic_standard_payload_fallback_allowed`] allow-list or a family arm
    /// that pushes the `generic_standard_payload` candidate directly (e.g.
    /// `ak.applet.discovery`, `ak.strand.tracks.update`).
    ///
    /// Every entry is a deliberate "no dedicated event-payload def" decision. A
    /// *new* active standard kind that silently inherits this loose shape must be
    /// added here with a rationale, which is exactly what
    /// [`every_active_standard_kind_resolves_to_dedicated_or_documented_catch_all`]
    /// forces — so the hand-maintained match table cannot quietly drift a new
    /// kind onto an under-specified payload surface.
    const KINDS_USING_GENERIC_STANDARD_PAYLOAD: &[&str] = &[
        "ak.applet.discovery",
        "ak.attestation.range_completeness",
        "ak.audit.erasure_receipt",
        "ak.circle.archive",
        "ak.circle.restore",
        "ak.circle.tombstone",
        "ak.circle.update",
        "ak.did.proof",
        "ak.key.verification.accept",
        "ak.key.verification.cancel",
        "ak.key.verification.done",
        "ak.key.verification.key",
        "ak.key.verification.mac",
        "ak.key.verification.ready",
        "ak.key.verification.request",
        "ak.key.verification.start",
        "ak.moderation.appeal.close",
        "ak.moderation.appeal.decision",
        "ak.moderation.appeal.review",
        "ak.moderation.appeal.submit",
        "ak.presence",
        "ak.realm.asset_privacy_policy",
        "ak.realm.delivery_binding_policy",
        "ak.realm.media_service",
        "ak.realm.moderation_policy",
        "ak.realm.plaintext_visible_services",
        "ak.realm.policy",
        "ak.realm.policy_components",
        "ak.realm.policy_server",
        "ak.realm.preview_policy",
        "ak.realm.schema",
        "ak.realm.upgrade",
        "ak.realm_key.request",
        "ak.receipt.read",
        "ak.secret.request",
        "ak.secret.send",
        "ak.self.agent.deactivate",
        "ak.self.agent.pause",
        "ak.self.agent.resume",
        "ak.self.moderation.report",
        "ak.strand.tracks.update",
        "ak.typing",
    ];

    /// F-04 full-assertion guard (part 2): active standard kinds validated only
    /// against the generic `state_payload` state-transition shape, reached via a
    /// broad family arm in [`payload_def_candidates`] (`["space", ..]`,
    /// `["organization", ..]`, `["identity", ..]`, `["policy", ..]`, `["schema",
    /// ..]`, `["actor", ..]`, `["handle", ..]`, `["sovereign", ..]`, plus the
    /// `["strand", "track", ...]` state arm). Same fail-closed contract as the
    /// generic list: a new family member that silently inherits `state_payload`
    /// must be registered here explicitly.
    const KINDS_USING_STATE_PAYLOAD: &[&str] = &[
        "ak.actor.discovery",
        "ak.handle.discovery",
        "ak.identity.disclosure_policy",
        "ak.identity.disclosure_receipt",
        "ak.identity.presentation_request",
        "ak.identity.presentation_response",
        "ak.organization.discovery",
        "ak.organization.moderation_policy",
        "ak.policy.action",
        "ak.policy.rule",
        "ak.policy.set",
        "ak.profile.create",
        "ak.schema.define",
        "ak.schema.update",
        "ak.sovereign.did_policy",
    ];

    /// F-04 residual closed: beyond [`catalog_covers_every_active_standard_kind`]
    /// (which fails closed when a kind resolves to *no* validator), this test
    /// pins *which* kinds are allowed to resolve to a **catch-all** payload shape
    /// (`generic_standard_payload` / `state_payload`) rather than a dedicated
    /// `event-payload.schema.json#/$defs/*_payload` def.
    ///
    /// It asserts, over the full embedded spec event-kind registry, that the set
    /// of active standard kinds landing on each catch-all shape is *exactly* the
    /// documented list — catching drift in both directions:
    /// - a newly registered kind that silently inherits a catch-all via a broad family arm (appears
    ///   in the computed set, absent from the list) → red;
    /// - a kind that gained a dedicated def in the spec but is still listed as catch-all here
    ///   (absent from the computed set, still listed) → red, prompting removal from the list.
    ///
    /// Any kind resolving to a dedicated `*_payload` def is, by construction, in
    /// neither set and needs no maintenance here. This turns hand-table drift
    /// toward under-validation into a CI-catchable failure.
    #[test]
    fn every_active_standard_kind_resolves_to_dedicated_or_documented_catch_all() {
        const GENERIC_DEF: &str = "generic_standard_payload";
        const STATE_DEF: &str = "state_payload";

        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        let bundle = SpecArtifactBundle::load_embedded().unwrap();
        let entries = bundle
            .event_kind_registry
            .get("event_kinds")
            .and_then(Value::as_array)
            .unwrap();

        let mut generic = BTreeSet::new();
        let mut state = BTreeSet::new();
        for entry in entries {
            if entry.get("status").and_then(Value::as_str) != Some("active") {
                continue;
            }
            let Some(event_kind) = entry.get("event_kind").and_then(Value::as_str) else {
                continue;
            };
            if !events::is_standard_event_kind(event_kind) {
                continue;
            }
            let Some(rule) = catalog.rules.get(event_kind) else {
                // No validator at all is the concern of
                // `catalog_covers_every_active_standard_kind`, not this test.
                continue;
            };
            let def = rule
                .payload_schema_id
                .rsplit("#/$defs/")
                .next()
                .unwrap_or(rule.payload_schema_id.as_str());
            match def {
                GENERIC_DEF => {
                    generic.insert(event_kind.to_owned());
                }
                STATE_DEF => {
                    state.insert(event_kind.to_owned());
                }
                _ => {}
            }
        }

        let expected_generic: BTreeSet<String> = KINDS_USING_GENERIC_STANDARD_PAYLOAD
            .iter()
            .map(|k| (*k).to_owned())
            .collect();
        let expected_state: BTreeSet<String> = KINDS_USING_STATE_PAYLOAD
            .iter()
            .map(|k| (*k).to_owned())
            .collect();

        assert_eq!(
            generic, expected_generic,
            "active standard kinds resolving to the loose `generic_standard_payload` shape \
             drifted from the documented KINDS_USING_GENERIC_STANDARD_PAYLOAD set; either wire \
             the new kind to a dedicated `*_payload` def in payload_def_candidates or register \
             it here with a rationale"
        );
        assert_eq!(
            state, expected_state,
            "active standard kinds resolving to the loose `state_payload` shape drifted from the \
             documented KINDS_USING_STATE_PAYLOAD set; either wire the new kind to a dedicated \
             `*_payload` def in payload_def_candidates or register it here with a rationale"
        );
    }

    #[test]
    fn applet_registration_resolves_to_strong_payload_not_generic() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        // The strong def wins over the generic fallback.
        assert_eq!(
            catalog.rules["ak.applet.registration"].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/applet_registration_payload")
        );
        // The legacy `{service_id, namespace, capabilities}` short form is
        // rejected by the strong validator (missing required fields).
        let legacy = json!({
            "service_id": "did:webvh:z6mkfixture:applet.example",
            "namespace": "ns",
            "capabilities": ["ak.message.create"]
        });
        assert!(
            catalog
                .validate_payload("ak.applet.registration", &legacy)
                .is_err(),
            "legacy short-form applet registration payload must be rejected"
        );
        // `ak.applet.discovery` retains the generic body (no dedicated def).
        assert_eq!(
            catalog.rules["ak.applet.discovery"].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/generic_standard_payload")
        );
    }

    #[test]
    fn catalog_reports_registered_payload_validators() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();

        assert!(catalog.has_payload_validator(events::EventKind::REALM_KEY_SHARE));
        assert!(!catalog.has_payload_validator("ak.unknown.test"));
    }

    #[test]
    fn selector_claim_resolves_to_its_registered_schema() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        let rule = &catalog.rules[events::EventKind::AGENT_SELECTOR_CLAIM];

        assert_eq!(
            rule.payload_schema_id,
            arkret_wire::AGENT_SELECTOR_CLAIM_SCHEMA
        );
        assert!(
            rule.required_fields
                .contains(&"controller_subject".to_owned())
        );
        assert!(rule.required_fields.contains(&"proofs".to_owned()));
        assert!(
            catalog
                .validate_payload(
                    events::EventKind::AGENT_SELECTOR_CLAIM,
                    &json!({"schema": arkret_wire::AGENT_SELECTOR_CLAIM_SCHEMA})
                )
                .is_err(),
            "partial selector claims must fail the dedicated schema validator"
        );
    }

    #[test]
    fn new_unmatched_event_kind_does_not_fall_back_to_generic_payload() {
        let event_payload_schema = json!({
            "$defs": {
                "generic_standard_payload": {},
                "state_payload": {}
            }
        });

        assert_eq!(
            payload_def_name_for_event_kind("ak.realm.new_policy", &event_payload_schema),
            None
        );
        assert_eq!(
            payload_def_name_for_event_kind("ak.realm.policy", &event_payload_schema),
            Some("generic_standard_payload".to_owned())
        );
        assert_eq!(
            payload_def_name_for_event_kind("ak.account.status", &event_payload_schema),
            Some("state_payload".to_owned())
        );
    }

    #[test]
    fn strong_catalog_accepts_read_receipt_policy_payload() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        assert_eq!(
            catalog.rules["ak.realm.read_receipt_policy"].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/read_receipt_policy_payload")
        );
        catalog
            .validate_payload(
                "ak.realm.read_receipt_policy",
                &json!({
                    "disclosure": "required"
                }),
            )
            .unwrap();
    }

    #[cfg(feature = "embedded-artifacts")]
    #[test]
    fn realm_join_rule_and_discovery_use_closed_payloads() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        assert_eq!(
            catalog.rules["ak.realm.join_rule"].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/realm_join_rule_payload")
        );
        assert_eq!(
            catalog.rules["ak.realm.discovery"].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/realm_discovery_payload")
        );

        for value in [
            "public",
            "invite",
            "knock",
            "restricted",
            "knock_restricted",
            "closed",
        ] {
            catalog
                .validate_payload("ak.realm.join_rule", &json!({"value": value}))
                .unwrap();
        }
        for value in [
            "public",
            "listed",
            "restricted",
            "unlisted",
            "invite_only",
            "secret",
        ] {
            catalog
                .validate_payload("ak.realm.discovery", &json!({"value": value}))
                .unwrap();
        }
        for (kind, payload) in [
            ("ak.realm.join_rule", json!({"value": "open"})),
            ("ak.realm.discovery", json!({"value": "private"})),
            ("ak.realm.join_rule", json!({"value": 1})),
            (
                "ak.realm.discovery",
                json!({"value": "listed", "unexpected": true}),
            ),
        ] {
            assert!(
                catalog.validate_payload(kind, &payload).is_err(),
                "{kind} unexpectedly accepted {payload}"
            );
        }
    }

    fn service_attested_device_authorize_payload() -> Value {
        json!({
            "principal_id": "did:webvh:z6mkfixture:alice.example",
            "device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "device_public_key": "z6Mki3devicepublickey",
            "hpke_key": "z6LSdevicehpke",
            "algorithms": ["ed25519", "x25519-hpke"],
            "authorized_by": "did:webvh:z6mkfixture:authority.example",
            "not_before": "2026-06-30T00:00:00Z",
            "enrollment_authority_binding": {
                "kind": "service_attested",
                "authority_did": "did:webvh:z6mkfixture:authority.example",
                "authorization_ref": "ak:grant:0196419b-0000-7000-8000-000000000002"
            }
        })
    }

    #[test]
    fn strong_catalog_accepts_device_authorize_payload() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        assert_eq!(
            catalog.rules["ak.device.authorize"].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/device_authorize_payload")
        );
        catalog
            .validate_payload(
                "ak.device.authorize",
                &service_attested_device_authorize_payload(),
            )
            .unwrap();
    }

    fn realm_organization_active_payload() -> Value {
        json!({
            "statement_id": "org-stmt-1",
            "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000010",
            "organization_id": "did:webvh:example.test:orgs:org1",
            "relationship": "owner",
            "status": "active",
            "control_scopes": ["official_badge", "realm_admin"],
            "issued_at": "2026-06-25T00:00:00Z",
            "authorization": {
                "issuer": "did:webvh:example.test:orgs:org1",
                "issuer_role": "organization_did",
                "verification_method": "did:webvh:example.test:orgs:org1#k1",
                "signed_at": "2026-06-25T00:00:00Z",
                "proof": "c2ln"
            }
        })
    }

    /// SDK-ORG-03: the strong catalog MUST resolve `ak.realm.organization` to
    /// the `realm_organization_payload` def (exact dispatch, no fallback to a
    /// generic / legacy shape) and derive the 8 top-level required fields.
    #[test]
    fn strong_catalog_validates_realm_organization_relationship_statement() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        assert_eq!(
            catalog.rules["ak.realm.organization"].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/realm_organization_payload")
        );
        let required: BTreeSet<&str> = catalog.rules["ak.realm.organization"]
            .required_fields
            .iter()
            .map(String::as_str)
            .collect();
        for field in [
            "statement_id",
            "realm_id",
            "organization_id",
            "relationship",
            "status",
            "control_scopes",
            "issued_at",
            "authorization",
        ] {
            assert!(required.contains(field), "missing required field {field}");
        }

        // Active positive case.
        catalog
            .validate_payload(
                "ak.realm.organization",
                &realm_organization_active_payload(),
            )
            .unwrap();

        // Revoked positive case (carries revokes_statement_id).
        let mut revoked = realm_organization_active_payload();
        revoked["status"] = json!("revoked");
        revoked["revokes_statement_id"] = json!("org-stmt-0");
        catalog
            .validate_payload("ak.realm.organization", &revoked)
            .unwrap();
    }

    /// SDK-ORG-03 negative cases: each MUST be rejected by the strong schema.
    #[test]
    fn strong_catalog_rejects_invalid_realm_organization_statements() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();

        // revoked status without revokes_statement_id.
        let mut revoked_missing = realm_organization_active_payload();
        revoked_missing["status"] = json!("revoked");
        assert!(
            catalog
                .validate_payload("ak.realm.organization", &revoked_missing)
                .is_err(),
            "revoked without revokes_statement_id must fail"
        );

        // governance_service issuer without delegation_ref.
        let mut gov_missing = realm_organization_active_payload();
        gov_missing["authorization"]["issuer_role"] = json!("governance_service");
        assert!(
            catalog
                .validate_payload("ak.realm.organization", &gov_missing)
                .is_err(),
            "governance_service without delegation_ref must fail"
        );

        // account_authority issuer without delegation_ref.
        let mut acct_missing = realm_organization_active_payload();
        acct_missing["authorization"]["issuer_role"] = json!("account_authority");
        assert!(
            catalog
                .validate_payload("ak.realm.organization", &acct_missing)
                .is_err(),
            "account_authority without delegation_ref must fail"
        );

        // missing proof.
        let mut no_proof = realm_organization_active_payload();
        no_proof["authorization"]
            .as_object_mut()
            .unwrap()
            .remove("proof");
        assert!(
            catalog
                .validate_payload("ak.realm.organization", &no_proof)
                .is_err(),
            "missing authorization.proof must fail"
        );

        // bad relationship.
        let mut bad_rel = realm_organization_active_payload();
        bad_rel["relationship"] = json!("admin");
        assert!(
            catalog
                .validate_payload("ak.realm.organization", &bad_rel)
                .is_err(),
            "invalid relationship must fail"
        );

        // bad control_scopes item.
        let mut bad_scope = realm_organization_active_payload();
        bad_scope["control_scopes"] = json!(["not_a_scope"]);
        assert!(
            catalog
                .validate_payload("ak.realm.organization", &bad_scope)
                .is_err(),
            "invalid control_scopes item must fail"
        );

        // legacy singleton shape must be rejected (required fields missing).
        let legacy = json!({ "organization_ref": "did:webvh:z6mkfixture:org.example" });
        assert!(
            catalog
                .validate_payload("ak.realm.organization", &legacy)
                .is_err(),
            "legacy {{ organization_ref }} shape must fail"
        );
    }
}
