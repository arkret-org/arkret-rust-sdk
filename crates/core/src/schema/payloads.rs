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
        if !crate::events::is_standard_event_kind(event_kind) {
            continue;
        }
        let Some(payload_schema_id) =
            payload_schema_ref_for_event_entry(entry, event_payload_schema)
        else {
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
) -> Option<String> {
    if let Some(schema_id) = entry.get("payload_schema").and_then(Value::as_str) {
        return Some(schema_id.to_owned());
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
        "ck.attestation.range_completeness"
            | "ck.audit.erasure_receipt"
            | "ck.circle.archive"
            | "ck.circle.restore"
            | "ck.circle.tombstone"
            | "ck.circle.update"
            | "ck.did.proof"
            | "ck.key.verification.accept"
            | "ck.key.verification.cancel"
            | "ck.key.verification.done"
            | "ck.key.verification.key"
            | "ck.key.verification.mac"
            | "ck.key.verification.ready"
            | "ck.key.verification.request"
            | "ck.key.verification.start"
            | "ck.moderation.appeal.close"
            | "ck.moderation.appeal.decision"
            | "ck.moderation.appeal.review"
            | "ck.moderation.appeal.submit"
            | "ck.presence"
            | "ck.realm.asset_privacy_policy"
            | "ck.realm.delivery_binding_policy"
            | "ck.realm.discovery"
            | "ck.realm.join_rule"
            | "ck.realm.media_service"
            | "ck.realm.moderation_policy"
            | "ck.realm.plaintext_visible_services"
            | "ck.realm.policy"
            | "ck.realm.policy_components"
            | "ck.realm.policy_server"
            | "ck.realm.preview_policy"
            | "ck.realm.schema"
            | "ck.realm.upgrade"
            | "ck.realm_key.request"
            | "ck.receipt.read"
            | "ck.secret.request"
            | "ck.secret.send"
            | "ck.self.agent.deactivate"
            | "ck.self.agent.pause"
            | "ck.self.agent.resume"
            | "ck.self.moderation.report"
            | "ck.typing"
    )
}

fn payload_def_candidates(event_kind: &str) -> Vec<String> {
    let suffix = event_kind.strip_prefix("ck.").unwrap_or(event_kind);
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
        ["container", "move_item" | "rebalance"] => {
            candidates.push("container_position_payload".to_owned());
        }
        ["view", "create" | "update" | "reconcile"] => candidates.push("view_payload".to_owned()),
        ["agent", "endpoint"] => candidates.push("agent_endpoint_payload".to_owned()),
        // Agent/applet interop-session events resolve through the `exact`
        // candidate above (agent_interop_session_*_payload /
        // applet_interop_session_*_payload), which the spec event-payload
        // schema defines directly. No family override needed.
        // `ck.applet.registration` resolves through the `exact` candidate above
        // (`applet_registration_payload`, defined directly in the spec
        // event-payload schema) — it MUST NOT fall back to the generic shape.
        // Only `ck.applet.discovery` (no dedicated def) uses the generic body.
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
    if event_kind == crate::events::INVITE_CREATE {
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
    /// - `ck.relation.tombstone` — `relation.schema.json`
    /// - `ck.moderation.franking_proof` — `moderation-report.schema.json`
    /// - `ck.read_cursor.advance` — `read-cursor-operations.schema.json` (actor-private,
    ///   `reducer_input:false`)
    ///
    /// Any *new* active standard kind that neither resolves to an event-payload
    /// def nor is added here MUST make [`catalog_covers_every_active_standard_kind`]
    /// fail closed, forcing an explicit wiring decision.
    const KINDS_WITHOUT_EVENT_PAYLOAD_VALIDATOR: &[&str] = &[
        "ck.moderation.franking_proof",
        "ck.read_cursor.advance",
        "ck.relation.tombstone",
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
            if !crate::events::is_standard_event_kind(event_kind) {
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

    #[test]
    fn applet_registration_resolves_to_strong_payload_not_generic() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        // The strong def wins over the generic fallback.
        assert_eq!(
            catalog.rules["ck.applet.registration"].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/applet_registration_payload")
        );
        // The legacy `{service_did, namespace, capabilities}` short form is
        // rejected by the strong validator (missing required fields).
        let legacy = json!({
            "service_did": "did:webvh:z6mkfixture:applet.example",
            "namespace": "ns",
            "capabilities": ["ck.message.create"]
        });
        assert!(
            catalog
                .validate_payload("ck.applet.registration", &legacy)
                .is_err(),
            "legacy short-form applet registration payload must be rejected"
        );
        // `ck.applet.discovery` retains the generic body (no dedicated def).
        assert_eq!(
            catalog.rules["ck.applet.discovery"].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/generic_standard_payload")
        );
    }

    #[test]
    fn catalog_reports_registered_payload_validators() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();

        assert!(catalog.has_payload_validator(crate::events::kinds::REALM_KEY_SHARE));
        assert!(!catalog.has_payload_validator("ck.unknown.test"));
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
            payload_def_name_for_event_kind("ck.realm.new_policy", &event_payload_schema),
            None
        );
        assert_eq!(
            payload_def_name_for_event_kind("ck.realm.policy", &event_payload_schema),
            Some("generic_standard_payload".to_owned())
        );
        assert_eq!(
            payload_def_name_for_event_kind("ck.account.status", &event_payload_schema),
            Some("state_payload".to_owned())
        );
    }

    #[test]
    fn strong_catalog_accepts_read_receipt_policy_payload() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        assert_eq!(
            catalog.rules["ck.realm.read_receipt_policy"].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/read_receipt_policy_payload")
        );
        catalog
            .validate_payload(
                "ck.realm.read_receipt_policy",
                &json!({
                    "disclosure": "required"
                }),
            )
            .unwrap();
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
            catalog.rules["ck.device.authorize"].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/device_authorize_payload")
        );
        catalog
            .validate_payload(
                "ck.device.authorize",
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

    /// SDK-ORG-03: the strong catalog MUST resolve `ck.realm.organization` to
    /// the `realm_organization_payload` def (exact dispatch, no fallback to a
    /// generic / legacy shape) and derive the 8 top-level required fields.
    #[test]
    fn strong_catalog_validates_realm_organization_relationship_statement() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        assert_eq!(
            catalog.rules["ck.realm.organization"].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/realm_organization_payload")
        );
        let required: BTreeSet<&str> = catalog.rules["ck.realm.organization"]
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
                "ck.realm.organization",
                &realm_organization_active_payload(),
            )
            .unwrap();

        // Revoked positive case (carries revokes_statement_id).
        let mut revoked = realm_organization_active_payload();
        revoked["status"] = json!("revoked");
        revoked["revokes_statement_id"] = json!("org-stmt-0");
        catalog
            .validate_payload("ck.realm.organization", &revoked)
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
                .validate_payload("ck.realm.organization", &revoked_missing)
                .is_err(),
            "revoked without revokes_statement_id must fail"
        );

        // governance_service issuer without delegation_ref.
        let mut gov_missing = realm_organization_active_payload();
        gov_missing["authorization"]["issuer_role"] = json!("governance_service");
        assert!(
            catalog
                .validate_payload("ck.realm.organization", &gov_missing)
                .is_err(),
            "governance_service without delegation_ref must fail"
        );

        // account_authority issuer without delegation_ref.
        let mut acct_missing = realm_organization_active_payload();
        acct_missing["authorization"]["issuer_role"] = json!("account_authority");
        assert!(
            catalog
                .validate_payload("ck.realm.organization", &acct_missing)
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
                .validate_payload("ck.realm.organization", &no_proof)
                .is_err(),
            "missing authorization.proof must fail"
        );

        // bad relationship.
        let mut bad_rel = realm_organization_active_payload();
        bad_rel["relationship"] = json!("admin");
        assert!(
            catalog
                .validate_payload("ck.realm.organization", &bad_rel)
                .is_err(),
            "invalid relationship must fail"
        );

        // bad control_scopes item.
        let mut bad_scope = realm_organization_active_payload();
        bad_scope["control_scopes"] = json!(["not_a_scope"]);
        assert!(
            catalog
                .validate_payload("ck.realm.organization", &bad_scope)
                .is_err(),
            "invalid control_scopes item must fail"
        );

        // legacy singleton shape must be rejected (required fields missing).
        let legacy = json!({ "organization_ref": "did:webvh:z6mkfixture:org.example" });
        assert!(
            catalog
                .validate_payload("ck.realm.organization", &legacy)
                .is_err(),
            "legacy {{ organization_ref }} shape must fail"
        );
    }
}
