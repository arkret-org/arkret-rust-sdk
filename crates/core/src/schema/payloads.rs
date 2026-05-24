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
    #[serde(skip)]
    registry: Option<ProtocolSchemaRegistry>,
}

impl EventPayloadValidatorCatalog {
    pub fn validate_payload(&self, event_kind: &str, payload: &Value) -> Result<()> {
        let Some(rule) = self.rules.get(event_kind) else {
            return Err(Error::Protocol(format!(
                "event kind '{event_kind}' has no payload validator"
            )));
        };
        validate_required_payload_fields(event_kind, payload, &rule.required_fields)?;
        if let Some(registry) = &self.registry {
            registry.validate_value(&rule.payload_schema_id, payload).map_err(|error| {
                Error::Protocol(format!(
                    "event kind '{event_kind}' payload violates {}: {error}",
                    rule.payload_schema_id
                ))
            })?;
        }
        Ok(())
    }

    pub fn missing_payload_validators_for<'a>(
        &self,
        event_kinds: impl IntoIterator<Item = &'a str>,
    ) -> Vec<String> {
        event_kinds
            .into_iter()
            .filter(|event_kind| !self.rules.contains_key(*event_kind))
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
        Error::Protocol(format!("event kind '{event_kind}' payload must be a JSON object"))
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

pub fn event_payload_validator_catalog() -> EventPayloadValidatorCatalog {
    if let Some(artifacts_dir) = default_spec_artifacts_dir()
        && let Ok(catalog) = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir)
    {
        return catalog;
    }
    fallback_event_payload_validator_catalog()
}

pub fn event_payload_validator_catalog_from_spec_artifacts(
    artifacts_dir: impl AsRef<Path>,
) -> Result<EventPayloadValidatorCatalog> {
    let artifacts_dir = artifacts_dir.as_ref();
    let bundle = SpecArtifactBundle::load(artifacts_dir)?;
    let registry = schema_registry_from_spec_artifacts(artifacts_dir)?;
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
            required_fields_for_schema_ref(&registry, &payload_schema_id).unwrap_or_default();
        rules.insert(
            event_kind.to_owned(),
            EventPayloadSchemaRule {
                event_kind: event_kind.to_owned(),
                payload_schema_id,
                required_fields,
            },
        );
    }
    Ok(EventPayloadValidatorCatalog { rules, registry: Some(registry) })
}

fn fallback_event_payload_validator_catalog() -> EventPayloadValidatorCatalog {
    let rules = [
        ("cx.flow.create", EVENT_PAYLOAD_SCHEMA, &["object"][..]),
        ("cx.flow.update", EVENT_PAYLOAD_SCHEMA, &["patch"][..]),
        (
            "cx.flow.move",
            EVENT_PAYLOAD_SCHEMA,
            &["board_space_id", "flow_id", "target_space_id", "rank"][..],
        ),
        (
            "cx.flow.reorder",
            EVENT_PAYLOAD_SCHEMA,
            &["board_space_id", "flow_id", "space_id", "rank"][..],
        ),
        ("cx.message.create", EVENT_PAYLOAD_SCHEMA, &["flow_id", "track"][..]),
        ("cx.member.state", EVENT_PAYLOAD_SCHEMA, &["membership"][..]),
        (
            "cx.capability.grant",
            CAPABILITY_SCHEMA,
            &["grant_id", "subject", "actions", "resources"][..],
        ),
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
    EventPayloadValidatorCatalog { rules, registry: Some(ProtocolSchemaRegistry::default()) }
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
    let defs = event_payload_schema.get("$defs").and_then(Value::as_object)?;
    for candidate in payload_def_candidates(event_kind) {
        if defs.contains_key(&candidate) {
            return Some(candidate);
        }
    }
    if defs.contains_key("generic_standard_payload") {
        Some("generic_standard_payload".to_owned())
    } else {
        None
    }
}

fn payload_def_candidates(event_kind: &str) -> Vec<String> {
    let suffix = event_kind.strip_prefix("cx.").unwrap_or(event_kind);
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
        ["space", "inheritance_policy"] => {
            candidates.push("space_inheritance_policy_payload".to_owned());
        }
        ["space", "freeze"] => candidates.push("space_freeze_payload".to_owned()),
        ["space", "destroy"] => candidates.push("space_destroy_payload".to_owned()),
        ["realm", "update"] => candidates.push("object_patch_payload".to_owned()),
        ["flow", "create"] => candidates.push("flow_create_payload".to_owned()),
        ["flow", "move"] => candidates.push("flow_move_payload".to_owned()),
        ["flow", "reorder"] => candidates.push("flow_reorder_payload".to_owned()),
        ["flow", "update"] => candidates.push("object_patch_payload".to_owned()),
        ["flow", "archive" | "restore"] => candidates.push("object_lifecycle_payload".to_owned()),
        ["flow", "track", "enable" | "disable" | "set_primary"] => {
            candidates.push("state_payload".to_owned());
        }
        ["flow", "track" | "tracks", "update"] => {
            candidates.push("object_patch_payload".to_owned())
        }
        ["message", "create"] => candidates.push("message_create_payload".to_owned()),
        ["message", "revise"] => candidates.push("message_revise_payload".to_owned()),
        ["message", "redact"] | ["redaction"] => {
            candidates.push("message_redact_payload".to_owned());
        }
        ["reaction", "add" | "remove"] => candidates.push("reaction_payload".to_owned()),
        ["member", "state"] => candidates.push("membership_payload".to_owned()),
        ["morph", "create"] => candidates.push("morph_create_payload".to_owned()),
        ["morph", "update"] => candidates.push("object_patch_payload".to_owned()),
        ["morph", "archive" | "restore"] => candidates.push("object_lifecycle_payload".to_owned()),
        ["relation", "create"] => candidates.push("relation_create_payload".to_owned()),
        ["relation", "update"] => candidates.push("relation_update_payload".to_owned()),
        ["relation", "delete"] => candidates.push("object_lifecycle_payload".to_owned()),
        ["container", "move_item" | "rebalance"] => {
            candidates.push("container_position_payload".to_owned());
        }
        ["view", "create" | "update" | "reconcile"] => candidates.push("view_payload".to_owned()),
        ["agent", "endpoint"] => candidates.push("agent_endpoint_payload".to_owned()),
        ["agent", "protocol_session", "start"] => {
            candidates.push("agent_session_start_payload".to_owned());
        }
        ["agent", "protocol_session", "status"] => {
            candidates.push("agent_session_status_payload".to_owned());
        }
        ["agent", "protocol_session", "result"] => {
            candidates.push("agent_session_result_payload".to_owned());
        }
        ["capability", "grant" | "delegate" | "derived"] => {
            candidates.push("capability_grant_payload".to_owned());
        }
        ["capability", "revoke"] => candidates.push("capability_revoke_payload".to_owned()),
        ["session", "grant"] => candidates.push("session_grant_payload".to_owned()),
        ["consent", "grant"] => candidates.push("consent_grant_payload".to_owned()),
        ["consent", "revoke"] => candidates.push("consent_revoke_payload".to_owned()),
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
        ["call", "state"] | ["call", "recording", "start"] => {
            candidates.push("call_payload".to_owned());
        }
        ["invite", ..] => candidates.push("invite_payload".to_owned()),
        ["profile", "update" | "space_override"] => {
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
    let registry = schema_registry_from_default_spec_artifacts()?
        .unwrap_or_else(ProtocolSchemaRegistry::default);
    registry
        .schema_ids()
        .map(|schema_id| Ok((schema_id.to_owned(), registry.generated_validator(schema_id)?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fallback_catalog_accepts_flow_create_payload_wrapper() {
        let catalog = fallback_event_payload_validator_catalog();

        assert_eq!(catalog.rules["cx.flow.create"].payload_schema_id, EVENT_PAYLOAD_SCHEMA);
        catalog
            .validate_payload(
                "cx.flow.create",
                &json!({
                    "object": {
                        "id": "cx:flow:0196419b-0000-7000-8000-000000000001",
                        "schema": FLOW_SCHEMA,
                        "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000010",
                        "title": "Move-backed card",
                        "tracks": { "synthesis": { "is_primary": true } },
                        "created_by": "did:web:alice.example",
                        "created_at": "2026-05-22T00:00:00Z"
                    }
                }),
            )
            .unwrap();

        assert!(catalog.validate_payload("cx.flow.create", &json!({ "title": "legacy" })).is_err());
    }

    #[test]
    fn fallback_catalog_accepts_current_flow_move_keys() {
        let catalog = fallback_event_payload_validator_catalog();

        catalog
            .validate_payload(
                "cx.flow.move",
                &json!({
                    "board_space_id": "cx:space:0196419b-0000-7000-8000-000000000010",
                    "flow_id": "cx:flow:0196419b-0000-7000-8000-000000000001",
                    "target_space_id": "cx:space:0196419b-0000-7000-8000-000000000020",
                    "rank": "U"
                }),
            )
            .unwrap();

        assert!(
            catalog
                .validate_payload(
                    "cx.flow.move",
                    &json!({
                        "board_place_id": "cx:place:legacy",
                        "flow_id": "cx:flow:0196419b-0000-7000-8000-000000000001",
                        "target_place_id": "cx:place:legacy",
                        "rank": "U"
                    }),
                )
                .is_err()
        );
    }

    #[test]
    fn fallback_catalog_accepts_message_create_payload_not_event_envelope() {
        let catalog = fallback_event_payload_validator_catalog();

        assert_eq!(catalog.rules["cx.message.create"].payload_schema_id, EVENT_PAYLOAD_SCHEMA);
        catalog
            .validate_payload(
                "cx.message.create",
                &json!({
                    "flow_id": "cx:flow:0196419b-0000-7000-8000-000000000001",
                    "track": "discussion",
                    "content": {
                        "kind": "cx.content.text",
                        "body": "hello"
                    },
                    "encrypted": false
                }),
            )
            .unwrap();

        assert!(
            catalog
                .validate_payload(
                    "cx.message.create",
                    &json!({
                        "kind": "cx.message.create",
                        "payload": {
                            "flow_id": "cx:flow:0196419b-0000-7000-8000-000000000001",
                            "track": "discussion"
                        }
                    }),
                )
                .is_err()
        );
    }

    #[test]
    fn fallback_catalog_accepts_member_state_payload_not_event_envelope() {
        let catalog = fallback_event_payload_validator_catalog();

        assert_eq!(catalog.rules["cx.member.state"].payload_schema_id, EVENT_PAYLOAD_SCHEMA);
        catalog
            .validate_payload(
                "cx.member.state",
                &json!({
                    "actor_id": "did:web:bob.example",
                    "membership": "invite",
                    "reason": "seed member"
                }),
            )
            .unwrap();

        assert!(
            catalog
                .validate_payload(
                    "cx.member.state",
                    &json!({
                        "event_id": "cx:event:0196419b-0000-7000-8000-000000000001",
                        "kind": "cx.member.state",
                        "actor_id": "did:web:bob.example"
                    }),
                )
                .is_err()
        );
    }
}
