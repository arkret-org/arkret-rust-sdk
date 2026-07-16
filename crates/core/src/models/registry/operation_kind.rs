use super::super::*;
use crate::events::EventKind;

/// Registry entry for one operation kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventDraftKindSpec {
    pub kind: String,
    pub schema: String,
    #[serde(default)]
    pub required_content_fields: Vec<String>,
}

/// Result of validating an operation kind against the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventDraftKindValidation {
    pub canonical_kind: String,
}

/// Canonical operation registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventDraftKindRegistry {
    specs: BTreeMap<String, EventDraftKindSpec>,
}

impl EventDraftKindRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            specs: BTreeMap::new(),
        }
    }

    /// Register one operation kind.
    pub fn register(&mut self, spec: EventDraftKindSpec) {
        self.specs.insert(spec.kind.clone(), spec);
    }

    /// Return the spec for a canonical kind.
    pub fn spec(&self, kind: &str) -> Option<&EventDraftKindSpec> {
        self.specs.get(kind)
    }

    /// Resolve a canonical kind.
    pub fn canonicalize(&self, kind: &str) -> Result<EventDraftKindValidation> {
        if self.specs.contains_key(kind) {
            return Ok(EventDraftKindValidation {
                canonical_kind: kind.to_owned(),
            });
        }
        Err(Error::Protocol(format!("unknown operation kind '{kind}'")))
    }

    /// Validate an operation envelope against registered semantic requirements.
    pub fn validate_envelope(
        &self,
        envelope: &OperationEnvelope,
    ) -> Result<EventDraftKindValidation> {
        let validation = self.canonicalize(&envelope.kind)?;
        let spec = self
            .specs
            .get(&validation.canonical_kind)
            .ok_or_else(|| Error::Protocol("operation kind registry is inconsistent".to_owned()))?;
        let Some(payload) = envelope.payload.as_object() else {
            return Err(Error::Protocol(
                "operation envelope payload must be a JSON object".to_owned(),
            ));
        };
        for field in &spec.required_content_fields {
            if !payload.contains_key(field) {
                return Err(Error::Protocol(format!(
                    "operation kind '{}' requires payload field '{}'",
                    spec.kind, field
                )));
            }
        }
        Ok(validation)
    }

    /// Iterate registered canonical operation kinds.
    pub fn kinds(&self) -> impl Iterator<Item = &str> {
        self.specs.keys().map(String::as_str)
    }
}

impl Default for EventDraftKindRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        for kind in EventKind::ALL {
            registry.register(EventDraftKindSpec {
                kind: kind.as_str().to_owned(),
                schema: EVENT_SCHEMA.to_owned(),
                required_content_fields: required_fields_for_operation_kind(kind.as_str()),
            });
        }
        registry
    }
}

pub(in crate::models) fn required_fields_for_operation_kind(kind: &str) -> Vec<String> {
    match kind {
        crate::events::EventKind::STRAND_CREATE => vec!["object".to_owned()],
        crate::events::EventKind::STRAND_UPDATE => {
            vec!["target_ref".to_owned(), "patch".to_owned()]
        }
        crate::events::EventKind::STRAND_ARCHIVE | crate::events::EventKind::STRAND_RESTORE => {
            vec!["target_ref".to_owned()]
        }
        crate::events::EventKind::STRAND_STAGE_SET => {
            vec!["strand_id".to_owned(), "stage".to_owned()]
        }
        crate::events::EventKind::STRAND_MOVE => {
            ["board_space_id", "strand_id", "target_space_id", "rank"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        crate::events::EventKind::STRAND_REORDER => {
            ["board_space_id", "strand_id", "space_id", "rank"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        crate::events::EventKind::APPLET_REGISTRATION => {
            vec!["service_id".to_owned(), "namespace".to_owned()]
        }
        crate::events::EventKind::APPLET_DISCOVERY => {
            vec!["service_id".to_owned(), "manifest".to_owned()]
        }
        crate::events::EventKind::APPLET_BRIDGE_ERROR => {
            vec!["session_id".to_owned(), "errcode".to_owned()]
        }
        crate::events::EventKind::AGENT_KEY_AUTHORIZE => [
            "agent_id",
            "key_id",
            "verification_method",
            "accountable_principal_id",
            "agent_key_scope",
            "audience",
            "issued_at",
            "approval_evidence",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        crate::events::EventKind::AGENT_KEY_REVOKE => {
            ["agent_id", "key_id", "revoked_at", "revoked_by"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        crate::events::EventKind::MORPH_CREATE => vec!["object".to_owned()],
        crate::events::EventKind::MORPH_UPDATE => vec!["target_ref".to_owned(), "patch".to_owned()],
        crate::events::EventKind::MORPH_ARCHIVE | crate::events::EventKind::MORPH_RESTORE => {
            vec!["target_ref".to_owned()]
        }
        crate::events::EventKind::MORPH_STAGE_SET => {
            vec!["morph_id".to_owned(), "stage".to_owned()]
        }
        // Space container event kinds. The container primary key is `space_id`
        // (matching `parent_space_id`).
        crate::events::EventKind::SPACE_CREATE => vec!["object".to_owned()],
        crate::events::EventKind::SPACE_UPDATE => vec!["space_id".to_owned(), "patch".to_owned()],
        crate::events::EventKind::SPACE_PARENT => {
            vec!["space_id".to_owned(), "parent_space_id".to_owned()]
        }
        crate::events::EventKind::SPACE_ARCHIVE
        | crate::events::EventKind::SPACE_RESTORE
        | crate::events::EventKind::SPACE_TOMBSTONE => vec!["space_id".to_owned()],
        crate::events::EventKind::RELATION_CREATE => ["kind", "from_ref", "to_ref"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        crate::events::EventKind::RELATION_UPDATE => {
            vec!["relation_id".to_owned(), "patch".to_owned()]
        }
        crate::events::EventKind::RELATION_TOMBSTONE => vec!["relation_id".to_owned()],
        crate::events::EventKind::CONTAINER_MOVE_ITEM => [
            "scope_container_id",
            "relation_kind",
            "object_ref",
            "to_container_id",
            "rank",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        crate::events::EventKind::CONTAINER_REBALANCE => [
            "scope_container_id",
            "container_id",
            "relation_kind",
            "expected_state_digest",
            "assignments",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        crate::events::EventKind::MESSAGE_CREATE => {
            vec!["strand_id".to_owned(), "track_name".to_owned()]
        }
        crate::ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_SEND => [
            "kind",
            "recipient_principal_id",
            "recipient_device_id",
            "content",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        crate::ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK => vec!["ack_token".to_owned()],
        crate::ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION => [
            "schema",
            "applet_id",
            "service_id",
            "ghost_actor_id",
            "protocol",
            "tenant",
            "external_user_id",
            "realm_id",
            "external_ref",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        crate::ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE => [
            "backup_id",
            "actor_id",
            "backup_class",
            "backup_version",
            "ciphertext",
            "ciphertext_digest",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        crate::ServiceOperationId::SELF_KEYS_BACKUPS_QUERY_LIST
        | crate::ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK
        | crate::ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_DELETE => {
            vec!["backup_id".to_owned()]
        }
        crate::ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE => {
            ["principal_id", "device_id", "keypackages"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        crate::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM => [
            "target_principal_id",
            "intended_space_id",
            "requester",
            "claim_nonce",
            "expires_at",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        crate::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME => {
            ["claim_id", "keypackage_ref"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        crate::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE => {
            ["principal_id", "device_id", "keypackage_ref"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        crate::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_HANDLE => vec!["handle".to_owned()],
        crate::ServiceOperationId::FIND_DIRECTORY_QUERY_LIST_HANDLES_FOR_SUBJECT => {
            vec!["subject".to_owned()]
        }
        crate::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_TARGET => {
            vec!["address".to_owned()]
        }
        crate::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_ORGANIZATION
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_REALM => {
            vec!["target".to_owned()]
        }
        crate::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ACTORS
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ORGANIZATIONS
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_REALMS => {
            vec!["query".to_owned()]
        }
        crate::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_USERS => vec!["q".to_owned()],
        crate::ServiceOperationId::FIND_DIRECTORY_PUSH_COMMAND_REGISTER => {
            ["subscriber_did", "webhook_endpoint"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        crate::ServiceOperationId::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET
        | crate::ServiceOperationId::ROOT_IDENTITY_LOG_QUERY_LIST
        | crate::ServiceOperationId::ROOT_IDENTITY_RECEIPTS_QUERY_LIST => {
            vec!["did".to_owned()]
        }
        crate::ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET => Vec::new(),
        crate::ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH => {
            ["policy_id", "principal_id", "version"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        crate::ServiceOperationId::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION => {
            ["did", "operation"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        crate::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_DEVICE => {
            ["principal_id", "device_id"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        crate::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT => {
            ["principal_id", "device_id", "audience", "scopes"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        crate::ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE => ["device_id", "endpoint"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        crate::ServiceOperationId::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE => {
            vec!["device_id".to_owned()]
        }
        crate::ServiceOperationId::SELF_MODERATION_COMMAND_REPORT => ["target_ref", "reason"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        crate::ServiceOperationId::SELF_POLICY_QUERY_CHECK => vec!["resource".to_owned()],
        crate::ServiceOperationId::SELF_AUTHZ_GRANTS_QUERY_EFFECTIVE => vec!["actor_id".to_owned()],
        crate::ServiceOperationId::SELF_AUTHZ_INVITES_QUERY_LIST => vec!["realm_id".to_owned()],
        crate::ServiceOperationId::OPEN_INVITE_LOCATOR_QUERY_RESOLVE => {
            vec!["locator_token".to_owned()]
        }
        crate::ServiceOperationId::PEER_INVITES_COMMAND_SUBMIT => [
            "schema",
            "invite_event",
            "invite_address",
            "introduction_evidence",
            "idempotency_key",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        crate::ServiceOperationId::SELF_EVENTS_RESOURCE_GET
        | crate::ServiceOperationId::SELF_EVENTS_QUERY_RESOLVE => vec!["event_id".to_owned()],
        crate::ServiceOperationId::SELF_EVENTS_QUERY_FRONTIER => vec!["realm_id".to_owned()],
        crate::ServiceOperationId::SELF_EVENTS_QUERY_SCAN => Vec::new(), /* selector =
                                                                           * realms[]?+actors[]?
                                                                           * — neither is
                                                                           * strictly */
        // required
        crate::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE => Vec::new(), /* selector arrays may be empty for "all reachable"; */
        // subscription
        crate::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT => vec!["events".to_owned()],
        crate::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE => Vec::new(),
        crate::ServiceOperationId::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR => ["cursor", "reason_code"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        crate::ServiceOperationId::SELF_SNAPSHOT_QUERY_MANIFEST_HEAD => vec!["realm_id".to_owned()],
        crate::ServiceOperationId::SELF_MORPH_RESOURCE_GET => {
            vec!["realm_id".to_owned(), "morph_id".to_owned()]
        }
        crate::ServiceOperationId::SELF_VIEWS_COLLECTION_PROJECTION_COMMAND_MATERIALIZE => {
            vec!["view_id".to_owned()]
        }
        _ => Vec::new(),
    }
}

/// Operation registry conformance vector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventDraftKindConformanceVector {
    pub input_kind: String,
    pub canonical_kind: String,
}

/// Conformance vectors for every built-in operation kind.
pub fn event_draft_kind_conformance_vectors() -> Vec<EventDraftKindConformanceVector> {
    EventKind::ALL
        .iter()
        .map(|kind| EventDraftKindConformanceVector {
            input_kind: kind.as_str().to_owned(),
            canonical_kind: kind.as_str().to_owned(),
        })
        .collect()
}
