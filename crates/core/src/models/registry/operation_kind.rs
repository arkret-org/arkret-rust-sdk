use super::super::*;

/// Registry entry for one operation kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OperationKindSpec {
    pub kind: String,
    pub schema: String,
    #[serde(default)]
    pub required_content_fields: Vec<String>,
}

/// Result of validating an operation kind against the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OperationKindValidation {
    pub canonical_kind: String,
}

/// Canonical operation registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OperationKindRegistry {
    specs: BTreeMap<String, OperationKindSpec>,
}

impl OperationKindRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            specs: BTreeMap::new(),
        }
    }

    /// Register one operation kind.
    pub fn register(&mut self, spec: OperationKindSpec) {
        self.specs.insert(spec.kind.clone(), spec);
    }

    /// Return the spec for a canonical kind.
    pub fn spec(&self, kind: &str) -> Option<&OperationKindSpec> {
        self.specs.get(kind)
    }

    /// Resolve a canonical kind.
    pub fn canonicalize(&self, kind: &str) -> Result<OperationKindValidation> {
        if self.specs.contains_key(kind) {
            return Ok(OperationKindValidation {
                canonical_kind: kind.to_owned(),
            });
        }
        Err(Error::Protocol(format!("unknown operation kind '{kind}'")))
    }

    /// Validate an operation envelope against registered semantic requirements.
    pub fn validate_envelope(
        &self,
        envelope: &OperationEnvelope,
    ) -> Result<OperationKindValidation> {
        let validation = self.canonicalize(&envelope.kind)?;
        let spec = self
            .specs
            .get(&validation.canonical_kind)
            .ok_or_else(|| Error::Protocol("operation kind registry is inconsistent".to_owned()))?;
        let Some(content) = envelope.content.as_object() else {
            return Err(Error::Protocol(
                "operation envelope content must be a JSON object".to_owned(),
            ));
        };
        for field in &spec.required_content_fields {
            if !content.contains_key(field) {
                return Err(Error::Protocol(format!(
                    "operation kind '{}' requires content field '{}'",
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

impl Default for OperationKindRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        for kind in BUILT_IN_OPERATION_KINDS {
            registry.register(OperationKindSpec {
                kind: (*kind).to_owned(),
                schema: OPERATION_SCHEMA.to_owned(),
                required_content_fields: required_fields_for_operation_kind(kind),
            });
        }
        for kind in crate::events::STANDARD_EVENT_KINDS {
            registry.register(OperationKindSpec {
                kind: (*kind).to_owned(),
                schema: EVENT_SCHEMA.to_owned(),
                required_content_fields: required_fields_for_operation_kind(kind),
            });
        }
        registry
    }
}

pub(in crate::models) fn required_fields_for_operation_kind(kind: &str) -> Vec<String> {
    match kind {
        OP_STRAND_CREATE => vec!["object".to_owned()],
        OP_STRAND_UPDATE => vec!["strand_id".to_owned(), "patch".to_owned()],
        OP_STRAND_ARCHIVE | OP_STRAND_RESTORE => vec!["strand_id".to_owned()],
        OP_STRAND_STAGE_SET => vec!["strand_id".to_owned(), "stage".to_owned()],
        OP_STRAND_MOVE => ["board_space_id", "strand_id", "target_space_id", "rank"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_STRAND_REORDER => ["board_space_id", "strand_id", "space_id", "rank"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        // Round 13 — Applet / Agent protocol-session sub-events. Mirrors
        // soland round 14f wire validator (`src/routing/events/operations.rs`).
        // Spec `extensions/applet-integration.md` + `agent-integration.md`.
        OP_APPLET_REGISTRATION => {
            vec!["service_did".to_owned(), "namespace".to_owned()]
        }
        OP_APPLET_DISCOVERY => vec!["service_did".to_owned(), "manifest".to_owned()],
        OP_APPLET_INTEROP_SESSION_START => {
            vec!["applet_id".to_owned(), "session_id".to_owned()]
        }
        OP_APPLET_INTEROP_SESSION_STATUS => {
            vec!["session_id".to_owned(), "status".to_owned()]
        }
        OP_APPLET_BRIDGE_ERROR => vec!["session_id".to_owned(), "errcode".to_owned()],
        OP_AGENT_ENDPOINT => vec!["agent_id".to_owned(), "endpoints".to_owned()],
        OP_AGENT_KEY_AUTHORIZE => [
            "agent_principal_id",
            "key_id",
            "verification_method",
            "accountable_principal_id",
            "agent_key_scope",
            "audience",
            "issued_at",
            "expires_at",
            "approval_evidence",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        OP_AGENT_KEY_REVOKE => ["agent_principal_id", "key_id", "revoked_at", "revoked_by"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_AGENT_KEY_ROTATE => [
            "agent_principal_id",
            "key_id",
            "replacement_key_id",
            "replacement_verification_method",
            "accountable_principal_id",
            "agent_key_scope",
            "audience",
            "issued_at",
            "expires_at",
            "approval_evidence",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        OP_AGENT_INTEROP_SESSION_START => {
            vec![
                "session_id".to_owned(),
                "counterparty_agent".to_owned(),
                "protocol".to_owned(),
                "capability_grant".to_owned(),
            ]
        }
        OP_AGENT_INTEROP_SESSION_STATUS => {
            vec!["session_id".to_owned(), "status".to_owned()]
        }
        OP_AGENT_INTEROP_SESSION_RESULT => {
            vec![
                "session_id".to_owned(),
                "result".to_owned(),
                "audit_binding".to_owned(),
            ]
        }
        OP_MORPH_CREATE => vec!["object".to_owned()],
        OP_MORPH_UPDATE => vec!["morph_id".to_owned(), "patch".to_owned()],
        OP_MORPH_ARCHIVE | OP_MORPH_RESTORE => vec!["morph_id".to_owned()],
        OP_MORPH_STAGE_SET => vec!["morph_id".to_owned(), "stage".to_owned()],
        // Space container event kinds. The container primary key is `space_id`
        // (matching `parent_space_id`).
        OP_SPACE_CREATE => vec!["object".to_owned()],
        OP_SPACE_UPDATE => vec!["space_id".to_owned(), "patch".to_owned()],
        OP_SPACE_PARENT => vec!["space_id".to_owned(), "parent_space_id".to_owned()],
        OP_SPACE_ARCHIVE | OP_SPACE_RESTORE | OP_SPACE_TOMBSTONE => vec!["space_id".to_owned()],
        OP_RELATION_CREATE => vec!["object".to_owned()],
        OP_RELATION_UPDATE => vec!["relation_id".to_owned(), "patch".to_owned()],
        OP_RELATION_TOMBSTONE => vec!["relation_id".to_owned()],
        OP_CONTAINER_MOVE_ITEM => [
            "scope_container_id",
            "relation_kind",
            "object_ref",
            "to_container_id",
            "rank",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        OP_CONTAINER_REBALANCE => [
            "scope_container_id",
            "container_id",
            "relation_kind",
            "expected_state_digest",
            "assignments",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        OP_MESSAGE_CREATE => vec!["strand_id".to_owned(), "track_name".to_owned()],
        OP_DEVICE_MESSAGES_PUT => [
            "kind",
            "recipient_principal_id",
            "recipient_device_id",
            "content",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        OP_DEVICE_MESSAGES_ACK => vec!["ack_token".to_owned()],
        OP_APPLET_GHOST_PROVISION => [
            "schema",
            "applet_id",
            "service_did",
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
        OP_KEYS_BACKUPS_PUT => [
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
        OP_KEYS_BACKUPS_LIST | OP_KEYS_BACKUPS_UNLOCK | OP_KEYS_BACKUPS_DELETE => {
            vec!["backup_id".to_owned()]
        }
        OP_KEYS_KEYPACKAGES_UPLOAD => ["principal_id", "device_id", "keypackages"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_KEYS_KEYPACKAGES_CLAIM => [
            "target_principal_id",
            "intended_space_id",
            "requester",
            "claim_nonce",
            "expires_at",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        OP_KEYS_KEYPACKAGES_CONSUME => ["claim_id", "keypackage_ref"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_KEYS_KEYPACKAGES_REVOKE => ["principal_id", "device_id", "keypackage_ref"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_DIRECTORY_RESOLVE_HANDLE => vec!["handle".to_owned()],
        OP_DIRECTORY_LIST_HANDLES_FOR_SUBJECT => vec!["subject".to_owned()],
        OP_DIRECTORY_RESOLVE_TARGET => vec!["address".to_owned()],
        OP_DIRECTORY_RESOLVE_ORGANIZATION | OP_DIRECTORY_RESOLVE_REALM => {
            vec!["target".to_owned()]
        }
        OP_DIRECTORY_SEARCH_ACTORS
        | OP_DIRECTORY_SEARCH_ORGANIZATIONS
        | OP_DIRECTORY_SEARCH_REALMS => {
            vec!["query".to_owned()]
        }
        OP_DIRECTORY_SEARCH_USERS => vec!["q".to_owned()],
        OP_DIRECTORY_PUSH_REGISTER => ["subscriber_did", "webhook_endpoint"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_IDENTITY_GET_DOCUMENT | OP_IDENTITY_GET_LOG | OP_IDENTITY_GET_RECEIPTS => {
            vec!["did".to_owned()]
        }
        OP_IDENTITY_RECOVERY_POLICY_GET => Vec::new(),
        OP_IDENTITY_RECOVERY_POLICY_PUT => ["policy_id", "principal_id", "version"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_IDENTITY_SUBMIT_DID_OPERATION => ["did", "operation"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_ACCOUNT_DEVICE_PAIR => ["principal_id", "device_id"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_ACCOUNT_ISSUE_SESSION_GRANT => ["principal_id", "device_id", "audience", "scopes"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_PUSH_REGISTER_DEVICE => ["device_id", "endpoint"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_PUSH_UNREGISTER_DEVICE => vec!["device_id".to_owned()],
        OP_MODERATION_REPORT => ["target_ref", "reason"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_POLICY_CHECK => vec!["resource".to_owned()],
        OP_AUTHZ_GET_EFFECTIVE_GRANTS => vec!["actor_id".to_owned()],
        OP_AUTHZ_GET_INVITES => vec!["realm_id".to_owned()],
        OP_OPEN_INVITE_LOCATOR_RESOLVE => vec!["locator_token".to_owned()],
        OP_PEER_INVITES_SUBMIT => [
            "schema",
            "invite_event",
            "invite_address",
            "introduction_evidence",
            "idempotency_key",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        OP_EVENTS_GET | OP_EVENTS_RESOLVE => vec!["event_id".to_owned()],
        OP_EVENTS_FRONTIER => vec!["realm_id".to_owned()],
        OP_EVENTS_QUERY => Vec::new(), // selector = realms[]?+actors[]? — neither is strictly
        // required
        OP_EVENTS_SUBSCRIBE => Vec::new(), // selector arrays may be empty for "all reachable";
        // subscription
        OP_EVENTS_SUBMIT => vec!["events".to_owned()],
        OP_ACCOUNT_SUBSCRIBE => Vec::new(),
        OP_ACCOUNT_CURSOR_REVOKE => ["cursor", "reason_code"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        OP_SNAPSHOT_HEAD => vec!["realm_id".to_owned()],
        OP_PROJECTION_DOCUMENT => vec!["morph_id".to_owned()],
        OP_VIEW_COLLECTION_PROJECTION => vec!["view_id".to_owned()],
        _ => Vec::new(),
    }
}

/// Operation registry conformance vector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OperationKindConformanceVector {
    pub input_kind: String,
    pub canonical_kind: String,
}

/// Conformance vectors for every built-in operation kind.
pub fn operation_kind_conformance_vectors() -> Vec<OperationKindConformanceVector> {
    BUILT_IN_OPERATION_KINDS
        .iter()
        .map(|kind| OperationKindConformanceVector {
            input_kind: (*kind).to_owned(),
            canonical_kind: (*kind).to_owned(),
        })
        .collect()
}
