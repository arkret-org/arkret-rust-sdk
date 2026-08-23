//! Agent-lifecycle and agent-key payloads.

use arkret_models_identity::handle::HandleVisibility;
use arkret_wire::DidCoreId;
use arkret_wire::serde_helpers::{canonical_timestamp, optional_canonical_timestamp};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::internal_prelude::*;

/// Exact schema discriminator for a controller-authored Agent provision fact.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentProvisionSchema {
    #[default]
    #[serde(rename = "ak.schema.agent_provision.v1")]
    V1,
}

/// Closed accountability scope projected atomically by Agent provisioning.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentProvisionAccountabilityScope {
    #[default]
    #[serde(rename = "agent_operator")]
    AgentOperator,
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-provision.schema.json`.
///
/// The containing Event proof is the only signature. Receivers project the
/// provision, accountability and selector cells atomically from this payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionPayload {
    pub schema: AgentProvisionSchema,
    pub agent_id: DidCoreId,
    pub controller_id: DidCoreId,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: DidUrl,
    pub agent_slug: String,
    pub accountability_scope: AgentProvisionAccountabilityScope,
    pub requested_scope_digest: Hash,
    pub selector_visibility: HandleVisibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector_audience: Option<String>,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl AgentProvisionPayload {
    pub fn validate(&self) -> Result<()> {
        let prepared = prepare_agent_slug(&self.agent_slug)?;
        if prepared != self.agent_slug {
            return Err(WireError::Protocol(
                "agent_slug must already use the canonical agent-slug profile".to_owned(),
            ));
        }
        match (self.selector_visibility, self.selector_audience.as_deref()) {
            (HandleVisibility::Restricted, Some(audience))
                if !audience.is_empty() && audience.chars().count() <= 512 => {}
            (HandleVisibility::Restricted, _) => {
                return Err(WireError::Protocol(
                    "restricted selector visibility requires a 1..=512 character audience"
                        .to_owned(),
                ));
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(WireError::Protocol(
                    "selector_audience is only valid for restricted visibility".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Why an Event does not carry the registered Agent provision payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentProvisionPayloadError {
    UnexpectedKind(String),
    InvalidPayload(String),
}

impl core::fmt::Display for AgentProvisionPayloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedKind(kind) => {
                write!(f, "event kind must be ak.agent.provision, got {kind}")
            }
            Self::InvalidPayload(reason) => {
                write!(f, "ak.agent.provision payload is invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for AgentProvisionPayloadError {}

impl TryFrom<&Event> for AgentProvisionPayload {
    type Error = AgentProvisionPayloadError;

    fn try_from(event: &Event) -> core::result::Result<Self, Self::Error> {
        if event.kind != EventKind::AgentProvision {
            return Err(AgentProvisionPayloadError::UnexpectedKind(
                event.kind.as_str().to_owned(),
            ));
        }
        let value = Value::Object(event.payload.clone().into_iter().collect());
        let payload: Self = serde_path_to_error::deserialize(value).map_err(|error| {
            let path = error.path().to_string();
            let reason = error.into_inner().to_string();
            AgentProvisionPayloadError::InvalidPayload(if path.is_empty() || path == "." {
                reason
            } else {
                format!("{path}: {reason}")
            })
        })?;
        payload
            .validate()
            .map_err(|error| AgentProvisionPayloadError::InvalidPayload(error.to_string()))?;
        Ok(payload)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_approve_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionApprovePayload {
    pub approval_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_id: Option<String>,
    pub agent_id: DidCoreId,
    pub controller_id: DidCoreId,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub approved_payload_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_content_digest: Option<Hash>,
    pub approval_nonce: String,
    #[serde(with = "canonical_timestamp")]
    pub approved_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_reject_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionRejectPayload {
    pub rejection_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_id: Option<String>,
    pub agent_id: DidCoreId,
    pub controller_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(with = "canonical_timestamp")]
    pub rejected_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_request_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionRequestPayload {
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_id: Option<String>,
    pub agent_id: DidCoreId,
    pub controller_id: DidCoreId,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub request_canonical_digest: Hash,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_target`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionTarget {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data_key: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_deactivate_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDeactivatePayload {
    pub agent_id: DidCoreId,
    pub controller_id: DidCoreId,
    pub transition: String,
    pub previous_status: String,
    #[serde(with = "canonical_timestamp")]
    pub status_changed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_draft_propose_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDraftProposePayload {
    pub draft_id: String,
    pub agent_id: DidCoreId,
    pub controller_id: DidCoreId,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub content_digest: Hash,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data_key: Option<String>,
}
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_approval_evidence`
/// `kind` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKeyApprovalEvidenceKind {
    CapabilityGrant,
    ApprovalEvent,
    ProposalEvent,
    PolicyEvent,
    PairingRequest,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_approval_evidence`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyApprovalEvidence {
    pub kind: AgentKeyApprovalEvidenceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_canonical_digest: Option<Hash>,
    /// Profile-local pairing artifact. Present only when this authorization
    /// accepts an agent runtime pairing request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_request_id: Option<OpaqueLocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<DidCoreId>,
}

/// Counterpart for the `agent_key_scope.resources[].kind` enum in
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_scope`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKeyScopeResourceKind {
    Realm,
    Space,
    Circle,
    Strand,
    Message,
    Morph,
    Object,
    Relation,
    View,
    Event,
    Actor,
    Schema,
    Policy,
    Invite,
    Notification,
    ReadCursor,
    Blob,
    Operation,
    Service,
}

/// Counterpart for the `agent_key_scope.resources[]` item shape in
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_scope`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyScopeResource {
    pub kind: AgentKeyScopeResourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<DidCoreId>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_scope`
/// (also `agent-operations.schema.json#/$defs/agent_key_scope` via `$ref`).
///
/// Scope object used as the required immutable provision ceiling and as a
/// narrower per-key ceiling. `actions` may include service operation ids and
/// content capability action tokens. Provisioning records it but grants no
/// Realm access; later key scopes, Realm grants, participation and sessions
/// must remain subsets, and provision constraints stay mandatory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentKeyScope {
    pub actions: Vec<String>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub resources: Vec<AgentKeyScopeResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub constraints: Vec<GrantConstraint>,
}

/// Counterpart for the `runtime_attestation.kind` enum in
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_authorize_payload`.
/// v1 registers only `self_asserted`; unknown kinds fail closed at decode
/// (AKP-0008 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentKeyRuntimeAttestationKind {
    SelfAsserted,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_authorize_payload`
/// `runtime_attestation` object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentKeyAuthorizePayloadRuntimeAttestation {
    pub kind: AgentKeyRuntimeAttestationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<ObjectRef>,
}

/// One active authorization dot atomically replaced by a controller-signed
/// runtime re-pairing authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeySupersession {
    pub key_id: NonEmptyString,
    pub authorized_event_ref: EventId,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_authorize_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyAuthorizePayload {
    pub agent_id: DidCoreId,
    pub key_id: NonEmptyString,
    /// DID URL for the runtime signing key, including its key fragment.
    pub verification_method: DidUrl,
    pub public_key_digest: Hash,
    pub signing_key_binding_digest: Hash,
    pub accountable_principal_id: DidCoreId,
    pub agent_key_scope: AgentKeyScope,
    pub audience: Vec<String>,
    #[serde(with = "canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    /// Optional: absent means the key authorization is non-expiring and
    /// governed solely by revocation (key-management.md §3.6.1).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    pub approval_evidence: AgentKeyApprovalEvidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<AgentKeySupersession>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_check_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
}

/// Why an Event does not carry a valid `ak.agent.key.authorize` payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentKeyAuthorizePayloadError {
    /// The envelope's `kind` is something other than `ak.agent.key.authorize`.
    UnexpectedKind(String),
    /// The envelope's `payload` does not match the closed authorize shape.
    InvalidPayload(String),
}

impl core::fmt::Display for AgentKeyAuthorizePayloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::result::Result<(), core::fmt::Error> {
        match self {
            AgentKeyAuthorizePayloadError::UnexpectedKind(kind) => {
                write!(f, "event kind must be ak.agent.key.authorize, got {kind}")
            }
            AgentKeyAuthorizePayloadError::InvalidPayload(reason) => {
                write!(f, "ak.agent.key.authorize payload is invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for AgentKeyAuthorizePayloadError {}

/// Read the closed authorize payload out of a signed Event envelope.
///
/// Consumers (Coauth's runtime pairing gate, Soland's admission path) validate
/// business fields against this type rather than re-reading string keys off a
/// `serde_json::Value`, so a payload field rename is a compile error at every
/// call site instead of a silently absent check.
///
/// This borrows the Event rather than consuming it: signature verification MUST
/// keep using the original canonical Event bytes, never a re-serialization of
/// the typed payload.
impl TryFrom<&Event> for AgentKeyAuthorizePayload {
    type Error = AgentKeyAuthorizePayloadError;

    fn try_from(event: &Event) -> core::result::Result<Self, Self::Error> {
        if event.kind != EventKind::AgentKeyAuthorize {
            return Err(AgentKeyAuthorizePayloadError::UnexpectedKind(
                event.kind.as_str().to_owned(),
            ));
        }
        // The envelope keeps `payload` as an ordered map so the canonical
        // transcript is preserved; rebuild the object in place rather than
        // round-tripping through a JSON string.
        let payload = Value::Object(event.payload.clone().into_iter().collect());
        // Report which member failed, not just why. A closed payload type whose
        // rejection reads `premature end of input` tells an operator nothing
        // about *which* field their producer got wrong, and the field-name
        // precision this type exists to provide would stop at the type
        // boundary. `serde_json` drops the path when deserializing from a
        // `Value`, so recover it here.
        serde_path_to_error::deserialize(payload).map_err(|error| {
            let path = error.path().to_string();
            let reason = error.into_inner().to_string();
            AgentKeyAuthorizePayloadError::InvalidPayload(if path.is_empty() || path == "." {
                reason
            } else {
                format!("{path}: {reason}")
            })
        })
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_revoke_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyRevokePayload {
    pub agent_id: DidCoreId,
    pub key_id: NonEmptyString,
    pub revoked_by: DidCoreId,
    #[serde(with = "canonical_timestamp")]
    pub revoked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_pause_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPausePayload {
    pub agent_id: DidCoreId,
    pub controller_id: DidCoreId,
    pub transition: String,
    pub previous_status: String,
    #[serde(with = "canonical_timestamp")]
    pub status_changed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_resume_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResumePayload {
    pub agent_id: DidCoreId,
    pub controller_id: DidCoreId,
    pub transition: String,
    pub previous_status: String,
    #[serde(with = "canonical_timestamp")]
    pub status_changed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(test)]
mod agent_key_authorize_payload_tests {
    use serde_json::json;

    use super::{AgentKeyAuthorizePayload, AgentKeyAuthorizePayloadError};

    fn authorize_event(kind: &str, payload_overrides: serde_json::Value) -> arkret_wire::Event {
        let mut payload = json!({
            "agent_id": "ak:did_core:web:agent.example",
            "key_id": "runtime-key-1",
            "verification_method": "did:web:agent.example#runtime-key-1",
            "public_key_digest":
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "signing_key_binding_digest":
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "accountable_principal_id": "ak:did_core:web:controller.example",
            "agent_key_scope": { "actions": ["ak.event.read"], "resources": [] },
            "audience": ["did:web:soland.local"],
            "issued_at": "2026-07-06T00:00:00.000Z",
            "approval_evidence": {
                "kind": "pairing_request",
                "pairing_request_id":
                    "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
                "request_canonical_digest":
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "approved_by": "ak:did_core:web:controller.example"
            }
        });
        if let (Some(payload), Some(overrides)) =
            (payload.as_object_mut(), payload_overrides.as_object())
        {
            for (key, value) in overrides {
                payload.insert(key.clone(), value.clone());
            }
        }
        serde_json::from_value(json!({
            "event_id": "ak:event:AaWlxNyGs0FzlOCJpyhjSRcmOcoYvk0qQ4X91NlGuKSZ",
            "kind": kind,
            "realm_id": "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm",
            "scope_ref": {
                "kind": "realm",
                "realm_id": "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm"
            },
            "actor_id": "ak:did_core:web:agent.example",
            "executed_by": "ak:did_core:web:controller.example",
            "principal_server_id": "ak:did_core:web:ps.example",
            "actor_seq": 1,
            "created_at": "2026-07-06T00:00:00.000Z",
            "prev_refs": [],
            "payload": payload,
            "proofs": []
        }))
        .expect("fixture is a wire Event")
    }

    #[test]
    fn reads_the_closed_payload_from_a_matching_event() {
        let event = authorize_event("ak.agent.key.authorize", json!({}));
        let payload = AgentKeyAuthorizePayload::try_from(&event).expect("payload parses");
        assert_eq!(payload.key_id.as_str(), "runtime-key-1");
        assert_eq!(payload.audience, vec!["did:web:soland.local".to_owned()]);
        assert!(payload.expires_at.is_none());
        assert!(payload.supersedes.is_empty());
    }

    #[test]
    fn rejects_an_event_of_another_kind() {
        let event = authorize_event("ak.agent.key.revoke", json!({}));
        assert!(matches!(
            AgentKeyAuthorizePayload::try_from(&event),
            Err(AgentKeyAuthorizePayloadError::UnexpectedKind(kind)) if kind == "ak.agent.key.revoke"
        ));
    }

    #[test]
    fn rejects_an_unregistered_payload_field() {
        let event = authorize_event(
            "ak.agent.key.authorize",
            json!({ "unregistered_field": true }),
        );
        assert!(matches!(
            AgentKeyAuthorizePayload::try_from(&event),
            Err(AgentKeyAuthorizePayloadError::InvalidPayload(_))
        ));
    }
}
