//! HTTP JSON request/outcome DTOs retained by `arkret-core`.
//!
//! The events/projection/blob/MIMI bodies migrated to
//! `arkret-models-collaboration`, the key-package bodies to
//! `arkret-models-crypto`, and the private-contact-discovery bodies to
//! `arkret-models-discovery` (all re-exported below). This module keeps
//! the auth/session and account-lifecycle bodies (phase 2:
//! `arkret-auth`), the contact bodies bound to the core cursor type, the
//! applet third-party lookups (applet carve-out), and the cross-domain
//! transparent outcome wrappers used by the Salvo OpenAPI bindings.

use std::collections::BTreeMap;

pub use arkret_models_collaboration::http_bodies::*;
pub use arkret_models_crypto::http_bodies::*;
pub use arkret_models_discovery::http_bodies::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

// is_false is used as a serde skip_serializing_if predicate in this module.
fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsQueryOutcome {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_bootstrap: Option<SnapshotBootstrap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range_completeness: Option<EventsRangeCompleteness>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct EventsRangeCompleteness {
    pub attestation_refs: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<Event>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ContactState {
    PendingOutgoing,
    PendingIncoming,
    Accepted,
    Rejected,
    Tombstoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationBindingState {
    Active,
    Retired,
    Duplicate,
    NonCanonical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationResolveState {
    Found,
    Created,
    NotFound,
    Retired,
    NonCanonical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectConversationSummary {
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_event_ref: Option<EventId>,
    pub state: DirectConversationBindingState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactAgentProjection {
    pub agent_id: Did,
    pub controller_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_conversation: Option<DirectConversationSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactListRow {
    pub peer: Did,
    pub state: ContactState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstone_event_ref: Option<EventId>,
    #[serde(default)]
    pub granted_by_me: Vec<String>,
    #[serde(default)]
    pub granted_to_me: Vec<String>,
    #[serde(default)]
    pub bidirectional_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_consent_grant_ref: Option<EventId>,
    /// Principal Server service DID hosting the peer, when known (e.g. learned
    /// from a cross-Principal-Server contact delivery). Lets the holder address
    /// responses/invites to the peer's home server. Omitted for
    /// same-Principal-Server contacts (spec contact-operations.schema.json).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_conversation: Option<DirectConversationSummary>,
    /// Active agents controlled by this contact that currently accept direct
    /// messages from the authenticated actor. This is a viewer-specific,
    /// fail-closed projection; clients must not infer it from public selector
    /// claims.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<ContactAgentProjection>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactRequestRequestBody {
    pub target: Did,
    #[serde(default)]
    pub requested_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Cross-Principal-Server addressing (spec contact-and-direct-conversation.md
    /// §4.1): when `target` is hosted on a different Principal Server, the
    /// requester MUST supply the target's home service DID so the issuer-side
    /// server can federate the signed `ak.contact.requested` fact via
    /// `ak.peer.contacts.command.submit`. Omit for same-server requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduction_evidence: Option<ContactIntroductionEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactRequestOutcome {
    pub request_event_ref: EventId,
    #[serde(default)]
    pub requester_consent_refs: Vec<EventId>,
    pub state: ContactState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactRespondRequestBody {
    pub request_id: EventId,
    pub requester: Did,
    pub action: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted_scopes: Vec<String>,
    /// Cross-Principal-Server addressing (spec §4.1): when the original
    /// `requester` is hosted on a different Principal Server, the responder
    /// supplies the requester's home service DID so the accept / reject fact
    /// is federated back via `ak.peer.contacts.command.submit`. Omit for same-server
    /// responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_service_id: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactRespondOutcome {
    pub response_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consent_grant_refs: Vec<EventId>,
    pub state: ContactState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct ContactListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub state: Option<ContactState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactList {
    #[serde(default)]
    pub contacts: Vec<ContactListRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactTombstoneRequestBody {
    pub contact: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoke_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub full_peer_revoke: bool,
    #[serde(default)]
    pub block_peer: bool,
    /// Cross-Principal-Server addressing (spec contact-and-direct-conversation.md
    /// §4.1): when `contact` (the peer) is hosted on a different Principal
    /// Server, the holder supplies the peer's home service DID so the
    /// `ak.contact.tombstoned` fact is federated to the peer's server via
    /// `ak.peer.contacts.command.submit`. Omit for same-server tombstones; when absent
    /// the issuer falls back to the peer's recorded `peer_service_id` on the
    /// stored contact row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_service_id: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactTombstone {
    pub tombstone_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consent_revoke_refs: Vec<EventId>,
    pub state: ContactState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_revoke: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectConversationResolveRequestBody {
    pub peer: Did,
    #[serde(default, skip_serializing_if = "is_false")]
    pub create: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectConversationResolveOutcome {
    pub state: DirectConversationResolveState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantRequestBody {
    /// Existing principal DID. OIDC verifies a login factor and never mints or
    /// derives protocol identity.
    pub principal_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_scope: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_key_authorization_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_scope_request: Option<SessionGrantAgentScopeRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_binding_proof: Option<SessionGrantDpopBindingProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_delegation: Option<SessionGrantAppletDelegation>,
    pub proof: SessionGrantRequestProof,
}

impl SessionGrantRequestBody {
    /// Digest the complete request while excluding the self-referential digest
    /// and detached signature fields.
    pub fn canonical_request_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        let proof = value
            .get_mut("proof")
            .and_then(Value::as_object_mut)
            .expect("session grant proof serializes as an object");
        proof.remove("request_canonical_digest");
        proof.remove("signature");
        Hash::new(canonical::canonical_sha256(&value)?).map_err(Into::into)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantDpopBindingProof {
    pub proof_jwt: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SessionGrantAgentScopeRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strand_ids: Vec<StrandId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub track_names: Vec<NonEmptyString>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantAppletDelegation {
    pub applet_id: String,
    pub effective_scope: EffectiveScope,
    pub registration_epoch: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantRequestProof {
    pub proof_kind: SessionGrantProofKind,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub signature: String,
    // `ak.profile.agent_auth.v1` overlay (AKP-0008 §4.6): the agent runtime
    // key the proof is signed with. Required at runtime when
    // `proof_kind == agent_key_proof`; the server enforces presence and binds
    // it to the active `ak.agent.key.authorize`. Absent for human proof kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
    // OIDC code-exchange fields. Required at runtime when
    // `proof_kind == oidc_code_exchange` (per
    // `service-operation-dtos.schema.json#/$defs/SessionGrantRequestBody`),
    // but kept `Option` here — validation is the server's job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,
}

impl SessionGrantRequestProof {
    /// Canonical detached-signature transcript for human proof kinds.
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("session grant proof serializes as an object")
            .remove("signature");
        canonical::canonical_json_bytes(&value).map_err(Into::into)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantOutcome {
    pub principal_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub session_grant: String,
    pub expires_at: DateTime<Utc>,
    /// Stable id of the issued session grant. Returned for every grant (human
    /// and agent). Mirrors `SessionGrantRefreshOutcome.grant_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<GrantId>,
    /// JWK of the holder/session key the grant is bound to. The client needs
    /// this for RFC 9421 PoP / DPoP `cnf.jkt` derivation on `/_arkret/self/*`
    /// requests, returned at issue time to avoid a mandatory introspect
    /// round-trip. Mirrors `SessionGrantRefreshOutcome.session_public_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_public_key: Option<String>,
    /// Audience the grant is bound to. Mirrors `SessionGrantRefreshOutcome.audience`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted_scope: Vec<String>,
    /// `ak.profile.agent_auth.v1` overlay (AKP-0008 §4.6). Materialized narrow
    /// scope granted to the agent runtime session. Service-surface scope is
    /// intersected separately from content capability grants. Present iff the
    /// request was the `agent_key_proof` branch; `None` (absent) for human
    /// session grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_details: Option<SessionGrantScopeDetails>,
}

/// Enforce the v1 separation between an ephemeral session holder/PoP key and
/// the long-term device identity key.
pub fn validate_session_device_key_separation(
    session_public_key_fingerprint: &str,
    device_public_key_fingerprint: &str,
) -> Result<()> {
    if session_public_key_fingerprint.is_empty() || device_public_key_fingerprint.is_empty() {
        return Err(Error::Protocol(
            "session and device key fingerprints must not be empty".to_owned(),
        ));
    }
    if session_public_key_fingerprint == device_public_key_fingerprint {
        return Err(Error::Protocol(
            "session and device identity key material must be distinct".to_owned(),
        ));
    }
    Ok(())
}

/// `ak.profile.agent_auth.v1` overlay describing the narrow scope actually
/// granted to an agent runtime session. Agent-only; absent for human grants.
///
/// Mirrors `service-operation-dtos.schema.json#/$defs/SessionGrantOutcome.scope_details`
/// (`additionalProperties: false`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SessionGrantScopeDetails {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strand_ids: Vec<StrandId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub track_names: Vec<String>,
    /// `ak.profile.agent_participation_policy.v1` overlay (AKP-0016). Each entry
    /// is isomorphic to `agent_participation_entry`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub participation: Vec<AgentParticipationEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SessionLoginOutcome {
    pub session_credential: String,
    pub token_type: String,
    pub actor: Did,
    pub device_id: DeviceId,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SessionGrantIntrospectionProof {
    pub challenge: String,
    pub proof_jwt: String,
}

pub const SESSION_GRANT_INTROSPECTION_PROOF_CLAIMS_TYPE: &str =
    "ak.session_grant.introspection_proof.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SessionGrantIntrospectionProofClaims {
    #[serde(rename = "type")]
    pub kind: String,
    pub grant_id: String,
    pub grant_jwt_hash: String,
    pub audience: Did,
    pub challenge: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

// ─── DPoP-bound session-grant lifecycle (account-lifecycle §4.1) ─────────────
//
// Wire shapes for the `/_arkret/gate/account/session-grants/{refresh,
// introspect}`, `/_arkret/gate/account/auth-sessions/logout`, and
// `/_arkret/gate/account/logout` operations. These mirror
// `service-operation-dtos.schema.json#/$defs/SessionGrant{Refresh,Introspect}*`,
// `AuthSessionLogout*`, and `AccountLogout*` so callers bind to the same strong
// types the spec/OpenAPI declare instead of hand-rolled structs.

/// `ak.gate.account.command.refresh_session_grant` request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantRefreshRequestBody {
    pub grant_jwt: String,
    /// MUST equal the grant's bound audience if present (audience MUST NOT
    /// change across rotation, else `audience_mismatch`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Did>,
    /// Required when recovering from `soft_logged_out`; binds the signed
    /// challenge to the concrete authorized device that owns this grant chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    /// Fresh DID/device proof for `soft_logged_out -> active` recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SessionGrantRefreshProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantRefreshProof {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_kind: Option<SessionGrantProofKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_canonical_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, alias = "proof_jws", skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
}

/// `ak.gate.account.command.refresh_session_grant` outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantRefreshOutcome {
    pub grant_id: GrantId,
    pub grant_jwt: String,
    /// JWK the rotated grant is bound to (the device holder key); the server
    /// does not mint a fresh session private key on rotation.
    pub session_public_key: String,
    pub expires_at: DateTime<Utc>,
    pub audience: Did,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// RFC 7638 thumbprint of the holder key (equals the grant's `cnf.jkt`).
    pub dpop_jkt: String,
    /// The prior grant, single-use revoked on success.
    pub previous_grant_id: GrantId,
}

/// `ak.gate.account.command.logout_auth_session` request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuthSessionLogoutRequestBody {
    pub grant_jwt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logout_request_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

/// `ak.gate.account.command.logout_auth_session` outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuthSessionLogoutOutcome {
    pub ok: bool,
    pub grant_chain_terminated: bool,
    pub auth_session_logged_out: bool,
}

/// Standardized status returned by session-grant introspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantIntrospectStatus {
    Active,
    Revoked,
    Expired,
    Locked,
    Suspended,
    AudienceMismatch,
    ProofRequired,
    InvalidProof,
    NotFound,
}

/// Non-secret grant metadata returned to a validating Principal Server. Never
/// includes the grant JWT, refresh token, or session private key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantIntrospectGrant {
    pub id: GrantId,
    pub issuer: String,
    pub subject: String,
    pub service_account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub audience: Did,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_ref: String,
    /// Session signing key (JWK) for RFC 9421 PoP verification on
    /// `/_arkret/self/*`. Server-to-server only.
    pub session_public_key: String,
    /// RFC 7638 JWK SHA-256 thumbprint of the holder (DPoP) key the grant is
    /// bound to (the grant's `cnf.jkt`); the Principal Server uses it to verify
    /// the per-request DPoP proof on `/_arkret/self/*`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf_jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_kind: Option<SessionGrantProofKind>,
    /// Materialized scope details for `agent_key_proof` sessions. Human session
    /// grants omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_details: Option<SessionGrantScopeDetails>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_state: Option<FreshnessState>,
}

/// `ak.gate.account.command.introspect_session_grant` request. Exactly one of
/// `id` / `grant_jwt` identifies the grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantIntrospectRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<GrantId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_jwt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SessionGrantIntrospectionProof>,
}

/// `ak.gate.account.command.introspect_session_grant` outcome. READ-ONLY:
/// introspection never consumes the grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantIntrospectOutcome {
    pub active: bool,
    pub status: SessionGrantIntrospectStatus,
    pub proof_required: bool,
    /// Always false: introspection never consumes single-use state.
    pub one_time_use_consumed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<SessionGrantIntrospectGrant>,
}

/// `ak.gate.account.command.logout` request (Principal Server device logout).
/// Empty body — the session bearer identifies the device session to terminate.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountLogoutRequestBody {}

/// `ak.gate.account.command.logout` outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountLogoutOutcome {
    pub ok: bool,
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountDevicePairRequestBody {
    pub pairing_code: NonEmptyString,
    pub new_device_pubkey: PublicKey,
    pub challenge_signature: Base64UrlString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_metadata: Option<DeviceMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountDevicePairOutcome {
    pub device_id: DeviceId,
    pub authorized_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_grant: Option<GrantSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_backup_hint: Option<BTreeMap<String, Value>>,
}

/// Request body for `ak.gate.account.command.enroll_device`
/// (`POST /_arkret/gate/account/device-enroll`). The authenticated session
/// asks its designated enrollment authority to mint a `service_attested`
/// `ak.device.authorize` for this session's own device (device-lifecycle.md
/// §5.4, key-management.md §5.0.6). Mirrors
/// `agent-operations.schema.json#/$defs/account_device_enroll_request_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountDeviceEnrollRequestBody {
    pub device_id: DeviceId,
    /// did:key multibase (`z6Mk…`) or base64 of this session's device public key.
    pub device_public_key: String,
    /// This device's HPKE sealing public key (multibase); enters
    /// `ak.device.authorize.payload.hpke_key` verbatim (§5.4).
    pub hpke_key: String,
    /// Canonical sorted unique algorithm ids; enters
    /// `ak.device.authorize.payload.algorithms` verbatim (§5.2/§5.4).
    pub algorithms: Vec<String>,
    pub actor_seq: u64,
    /// Root-signed `ak.realm.create` Event id immediately preceding the
    /// authority-signed authorize in the atomic first-device bootstrap unit.
    /// Required exactly when `actor_seq == 1` and copied to the authorize
    /// Event's sole `prev_refs` entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_create_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
}

/// Outcome for `ak.gate.account.command.enroll_device`. The account authority
/// does not contact the Principal Server; the caller submits `authorized_event`
/// verbatim to `POST /_arkret/self/events`. Mirrors
/// `agent-operations.schema.json#/$defs/account_device_enroll_outcome`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountDeviceEnrollOutcome {
    pub principal_id: Did,
    pub device_id: DeviceId,
    /// Enrollment authority DID (= `executed_by` /
    /// `enrollment_authority_binding.authority_did`).
    pub authority_did: Did,
    /// Fully-signed `service_attested` `ak.device.authorize` Event envelope.
    pub authorized_event: Event,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountOidcCallbackRequestBody {
    pub state: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountOidcCallbackOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_session_state: Option<SessionGrantOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletThirdPartyUserList {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    pub exists: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletThirdPartyLocationList {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub exists: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = ServiceDescribe)))]
pub struct ServerDescribeOutcome(pub ServiceDescribe);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityDescription)))]
pub struct IdentityDescribeOutcome(pub IdentityDescription);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityDocumentView)))]
pub struct IdentityDocumentViewOutcome(pub IdentityDocumentView);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityLogListOutcome)))]
pub struct IdentityLogResultBody(pub IdentityLogListOutcome);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DidOperationSubmitRequestBody)))]
pub struct IdentitySubmitDidOperationRequestBody(pub DidOperationSubmitRequestBody);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = DidOperationSubmitOutcome)))]
pub struct IdentitySubmitDidOperationOutcome(pub DidOperationSubmitOutcome);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = IdentityReceiptListOutcome)))]
pub struct IdentityReceiptsResultBody(pub IdentityReceiptListOutcome);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = SyncRequestBody)))]
pub struct AccountSubscribeRequestBody(pub SyncRequestBody);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = ServiceDescribe)))]
pub struct DirectoryDescribeOutcome(pub ServiceDescribe);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = BlobUploadMetadata)))]
pub struct BlobUploadRequestBody(pub BlobUploadMetadata);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeyBackup)))]
pub struct KeysBackupsPutRequestBody(pub KeyBackup);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = KeyBackup)))]
pub struct KeysBackupsGetOutcome(pub KeyBackup);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = GrantList)))]
pub struct GrantListOutcome(pub GrantList);
