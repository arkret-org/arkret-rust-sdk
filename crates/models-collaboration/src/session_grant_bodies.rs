//! Session-grant HTTP request/outcome DTOs
//! (`service-operation-dtos.schema.json`): the `ak.session.grant` issue proof
//! bodies, the DPoP-bound session-grant lifecycle (refresh / introspect /
//! auth-session logout), and the session-login outcome. `arkret-auth` binds
//! directly to these owner-defined types; the `arkret` umbrella re-exports them.

use arkret_models_identity::{
    SessionGrantCredentialClass, SessionGrantDeviceBinding, SessionGrantProofKind,
    SessionGrantRecoveryBinding,
};
use arkret_wire::{
    DeviceId, Did, Error, FreshnessState, GrantId, Hash, NonEmptyString, RealmId, Result, ScopeRef,
    StrandId, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::governance::agent_participation::AgentParticipationEntry;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub applet_authority: Option<SessionGrantAppletDelegation>,
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionGrantDpopBindingProof {
    pub proof_jwt: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantAgentScopeRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strand_ids: Vec<StrandId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub track_names: Vec<NonEmptyString>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionGrantAppletDelegation {
    pub applet_id: String,
    pub effective_scope: ScopeRef,
    pub registration_epoch: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionGrantRequestProof {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub proof_kind: SessionGrantProofKind,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionGrantOutcome {
    pub principal_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub session_grant: String,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLoginOutcome {
    pub session_credential: String,
    pub token_type: String,
    pub actor: Did,
    pub device_id: DeviceId,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantIntrospectionProof {
    pub challenge: String,
    pub proof_jwt: String,
}

pub const SESSION_GRANT_INTROSPECTION_PROOF_CLAIMS_KIND: &str =
    "ak.session_grant.introspection_proof.v1";

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantIntrospectionProofClaims {
    pub kind: String,
    pub grant_id: String,
    pub grant_jwt_hash: String,
    pub audience: Did,
    pub challenge: String,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionGrantRefreshProof {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub proof_kind: Option<SessionGrantProofKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_canonical_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub issued_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, alias = "proof_jws", skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
}

/// `ak.gate.account.command.refresh_session_grant` outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionGrantRefreshOutcome {
    pub grant_id: GrantId,
    pub grant_jwt: String,
    /// JWK the rotated grant is bound to (the device holder key); the server
    /// does not mint a fresh session private key on rotation.
    pub session_public_key: String,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthSessionLogoutRequestBody {
    pub grant_jwt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logout_request_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub validated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

/// `ak.gate.account.command.logout_auth_session` outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthSessionLogoutOutcome {
    pub ok: bool,
    pub grant_chain_terminated: bool,
    pub auth_session_logged_out: bool,
}

/// Standardized status returned by session-grant introspection.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
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
    pub credential_class: SessionGrantCredentialClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_binding: Option<SessionGrantRecoveryBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_binding: Option<SessionGrantDeviceBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionGrantIntrospectOutcome {
    pub active: bool,
    pub status: SessionGrantIntrospectStatus,
    pub proof_required: bool,
    /// Always false: introspection never consumes single-use state.
    pub one_time_use_consumed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<SessionGrantIntrospectGrant>,
}
