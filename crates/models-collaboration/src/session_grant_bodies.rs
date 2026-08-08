//! Session-grant HTTP request/outcome DTOs
//! (`service-operation-dtos.schema.json`): the `ak.session.grant` issue proof
//! bodies, the DPoP-bound session-grant lifecycle (refresh / introspect /
//! auth-session logout), and the session-login outcome. `arkret-auth` binds
//! directly to these owner-defined types; the `arkret` umbrella re-exports them.

use arkret_models_identity::{
    CanonicalSessionPublicJwk, SessionGrantCredentialClass, SessionGrantHolderBinding,
    SessionGrantProofKind,
};
use arkret_wire::{
    DeviceId, Did, DidUrl, Error, Hash, NonEmptyString, RealmId, Result, ScopeRef, SessionGrantId,
    StrandId, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent_operations::AgentRequestedScopeDisclosure;
use crate::governance::agent_participation::AgentParticipationEntry;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    pub requested_scope_disclosure: Option<AgentRequestedScopeDisclosure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_binding_proof: Option<SessionGrantDpopBindingProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_authority: Option<SessionGrantAppletDelegation>,
    pub proof: SessionGrantRequestProof,
}

impl SessionGrantRequestBody {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }

    /// Digest the complete request while excluding the self-referential digest
    /// and detached signature fields.
    pub fn canonical_request_digest(&self) -> Result<Hash> {
        self.validate()?;
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct SessionGrantRequestProof {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub proof_kind: SessionGrantProofKind,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    pub signature: String,
    // `ak.profile.agent_auth.v1` overlay (AKP-0008 §4.6): the agent runtime
    // key the proof is signed with. Required at runtime when
    // `proof_kind == agent_key_proof`; the server enforces presence and binds
    // it to the active `ak.agent.key.authorize`. Absent for human proof kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<DidUrl>,
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
#[serde(deny_unknown_fields)]
pub struct SessionGrantOutcome {
    pub principal_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub session_grant: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    /// Stable id of the issued session grant. Returned for every grant (human
    /// and agent). Mirrors `SessionGrantRefreshOutcome.grant_id`.
    pub grant_id: SessionGrantId,
    /// JWK of the holder/session key the grant is bound to. The client needs
    /// this for RFC 9421 PoP / DPoP `cnf.jkt` derivation on `/_arkret/self/*`
    /// requests, returned at issue time to avoid a mandatory introspect
    /// round-trip. Mirrors `SessionGrantRefreshOutcome.session_public_key`.
    pub session_public_key: CanonicalSessionPublicJwk,
    /// Audience the grant is bound to. Mirrors `SessionGrantRefreshOutcome.audience`.
    pub audience: Did,
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
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
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
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
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
#[serde(deny_unknown_fields)]
pub struct SessionGrantRefreshRequestBody {
    pub grant_jwt: String,
    /// MUST equal the grant's bound audience if present (audience MUST NOT
    /// change across rotation, else `audience_mismatch`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Did>,
    /// Required when recovering from `soft_logged_out`; binds the signed
    /// challenge to the concrete authorized device that owns this grant chain.
    pub device_id: DeviceId,
    /// Fresh DID/device proof for `soft_logged_out -> active` recovery.
    pub proof: SessionGrantRefreshProof,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantRefreshProof {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub proof_kind: SessionGrantProofKind,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<DidUrl>,
}

/// Canonical operation selector bound into every session-grant refresh proof.
pub const SESSION_GRANT_REFRESH_OPERATION: &str = "resume_soft_logged_out_session";

#[derive(Serialize)]
struct SessionGrantRefreshRequestDigestInput<'a> {
    operation: &'static str,
    grant_jwt_hash: String,
    principal_id: &'a str,
    device_id: &'a str,
    audience: &'a str,
    grant_binding_key_id: &'a str,
}

#[derive(Serialize)]
struct SessionGrantRefreshProofSigningInput<'a> {
    principal_id: &'a str,
    device_id: &'a str,
    audience: &'a str,
    challenge: &'a str,
    request_canonical_digest: &'a str,
    #[serde(serialize_with = "arkret_canonical::serialize_canonical_timestamp")]
    issued_at: DateTime<Utc>,
    #[serde(serialize_with = "arkret_canonical::serialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
}

/// Compute the single protocol-owned digest for a session-grant refresh
/// request. Human-device and Agent-runtime refresh branches MUST call this
/// function rather than defining local signing-input structs.
pub fn session_grant_refresh_request_digest(
    grant_jwt: &str,
    principal_id: &str,
    device_id: &str,
    audience: &str,
    grant_binding_key_id: &str,
) -> Result<Hash> {
    let input = SessionGrantRefreshRequestDigestInput {
        operation: SESSION_GRANT_REFRESH_OPERATION,
        grant_jwt_hash: canonical::sha256_digest(grant_jwt.as_bytes()),
        principal_id,
        device_id,
        audience,
        grant_binding_key_id,
    };
    Ok(Hash::new(canonical::canonical_sha256(&input)?)?)
}

/// Produce the canonical bytes signed by a session-grant refresh proof. This
/// is shared by every authentication branch so field order, timestamp
/// encoding, and future transcript changes cannot drift between products.
#[allow(clippy::too_many_arguments)]
pub fn session_grant_refresh_proof_signing_bytes(
    principal_id: &str,
    device_id: &str,
    audience: &str,
    challenge: &str,
    request_canonical_digest: &str,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<Vec<u8>> {
    Ok(canonical::canonical_json_bytes(
        &SessionGrantRefreshProofSigningInput {
            principal_id,
            device_id,
            audience,
            challenge,
            request_canonical_digest,
            issued_at,
            expires_at,
        },
    )?)
}

/// `ak.gate.account.command.refresh_session_grant` outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantRefreshOutcome {
    pub grant_id: SessionGrantId,
    pub grant_jwt: String,
    /// JWK the rotated grant is bound to (the device holder key); the server
    /// does not mint a fresh session private key on rotation.
    pub session_public_key: CanonicalSessionPublicJwk,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub audience: Did,
    pub scopes: Vec<String>,
    /// RFC 7638 thumbprint of the holder key (equals the grant's `cnf.jkt`).
    pub dpop_jkt: String,
    /// The predecessor grant, atomically superseded on success.
    pub previous_grant_id: SessionGrantId,
}

/// `ak.gate.account.command.logout_auth_session` request.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthSessionLogoutRequestBody {
    pub grant_jwt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logout_request_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
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
    Superseded,
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
#[serde(try_from = "SessionGrantIntrospectGrantWire")]
pub struct SessionGrantIntrospectGrant {
    pub id: SessionGrantId,
    pub issuer: String,
    pub subject: String,
    pub service_account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub audience: Did,
    pub scopes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_ref: String,
    /// Session signing key (JWK) for RFC 9421 PoP verification on
    /// `/_arkret/self/*`. Server-to-server only.
    pub session_public_key: CanonicalSessionPublicJwk,
    /// RFC 7638 JWK SHA-256 thumbprint of the holder (DPoP) key the grant is
    /// bound to (the grant's `cnf.jkt`); the Principal Server uses it to verify
    /// the per-request DPoP proof on `/_arkret/self/*`.
    pub cnf_jkt: String,
    pub credential_class: SessionGrantCredentialClass,
    pub holder_binding: SessionGrantHolderBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionGrantIntrospectGrantWire {
    id: SessionGrantId,
    issuer: String,
    subject: String,
    service_account_id: String,
    #[serde(default)]
    device_id: Option<DeviceId>,
    audience: Did,
    scopes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: DateTime<Utc>,
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    revoked_at: Option<DateTime<Utc>>,
    revocation_ref: String,
    session_public_key: CanonicalSessionPublicJwk,
    cnf_jkt: String,
    credential_class: SessionGrantCredentialClass,
    holder_binding: SessionGrantHolderBinding,
}

impl TryFrom<SessionGrantIntrospectGrantWire> for SessionGrantIntrospectGrant {
    type Error = String;

    fn try_from(wire: SessionGrantIntrospectGrantWire) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            id: wire.id,
            issuer: wire.issuer,
            subject: wire.subject,
            service_account_id: wire.service_account_id,
            device_id: wire.device_id,
            audience: wire.audience,
            scopes: wire.scopes,
            expires_at: wire.expires_at,
            revoked_at: wire.revoked_at,
            revocation_ref: wire.revocation_ref,
            session_public_key: wire.session_public_key,
            cnf_jkt: wire.cnf_jkt,
            credential_class: wire.credential_class,
            holder_binding: wire.holder_binding,
        })
    }
}

/// `ak.gate.account.command.introspect_session_grant` request. Exactly one of
/// `id` / `grant_jwt` identifies the grant.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionGrantIntrospectRequestBody {
    ById(SessionGrantIntrospectById),
    ByJwt(SessionGrantIntrospectByJwt),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantIntrospectById {
    pub id: SessionGrantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SessionGrantIntrospectionProof>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantIntrospectByJwt {
    pub grant_jwt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SessionGrantIntrospectionProof>,
}

/// `ak.gate.account.command.introspect_session_grant` outcome. READ-ONLY:
/// introspection never consumes the grant.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantIntrospectOutcome {
    pub active: bool,
    pub status: SessionGrantIntrospectStatus,
    pub proof_required: bool,
    /// Always false: introspection never consumes single-use state.
    pub one_time_use_consumed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<SessionGrantIntrospectGrant>,
}

#[cfg(test)]
mod session_grant_contract_tests {
    use serde_json::json;

    use super::*;

    const GRANT_ID: &str = "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW";
    const CANONICAL_JWK: &str =
        r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;

    #[test]
    fn issue_outcome_requires_identity_key_and_audience() {
        let valid = json!({
            "principal_id": "did:example:alice",
            "session_grant": "signed.jwt",
            "expires_at": "2026-08-08T12:00:00.000Z",
            "grant_id": GRANT_ID,
            "session_public_key": CANONICAL_JWK,
            "audience": "did:example:service"
        });
        assert!(serde_json::from_value::<SessionGrantOutcome>(valid.clone()).is_ok());

        for field in ["grant_id", "session_public_key", "audience"] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<SessionGrantOutcome>(missing).is_err(),
                "{field} must be required"
            );
        }

        let mut noncanonical = valid;
        noncanonical["session_public_key"] = json!(
            r#"{"kty":"OKP", "crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#
        );
        assert!(serde_json::from_value::<SessionGrantOutcome>(noncanonical).is_err());
    }

    #[test]
    fn refresh_request_proof_is_required_and_closed() {
        let valid = json!({
            "grant_jwt": "signed.jwt",
            "device_id": "ak:device:01964137-0000-7000-8000-000000000041",
            "proof": {
                "proof_kind": "did_bound_signature",
                "challenge": "0123456789abcdef",
                "request_canonical_digest": format!("sha256:{}", "00".repeat(32)),
                "audience": "did:example:service",
                "issued_at": "2026-08-08T11:59:00.000Z",
                "expires_at": "2026-08-08T12:04:00.000Z",
                "signature": "detached.jws"
            }
        });
        assert!(serde_json::from_value::<SessionGrantRefreshRequestBody>(valid.clone()).is_ok());

        let mut missing_proof = valid.clone();
        missing_proof.as_object_mut().unwrap().remove("proof");
        assert!(serde_json::from_value::<SessionGrantRefreshRequestBody>(missing_proof).is_err());

        let mut open_proof = valid;
        open_proof["proof"]["retry_nonce"] = json!("must-not-be-accepted");
        assert!(serde_json::from_value::<SessionGrantRefreshRequestBody>(open_proof).is_err());
    }

    #[test]
    fn introspection_selector_is_exactly_one_and_status_includes_superseded() {
        let by_id = json!({"id": GRANT_ID, "audience": "did:example:service"});
        let by_jwt = json!({"grant_jwt": "signed.jwt"});
        assert!(serde_json::from_value::<SessionGrantIntrospectRequestBody>(by_id).is_ok());
        assert!(serde_json::from_value::<SessionGrantIntrospectRequestBody>(by_jwt).is_ok());
        assert!(
            serde_json::from_value::<SessionGrantIntrospectRequestBody>(json!({
                "id": GRANT_ID,
                "grant_jwt": "signed.jwt"
            }))
            .is_err()
        );
        assert!(serde_json::from_value::<SessionGrantIntrospectRequestBody>(json!({})).is_err());
        assert_eq!(
            serde_json::from_value::<SessionGrantIntrospectStatus>(json!("superseded")).unwrap(),
            SessionGrantIntrospectStatus::Superseded
        );
    }

    fn introspect_grant_base(credential_class: &str) -> Value {
        json!({
            "id": GRANT_ID,
            "issuer": "did:example:issuer",
            "subject": "did:example:alice",
            "service_account_id": "account-1",
            "audience": "did:example:service",
            "scopes": [],
            "expires_at": "2026-08-08T12:04:00.000Z",
            "revocation_ref": "ledger-row-1",
            "session_public_key": CANONICAL_JWK,
            "cnf_jkt": "holder-thumbprint",
            "credential_class": credential_class
        })
    }

    fn holder_binding() -> Value {
        json!({
            "kind": "human_device",
            "device_binding": "accepted-device-binding"
        })
    }

    #[test]
    fn introspection_grant_requires_standard_holder_binding() {
        let mut valid = introspect_grant_base("standard");
        valid["holder_binding"] = holder_binding();
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(valid.clone()).is_ok());

        valid.as_object_mut().unwrap().remove("holder_binding");
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(valid).is_err());

        let mut legacy = introspect_grant_base("temporary_recovery");
        legacy["holder_binding"] = holder_binding();
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(legacy).is_err());
    }

    #[test]
    fn refresh_and_introspection_scopes_are_required() {
        let mut introspect = introspect_grant_base("standard");
        introspect["holder_binding"] = holder_binding();
        introspect.as_object_mut().unwrap().remove("scopes");
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(introspect).is_err());

        let mut refresh = json!({
            "grant_id": GRANT_ID,
            "grant_jwt": "successor.jwt",
            "session_public_key": CANONICAL_JWK,
            "expires_at": "2026-08-08T12:04:00.000Z",
            "audience": "did:example:service",
            "scopes": [],
            "dpop_jkt": "holder-thumbprint",
            "previous_grant_id": GRANT_ID
        });
        assert!(serde_json::from_value::<SessionGrantRefreshOutcome>(refresh.clone()).is_ok());
        refresh.as_object_mut().unwrap().remove("scopes");
        assert!(serde_json::from_value::<SessionGrantRefreshOutcome>(refresh).is_err());
    }
}
