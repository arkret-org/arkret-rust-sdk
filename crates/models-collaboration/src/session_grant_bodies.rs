//! Session-grant HTTP request/outcome DTOs
//! (`service-operation-dtos.schema.json`): the `ak.session.grant` issue proof
//! bodies, the DPoP-bound session-grant lifecycle (refresh / introspect /
//! auth-session logout), and the session-login outcome. `arkret-auth` binds
//! directly to these owner-defined types; the `arkret` umbrella re-exports them.

use arkret_models_identity::{
    CanonicalSessionPublicJwk, SessionGrantCredentialClass, SessionGrantDeviceBinding,
    SessionGrantHolderBinding,
};
pub use arkret_wire::{AcceptedDeviceIssuePossessionProof, AcceptedDeviceRefreshPossessionProof};
use arkret_wire::{
    AcceptedDevicePossessionProof, AccountId, AppletId, Base64UrlString, DeviceId, DidCoreId,
    DidUrl, Hash, NonEmptyString, RealmId, RequestId, Result, ScopeRef, SessionGrantId, StrandId,
    WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent_operations::AgentRequestedScopeDisclosure;
use crate::governance::agent_participation::AgentParticipationEntry;

#[derive(Serialize)]
struct HumanSessionGrantIntent<'a> {
    operation: &'static str,
    request_id: &'a RequestId,
    principal_id: &'a DidCoreId,
    device_id: &'a DeviceId,
    audience_id: &'a DidCoreId,
    holder_jkt: &'a str,
}

pub fn human_session_grant_intent_digest(
    request_id: &RequestId,
    principal_id: &DidCoreId,
    device_id: &DeviceId,
    audience_id: &DidCoreId,
    holder_jkt: &str,
) -> Result<Hash> {
    Ok(Hash::new(canonical::canonical_sha256(
        &HumanSessionGrantIntent {
            operation: "issue_session_grant",
            request_id,
            principal_id,
            device_id,
            audience_id,
            holder_jkt,
        },
    )?)?)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum SessionGrantRequestBody {
    Human(HumanSessionGrantRequest),
    Recovery(RecoverySessionGrantRequest),
    Agent(AgentSessionGrantRequest),
}

impl SessionGrantRequestBody {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Human(request) => request.validate(),
            Self::Recovery(request) => request.validate(),
            Self::Agent(request) => request.validate(),
        }
    }
}

/// Fresh-device existing-principal recovery issuance. The Bound
/// AccountHandoff and its per-request DPoP proof authenticate this body; the
/// candidate device is intentionally not required to have an accepted-device
/// authorization yet.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionGrantRequest {
    pub credential_class: SessionGrantCredentialClass,
    pub request_id: RequestId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub audience_id: DidCoreId,
}

impl RecoverySessionGrantRequest {
    pub fn validate(&self) -> Result<()> {
        if self.credential_class != SessionGrantCredentialClass::RecoverySession {
            return Err(WireError::Protocol(
                "recovery session grant request requires credential_class=recovery_session"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Returning human session issuance authenticated by an account-handoff
/// credential and a long-term accepted-device possession proof. Human scope is
/// issuer_id-owned and therefore deliberately absent from this wire shape.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSessionGrantRequest {
    pub request_id: RequestId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub audience_id: DidCoreId,
    pub accepted_device_possession_proof: AcceptedDeviceIssuePossessionProof,
}

impl HumanSessionGrantRequest {
    pub fn validate(&self) -> Result<()> {
        let proof = &self.accepted_device_possession_proof;
        AcceptedDevicePossessionProof::Issue(proof.clone()).validate()?;
        if proof.request_id != self.request_id
            || proof.principal_id != self.principal_id
            || proof.device_id != self.device_id
            || proof.audience_id != self.audience_id
        {
            return Err(WireError::Protocol(
                "accepted-device issue proof does not bind the session request".to_owned(),
            ));
        }
        let expected_intent = human_session_grant_intent_digest(
            &self.request_id,
            &self.principal_id,
            &self.device_id,
            &self.audience_id,
            &proof.holder_jkt,
        )?;
        if proof.session_intent_digest != expected_intent {
            return Err(WireError::Protocol(
                "accepted-device issue proof has the wrong session intent digest".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Agent session issuance remains delegated and scope-bearing. Keeping it as a
/// separate closed variant makes `requested_scope` impossible on human issue.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionGrantRequest {
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub requested_scope: Vec<String>,
    pub agent_key_authorization_ref: String,
    pub agent_scope_request: SessionGrantAgentScopeRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_scope_disclosure: Option<AgentRequestedScopeDisclosure>,
    pub dpop_binding_proof: SessionGrantDpopBindingProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_authority: Option<SessionGrantAppletDelegation>,
    pub proof: AgentSessionGrantProof,
}

impl AgentSessionGrantRequest {
    pub fn validate(&self) -> Result<()> {
        if self.requested_scope.is_empty()
            || self
                .requested_scope
                .iter()
                .any(|scope| scope.trim().is_empty())
        {
            return Err(WireError::Protocol(
                "agent session grant requested_scope must be non-empty".to_owned(),
            ));
        }
        if self.agent_key_authorization_ref.trim().is_empty() {
            return Err(WireError::Protocol(
                "agent session grant authorization ref must not be empty".to_owned(),
            ));
        }
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
            .expect("agent session grant proof serializes as an object");
        proof.remove("request_canonical_digest");
        proof.remove("signature");
        session_grant_request_digest(&value)
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
    pub applet_id: AppletId,
    pub effective_scope: ScopeRef,
    pub registration_epoch: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionGrantProof {
    pub proof_kind: AgentSessionGrantProofKind,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub signature: String,
    pub verification_method: DidUrl,
    pub nonce: String,
}

impl AgentSessionGrantProof {
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("session grant proof serializes as an object")
            .remove("signature");
        session_grant_proof_signing_bytes(&value)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentSessionGrantProofKind {
    #[serde(rename = "agent_key_proof")]
    AgentKeyProof,
}

/// Agent proof members before the self-referential request digest and detached
/// signature have been derived. This type is not serializable.
#[derive(Clone, Debug)]
pub struct UnsignedAgentSessionGrantProof {
    pub challenge: String,
    pub audience_id: DidCoreId,
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
    pub nonce: String,
}

/// Non-serializable Agent session-grant authoring state. Only
/// [`Self::attach_signature`] can produce the outbound wire request.
#[derive(Clone, Debug)]
pub struct UnsignedAgentSessionGrantRequest {
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub requested_scope: Vec<String>,
    pub agent_key_authorization_ref: String,
    pub agent_scope_request: SessionGrantAgentScopeRequest,
    pub requested_scope_disclosure: Option<AgentRequestedScopeDisclosure>,
    pub dpop_binding_proof: SessionGrantDpopBindingProof,
    pub applet_authority: Option<SessionGrantAppletDelegation>,
    pub proof: UnsignedAgentSessionGrantProof,
}

impl UnsignedAgentSessionGrantRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal_id: DidCoreId,
        device_id: DeviceId,
        requested_scope: Vec<String>,
        agent_key_authorization_ref: String,
        agent_scope_request: SessionGrantAgentScopeRequest,
        requested_scope_disclosure: Option<AgentRequestedScopeDisclosure>,
        dpop_binding_proof: SessionGrantDpopBindingProof,
        applet_authority: Option<SessionGrantAppletDelegation>,
        proof: UnsignedAgentSessionGrantProof,
    ) -> Result<Self> {
        if proof.challenge.is_empty() {
            return Err(WireError::Protocol(
                "agent session grant proof challenge must not be empty".to_owned(),
            ));
        }
        if requested_scope.is_empty() || requested_scope.iter().any(|scope| scope.trim().is_empty())
        {
            return Err(WireError::Protocol(
                "agent session grant requested_scope must be non-empty".to_owned(),
            ));
        }
        if agent_key_authorization_ref.trim().is_empty() || proof.nonce.trim().is_empty() {
            return Err(WireError::Protocol(
                "agent session grant authorization ref and nonce must not be empty".to_owned(),
            ));
        }
        Ok(Self {
            principal_id,
            device_id,
            requested_scope,
            agent_key_authorization_ref,
            agent_scope_request,
            requested_scope_disclosure,
            dpop_binding_proof,
            applet_authority,
            proof,
        })
    }

    pub fn canonical_request_digest(&self) -> Result<Hash> {
        session_grant_request_digest(&self.unsigned_request_value())
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        let digest = self.canonical_request_digest()?;
        session_grant_proof_signing_bytes(&self.unsigned_proof_value(Some(&digest)))
    }

    pub fn attach_signature(self, signature: NonEmptyString) -> Result<SessionGrantRequestBody> {
        let request_canonical_digest = self.canonical_request_digest()?;
        Ok(SessionGrantRequestBody::Agent(AgentSessionGrantRequest {
            principal_id: self.principal_id,
            device_id: self.device_id,
            requested_scope: self.requested_scope,
            agent_key_authorization_ref: self.agent_key_authorization_ref,
            agent_scope_request: self.agent_scope_request,
            requested_scope_disclosure: self.requested_scope_disclosure,
            dpop_binding_proof: self.dpop_binding_proof,
            applet_authority: self.applet_authority,
            proof: AgentSessionGrantProof {
                proof_kind: AgentSessionGrantProofKind::AgentKeyProof,
                challenge: self.proof.challenge,
                request_canonical_digest,
                audience_id: self.proof.audience_id,
                expires_at: self.proof.expires_at,
                signature: signature.into_string(),
                verification_method: self.proof.verification_method,
                nonce: self.proof.nonce,
            },
        }))
    }

    fn unsigned_request_value(&self) -> Value {
        let mut value = serde_json::json!({
            "principal_id": &self.principal_id,
            "device_id": &self.device_id,
            "requested_scope": &self.requested_scope,
            "agent_key_authorization_ref": &self.agent_key_authorization_ref,
            "agent_scope_request": &self.agent_scope_request,
            "requested_scope_disclosure": &self.requested_scope_disclosure,
            "dpop_binding_proof": &self.dpop_binding_proof,
            "applet_authority": &self.applet_authority,
            "proof": self.unsigned_proof_value(None),
        });
        let object = value
            .as_object_mut()
            .expect("unsigned session grant request is an object");
        for field in ["requested_scope_disclosure", "applet_authority"] {
            if object.get(field).is_some_and(Value::is_null) {
                object.remove(field);
            }
        }
        value
    }

    fn unsigned_proof_value(&self, digest: Option<&Hash>) -> Value {
        let mut value = serde_json::json!({
            "proof_kind": AgentSessionGrantProofKind::AgentKeyProof,
            "challenge": &self.proof.challenge,
            "request_canonical_digest": digest,
            "audience_id": &self.proof.audience_id,
            "expires_at": canonical::format_timestamp_canonical(self.proof.expires_at),
            "verification_method": &self.proof.verification_method,
            "nonce": &self.proof.nonce,
        });
        let object = value
            .as_object_mut()
            .expect("unsigned session grant proof is an object");
        if object
            .get("request_canonical_digest")
            .is_some_and(Value::is_null)
        {
            object.remove("request_canonical_digest");
        }
        value
    }
}

fn session_grant_request_digest(value: &Value) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(value)?).map_err(Into::into)
}

fn session_grant_proof_signing_bytes(value: &Value) -> Result<Vec<u8>> {
    canonical::canonical_json_bytes(value).map_err(Into::into)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantOutcome {
    pub account_id: AccountId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub session_grant: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    /// Stable id of the issued session grant. Returned for every grant (human
    /// and agent). Mirrors `SessionGrantRefreshOutcome.session_grant_id`.
    pub session_grant_id: SessionGrantId,
    /// JWK of the holder/session key the grant is bound to. The client needs
    /// this for RFC 9421 PoP / DPoP `cnf.jkt` derivation on `/_arkret/self/*`
    /// requests, returned at issue time to avoid a mandatory introspect
    /// round-trip. Mirrors `SessionGrantRefreshOutcome.session_public_key`.
    pub session_public_key: CanonicalSessionPublicJwk,
    /// Audience the grant is bound to. Mirrors `SessionGrantRefreshOutcome.audience_id`.
    pub audience_id: DidCoreId,
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

/// `ak.profile.agent_auth.v1` overlay describing the narrow scope actually
/// granted to an agent runtime session. Agent-only; absent for human grants.
///
/// Mirrors `service-operation-dtos.schema.json#/$defs/SessionGrantOutcome/properties/scope_details`
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
    #[serde(
        rename = "participation_entries",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub agent_participation_entries: Vec<AgentParticipationEntry>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLoginOutcome {
    pub session_credential: String,
    pub token_type: String,
    pub actor: DidCoreId,
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
    pub session_grant_id: String,
    pub grant_jwt_digest: String,
    pub audience_id: DidCoreId,
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

/// `ak.gate.account.command.refresh_session_grant.v1` request.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionGrantRefreshRequestBody {
    Human(HumanSessionGrantRefreshRequest),
    Agent(AgentSessionGrantRefreshRequest),
}

impl SessionGrantRefreshRequestBody {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Human(request) => request.validate(),
            Self::Agent(request) => request.validate(),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSessionGrantRefreshRequest {
    pub grant_jwt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience_id: Option<DidCoreId>,
    pub device_id: DeviceId,
    pub accepted_device_possession_proof: AcceptedDeviceRefreshPossessionProof,
}

impl HumanSessionGrantRefreshRequest {
    pub fn validate(&self) -> Result<()> {
        if self.grant_jwt.trim().is_empty() {
            return Err(WireError::Protocol(
                "human session refresh grant_jwt must not be empty".to_owned(),
            ));
        }
        let proof = &self.accepted_device_possession_proof;
        AcceptedDevicePossessionProof::Refresh(proof.clone()).validate()?;
        if proof.device_id != self.device_id
            || self
                .audience_id
                .as_ref()
                .is_some_and(|audience_id| audience_id != &proof.audience_id)
        {
            return Err(WireError::Protocol(
                "accepted-device refresh proof does not bind the refresh request".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionGrantRefreshRequest {
    pub grant_jwt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience_id: Option<DidCoreId>,
    pub device_id: DeviceId,
    pub agent_session_refresh_proof: AgentSessionRefreshProof,
}

impl AgentSessionGrantRefreshRequest {
    pub fn validate(&self) -> Result<()> {
        if self.grant_jwt.trim().is_empty() {
            return Err(WireError::Protocol(
                "agent session refresh grant_jwt must not be empty".to_owned(),
            ));
        }
        self.agent_session_refresh_proof.validate()?;
        if self
            .audience_id
            .as_ref()
            .is_some_and(|audience_id| audience_id != &self.agent_session_refresh_proof.audience_id)
        {
            return Err(WireError::Protocol(
                "agent session refresh proof audience_id mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentSessionRefreshProofContext {
    #[serde(rename = "ak.agent_session_refresh_proof.v1")]
    V1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionRefreshProof {
    pub context: AgentSessionRefreshProofContext,
    pub request_canonical_digest: Hash,
    pub audience_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub signature: Base64UrlString,
    pub verification_method: DidUrl,
}

impl AgentSessionRefreshProof {
    pub fn validate(&self) -> Result<()> {
        validate_agent_session_refresh_proof(self.issued_at, self.expires_at, &self.signature)
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("agent refresh proof serializes as an object")
            .remove("signature");
        canonical::canonical_json_bytes(&value).map_err(Into::into)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct UnsignedAgentSessionRefreshProof {
    pub context: AgentSessionRefreshProofContext,
    pub request_canonical_digest: Hash,
    pub audience_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
}

impl UnsignedAgentSessionRefreshProof {
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        validate_agent_session_refresh_window(self.issued_at, self.expires_at)?;
        canonical::canonical_json_bytes(self).map_err(Into::into)
    }

    pub fn attach_signature(self, signature: Base64UrlString) -> Result<AgentSessionRefreshProof> {
        self.canonical_signing_bytes()?;
        let proof = AgentSessionRefreshProof {
            context: self.context,
            request_canonical_digest: self.request_canonical_digest,
            audience_id: self.audience_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            signature,
            verification_method: self.verification_method,
        };
        proof.validate()?;
        Ok(proof)
    }
}

fn validate_agent_session_refresh_proof(
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    signature: &Base64UrlString,
) -> Result<()> {
    validate_agent_session_refresh_window(issued_at, expires_at)?;
    let signature_bytes = arkret_wire::base64url::base64url_decode(signature.as_str())
        .map_err(|_| WireError::Protocol("agent refresh proof signature is invalid".to_owned()))?;
    if signature_bytes.len() != 64 {
        return Err(WireError::Protocol(
            "agent refresh proof signature must encode 64 Ed25519 bytes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_agent_session_refresh_window(
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    if expires_at <= issued_at || (expires_at - issued_at).num_seconds() > 300 {
        return Err(WireError::Protocol(
            "agent refresh proof validity window must be positive and at most 300 seconds"
                .to_owned(),
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct AgentSessionRefreshRequestDigestInput<'a> {
    operation: &'static str,
    grant_jwt_digest: String,
    principal_id: &'a DidCoreId,
    device_id: &'a DeviceId,
    audience_id: &'a DidCoreId,
    verification_method: &'a DidUrl,
}

pub fn agent_session_refresh_request_digest(
    grant_jwt: &str,
    principal_id: &DidCoreId,
    device_id: &DeviceId,
    audience_id: &DidCoreId,
    verification_method: &DidUrl,
) -> Result<Hash> {
    Ok(Hash::new(canonical::canonical_sha256(
        &AgentSessionRefreshRequestDigestInput {
            operation: SESSION_GRANT_REFRESH_OPERATION,
            grant_jwt_digest: canonical::sha256_digest(grant_jwt.as_bytes()),
            principal_id,
            device_id,
            audience_id,
            verification_method,
        },
    )?)?)
}

pub const SESSION_GRANT_REFRESH_OPERATION: &str = "refresh_session_grant";

#[derive(Serialize)]
struct SessionGrantRefreshRequestDigestInput<'a> {
    operation: &'static str,
    grant_jwt_digest: String,
    predecessor_session_grant_id: &'a SessionGrantId,
    principal_id: &'a DidCoreId,
    device_id: &'a DeviceId,
    audience_id: &'a str,
    holder_jkt: &'a str,
}

/// Compute the human rotation intent digest. The predecessor JWT is hashed,
/// while its signed stable id is carried separately to prevent cross-chain
/// replay.
#[allow(clippy::too_many_arguments)]
pub fn session_grant_refresh_request_digest(
    grant_jwt: &str,
    predecessor_session_grant_id: &SessionGrantId,
    principal_id: &DidCoreId,
    device_id: &DeviceId,
    audience_id: &DidCoreId,
    holder_jkt: &str,
) -> Result<Hash> {
    let input = SessionGrantRefreshRequestDigestInput {
        operation: SESSION_GRANT_REFRESH_OPERATION,
        grant_jwt_digest: canonical::sha256_digest(grant_jwt.as_bytes()),
        predecessor_session_grant_id,
        principal_id,
        device_id,
        audience_id: audience_id.as_str(),
        holder_jkt,
    };
    Ok(Hash::new(canonical::canonical_sha256(&input)?)?)
}

/// `ak.gate.account.command.refresh_session_grant.v1` outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantRefreshOutcome {
    pub session_grant_id: SessionGrantId,
    pub account_id: AccountId,
    pub grant_jwt: String,
    /// JWK the rotated grant is bound to (the device holder key); the server
    /// does not mint a fresh session private key on rotation.
    pub session_public_key: CanonicalSessionPublicJwk,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub audience_id: DidCoreId,
    pub scopes: Vec<String>,
    /// RFC 7638 thumbprint of the holder key (equals the grant's `cnf.jkt`).
    pub dpop_jkt: String,
    /// The predecessor grant, atomically superseded on success.
    pub previous_session_grant_id: SessionGrantId,
}

/// `ak.gate.account.command.logout_auth_session.v1` request.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// `ak.gate.account.command.logout_auth_session.v1` outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSessionLogoutOutcome {
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

/// Non-secret grant metadata returned to a validating Station. Never
/// includes the grant JWT, refresh token, or session private key.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "SessionGrantIntrospectGrantWire")]
pub struct SessionGrantIntrospectGrant {
    pub id: SessionGrantId,
    pub issuer_id: DidCoreId,
    pub account_id: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub audience_id: DidCoreId,
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
    /// bound to (the grant's `cnf.jkt`); the Station uses it to verify
    /// the per-request DPoP proof on `/_arkret/self/*`.
    pub cnf_jkt: String,
    pub credential_class: SessionGrantCredentialClass,
    pub holder_binding: SessionGrantHolderBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_binding: Option<SessionGrantDeviceBinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionGrantIntrospectGrantWire {
    id: SessionGrantId,
    issuer_id: DidCoreId,
    account_id: AccountId,
    #[serde(default)]
    device_id: Option<DeviceId>,
    audience_id: DidCoreId,
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
    #[serde(default)]
    device_binding: Option<SessionGrantDeviceBinding>,
}

impl SessionGrantIntrospectGrant {
    /// Exact account bound into this grant.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Typed selector for replaying the accepted device authorization row in
    /// an online human request transaction. Agent grants use their delegated
    /// runtime binding instead and cannot be coerced into this human lane.
    pub fn human_device_authorization_selector(&self) -> Result<&SessionGrantDeviceBinding> {
        match (&self.holder_binding, self.device_binding.as_ref()) {
            (SessionGrantHolderBinding::HumanDevice { .. }, Some(binding)) => Ok(binding),
            (SessionGrantHolderBinding::HumanDevice { .. }, None) => Err(WireError::Protocol(
                "online human request context is missing device authorization selector".to_owned(),
            )),
            (SessionGrantHolderBinding::RecoveryCandidateDevice { .. }, _) => {
                Err(WireError::Protocol(
                    "recovery candidate request context has no accepted-device selector".to_owned(),
                ))
            }
            (SessionGrantHolderBinding::AgentRuntime { .. }, _) => Err(WireError::Protocol(
                "Agent request context must use delegated runtime authority".to_owned(),
            )),
        }
    }

    pub fn validate(&self) -> Result<()> {
        match (self.credential_class, &self.holder_binding) {
            (
                SessionGrantCredentialClass::Standard,
                SessionGrantHolderBinding::HumanDevice { .. }
                | SessionGrantHolderBinding::AgentRuntime { .. },
            )
            | (
                SessionGrantCredentialClass::RecoverySession,
                SessionGrantHolderBinding::RecoveryCandidateDevice { .. },
            ) => {}
            _ => {
                return Err(WireError::Protocol(
                    "session grant introspection credential_class and holder_binding are incompatible"
                        .to_owned(),
                ));
            }
        }
        match (&self.holder_binding, &self.device_id, &self.device_binding) {
            (
                SessionGrantHolderBinding::HumanDevice { .. },
                Some(device_id),
                Some(device_binding),
            ) => {
                if device_binding.device_id != *device_id {
                    return Err(WireError::Protocol(
                        "session grant introspection device_binding.device_id must match device_id"
                            .to_owned(),
                    ));
                }
                if device_binding.model_generation_ref == 0 {
                    return Err(WireError::Protocol(
                        "session grant introspection device generation must be positive".to_owned(),
                    ));
                }
            }
            (SessionGrantHolderBinding::HumanDevice { .. }, ..) => {
                return Err(WireError::Protocol(
                    "human session grant introspection requires device_id and device_binding"
                        .to_owned(),
                ));
            }
            (
                SessionGrantHolderBinding::RecoveryCandidateDevice {
                    device_id: holder_device_id,
                },
                Some(device_id),
                None,
            ) if holder_device_id == device_id => {}
            (SessionGrantHolderBinding::RecoveryCandidateDevice { .. }, ..) => {
                return Err(WireError::Protocol(
                    "recovery session grant introspection requires matching device_id and forbids device_binding"
                        .to_owned(),
                ));
            }
            (SessionGrantHolderBinding::AgentRuntime { .. }, None, None) => {}
            (SessionGrantHolderBinding::AgentRuntime { .. }, ..) => {
                return Err(WireError::Protocol(
                    "agent session grant introspection must not contain human device binding"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl TryFrom<SessionGrantIntrospectGrantWire> for SessionGrantIntrospectGrant {
    type Error = String;

    fn try_from(wire: SessionGrantIntrospectGrantWire) -> std::result::Result<Self, Self::Error> {
        let grant = Self {
            id: wire.id,
            issuer_id: wire.issuer_id,
            account_id: wire.account_id,
            device_id: wire.device_id,
            audience_id: wire.audience_id,
            scopes: wire.scopes,
            expires_at: wire.expires_at,
            revoked_at: wire.revoked_at,
            revocation_ref: wire.revocation_ref,
            session_public_key: wire.session_public_key,
            cnf_jkt: wire.cnf_jkt,
            credential_class: wire.credential_class,
            holder_binding: wire.holder_binding,
            device_binding: wire.device_binding,
        };
        grant.validate().map_err(|error| error.to_string())?;
        Ok(grant)
    }
}

/// `ak.gate.account.command.introspect_session_grant.v1` request. Exactly one of
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
    pub audience_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SessionGrantIntrospectionProof>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantIntrospectByJwt {
    pub grant_jwt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SessionGrantIntrospectionProof>,
}

/// `ak.gate.account.command.introspect_session_grant.v1` outcome. READ-ONLY:
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
    fn issue_outcome_requires_account_id_and_audience() {
        let valid = json!({
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:service.example"
            },
            "session_grant": "signed.jwt",
            "expires_at": "2026-08-08T12:00:00.000Z",
            "session_grant_id": GRANT_ID,
            "session_public_key": CANONICAL_JWK,
            "audience_id": "ak:did_core:web:service.example"
        });
        assert!(serde_json::from_value::<SessionGrantOutcome>(valid.clone()).is_ok());

        for field in [
            "account_id",
            "session_grant_id",
            "session_public_key",
            "audience_id",
        ] {
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
    fn issue_request_has_a_closed_recovery_branch() {
        let valid = json!({
            "credential_class": "recovery_session",
            "request_id": "ak:request:01964137-0000-7000-8000-000000000040",
            "principal_id": "ak:did_core:web:alice.example",
            "device_id": "ak:device:01964137-0000-7000-8000-000000000041",
            "audience_id": "ak:did_core:web:service.example"
        });
        let request = serde_json::from_value::<SessionGrantRequestBody>(valid.clone()).unwrap();
        assert!(matches!(request, SessionGrantRequestBody::Recovery(_)));
        request.validate().unwrap();

        let mut wrong_class = valid.clone();
        wrong_class["credential_class"] = json!("standard");
        let request = serde_json::from_value::<SessionGrantRequestBody>(wrong_class).unwrap();
        assert!(request.validate().is_err());

        let mut open = valid;
        open["requested_scope"] = json!(["ak.self.events.read.scan.v1"]);
        assert!(serde_json::from_value::<SessionGrantRequestBody>(open).is_err());
    }

    #[test]
    fn refresh_request_is_a_closed_agent_or_human_union() {
        let valid = json!({
            "grant_jwt": "signed.jwt",
            "device_id": "ak:device:01964137-0000-7000-8000-000000000041",
            "agent_session_refresh_proof": {
                "context": "ak.agent_session_refresh_proof.v1",
                "request_canonical_digest": format!("sha256:{}", "00".repeat(32)),
                "audience_id": "ak:did_core:web:service.example",
                "issued_at": "2026-08-08T11:59:00.000Z",
                "expires_at": "2026-08-08T12:04:00.000Z",
                "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "verification_method": "did:web:agent.example#runtime-key-1"
            }
        });
        assert!(serde_json::from_value::<SessionGrantRefreshRequestBody>(valid.clone()).is_ok());

        let mut missing_proof = valid.clone();
        missing_proof
            .as_object_mut()
            .unwrap()
            .remove("agent_session_refresh_proof");
        assert!(serde_json::from_value::<SessionGrantRefreshRequestBody>(missing_proof).is_err());

        let mut open_proof = valid;
        open_proof["agent_session_refresh_proof"]["retry_nonce"] = json!("must-not-be-accepted");
        assert!(serde_json::from_value::<SessionGrantRefreshRequestBody>(open_proof).is_err());
    }

    #[test]
    fn agent_refresh_unsigned_authoring_matches_the_final_transcript() {
        let unsigned = UnsignedAgentSessionRefreshProof {
            context: AgentSessionRefreshProofContext::V1,
            request_canonical_digest: Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap(),
            audience_id: DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            issued_at: "2026-08-08T11:59:00Z".parse().unwrap(),
            expires_at: "2026-08-08T12:04:00Z".parse().unwrap(),
            verification_method: DidUrl::new("did:web:agent.example#runtime-key-1").unwrap(),
        };
        let signing_bytes = unsigned.canonical_signing_bytes().unwrap();
        let signature =
            Base64UrlString::new(arkret_wire::base64url::base64url_encode([0u8; 64])).unwrap();
        let proof = unsigned.attach_signature(signature).unwrap();

        assert_eq!(signing_bytes, proof.canonical_signing_bytes().unwrap());
    }

    #[test]
    fn introspection_selector_is_exactly_one_and_status_includes_superseded() {
        let by_id = json!({"id": GRANT_ID, "audience_id": "ak:did_core:web:service.example"});
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
            "issuer_id": "ak:did_core:web:account-authority.example",
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:service.example"
            },
            "device_id": "ak:device:019a6aa0-0000-7000-8000-000000000000",
            "audience_id": "ak:did_core:web:service.example",
            "scopes": [],
            "expires_at": "2026-08-08T12:04:00.000Z",
            "revocation_ref": "ledger-row-1",
            "session_public_key": CANONICAL_JWK,
            "cnf_jkt": "holder-thumbprint",
            "credential_class": credential_class,
            "device_binding": {
                "device_id": "ak:device:019a6aa0-0000-7000-8000-000000000000",
                "authorization_event_id": "ak:event:ARKvbHo7orDUG4lSf-XaWVE2UDU5C-hOBPqUSLx8PmM3",
                "model_generation_ref": 7
            }
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
        let grant = serde_json::from_value::<SessionGrantIntrospectGrant>(valid.clone()).unwrap();
        assert_eq!(
            grant.account_id().principal_id.as_str(),
            "ak:did_core:web:alice.example"
        );
        assert_eq!(grant.account_id().station_id, grant.audience_id);
        assert_eq!(
            grant
                .human_device_authorization_selector()
                .unwrap()
                .model_generation_ref,
            7
        );

        valid.as_object_mut().unwrap().remove("holder_binding");
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(valid).is_err());

        let mut bare_did_issuer = introspect_grant_base("standard");
        bare_did_issuer["holder_binding"] = holder_binding();
        bare_did_issuer["issuer_id"] = json!("did:web:account-authority.example");
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(bare_did_issuer).is_err());
    }

    #[test]
    fn introspection_grant_closes_human_and_agent_device_binding_branches() {
        let mut human = introspect_grant_base("standard");
        human["holder_binding"] = holder_binding();
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(human.clone()).is_ok());

        human.as_object_mut().unwrap().remove("device_binding");
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(human.clone()).is_err());

        human["device_binding"] = json!({
            "device_id": "ak:device:019a6aa0-0000-7000-8000-000000000001",
            "authorization_event_id": "ak:event:ARKvbHo7orDUG4lSf-XaWVE2UDU5C-hOBPqUSLx8PmM3",
            "model_generation_ref": 7
        });
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(human).is_err());

        let mut agent = introspect_grant_base("standard");
        agent["holder_binding"] = json!({
            "kind": "agent_runtime",
            "agent_id": "ak:did_core:web:agent.example",
            "device_id": "ak:device:019a6aa0-0000-7000-8000-000000000002",
            "agent_key_authorization_ref": "ak:event:ARKvbHo7orDUG4lSf-XaWVE2UDU5C-hOBPqUSLx8PmM3",
            "verification_method": "did:web:agent.example#agent-key"
        });
        agent.as_object_mut().unwrap().remove("device_id");
        agent.as_object_mut().unwrap().remove("device_binding");
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(agent.clone()).is_ok());

        agent["device_binding"] = json!({
            "device_id": "ak:device:019a6aa0-0000-7000-8000-000000000002",
            "authorization_event_id": "ak:event:ARKvbHo7orDUG4lSf-XaWVE2UDU5C-hOBPqUSLx8PmM3",
            "model_generation_ref": 7
        });
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(agent).is_err());

        let mut recovery = introspect_grant_base("recovery_session");
        recovery["holder_binding"] = json!({
            "kind": "recovery_candidate_device",
            "device_id": "ak:device:019a6aa0-0000-7000-8000-000000000000"
        });
        recovery.as_object_mut().unwrap().remove("device_binding");
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(recovery.clone()).is_ok());

        recovery["device_binding"] = json!({
            "device_id": "ak:device:019a6aa0-0000-7000-8000-000000000000",
            "authorization_event_id": "ak:event:ARKvbHo7orDUG4lSf-XaWVE2UDU5C-hOBPqUSLx8PmM3",
            "model_generation_ref": 7
        });
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(recovery).is_err());
    }

    #[test]
    fn refresh_and_introspection_scopes_are_required() {
        let mut introspect = introspect_grant_base("standard");
        introspect["holder_binding"] = holder_binding();
        introspect.as_object_mut().unwrap().remove("scopes");
        assert!(serde_json::from_value::<SessionGrantIntrospectGrant>(introspect).is_err());

        let mut refresh = json!({
            "session_grant_id": GRANT_ID,
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:service.example"
            },
            "grant_jwt": "successor.jwt",
            "session_public_key": CANONICAL_JWK,
            "expires_at": "2026-08-08T12:04:00.000Z",
            "audience_id": "ak:did_core:web:service.example",
            "scopes": [],
            "dpop_jkt": "holder-thumbprint",
            "previous_session_grant_id": GRANT_ID
        });
        assert!(serde_json::from_value::<SessionGrantRefreshOutcome>(refresh.clone()).is_ok());
        refresh.as_object_mut().unwrap().remove("scopes");
        assert!(serde_json::from_value::<SessionGrantRefreshOutcome>(refresh).is_err());
    }

    #[test]
    fn auth_session_logout_contract_is_closed() {
        assert!(
            serde_json::from_value::<AuthSessionLogoutRequestBody>(json!({
                "grant_jwt": "header.payload.signature",
                "unknown": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AuthSessionLogoutOutcome>(json!({
                "grant_chain_terminated": true,
                "auth_session_logged_out": true,
                "unknown": true
            }))
            .is_err()
        );
    }
}
