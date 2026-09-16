//! Session-grant request DTOs used by the authentication builder, plus the
//! server-to-server introspection and Auth-side logout wire shapes
//! (`service-operation-dtos.schema.json`).

use arkret_models_identity::{
    CanonicalSessionPublicJwk, SessionGrantAdminIntrospectionStatus, SessionGrantCredentialClass,
    SessionGrantDeviceBinding, SessionGrantHolderBinding,
};
pub use arkret_wire::{AcceptedDeviceIssuePossessionProof, AcceptedDeviceRefreshPossessionProof};
use arkret_wire::{
    AcceptedDevicePossessionProof, AccountId, AppletId, DeviceId, DidCoreId, DidUrl, Hash,
    NonEmptyString, PairwiseEndpointPossessionProof, RealmId, RequestId, Result, ScopeRef,
    SessionGrantId, StrandId, WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent_scope::AgentRequestedScopeDisclosure;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantOutcome {
    pub account_id: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub session_grant: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub session_grant_id: SessionGrantId,
    pub session_public_key: CanonicalSessionPublicJwk,
    pub audience_id: DidCoreId,
    pub granted_scope: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_session_grant_id: Option<SessionGrantId>,
}

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
    Hash::new(canonical::canonical_sha256(&HumanSessionGrantIntent {
        operation: "issue_session_grant",
        request_id,
        principal_id,
        device_id,
        audience_id,
        holder_jkt,
    })?)
    .map_err(Into::into)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum SessionGrantRequestBody {
    Human(HumanSessionGrantRequest),
    Agent(AgentSessionGrantRequest),
    PairwiseEndpoint(PairwiseEndpointSessionGrantRequest),
}

impl SessionGrantRequestBody {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Human(request) => request.validate(),
            Self::Agent(request) => request.validate(),
            Self::PairwiseEndpoint(request) => request.validate(),
        }
    }
}

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
            || proof.account_id.principal_id != self.principal_id
            || proof.device_id != self.device_id
            || proof.audience_id != self.audience_id
        {
            return Err(WireError::Protocol(
                "accepted-device issue proof does not bind the session request".into(),
            ));
        }
        let expected = human_session_grant_intent_digest(
            &self.request_id,
            &self.principal_id,
            &self.device_id,
            &self.audience_id,
            &proof.holder_jkt,
        )?;
        if proof.session_intent_digest != expected {
            return Err(WireError::Protocol(
                "accepted-device issue proof has the wrong session intent digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairwiseEndpointSessionGrantRequest {
    pub request_id: RequestId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub audience_id: DidCoreId,
    pub accepted_device_possession_proof: AcceptedDeviceIssuePossessionProof,
    pub pairwise_endpoint_possession_proof: PairwiseEndpointPossessionProof,
}

impl PairwiseEndpointSessionGrantRequest {
    pub fn validate(&self) -> Result<()> {
        let accepted = &self.accepted_device_possession_proof;
        AcceptedDevicePossessionProof::Issue(accepted.clone()).validate()?;
        if accepted.request_id != self.request_id
            || accepted.account_id.principal_id != self.principal_id
            || accepted.device_id != self.device_id
            || accepted.audience_id != self.audience_id
        {
            return Err(WireError::Protocol(
                "accepted-device issue proof does not bind the session request".into(),
            ));
        }
        let expected = human_session_grant_intent_digest(
            &self.request_id,
            &self.principal_id,
            &self.device_id,
            &self.audience_id,
            &accepted.holder_jkt,
        )?;
        if accepted.session_intent_digest != expected {
            return Err(WireError::Protocol(
                "accepted-device issue proof has the wrong session intent digest".into(),
            ));
        }
        let pairwise = &self.pairwise_endpoint_possession_proof;
        pairwise.validate()?;
        if pairwise.request_id != self.request_id
            || pairwise.account_id != accepted.account_id
            || pairwise.audience_id != self.audience_id
            || pairwise.holder_jkt != accepted.holder_jkt
            || pairwise.session_intent_digest != expected
        {
            return Err(WireError::Protocol(
                "pairwise endpoint possession proof does not bind the same issuance intent".into(),
            ));
        }
        Ok(())
    }

    pub fn expected_holder_binding(&self) -> SessionGrantHolderBinding {
        let proof = &self.pairwise_endpoint_possession_proof;
        SessionGrantHolderBinding::MinimalMetadataPairwise {
            realm_id: proof.realm_id.clone(),
            actor_id: proof.actor_id.clone(),
            verification_method: proof.verification_method.clone(),
        }
    }
}

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
        self.proof.validate_structure()?;
        if self.requested_scope.is_empty()
            || self
                .requested_scope
                .iter()
                .any(|scope| scope.trim().is_empty())
        {
            return Err(WireError::Protocol(
                "agent session grant requested_scope must be non-empty".into(),
            ));
        }
        if self.agent_key_authorization_ref.trim().is_empty() {
            return Err(WireError::Protocol(
                "agent session grant authorization ref must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantDpopBindingProof {
    pub proof_jwt: String,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentSessionGrantProofKind {
    #[serde(rename = "agent_key_proof")]
    AgentKeyProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionGrantProof {
    pub proof_kind: AgentSessionGrantProofKind,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
    pub signature: String,
}

impl AgentSessionGrantProof {
    pub fn validate_structure(&self) -> Result<()> {
        if !valid_agent_session_challenge(&self.challenge)
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > chrono::Duration::seconds(300)
        {
            return Err(WireError::Protocol(
                "invalid Agent session proof challenge or time window".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct UnsignedAgentSessionGrantProof {
    pub challenge: String,
    pub audience_id: DidCoreId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
}

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
        if !valid_agent_session_challenge(&proof.challenge) {
            return Err(WireError::Protocol("agent session grant proof challenge must be canonical Base64URL with at least 128 bits".into()));
        }
        if requested_scope.is_empty() || requested_scope.iter().any(|scope| scope.trim().is_empty())
        {
            return Err(WireError::Protocol(
                "agent session grant requested_scope must be non-empty".into(),
            ));
        }
        if agent_key_authorization_ref.trim().is_empty() {
            return Err(WireError::Protocol(
                "agent session grant authorization ref must not be empty".into(),
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
        Hash::new(canonical::canonical_sha256(&self.unsigned_request_value())?).map_err(Into::into)
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
                issued_at: self.proof.issued_at,
                expires_at: self.proof.expires_at,
                verification_method: self.proof.verification_method,
                signature: signature.into_string(),
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
            "proof": {
                "proof_kind": AgentSessionGrantProofKind::AgentKeyProof,
                "challenge": &self.proof.challenge,
                "audience_id": &self.proof.audience_id,
                "issued_at": canonical::format_timestamp_canonical(self.proof.issued_at),
                "expires_at": canonical::format_timestamp_canonical(self.proof.expires_at),
                "verification_method": &self.proof.verification_method,
            },
        });
        let object = value.as_object_mut().expect("session request is an object");
        for field in ["requested_scope_disclosure", "applet_authority"] {
            if object.get(field).is_some_and(Value::is_null) {
                object.remove(field);
            }
        }
        value
    }
}

fn valid_agent_session_challenge(challenge: &str) -> bool {
    arkret_wire::base64url::base64url_decode(challenge).is_ok_and(|bytes| {
        bytes.len() >= 16 && arkret_wire::base64url::base64url_encode(&bytes) == challenge
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionGrantRefreshRequestBody {
    Human(HumanSessionGrantRefreshRequest),
}

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
                "human session refresh grant_jwt must not be empty".into(),
            ));
        }
        let proof = &self.accepted_device_possession_proof;
        AcceptedDevicePossessionProof::Refresh(proof.clone()).validate()?;
        if proof.device_id != self.device_id
            || self
                .audience_id
                .as_ref()
                .is_some_and(|audience| audience != &proof.audience_id)
        {
            return Err(WireError::Protocol(
                "accepted-device refresh proof does not bind the refresh request".into(),
            ));
        }
        Ok(())
    }
}

// --- Session-grant introspection and Auth-side logout ----------------------
//
// Wire shapes for `POST /_arkret/gate/account/session-grants/introspect`
// (`ak.gate.account.command.introspect_session_grant.v1`) and
// `POST /_arkret/gate/account/auth-sessions/logout`
// (`ak.gate.account.command.logout_auth_session.v1`). The introspection status
// vocabulary is the closed enum already carried by
// `arkret_models_identity::SessionGrantAdminIntrospectionStatus`, which is
// member-for-member the schema's `status` enum, so it is reused here.

/// Claim-set kind of the JWS carried in
/// [`SessionGrantIntrospectionProof::proof_jwt`].
pub const SESSION_GRANT_INTROSPECTION_PROOF_CLAIMS_KIND: &str =
    "ak.session_grant.introspection_proof.v1";

/// Optional server-to-server holder confirmation signed by the session key
/// bound into the grant. Stations validating `/_arkret/self/*` grant+DPoP
/// requests do not carry this proof; they verify the request DPoP locally
/// against the returned `cnf_jkt`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `service-operation-dtos.schema.json#/$defs/SessionGrantIntrospectRequestBody`
// member `proof`.
pub struct SessionGrantIntrospectionProof {
    pub challenge: String,
    pub proof_jwt: String,
}

/// Claims of the `ak.session_grant.introspection_proof.v1` JWS presented in
/// [`SessionGrantIntrospectionProof::proof_jwt`].
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

/// Non-secret grant metadata returned to the validating Station. Never
/// includes the grant JWT, refresh token, or session private key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "SessionGrantIntrospectGrantWire")]
// Field declaration order is byte-for-byte the `properties` order of
// `service-operation-dtos.schema.json#/$defs/SessionGrantIntrospectGrant`.
pub struct SessionGrantIntrospectGrant {
    pub id: SessionGrantId,
    pub issuer_id: DidCoreId,
    pub account_id: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    /// Stable `did_core_id` of the resource service this grant is valid for.
    pub audience_id: DidCoreId,
    pub scopes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_ref: String,
    /// Session signing key (JWK) for RFC 9421 PoP verification on
    /// `/_arkret/self/*`. Server-to-server only.
    pub session_public_key: CanonicalSessionPublicJwk,
    /// RFC 7638 JWK SHA-256 thumbprint of the holder (DPoP) key this grant is
    /// bound to (its `cnf.jkt`); the Station uses it to verify the per-request
    /// DPoP proof on `/_arkret/self/*`. Server-to-server only.
    pub cnf_jkt: String,
    pub credential_class: SessionGrantCredentialClass,
    /// Closed accepted human-device, recovery candidate-device, or
    /// Agent-runtime holder binding.
    pub holder_binding: SessionGrantHolderBinding,
    /// Exact origin-derived device authorization preimage taken from the
    /// revocation gate's allow receipt. Present only for standard
    /// `human_device` grants.
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
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
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
    pub const fn account_id(&self) -> &AccountId {
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
            (SessionGrantHolderBinding::MinimalMetadataPairwise { .. }, _) => {
                Err(WireError::Protocol(
                    "minimal-metadata pairwise endpoint is not an introspectable grant holder"
                        .to_owned(),
                ))
            }
        }
    }

    /// Enforces the closed `credential_class` / `holder_binding` /
    /// `device_binding` combinations the schema declares.
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
            (SessionGrantHolderBinding::MinimalMetadataPairwise { .. }, ..) => {
                return Err(WireError::Protocol(
                    "minimal-metadata pairwise endpoint is not an introspectable grant holder"
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

/// `ak.gate.account.command.introspect_session_grant.v1` request. Exactly one
/// of `id` / `grant_jwt` identifies the grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
// Field declaration order is byte-for-byte the `properties` order of
// `service-operation-dtos.schema.json#/$defs/SessionGrantIntrospectRequestBody`,
// split across the two selector branches of its `oneOf`.
pub enum SessionGrantIntrospectRequestBody {
    ById(SessionGrantIntrospectById),
    ByJwt(SessionGrantIntrospectByJwt),
}

/// `id` selector branch of [`SessionGrantIntrospectRequestBody`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `service-operation-dtos.schema.json#/$defs/SessionGrantIntrospectRequestBody`
// restricted to the `id` branch of its `oneOf`.
pub struct SessionGrantIntrospectById {
    pub id: SessionGrantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SessionGrantIntrospectionProof>,
}

/// `grant_jwt` selector branch of [`SessionGrantIntrospectRequestBody`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `service-operation-dtos.schema.json#/$defs/SessionGrantIntrospectRequestBody`
// restricted to the `grant_jwt` branch of its `oneOf`.
pub struct SessionGrantIntrospectByJwt {
    pub grant_jwt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SessionGrantIntrospectionProof>,
}

/// `ak.gate.account.command.introspect_session_grant.v1` outcome. READ-ONLY:
/// introspection never consumes the grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `service-operation-dtos.schema.json#/$defs/SessionGrantIntrospectOutcome`.
pub struct SessionGrantIntrospectOutcome {
    /// Whether the grant is currently valid for the requested audience.
    pub active: bool,
    pub status: SessionGrantAdminIntrospectionStatus,
    /// Whether an additional S2S holder proof is required to confirm the grant
    /// active for this introspection request.
    pub proof_required: bool,
    /// Always false: introspection is read-only and never consumes single-use
    /// state.
    pub one_time_use_consumed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<SessionGrantIntrospectGrant>,
}

impl SessionGrantIntrospectOutcome {
    /// An `active` outcome MUST carry the grant projection.
    pub fn validate(&self) -> Result<()> {
        match (self.active, &self.grant) {
            (true, None) => Err(WireError::Protocol(
                "active session grant introspection must carry grant metadata".to_owned(),
            )),
            (_, Some(grant)) => grant.validate(),
            (false, None) => Ok(()),
        }
    }
}

/// Reason the Account Authority logs out an Auth-side session. v1 defines only
/// `account_logout` for this server-to-server sub-operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthSessionLogoutReasonCode {
    AccountLogout,
}

/// `ak.gate.account.command.logout_auth_session.v1` request: the Account
/// Authority to Auth Server call that logs out the Auth-side session owning an
/// `ak.session.grant` rotation chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `service-operation-dtos.schema.json#/$defs/AuthSessionLogoutRequestBody`.
pub struct AuthSessionLogoutRequestBody {
    /// Session grant used to locate the Auth-side session and its rotation
    /// chain.
    pub grant_jwt: String,
    /// Digest of the validated client-visible account `/logout` request that
    /// caused this sub-operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logout_request_digest: Option<Hash>,
    /// When the Account Authority validated the client-visible account
    /// `/logout` request.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub validated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<AuthSessionLogoutReasonCode>,
}

/// `ak.gate.account.command.logout_auth_session.v1` outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `service-operation-dtos.schema.json#/$defs/AuthSessionLogoutOutcome`.
pub struct AuthSessionLogoutOutcome {
    /// Whether the grant rotation chain is now unable to refresh, including
    /// the already-terminated idempotent case.
    pub grant_chain_terminated: bool,
    /// Whether the underlying Auth-side browser/auth session is now logged
    /// out, including the already-logged-out idempotent case.
    pub auth_session_logged_out: bool,
}

#[cfg(test)]
mod session_grant_introspection_tests {
    use arkret_wire::{CommitStreamRef, CommittedEventRef, EventId, RealmCommitId};
    use serde_json::json;

    use super::*;

    const GRANT_ID: &str = "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW";
    const DEVICE_ID: &str = "ak:device:019a6aa0-0000-7000-8000-000000000000";
    const AUDIENCE_ID: &str = "ak:did_core:web:service.example";
    const CANONICAL_JWK: &str =
        r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
    const LOGOUT_REQUEST_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn device_authorization_ref() -> Value {
        let realm_id =
            RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
        serde_json::to_value(CommittedEventRef {
            event_id: EventId::new("ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g")
                .unwrap(),
            commit_id: RealmCommitId::from_digest([7; 32]),
            stream_ref: CommitStreamRef::Realm { realm_id },
            stream_position: 1,
        })
        .unwrap()
    }

    fn human_grant_value() -> Value {
        json!({
            "id": GRANT_ID,
            "issuer_id": "ak:did_core:web:account-authority.example",
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": AUDIENCE_ID
            },
            "device_id": DEVICE_ID,
            "audience_id": AUDIENCE_ID,
            "scopes": ["ak.self.events.read.scan.v1"],
            "expires_at": "2026-08-08T12:04:00.000Z",
            "revocation_ref": "org.arkret.coauth.session_grant:1",
            "session_public_key": CANONICAL_JWK,
            "cnf_jkt": "holder-thumbprint",
            "credential_class": "standard",
            "holder_binding": {
                "kind": "human_device",
                "device_binding": "accepted-device-binding"
            },
            "device_binding": {
                "device_id": DEVICE_ID,
                "authorization_ref": device_authorization_ref(),
                "model_generation_ref": 7
            }
        })
    }

    fn with_unknown_member(mut value: Value) -> Value {
        value
            .as_object_mut()
            .expect("fixture is an object")
            .insert("unknown_member".to_owned(), json!(true));
        value
    }

    fn without_member(mut value: Value, member: &str) -> Value {
        value
            .as_object_mut()
            .expect("fixture is an object")
            .remove(member);
        value
    }

    #[test]
    fn introspect_request_round_trips_and_stays_closed() {
        let by_id = json!({
            "id": GRANT_ID,
            "audience_id": AUDIENCE_ID,
            "proof": {
                "challenge": "Zm9vYmFyZm9vYmFyZm9vYmFy",
                "proof_jwt": "header.payload.signature"
            }
        });
        let parsed = serde_json::from_value::<SessionGrantIntrospectRequestBody>(by_id.clone())
            .expect("id selector parses");
        assert!(matches!(
            parsed,
            SessionGrantIntrospectRequestBody::ById(ref body)
                if body.id.as_str() == GRANT_ID
        ));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), by_id);

        let by_jwt = json!({ "grant_jwt": "header.payload.signature" });
        let parsed = serde_json::from_value::<SessionGrantIntrospectRequestBody>(by_jwt.clone())
            .expect("grant_jwt selector parses");
        assert!(matches!(
            parsed,
            SessionGrantIntrospectRequestBody::ByJwt(_)
        ));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), by_jwt);

        for open in [with_unknown_member(by_id), with_unknown_member(by_jwt)] {
            assert!(
                serde_json::from_value::<SessionGrantIntrospectRequestBody>(open).is_err(),
                "an unknown member must be rejected"
            );
        }

        let proof_open = json!({
            "id": GRANT_ID,
            "proof": {
                "challenge": "Zm9vYmFyZm9vYmFyZm9vYmFy",
                "proof_jwt": "header.payload.signature",
                "unknown_member": true
            }
        });
        assert!(serde_json::from_value::<SessionGrantIntrospectRequestBody>(proof_open).is_err());

        for missing_selector in [json!({}), json!({ "audience_id": AUDIENCE_ID })] {
            assert!(
                serde_json::from_value::<SessionGrantIntrospectRequestBody>(missing_selector)
                    .is_err(),
                "a request without a selector must be rejected"
            );
        }

        assert!(
            serde_json::from_value::<SessionGrantIntrospectRequestBody>(json!({
                "id": GRANT_ID,
                "grant_jwt": "header.payload.signature"
            }))
            .is_err(),
            "the two selectors are mutually exclusive"
        );

        assert!(
            serde_json::from_value::<SessionGrantIntrospectionProof>(json!({
                "challenge": "Zm9vYmFyZm9vYmFyZm9vYmFy"
            }))
            .is_err(),
            "proof_jwt is required"
        );
    }

    #[test]
    fn introspect_outcome_round_trips_and_stays_closed() {
        let active = json!({
            "active": true,
            "status": "active",
            "proof_required": false,
            "one_time_use_consumed": false,
            "grant": human_grant_value()
        });
        let parsed = serde_json::from_value::<SessionGrantIntrospectOutcome>(active.clone())
            .expect("active outcome parses");
        parsed.validate().expect("active outcome carries a grant");
        assert_eq!(
            parsed.status,
            SessionGrantAdminIntrospectionStatus::Active,
            "the outcome reuses the shared introspection status vocabulary"
        );
        assert_eq!(serde_json::to_value(&parsed).unwrap(), active);

        let inactive = json!({
            "active": false,
            "status": "not_found",
            "proof_required": false,
            "one_time_use_consumed": false
        });
        let parsed = serde_json::from_value::<SessionGrantIntrospectOutcome>(inactive.clone())
            .expect("inactive outcome parses");
        parsed.validate().expect("inactive outcome needs no grant");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), inactive);

        assert!(
            serde_json::from_value::<SessionGrantIntrospectOutcome>(with_unknown_member(
                active.clone()
            ))
            .is_err(),
            "an unknown member must be rejected"
        );

        let mut grant_open = active.clone();
        grant_open["grant"] = with_unknown_member(human_grant_value());
        assert!(
            serde_json::from_value::<SessionGrantIntrospectOutcome>(grant_open).is_err(),
            "the nested grant projection is closed too"
        );

        for member in [
            "active",
            "status",
            "proof_required",
            "one_time_use_consumed",
        ] {
            assert!(
                serde_json::from_value::<SessionGrantIntrospectOutcome>(without_member(
                    active.clone(),
                    member
                ))
                .is_err(),
                "{member} must be required"
            );
        }

        let mut active_without_grant = without_member(active, "grant");
        active_without_grant["status"] = json!("active");
        let parsed =
            serde_json::from_value::<SessionGrantIntrospectOutcome>(active_without_grant).unwrap();
        assert!(
            parsed.validate().is_err(),
            "an active outcome must carry grant metadata"
        );

        for member in [
            "id",
            "issuer_id",
            "account_id",
            "audience_id",
            "scopes",
            "expires_at",
            "revocation_ref",
            "session_public_key",
            "cnf_jkt",
            "credential_class",
            "holder_binding",
        ] {
            assert!(
                serde_json::from_value::<SessionGrantIntrospectGrant>(without_member(
                    human_grant_value(),
                    member
                ))
                .is_err(),
                "grant member {member} must be required"
            );
        }

        let human = serde_json::from_value::<SessionGrantIntrospectGrant>(human_grant_value())
            .expect("human grant parses");
        assert_eq!(
            human
                .human_device_authorization_selector()
                .unwrap()
                .model_generation_ref,
            7
        );
        assert_eq!(human.account_id().station_id, human.audience_id);

        let mut pairwise = human_grant_value();
        pairwise["holder_binding"] = json!({
            "kind": "minimal_metadata_pairwise",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "actor_id": { "kind": "service", "service_id": AUDIENCE_ID },
            "verification_method": "did:web:service.example#endpoint-key"
        });
        assert!(
            serde_json::from_value::<SessionGrantIntrospectGrant>(pairwise).is_err(),
            "a pairwise endpoint is not an introspectable grant holder"
        );
    }

    #[test]
    fn auth_session_logout_round_trips_and_stays_closed() {
        let full = json!({
            "grant_jwt": "header.payload.signature",
            "logout_request_digest": LOGOUT_REQUEST_DIGEST,
            "validated_at": "2026-08-08T12:00:00.000Z",
            "reason_code": "account_logout"
        });
        let parsed = serde_json::from_value::<AuthSessionLogoutRequestBody>(full.clone())
            .expect("full request parses");
        assert_eq!(
            parsed.reason_code,
            Some(AuthSessionLogoutReasonCode::AccountLogout)
        );
        assert_eq!(serde_json::to_value(&parsed).unwrap(), full);

        let minimal = json!({ "grant_jwt": "header.payload.signature" });
        let parsed = serde_json::from_value::<AuthSessionLogoutRequestBody>(minimal.clone())
            .expect("minimal request parses");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), minimal);

        assert!(
            serde_json::from_value::<AuthSessionLogoutRequestBody>(with_unknown_member(
                full.clone()
            ))
            .is_err(),
            "an unknown member must be rejected"
        );

        assert!(
            serde_json::from_value::<AuthSessionLogoutRequestBody>(without_member(
                full.clone(),
                "grant_jwt"
            ))
            .is_err(),
            "grant_jwt must be required"
        );

        let mut open_reason = full.clone();
        open_reason["reason_code"] = json!("session_expired");
        assert!(
            serde_json::from_value::<AuthSessionLogoutRequestBody>(open_reason).is_err(),
            "reason_code is a closed vocabulary"
        );

        let mut bare_digest = full;
        bare_digest["logout_request_digest"] = json!("1111111111111111");
        assert!(
            serde_json::from_value::<AuthSessionLogoutRequestBody>(bare_digest).is_err(),
            "logout_request_digest must carry its digest suite"
        );

        let outcome = json!({
            "grant_chain_terminated": true,
            "auth_session_logged_out": true
        });
        let parsed = serde_json::from_value::<AuthSessionLogoutOutcome>(outcome.clone())
            .expect("outcome parses");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), outcome);
        assert!(
            serde_json::from_value::<AuthSessionLogoutOutcome>(with_unknown_member(
                outcome.clone()
            ))
            .is_err()
        );
        for member in ["grant_chain_terminated", "auth_session_logged_out"] {
            assert!(
                serde_json::from_value::<AuthSessionLogoutOutcome>(without_member(
                    outcome.clone(),
                    member
                ))
                .is_err(),
                "{member} must be required"
            );
        }
    }
}
