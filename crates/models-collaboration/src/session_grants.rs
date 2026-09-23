//! Session-grant request DTOs used by the authentication builder, plus domain
//! values used by deployment-private grant validation and Auth-session
//! termination adapters.

use arkret_models_identity::{
    CanonicalSessionPublicJwk, SessionGrantAdminIntrospectionStatus, SessionGrantCredentialClass,
    SessionGrantDeviceBinding, SessionGrantHolderBinding,
};
pub use arkret_wire::{AcceptedDeviceIssuePossessionProof, AcceptedDeviceRefreshPossessionProof};
use arkret_wire::{
    AcceptedDevicePossessionProof, AccountId, AppletId, DeviceId, DidCoreId, DidUrl, EventId, Hash,
    NonEmptyString, RealmId, RequestId, Result, ScopeRef, SessionGrantId, StrandId, WireError,
    canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent_scope::AgentRequestedScopeDisclosure;
pub use crate::session_grant_bodies::{
    AgentSessionGrantRefreshRequest, RecoverySessionGrantRequest,
};

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

/// Closed returning-human, Agent runtime or fresh-device recovery issuance union
/// (`service-operation-dtos.schema.json#/$defs/SessionGrantRequestBody`).
/// OIDC authorization codes are consumed only by the account-handoff body.
///
/// `Recovery` is declared before `Human` because an untagged union takes the
/// first matching branch and the recovery body is the one pinned by its
/// `credential_class` const.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum SessionGrantRequestBody {
    Recovery(RecoverySessionGrantRequest),
    Human(HumanSessionGrantRequest),
    Agent(AgentSessionGrantRequest),
}

impl SessionGrantRequestBody {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Recovery(request) => request.validate(),
            Self::Human(request) => request.validate(),
            Self::Agent(request) => request.validate(),
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
pub struct AgentSessionGrantRequest {
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub requested_scope: Vec<String>,
    /// Event id of the accepted `ak.agent.key.authorize` that authorized the
    /// runtime key. The Spec pins it to the `ak:event:` form, and
    /// `SessionGrantHolderBinding::AgentRuntime` names the same id, so the two
    /// surfaces meet without a boundary reparse.
    pub agent_key_authorization_ref: EventId,
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
        if self.proof.request_canonical_digest != self.canonical_request_digest()? {
            return Err(WireError::Protocol(
                "agent session grant proof does not bind this request".into(),
            ));
        }
        Ok(())
    }

    /// The immutable request intent the runtime key signs: JCS-SHA256 of this
    /// body with the proof's own `signature` and `request_canonical_digest`
    /// omitted, so the digest never covers itself.
    pub fn canonical_request_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        let proof = value
            .get_mut("proof")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                WireError::Protocol("agent session grant request carries no proof".into())
            })?;
        proof.remove("signature");
        proof.remove("request_canonical_digest");
        Hash::new(canonical::canonical_sha256(&value)?).map_err(Into::into)
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

/// Longest validity window an initial Agent session proof may claim.
pub const AGENT_SESSION_PROOF_MAX_LIFETIME_SECONDS: i64 = 300;
/// Largest accepted clock skew ahead of the verifier for `issued_at`.
pub const AGENT_SESSION_PROOF_MAX_CLOCK_SKEW_SECONDS: i64 = 30;

impl AgentSessionGrantProof {
    pub fn validate_structure(&self) -> Result<()> {
        if !valid_agent_session_challenge(&self.challenge)
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at
                > chrono::Duration::seconds(AGENT_SESSION_PROOF_MAX_LIFETIME_SECONDS)
        {
            return Err(WireError::Protocol(
                "invalid Agent session proof challenge or time window".into(),
            ));
        }
        Ok(())
    }

    /// First validation at the verifier's clock: the structural window plus
    /// `issued_at <= now + 30s` and `now < expires_at`. There is no additional
    /// nonce; an exact completed issuer-ledger replay reuses the durable
    /// one-shot verification instead of re-running this check.
    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<()> {
        self.validate_structure()?;
        if self.issued_at
            > now + chrono::Duration::seconds(AGENT_SESSION_PROOF_MAX_CLOCK_SKEW_SECONDS)
            || now >= self.expires_at
        {
            return Err(WireError::Protocol(
                "Agent session proof is outside its validity window".into(),
            ));
        }
        Ok(())
    }

    /// RFC 8785/JCS bytes of the whole proof with `signature` omitted. Every
    /// other closed member, `proof_kind` included, stays covered; there is no
    /// Event JWS wrapper and no extra prefix.
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        let value = canonical::unsigned_value(self, &["signature"])?;
        Ok(canonical::canonical_json_bytes(&value)?)
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
    /// Event id of the accepted `ak.agent.key.authorize` that authorized the
    /// runtime key. The Spec pins it to the `ak:event:` form, and
    /// `SessionGrantHolderBinding::AgentRuntime` names the same id, so the two
    /// surfaces meet without a boundary reparse.
    pub agent_key_authorization_ref: EventId,
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
        agent_key_authorization_ref: EventId,
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

/// Closed human-versus-Agent SessionGrant rotation union
/// (`service-operation-dtos.schema.json#/$defs/SessionGrantRefreshRequestBody`,
/// `key-management.md` §6.5). Neither branch accepts a client-generated
/// challenge or a generic `proof_kind`: the human branch presents an
/// accepted-device possession proof, the Agent branch its runtime-key refresh
/// proof. A minimal-metadata pairwise holder satisfies neither and therefore
/// cannot be refreshed at all.
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

// --- Deployment-private grant validation and Auth-session termination -----
//
// These domain values deliberately carry no Arkret operation identity. The
// issuer/resource-server and Account-Authority/Auth-Server boundaries are
// deployment-private adapters. The validation status vocabulary is the closed
// enum already carried by
// `arkret_models_identity::SessionGrantAdminIntrospectionStatus`, which is
// member-for-member the schema's `status` enum, so it is reused here.

/// Claim-set kind of the JWS carried in
/// [`SessionGrantHolderProof::proof_jwt`].
pub const SESSION_GRANT_HOLDER_PROOF_CLAIMS_KIND: &str = "ak.session_grant.introspection_proof.v1";

/// Optional server-to-server holder confirmation signed by the session key
/// bound into the grant. Stations validating `/_arkret/self/*` grant+DPoP
/// requests do not carry this proof; they verify the request DPoP locally
/// against the returned `cnf_jkt`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantHolderProof {
    pub challenge: String,
    pub proof_jwt: String,
}

/// Claims of the `ak.session_grant.introspection_proof.v1` JWS presented in
/// [`SessionGrantHolderProof::proof_jwt`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantHolderProofClaims {
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
#[serde(try_from = "SessionGrantValidationMetadataWire")]
pub struct SessionGrantValidationMetadata {
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
struct SessionGrantValidationMetadataWire {
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

impl SessionGrantValidationMetadata {
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
        }
        Ok(())
    }
}

impl TryFrom<SessionGrantValidationMetadataWire> for SessionGrantValidationMetadata {
    type Error = String;

    fn try_from(
        wire: SessionGrantValidationMetadataWire,
    ) -> std::result::Result<Self, Self::Error> {
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

/// Deployment-private grant selector. Exactly one of `id` / `grant_jwt`
/// identifies the grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionGrantValidationInput {
    ById(SessionGrantValidationById),
    ByJwt(SessionGrantValidationByJwt),
}

/// `id` selector branch of [`SessionGrantValidationInput`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantValidationById {
    pub id: SessionGrantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SessionGrantHolderProof>,
}

/// `grant_jwt` selector branch of [`SessionGrantValidationInput`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantValidationByJwt {
    pub grant_jwt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SessionGrantHolderProof>,
}

/// Read-only result returned by a deployment-private grant validator.
/// Validation never consumes the grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantValidationResult {
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
    pub grant: Option<SessionGrantValidationMetadata>,
}

impl SessionGrantValidationResult {
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

/// Reason a deployment-private adapter terminates an Auth-side session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthSessionTerminationReason {
    AccountLogout,
}

/// Deployment-private input for terminating the Auth-side session that owns an
/// `ak.session.grant` rotation chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSessionTerminationInput {
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
    pub reason_code: Option<AuthSessionTerminationReason>,
}

/// Deployment-private Auth-session termination result.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSessionTerminationResult {
    /// Whether the grant rotation chain is now unable to refresh, including
    /// the already-terminated idempotent case.
    pub grant_chain_terminated: bool,
    /// Whether the underlying Auth-side browser/auth session is now logged
    /// out, including the already-logged-out idempotent case.
    pub auth_session_logged_out: bool,
}

#[cfg(test)]
mod session_grant_private_adapter_tests {
    use serde_json::json;

    use super::*;

    const GRANT_ID: &str = "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW";
    const DEVICE_ID: &str = "ak:device:019a6aa0-0000-7000-8000-000000000000";
    const AUDIENCE_ID: &str = "ak:did_core:web:service.example";
    const CANONICAL_JWK: &str =
        r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
    const LOGOUT_REQUEST_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    const DEVICE_AUTHORIZATION_EVENT_ID: &str =
        "ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g";

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
            "scopes": ["ak.self.committed_event.read.scan.v1"],
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
                "authorization_event_id": DEVICE_AUTHORIZATION_EVENT_ID,
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
        let parsed = serde_json::from_value::<SessionGrantValidationInput>(by_id.clone())
            .expect("id selector parses");
        assert!(matches!(
            parsed,
            SessionGrantValidationInput::ById(ref body)
                if body.id.as_str() == GRANT_ID
        ));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), by_id);

        let by_jwt = json!({ "grant_jwt": "header.payload.signature" });
        let parsed = serde_json::from_value::<SessionGrantValidationInput>(by_jwt.clone())
            .expect("grant_jwt selector parses");
        assert!(matches!(parsed, SessionGrantValidationInput::ByJwt(_)));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), by_jwt);

        for open in [with_unknown_member(by_id), with_unknown_member(by_jwt)] {
            assert!(
                serde_json::from_value::<SessionGrantValidationInput>(open).is_err(),
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
        assert!(serde_json::from_value::<SessionGrantValidationInput>(proof_open).is_err());

        for missing_selector in [json!({}), json!({ "audience_id": AUDIENCE_ID })] {
            assert!(
                serde_json::from_value::<SessionGrantValidationInput>(missing_selector).is_err(),
                "a request without a selector must be rejected"
            );
        }

        assert!(
            serde_json::from_value::<SessionGrantValidationInput>(json!({
                "id": GRANT_ID,
                "grant_jwt": "header.payload.signature"
            }))
            .is_err(),
            "the two selectors are mutually exclusive"
        );

        assert!(
            serde_json::from_value::<SessionGrantHolderProof>(json!({
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
        let parsed = serde_json::from_value::<SessionGrantValidationResult>(active.clone())
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
        let parsed = serde_json::from_value::<SessionGrantValidationResult>(inactive.clone())
            .expect("inactive outcome parses");
        parsed.validate().expect("inactive outcome needs no grant");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), inactive);

        assert!(
            serde_json::from_value::<SessionGrantValidationResult>(with_unknown_member(
                active.clone()
            ))
            .is_err(),
            "an unknown member must be rejected"
        );

        let mut grant_open = active.clone();
        grant_open["grant"] = with_unknown_member(human_grant_value());
        assert!(
            serde_json::from_value::<SessionGrantValidationResult>(grant_open).is_err(),
            "the nested grant projection is closed too"
        );

        for member in [
            "active",
            "status",
            "proof_required",
            "one_time_use_consumed",
        ] {
            assert!(
                serde_json::from_value::<SessionGrantValidationResult>(without_member(
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
            serde_json::from_value::<SessionGrantValidationResult>(active_without_grant).unwrap();
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
                serde_json::from_value::<SessionGrantValidationMetadata>(without_member(
                    human_grant_value(),
                    member
                ))
                .is_err(),
                "grant member {member} must be required"
            );
        }

        let human = serde_json::from_value::<SessionGrantValidationMetadata>(human_grant_value())
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
            serde_json::from_value::<SessionGrantValidationMetadata>(pairwise).is_err(),
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
        let parsed = serde_json::from_value::<AuthSessionTerminationInput>(full.clone())
            .expect("full request parses");
        assert_eq!(
            parsed.reason_code,
            Some(AuthSessionTerminationReason::AccountLogout)
        );
        assert_eq!(serde_json::to_value(&parsed).unwrap(), full);

        let minimal = json!({ "grant_jwt": "header.payload.signature" });
        let parsed = serde_json::from_value::<AuthSessionTerminationInput>(minimal.clone())
            .expect("minimal request parses");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), minimal);

        assert!(
            serde_json::from_value::<AuthSessionTerminationInput>(with_unknown_member(
                full.clone()
            ))
            .is_err(),
            "an unknown member must be rejected"
        );

        assert!(
            serde_json::from_value::<AuthSessionTerminationInput>(without_member(
                full.clone(),
                "grant_jwt"
            ))
            .is_err(),
            "grant_jwt must be required"
        );

        let mut open_reason = full.clone();
        open_reason["reason_code"] = json!("session_expired");
        assert!(
            serde_json::from_value::<AuthSessionTerminationInput>(open_reason).is_err(),
            "reason_code is a closed vocabulary"
        );

        let mut bare_digest = full;
        bare_digest["logout_request_digest"] = json!("1111111111111111");
        assert!(
            serde_json::from_value::<AuthSessionTerminationInput>(bare_digest).is_err(),
            "logout_request_digest must carry its digest suite"
        );

        let outcome = json!({
            "grant_chain_terminated": true,
            "auth_session_logged_out": true
        });
        let parsed = serde_json::from_value::<AuthSessionTerminationResult>(outcome.clone())
            .expect("outcome parses");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), outcome);
        assert!(
            serde_json::from_value::<AuthSessionTerminationResult>(with_unknown_member(
                outcome.clone()
            ))
            .is_err()
        );
        for member in ["grant_chain_terminated", "auth_session_logged_out"] {
            assert!(
                serde_json::from_value::<AuthSessionTerminationResult>(without_member(
                    outcome.clone(),
                    member
                ))
                .is_err(),
                "{member} must be required"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        AcceptedDeviceIssuePossessionPurpose, AcceptedDevicePossessionProofContext, Base64UrlString,
    };
    use serde_json::json;

    use super::*;

    const DEVICE: &str = "ak:device:01964137-0000-7000-8000-000000000001";
    const PRINCIPAL: &str = "ak:did_core:web:alice.example";
    const AUDIENCE: &str = "ak:did_core:web:station.example";
    const REQUEST: &str = "ak:request:01970000-0000-7000-8000-000000000021";
    const AUTHORIZATION: &str = "ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g";
    const VERIFICATION_METHOD: &str = "did:web:agent.example#runtime-1";

    fn unsigned_agent_request() -> UnsignedAgentSessionGrantRequest {
        UnsignedAgentSessionGrantRequest::new(
            DidCoreId::new(PRINCIPAL).unwrap(),
            DeviceId::new(DEVICE).unwrap(),
            vec!["ak.self.committed_event.read.scan.v1".to_owned()],
            EventId::new(AUTHORIZATION).unwrap(),
            SessionGrantAgentScopeRequest {
                realm_ids: Vec::new(),
                strand_ids: Vec::new(),
                track_names: Vec::new(),
            },
            None,
            SessionGrantDpopBindingProof {
                proof_jwt: "header.body.signature".to_owned(),
            },
            None,
            UnsignedAgentSessionGrantProof {
                challenge: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                audience_id: DidCoreId::new(AUDIENCE).unwrap(),
                issued_at: "2026-08-15T00:00:00Z".parse().unwrap(),
                expires_at: "2026-08-15T00:04:00Z".parse().unwrap(),
                verification_method: DidUrl::new(VERIFICATION_METHOD).unwrap(),
            },
        )
        .unwrap()
    }

    fn signed_agent_request() -> AgentSessionGrantRequest {
        let unsigned = unsigned_agent_request();
        match unsigned
            .attach_signature(NonEmptyString::new("A".repeat(86)).unwrap())
            .unwrap()
        {
            SessionGrantRequestBody::Agent(request) => request,
            other => panic!("attach_signature must produce the Agent branch, got {other:?}"),
        }
    }

    /// The signed body and the pre-signature builder must agree byte for byte:
    /// The Spec pins `agent_key_authorization_ref` to the `ak:event:` form, and
    /// `SessionGrantHolderBinding::AgentRuntime` names that same accepted
    /// `ak.agent.key.authorize` Event. Typing it here is what lets an issuer
    /// carry the ref across without reparsing a free-form string, and a value
    /// outside that form is not representable at all.
    #[test]
    fn the_agent_key_authorization_ref_is_an_event_id() {
        let request = unsigned_agent_request()
            .attach_signature(NonEmptyString::new("c2ln".to_owned()).unwrap())
            .unwrap();
        let SessionGrantRequestBody::Agent(request) = request else {
            panic!("the Agent branch is the one that was built");
        };
        request.validate().unwrap();

        let mut encoded = serde_json::to_value(&request).unwrap();
        assert_eq!(encoded["agent_key_authorization_ref"], json!(AUTHORIZATION));
        encoded
            .as_object_mut()
            .unwrap()
            .insert("agent_key_authorization_ref".to_owned(), json!("not-an-id"));
        assert!(serde_json::from_value::<AgentSessionGrantRequest>(encoded).is_err());
    }

    /// the verifier recomputes this digest from the request it received.
    #[test]
    fn agent_request_digest_matches_the_pre_signature_transcript() {
        let unsigned = unsigned_agent_request();
        let expected = unsigned.canonical_request_digest().unwrap();
        let signed = signed_agent_request();
        assert_eq!(signed.proof.request_canonical_digest, expected);
        assert_eq!(signed.canonical_request_digest().unwrap(), expected);
        signed.validate().unwrap();
    }

    #[test]
    fn agent_request_rejects_a_proof_bound_to_another_request() {
        let mut request = signed_agent_request();
        request.requested_scope = vec!["ak.self.events.command.submit.v1".to_owned()];
        assert!(request.validate().is_err());
    }

    /// `proof_kind` and `signature` are the two members the transcript treats
    /// asymmetrically: the kind is covered, the signature is not.
    #[test]
    fn agent_proof_signing_bytes_cover_every_member_but_the_signature() {
        let proof = signed_agent_request().proof;
        let bytes = proof.canonical_signing_bytes().unwrap();
        let transcript = String::from_utf8(bytes.clone()).unwrap();
        assert!(transcript.contains("\"proof_kind\":\"agent_key_proof\""));
        assert!(!transcript.contains("\"signature\""));
        let mut other = proof.clone();
        other.signature = "B".repeat(86);
        assert_eq!(other.canonical_signing_bytes().unwrap(), bytes);
    }

    #[test]
    fn agent_proof_window_is_bounded_at_both_ends() {
        let proof = signed_agent_request().proof;
        proof
            .validate_at("2026-08-15T00:02:00Z".parse().unwrap())
            .unwrap();
        assert!(
            proof
                .validate_at("2026-08-15T00:04:00Z".parse().unwrap())
                .is_err()
        );
        assert!(
            proof
                .validate_at("2026-08-14T23:59:00Z".parse().unwrap())
                .is_err()
        );
        proof
            .validate_at("2026-08-14T23:59:45Z".parse().unwrap())
            .unwrap();
    }

    fn recovery_value() -> Value {
        json!({
            "credential_class": "recovery_session",
            "request_id": REQUEST,
            "principal_id": PRINCIPAL,
            "device_id": DEVICE,
            "audience_id": AUDIENCE
        })
    }

    fn human_issue_value() -> Value {
        let mut value = recovery_value();
        let object = value.as_object_mut().unwrap();
        object.remove("credential_class");
        object.insert(
            "accepted_device_possession_proof".to_owned(),
            json!({ "unused": true }),
        );
        value
    }

    /// The untagged union must not let the recovery body fall through into a
    /// returning-human issuance, which carries different authority.
    #[test]
    fn issuance_union_separates_the_recovery_branch() {
        let body: SessionGrantRequestBody = serde_json::from_value(recovery_value()).unwrap();
        assert!(matches!(body, SessionGrantRequestBody::Recovery(_)));
        body.validate().unwrap();
        assert_eq!(serde_json::to_value(&body).unwrap(), recovery_value());
        // A body with the human proof member is not a recovery request, and a
        // malformed proof leaves no branch to fall into.
        assert!(serde_json::from_value::<SessionGrantRequestBody>(human_issue_value()).is_err());
    }

    #[test]
    fn issuance_union_accepts_only_the_three_registered_branches() {
        let request_id = RequestId::new(REQUEST).unwrap();
        let principal_id = DidCoreId::new(PRINCIPAL).unwrap();
        let device_id = DeviceId::new(DEVICE).unwrap();
        let audience_id = DidCoreId::new(AUDIENCE).unwrap();
        let holder_jkt = "A".repeat(43);
        let proof = AcceptedDeviceIssuePossessionProof {
            context: AcceptedDevicePossessionProofContext::V1,
            purpose: AcceptedDeviceIssuePossessionPurpose::SessionGrantIssue,
            request_id: request_id.clone(),
            account_subject: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            account_handoff_grant_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            account_id: AccountId::new(principal_id.clone(), audience_id.clone()),
            device_id: device_id.clone(),
            audience_id: audience_id.clone(),
            holder_jkt: holder_jkt.clone(),
            session_intent_digest: human_session_grant_intent_digest(
                &request_id,
                &principal_id,
                &device_id,
                &audience_id,
                &holder_jkt,
            )
            .unwrap(),
            issued_at: "2026-08-15T00:00:00Z".parse().unwrap(),
            expires_at: "2026-08-15T00:04:00Z".parse().unwrap(),
            verification_method: DidUrl::new("did:web:alice.example#device-1").unwrap(),
            signature: Base64UrlString::new(arkret_wire::base64url::base64url_encode([7u8; 64]))
                .unwrap(),
        };
        let human = SessionGrantRequestBody::Human(HumanSessionGrantRequest {
            request_id,
            principal_id,
            device_id,
            audience_id,
            accepted_device_possession_proof: proof,
        });
        let mut old_fourth_branch = serde_json::to_value(&human).unwrap();
        for body in [
            human,
            SessionGrantRequestBody::Agent(signed_agent_request()),
            serde_json::from_value(recovery_value()).unwrap(),
        ] {
            body.validate().unwrap();
            let parsed: SessionGrantRequestBody =
                serde_json::from_value(serde_json::to_value(&body).unwrap()).unwrap();
            parsed.validate().unwrap();
        }

        old_fourth_branch["pairwise_endpoint_possession_proof"] = json!({
            "context": "ak.session_grant_pairwise_endpoint_possession_proof.v1"
        });
        assert!(serde_json::from_value::<SessionGrantRequestBody>(old_fourth_branch).is_err());
    }

    #[test]
    fn refresh_union_separates_human_and_agent_branches() {
        let agent = json!({
            "grant_jwt": "header.body.signature",
            "device_id": DEVICE,
            "agent_session_refresh_proof": {
                "context": "ak.agent_session_refresh_proof.v1",
                "request_canonical_digest": format!("sha256:{}", "1".repeat(64)),
                "audience_id": AUDIENCE,
                "issued_at": "2026-08-15T00:00:00.000Z",
                "expires_at": "2026-08-15T00:04:00.000Z",
                "verification_method": VERIFICATION_METHOD,
                "signature": "A".repeat(86)
            }
        });
        let body: SessionGrantRefreshRequestBody = serde_json::from_value(agent.clone()).unwrap();
        assert!(matches!(body, SessionGrantRefreshRequestBody::Agent(_)));
        body.validate().unwrap();
        assert_eq!(serde_json::to_value(&body).unwrap(), agent);

        // The human branch carries an accepted-device proof instead, so the
        // two branches never accept each other's body.
        let mut crossed = agent;
        let object = crossed.as_object_mut().unwrap();
        object.remove("agent_session_refresh_proof");
        object.insert(
            "accepted_device_possession_proof".to_owned(),
            json!({ "unused": true }),
        );
        assert!(serde_json::from_value::<SessionGrantRefreshRequestBody>(crossed).is_err());
    }
}
