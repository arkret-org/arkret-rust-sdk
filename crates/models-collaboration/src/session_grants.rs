//! Session-grant request DTOs used by the authentication builder, plus domain
//! values used by deployment-private grant validation and Auth-session
//! termination adapters.

pub use arkret_models_identity::SessionGrantResponseBody;
use arkret_models_identity::{
    CanonicalSessionPublicJwk, SessionGrantAdminIntrospectionStatus, SessionGrantCredentialClass,
    SessionGrantDeviceBinding, SessionGrantHolderBinding, SessionGrantMetadata,
};
pub use arkret_wire::{AcceptedDeviceIssuePossessionProof, AcceptedDeviceRefreshPossessionProof};
use arkret_wire::{
    AcceptedDevicePossessionProof, AccountId, DeviceId, DidCoreId, DidUrl, EventId, Hash,
    NonEmptyString, RealmId, RequestId, Result, SessionGrantId, SessionGrantRef,
    SessionGrantSecret, StrandId, WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent_scope::AgentRequestedScopeDisclosure;
pub use crate::session_grant_bodies::{
    AgentSessionGrantRefreshRequestBody, RecoverySessionGrantRequestBody,
};

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
    Recovery(RecoverySessionGrantRequestBody),
    Human(HumanSessionGrantRequestBody),
    Agent(AgentSessionGrantRequestBody),
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

impl HumanSessionGrantRequestBody {
    pub fn validate(&self) -> Result<()> {
        let proof = &self.accepted_device_possession_proof;
        proof.validate_purpose(
            arkret_wire::AcceptedDeviceIssuePossessionPurpose::SessionGrantIssue,
        )?;
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

impl AgentSessionGrantRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.proof.validate_structure()?;
        validate_agent_session_approval_evidence_refs(self.approval_evidence_refs.as_deref())?;
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

fn validate_agent_session_approval_evidence_refs(refs: Option<&[EventId]>) -> Result<()> {
    if refs.is_some_and(|refs| {
        refs.is_empty()
            || refs.len() > 32
            || refs
                .windows(2)
                .any(|pair| pair[0].as_str() >= pair[1].as_str())
    }) {
        return Err(WireError::Protocol(
            "approval_evidence_refs must contain 1..32 unique EventIds in canonical order".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantDpopBindingProof {
    pub proof_jwt: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedAgentSessionGrantScope {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strand_ids: Vec<StrandId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub track_names: Vec<NonEmptyString>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentSessionGrantProofKind {
    #[serde(rename = "agent_key_proof")]
    AgentKeyProof,
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
pub struct AgentSessionGrantProofInput {
    pub challenge: String,
    pub audience_id: DidCoreId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
}

#[derive(Clone, Debug)]
pub struct AgentSessionGrantSigningInput {
    pub principal_id: DidCoreId,
    pub requested_scope: Vec<String>,
    /// Event id of the accepted `ak.agent.key.authorize` that authorized the
    /// runtime key. The Spec pins it to the `ak:event:` form, and
    /// `SessionGrantHolderBinding::AgentRuntime` names the same id, so the two
    /// surfaces meet without a boundary reparse.
    pub agent_key_authorization_ref: EventId,
    pub agent_scope_request: RequestedAgentSessionGrantScope,
    pub approval_evidence_refs: Option<Vec<EventId>>,
    pub requested_scope_disclosure: Option<AgentRequestedScopeDisclosure>,
    pub dpop_binding_proof: SessionGrantDpopBindingProof,
    pub proof: AgentSessionGrantProofInput,
}

impl AgentSessionGrantSigningInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal_id: DidCoreId,
        requested_scope: Vec<String>,
        agent_key_authorization_ref: EventId,
        agent_scope_request: RequestedAgentSessionGrantScope,
        requested_scope_disclosure: Option<AgentRequestedScopeDisclosure>,
        dpop_binding_proof: SessionGrantDpopBindingProof,
        proof: AgentSessionGrantProofInput,
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
            requested_scope,
            agent_key_authorization_ref,
            agent_scope_request,
            approval_evidence_refs: None,
            requested_scope_disclosure,
            dpop_binding_proof,
            proof,
        })
    }

    pub fn canonical_request_digest(&self) -> Result<Hash> {
        validate_agent_session_approval_evidence_refs(self.approval_evidence_refs.as_deref())?;
        Hash::new(canonical::canonical_sha256(&self.unsigned_request_value())?).map_err(Into::into)
    }

    pub fn with_approval_evidence_refs(mut self, refs: Vec<EventId>) -> Result<Self> {
        validate_agent_session_approval_evidence_refs(Some(&refs))?;
        self.approval_evidence_refs = Some(refs);
        Ok(self)
    }

    pub fn attach_signature(self, signature: NonEmptyString) -> Result<SessionGrantRequestBody> {
        let request_canonical_digest = self.canonical_request_digest()?;
        Ok(SessionGrantRequestBody::Agent(
            AgentSessionGrantRequestBody {
                principal_id: self.principal_id,
                requested_scope: self.requested_scope,
                agent_key_authorization_ref: self.agent_key_authorization_ref,
                agent_scope_request: self.agent_scope_request,
                approval_evidence_refs: self.approval_evidence_refs,
                requested_scope_disclosure: self.requested_scope_disclosure,
                dpop_binding_proof: self.dpop_binding_proof,
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
            },
        ))
    }

    fn unsigned_request_value(&self) -> Value {
        let mut value = serde_json::json!({
            "principal_id": &self.principal_id,
            "requested_scope": &self.requested_scope,
            "agent_key_authorization_ref": &self.agent_key_authorization_ref,
            "agent_scope_request": &self.agent_scope_request,
            "approval_evidence_refs": &self.approval_evidence_refs,
            "requested_scope_disclosure": &self.requested_scope_disclosure,
            "dpop_binding_proof": &self.dpop_binding_proof,
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
        if self.approval_evidence_refs.is_none() {
            object.remove("approval_evidence_refs");
        }
        if object
            .get("requested_scope_disclosure")
            .is_some_and(Value::is_null)
        {
            object.remove("requested_scope_disclosure");
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
    Human(HumanSessionGrantRefreshRequestBody),
    Agent(AgentSessionGrantRefreshRequestBody),
}

impl SessionGrantRefreshRequestBody {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Human(request) => request.validate(),
            Self::Agent(request) => request.validate(),
        }
    }
}

impl HumanSessionGrantRefreshRequestBody {
    pub fn validate(&self) -> Result<()> {
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
        let expected = crate::session_grant_bodies::session_grant_refresh_request_digest(
            &self.session_grant,
            &proof.predecessor_session_grant_ref,
            &proof.account_id.principal_id,
            &self.device_id,
            &proof.audience_id,
            &proof.holder_jkt,
        )?;
        if proof.session_intent_digest != expected {
            return Err(WireError::Protocol(
                "accepted-device refresh proof has the wrong exact credential intent".into(),
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

pub const SESSION_GRANT_HOLDER_PROOF_CONTEXT: &str = "ak.session_grant.introspection_proof.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionGrantHolderProofContext {
    #[serde(rename = "ak.session_grant.introspection_proof.v1")]
    V1,
}

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

/// Closed optional S2S proof payload. Signature verification remains with the issuer adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantHolderProofClaims {
    pub context: SessionGrantHolderProofContext,
    pub session_grant_ref: SessionGrantRef,
    pub session_grant_digest: Hash,
    pub audience_id: DidCoreId,
    pub challenge: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl SessionGrantHolderProofClaims {
    pub fn validate_binding(
        &self,
        grant_ref: &SessionGrantRef,
        secret: &SessionGrantSecret,
        audience: &DidCoreId,
        challenge: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let digest = Hash::new(canonical::sha256_digest(secret.as_str().as_bytes()))?;
        if &self.session_grant_ref != grant_ref
            || self.session_grant_digest != digest
            || &self.audience_id != audience
            || self.challenge != challenge
            || challenge.is_empty()
            || self.expires_at <= self.issued_at
            || now < self.issued_at
            || now >= self.expires_at
        {
            return Err(WireError::Protocol(
                "S2S holder proof does not bind the exact credential/ref/request".into(),
            ));
        }
        Ok(())
    }
}

/// Non-secret exact issuer result. The immutable fields have one identity-domain owner.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "SessionGrantValidationMetadataWire")]
pub struct SessionGrantValidationMetadata {
    #[serde(flatten)]
    pub metadata: SessionGrantMetadata,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_ref: String,
}

impl std::ops::Deref for SessionGrantValidationMetadata {
    type Target = SessionGrantMetadata;

    fn deref(&self) -> &Self::Target {
        &self.metadata
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionGrantValidationMetadataWire {
    id: SessionGrantId,
    issuer_id: DidCoreId,
    account_id: AccountId,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    device_id: Option<DeviceId>,
    audience_id: DidCoreId,
    scopes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: DateTime<Utc>,
    session_id: String,
    session_public_key: CanonicalSessionPublicJwk,
    cnf_jkt: String,
    credential_class: SessionGrantCredentialClass,
    holder_binding: SessionGrantHolderBinding,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    device_binding: Option<SessionGrantDeviceBinding>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    proof_kind: Option<arkret_models_identity::SessionGrantProofKind>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    scope_details: Option<arkret_models_identity::SessionGrantScope>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    revoked_at: Option<DateTime<Utc>>,
    revocation_ref: String,
}

impl SessionGrantValidationMetadata {
    pub fn account_id(&self) -> &AccountId {
        &self.metadata.account_id
    }

    pub fn human_device_authorization_selector(&self) -> Result<&SessionGrantDeviceBinding> {
        self.metadata.human_device_authorization_selector()
    }

    pub fn validate(&self) -> Result<()> {
        self.metadata.validate()
    }
}

impl TryFrom<SessionGrantValidationMetadataWire> for SessionGrantValidationMetadata {
    type Error = WireError;

    fn try_from(wire: SessionGrantValidationMetadataWire) -> Result<Self> {
        let metadata = SessionGrantMetadata {
            id: wire.id,
            issuer_id: wire.issuer_id,
            account_id: wire.account_id,
            device_id: wire.device_id,
            audience_id: wire.audience_id,
            scopes: wire.scopes,
            not_before: wire.not_before,
            expires_at: wire.expires_at,
            session_id: wire.session_id,
            session_public_key: wire.session_public_key,
            cnf_jkt: wire.cnf_jkt,
            credential_class: wire.credential_class,
            holder_binding: wire.holder_binding,
            device_binding: wire.device_binding,
            proof_kind: wire.proof_kind,
            scope_details: wire.scope_details,
        };
        metadata.validate()?;
        Ok(Self {
            metadata,
            revoked_at: wire.revoked_at,
            revocation_ref: wire.revocation_ref,
        })
    }
}

/// Issuer-local management lookup and exact-secret authorization remain distinct branches.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionGrantValidationInput {
    ById(SessionGrantValidationById),
    BySecret(SessionGrantValidationBySecret),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantValidationById {
    pub id: SessionGrantId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub audience_id: Option<DidCoreId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub proof: Option<SessionGrantHolderProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantValidationBySecret {
    pub session_grant: SessionGrantSecret,
    pub audience_id: DidCoreId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub proof: Option<SessionGrantHolderProof>,
}

/// Read-only deployment-private result, authenticated and request-bound by its transport adapter.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantValidationResponseBody {
    pub active: bool,
    pub status: SessionGrantAdminIntrospectionStatus,
    pub proof_required: bool,
    pub one_time_use_consumed: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub grant: Option<SessionGrantValidationMetadata>,
}

impl SessionGrantValidationResponseBody {
    pub fn validate(&self) -> Result<()> {
        if self.one_time_use_consumed
            || self.active != (self.status == SessionGrantAdminIntrospectionStatus::Active)
            || (self.active
                && (self.proof_required
                    || self
                        .grant
                        .as_ref()
                        .is_none_or(|grant| grant.revoked_at.is_some())))
        {
            return Err(WireError::Protocol(
                "inconsistent read-only SessionGrant issuer status".into(),
            ));
        }
        if let Some(grant) = &self.grant {
            grant.validate()?;
        }
        Ok(())
    }
}

/// Local request/result association. It adds no issuer authority, cache freshness or current
/// permission.
#[derive(Debug)]
pub struct SessionGrantValidationBinding {
    session_grant: SessionGrantSecret,
    issuer_id: DidCoreId,
    audience_id: DidCoreId,
    response: SessionGrantValidationResponseBody,
}

impl SessionGrantValidationBinding {
    /// Called by the transport adapter immediately after authenticating and matching the issuer
    /// response. Parsing JSON or constructing a Metadata value alone does not satisfy that
    /// prerequisite.
    pub fn from_authenticated_response(
        request: &SessionGrantValidationInput,
        authenticated_issuer: &DidCoreId,
        response: SessionGrantValidationResponseBody,
    ) -> Result<Self> {
        response.validate()?;
        let SessionGrantValidationInput::BySecret(request) = request else {
            return Err(WireError::Protocol(
                "management ID lookup cannot authorize an exact credential".into(),
            ));
        };
        if response.grant.as_ref().is_some_and(|grant| {
            &grant.metadata.issuer_id != authenticated_issuer
                || grant.metadata.audience_id != request.audience_id
        }) {
            return Err(WireError::Protocol(
                "issuer response belongs to another channel or audience".into(),
            ));
        }
        Ok(Self {
            session_grant: request.session_grant.clone(),
            issuer_id: authenticated_issuer.clone(),
            audience_id: request.audience_id.clone(),
            response,
        })
    }

    pub fn response(&self) -> &SessionGrantValidationResponseBody {
        &self.response
    }

    /// Reuse within the same request only after the host checks current authority and permitted
    /// freshness.
    pub fn validate_request_binding(
        &self,
        presented_secret: &SessionGrantSecret,
        expected_issuer: &DidCoreId,
        expected_account: &AccountId,
        expected_audience: &DidCoreId,
        now: DateTime<Utc>,
    ) -> Result<&SessionGrantMetadata> {
        self.response.validate()?;
        if &self.session_grant != presented_secret
            || &self.issuer_id != expected_issuer
            || &self.audience_id != expected_audience
        {
            return Err(WireError::Protocol(
                "exact issuer result is bound to another credential or request context".into(),
            ));
        }
        if !self.response.active {
            return Err(WireError::Protocol(
                "issuer exact credential result is inactive".into(),
            ));
        }
        let grant = &self
            .response
            .grant
            .as_ref()
            .expect("active issuer result has metadata")
            .metadata;
        let expected_ref = SessionGrantRef::new(expected_issuer.clone(), grant.id.clone());
        grant.validate_request_binding(&expected_ref, expected_account, expected_audience, now)?;
        Ok(grant)
    }
}

/// Reason a deployment-private adapter terminates an Auth-side session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationSessionTerminationReason {
    AccountLogout,
}

/// Deployment-private input for terminating the Auth-side session that owns an
/// `ak.session.grant` rotation chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationSessionTerminationInput {
    /// Session grant used to locate the Auth-side session and its rotation
    /// chain.
    pub session_grant: SessionGrantSecret,
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
    pub reason_code: Option<AuthenticationSessionTerminationReason>,
}

/// Deployment-private Auth-session termination result.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationSessionTerminationResponseBody {
    /// Whether the grant rotation chain is now unable to refresh, including
    /// the already-terminated idempotent case.
    pub grant_chain_terminated: bool,
    /// Whether the underlying Auth-side browser/auth session is now logged
    /// out, including the already-logged-out idempotent case.
    pub authentication_session_logged_out: bool,
}

#[cfg(test)]
mod session_grant_private_adapter_tests {
    use serde_json::json;

    use super::*;

    fn vector(name: &str) -> Value {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/session-grant-issuance-fixture.json",
        )
        .unwrap();
        fixture["accepted_vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == name)
            .unwrap()
            .clone()
    }

    fn human_grant_value() -> Value {
        let mut value = vector("issuer_a_standard")["metadata"].clone();
        value["revocation_ref"] = json!("issuer-ledger:1");
        value
    }

    fn request_value() -> Value {
        let row = vector("issuer_a_standard");
        json!({"session_grant": row["session_grant"], "audience_id": row["metadata"]["audience_id"]})
    }

    fn outcome() -> SessionGrantValidationResponseBody {
        SessionGrantValidationResponseBody {
            active: true,
            status: SessionGrantAdminIntrospectionStatus::Active,
            proof_required: false,
            one_time_use_consumed: false,
            grant: Some(serde_json::from_value(human_grant_value()).unwrap()),
        }
    }

    #[test]
    fn introspection_keeps_exact_secret_and_management_xor_closed() {
        let exact = request_value();
        let parsed: SessionGrantValidationInput = serde_json::from_value(exact.clone()).unwrap();
        assert!(matches!(parsed, SessionGrantValidationInput::BySecret(_)));
        assert_eq!(serde_json::to_value(parsed).unwrap(), exact);
        let id = human_grant_value()["id"].clone();
        assert!(matches!(
            serde_json::from_value::<SessionGrantValidationInput>(json!({"id":id})).unwrap(),
            SessionGrantValidationInput::ById(_)
        ));
        for invalid in [
            json!({}),
            json!({"session_grant":exact["session_grant"]}),
            json!({"id":id,"session_grant":exact["session_grant"],"audience_id":exact["audience_id"]}),
            json!({"grant_jwt":exact["session_grant"],"audience_id":exact["audience_id"]}),
        ] {
            assert!(serde_json::from_value::<SessionGrantValidationInput>(invalid).is_err());
        }
    }

    #[test]
    fn metadata_roundtrip_uses_one_strict_identity_type() {
        let value = human_grant_value();
        let parsed: SessionGrantValidationMetadata = serde_json::from_value(value.clone()).unwrap();
        parsed.human_device_authorization_selector().unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), value);
        for (field, replacement) in [
            ("unknown", json!(true)),
            ("cnf_jkt", json!("A".repeat(43))),
            ("device_binding", Value::Null),
            ("revoked_at", Value::Null),
        ] {
            let mut invalid = value.clone();
            invalid[field] = replacement;
            assert!(serde_json::from_value::<SessionGrantValidationMetadata>(invalid).is_err());
        }
    }

    #[test]
    fn active_result_requires_metadata_and_consistent_current_status() {
        outcome().validate().unwrap();
        let mut missing = outcome();
        missing.grant = None;
        assert!(missing.validate().is_err());
        let mut revoked = outcome();
        revoked.status = SessionGrantAdminIntrospectionStatus::Revoked;
        assert!(revoked.validate().is_err());
        let mut consumed = outcome();
        consumed.one_time_use_consumed = true;
        assert!(consumed.validate().is_err());
        let mut proof = outcome();
        proof.proof_required = true;
        assert!(proof.validate().is_err());
        let mut revoked = outcome();
        let revoked_at = revoked.grant.as_ref().unwrap().metadata.not_before;
        revoked.grant.as_mut().unwrap().revoked_at = Some(revoked_at);
        assert!(revoked.validate().is_err());
    }

    #[test]
    fn issuer_binding_and_management_results_cannot_authorize_another_secret() {
        let response = outcome();
        let grant = response.grant.as_ref().unwrap().metadata.clone();
        let request: SessionGrantValidationInput = serde_json::from_value(request_value()).unwrap();
        let secret: SessionGrantSecret =
            serde_json::from_value(request_value()["session_grant"].clone()).unwrap();
        let result = SessionGrantValidationBinding::from_authenticated_response(
            &request,
            &grant.issuer_id,
            response,
        )
        .unwrap();
        result
            .validate_request_binding(
                &secret,
                &grant.issuer_id,
                &grant.account_id,
                &grant.audience_id,
                grant.not_before,
            )
            .unwrap();
        let management = SessionGrantValidationInput::ById(SessionGrantValidationById {
            id: grant.id.clone(),
            audience_id: Some(grant.audience_id.clone()),
            proof: None,
        });
        assert!(
            SessionGrantValidationBinding::from_authenticated_response(
                &management,
                &grant.issuer_id,
                outcome()
            )
            .is_err()
        );
        assert!(
            result
                .validate_request_binding(
                    &secret,
                    &"ak:did_core:web:another-issuer.example".parse().unwrap(),
                    &grant.account_id,
                    &grant.audience_id,
                    grant.not_before
                )
                .is_err()
        );
        assert!(
            result
                .validate_request_binding(
                    &SessionGrantSecret::from_bytes([9; 32]),
                    &grant.issuer_id,
                    &grant.account_id,
                    &grant.audience_id,
                    grant.not_before
                )
                .is_err()
        );
        assert!(
            result
                .validate_request_binding(
                    &secret,
                    &grant.issuer_id,
                    &grant.account_id,
                    &grant.audience_id,
                    grant.expires_at
                )
                .is_err()
        );
    }

    #[test]
    fn holder_confirmation_binds_full_issuer_ref_and_ascii_secret_digest() {
        let row = vector("issuer_a_standard");
        let secret: SessionGrantSecret =
            serde_json::from_value(row["session_grant"].clone()).unwrap();
        let metadata: SessionGrantMetadata =
            serde_json::from_value(row["metadata"].clone()).unwrap();
        let proof = SessionGrantHolderProofClaims {
            context: SessionGrantHolderProofContext::V1,
            session_grant_ref: metadata.grant_ref(),
            session_grant_digest: Hash::new(canonical::sha256_digest(secret.as_str().as_bytes()))
                .unwrap(),
            audience_id: metadata.audience_id.clone(),
            challenge: "one-server-challenge".into(),
            issued_at: metadata.not_before,
            expires_at: metadata.not_before + chrono::Duration::seconds(60),
        };
        proof
            .validate_binding(
                &metadata.grant_ref(),
                &secret,
                &metadata.audience_id,
                "one-server-challenge",
                metadata.not_before,
            )
            .unwrap();
        let mut other = metadata.grant_ref();
        other.issuer_id = "ak:did_core:web:other.example".parse().unwrap();
        assert!(
            proof
                .validate_binding(
                    &other,
                    &secret,
                    &metadata.audience_id,
                    "one-server-challenge",
                    metadata.not_before
                )
                .is_err()
        );
        assert!(
            proof
                .validate_binding(
                    &metadata.grant_ref(),
                    &SessionGrantSecret::from_bytes([9; 32]),
                    &metadata.audience_id,
                    "one-server-challenge",
                    metadata.not_before
                )
                .is_err()
        );
    }

    #[test]
    fn auth_logout_carries_the_exact_opaque_secret_and_closed_reason() {
        let request = request_value();
        let value = json!({"session_grant":request["session_grant"],"reason_code":"account_logout",
            "logout_request_digest":format!("sha256:{}","1".repeat(64)),"validated_at":"2026-08-08T12:00:00.000Z"});
        let decoded: AuthenticationSessionTerminationInput =
            serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), value);
        let mut invalid = value.clone();
        invalid["reason_code"] = json!("other");
        assert!(serde_json::from_value::<AuthenticationSessionTerminationInput>(invalid).is_err());
        let mut invalid = value;
        let secret = invalid
            .as_object_mut()
            .unwrap()
            .remove("session_grant")
            .unwrap();
        invalid["grant_jwt"] = secret;
        assert!(serde_json::from_value::<AuthenticationSessionTerminationInput>(invalid).is_err());
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

    fn unsigned_agent_request() -> AgentSessionGrantSigningInput {
        AgentSessionGrantSigningInput::new(
            DidCoreId::new(PRINCIPAL).unwrap(),
            vec!["ak.self.committed_event.read.scan.v1".to_owned()],
            EventId::new(AUTHORIZATION).unwrap(),
            RequestedAgentSessionGrantScope {
                realm_ids: Vec::new(),
                strand_ids: Vec::new(),
                track_names: Vec::new(),
            },
            None,
            SessionGrantDpopBindingProof {
                proof_jwt: "header.body.signature".to_owned(),
            },
            AgentSessionGrantProofInput {
                challenge: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                audience_id: DidCoreId::new(AUDIENCE).unwrap(),
                issued_at: "2026-08-15T00:00:00Z".parse().unwrap(),
                expires_at: "2026-08-15T00:04:00Z".parse().unwrap(),
                verification_method: DidUrl::new(VERIFICATION_METHOD).unwrap(),
            },
        )
        .unwrap()
    }

    fn signed_agent_request() -> AgentSessionGrantRequestBody {
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
        assert!(serde_json::from_value::<AgentSessionGrantRequestBody>(encoded).is_err());
    }

    #[test]
    fn agent_approval_references_are_canonical_and_bound_to_the_signed_intent() {
        let first = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [1; 32]);
        let second = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [2; 32]);
        let original = unsigned_agent_request().canonical_request_digest().unwrap();
        let unsigned = unsigned_agent_request()
            .with_approval_evidence_refs(vec![first.clone()])
            .unwrap();
        assert_ne!(unsigned.canonical_request_digest().unwrap(), original);
        let SessionGrantRequestBody::Agent(mut signed) = unsigned
            .attach_signature(NonEmptyString::new("A".repeat(86)).unwrap())
            .unwrap()
        else {
            unreachable!()
        };
        signed.validate().unwrap();
        signed.approval_evidence_refs = Some(vec![second.clone()]);
        assert!(signed.validate().is_err());
        assert!(
            unsigned_agent_request()
                .with_approval_evidence_refs(Vec::new())
                .is_err()
        );
        assert!(
            unsigned_agent_request()
                .with_approval_evidence_refs(vec![first.clone(), first.clone()])
                .is_err()
        );
        assert!(
            unsigned_agent_request()
                .with_approval_evidence_refs(vec![second, first])
                .is_err()
        );
        let mut value = serde_json::to_value(signed_agent_request()).unwrap();
        value["approval_evidence_refs"] = Value::Null;
        assert!(serde_json::from_value::<AgentSessionGrantRequestBody>(value).is_err());
    }

    #[test]
    fn agent_session_request_rejects_device_id() {
        let mut encoded = serde_json::to_value(signed_agent_request()).unwrap();
        assert!(encoded.get("device_id").is_none());
        encoded["device_id"] = json!(DEVICE);
        assert!(serde_json::from_value::<AgentSessionGrantRequestBody>(encoded).is_err());
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
        let mut other = proof;
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
        let human = SessionGrantRequestBody::Human(HumanSessionGrantRequestBody {
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
        let mut agent = json!({
            "session_grant": SessionGrantSecret::from_bytes([42; 32]),
            "principal_id": PRINCIPAL,
            "agent_key_authorization_ref": AUTHORIZATION,
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
        agent["agent_session_refresh_proof"]["request_canonical_digest"] = serde_json::to_value(
            crate::session_grant_bodies::agent_session_refresh_request_digest(
                &SessionGrantSecret::from_bytes([42; 32]),
                &PRINCIPAL.parse().unwrap(),
                &AUTHORIZATION.parse().unwrap(),
                &AUDIENCE.parse().unwrap(),
                &DidUrl::new(VERIFICATION_METHOD).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let body: SessionGrantRefreshRequestBody = serde_json::from_value(agent.clone()).unwrap();
        assert!(matches!(body, SessionGrantRefreshRequestBody::Agent(_)));
        body.validate().unwrap();
        assert_eq!(serde_json::to_value(&body).unwrap(), agent);

        // Agent MLS endpoints have no Device; an Agent refresh naming one is
        // invalid rather than read as the human branch.
        let mut with_device = agent.clone();
        with_device["device_id"] = json!(DEVICE);
        assert!(serde_json::from_value::<SessionGrantRefreshRequestBody>(with_device).is_err());

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

include!("generated/session_grants_contracts.rs");
