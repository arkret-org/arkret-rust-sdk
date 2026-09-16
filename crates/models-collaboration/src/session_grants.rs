//! Session-grant request DTOs used by the authentication builder.

use arkret_models_identity::{CanonicalSessionPublicJwk, SessionGrantHolderBinding};
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
