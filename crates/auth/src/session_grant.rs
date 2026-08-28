//! Strongly typed session-grant request builders.
//!
//! Human issuance is account-handoff + accepted-device proof only. Agent
//! issuance remains an explicitly scoped runtime-key-signed branch.

use arkret_models_collaboration::agent_operations::AgentRequestedScopeDisclosure;
use arkret_models_collaboration::session_grant_bodies::{
    AcceptedDeviceIssuePossessionProof, AcceptedDeviceRefreshPossessionProof,
    HumanSessionGrantRefreshRequest, HumanSessionGrantRequest, SessionGrantAgentScopeRequest,
    SessionGrantDpopBindingProof, SessionGrantRefreshRequestBody, SessionGrantRequestBody,
    UnsignedAgentSessionGrantProof, UnsignedAgentSessionGrantRequest,
};
use arkret_wire::{DeviceId, DidCoreId, DidUrl, Hash, NonEmptyString, RequestId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentKeyProofSigningInput {
    pub audience_id: DidCoreId,
    pub challenge: String,
    pub nonce: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub request_canonical_digest: Hash,
    pub verification_method: DidUrl,
}

impl AgentKeyProofSigningInput {
    pub fn canonical_bytes(&self) -> crate::Result<Vec<u8>> {
        arkret_canonical::canonical::canonical_json_bytes(self).map_err(Into::into)
    }

    pub fn canonical_digest(&self) -> crate::Result<Hash> {
        Ok(Hash::new(arkret_canonical::canonical::sha256_digest(
            self.canonical_bytes()?,
        ))?)
    }
}

pub fn human_session_grant_request(
    request_id: RequestId,
    principal_id: DidCoreId,
    device_id: DeviceId,
    audience_id: DidCoreId,
    accepted_device_possession_proof: AcceptedDeviceIssuePossessionProof,
) -> crate::Result<SessionGrantRequestBody> {
    let request = HumanSessionGrantRequest {
        request_id,
        principal_id,
        device_id,
        audience_id,
        accepted_device_possession_proof,
    };
    request.validate()?;
    Ok(SessionGrantRequestBody::Human(request))
}

pub fn human_session_grant_refresh_request(
    grant_jwt: impl Into<String>,
    audience_id: Option<DidCoreId>,
    device_id: DeviceId,
    accepted_device_possession_proof: AcceptedDeviceRefreshPossessionProof,
) -> crate::Result<SessionGrantRefreshRequestBody> {
    let request = HumanSessionGrantRefreshRequest {
        grant_jwt: grant_jwt.into(),
        audience_id,
        device_id,
        accepted_device_possession_proof,
    };
    request.validate()?;
    Ok(SessionGrantRefreshRequestBody::Human(request))
}

#[allow(clippy::too_many_arguments)]
pub fn agent_key_proof_session_grant_request(
    principal_id: DidCoreId,
    device_id: DeviceId,
    requested_scope: Vec<String>,
    agent_key_authorization_ref: impl Into<String>,
    agent_scope_request: SessionGrantAgentScopeRequest,
    requested_scope_disclosure: Option<AgentRequestedScopeDisclosure>,
    dpop_binding_proof: SessionGrantDpopBindingProof,
    verification_method: DidUrl,
    challenge: impl Into<String>,
    nonce: impl Into<String>,
    audience_id: DidCoreId,
    expires_at: DateTime<Utc>,
    signature: impl Into<String>,
) -> crate::Result<SessionGrantRequestBody> {
    let request = UnsignedAgentSessionGrantRequest::new(
        principal_id,
        device_id,
        requested_scope,
        agent_key_authorization_ref.into(),
        agent_scope_request,
        requested_scope_disclosure,
        dpop_binding_proof,
        None,
        UnsignedAgentSessionGrantProof {
            challenge: challenge.into(),
            audience_id,
            expires_at,
            verification_method,
            nonce: nonce.into(),
        },
    )?;
    let signature = NonEmptyString::new(signature.into())
        .map_err(|reason| crate::AuthError::Protocol(reason.to_owned()))?;
    request.attach_signature(signature).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_agent_scope_is_rejected() {
        let error = agent_key_proof_session_grant_request(
            DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            Vec::new(),
            "ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g",
            SessionGrantAgentScopeRequest {
                realm_ids: Vec::new(),
                strand_ids: Vec::new(),
                track_names: Vec::new(),
            },
            None,
            SessionGrantDpopBindingProof {
                proof_jwt: "p".into(),
            },
            DidUrl::new("did:web:agent.example#runtime-key-1").unwrap(),
            "challenge",
            "nonce",
            DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            "2026-08-08T12:05:00.000Z".parse().unwrap(),
            "signature",
        )
        .unwrap_err();
        assert!(error.to_string().contains("requested_scope"));
    }

    #[test]
    fn human_wire_rejects_agent_requested_scope() {
        let value = serde_json::json!({
            "request_id": "ak:request:01970000-0000-7000-8000-000000000021",
            "principal_id": "ak:did_core:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "audience_id": "ak:did_core:web:service.example",
            "requested_scope": ["ak.self.account.read.viewer.v1"],
            "accepted_device_possession_proof": {}
        });
        assert!(serde_json::from_value::<SessionGrantRequestBody>(value).is_err());
    }
}
