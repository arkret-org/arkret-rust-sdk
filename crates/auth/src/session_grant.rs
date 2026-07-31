//! Session-grant request builders for the human / OIDC login proof kinds.
//!
//! Parallels [`crate::agent::agent_key_proof_session_grant_request`] (the agent
//! runtime proof kind) so every signature-based `SessionGrantProofKind` has a
//! first-class SDK constructor and callers do not hand-assemble
//! `SessionGrantRequestBody`. The signature-based kinds
//! (`did_bound_signature`, `paired_device_proof`) share
//! [`SessionGrantProofFields`]; the OIDC kind
//! (`oidc_code_exchange`) uses [`oidc_session_grant_request`].

use arkret_models_collaboration::session_grant_bodies::{
    SessionGrantAgentScopeRequest, SessionGrantAppletDelegation, SessionGrantDpopBindingProof,
    SessionGrantRequestBody, SessionGrantRequestProof,
};
use arkret_models_identity::SessionGrantProofKind;
use arkret_wire::{DeviceId, Did, DidUrl, Hash};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentKeyProofSigningInput {
    pub audience: Did,
    pub challenge: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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

pub fn agent_key_proof_request_binding_digest(
    body: &SessionGrantRequestBody,
) -> crate::Result<Hash> {
    let mut value = serde_json::to_value(body)?;
    let proof = value
        .get_mut("proof")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            crate::AuthError::Protocol("session grant proof must be an object".to_owned())
        })?;
    proof.remove("signature");
    proof.remove("request_canonical_digest");
    Ok(Hash::new(arkret_canonical::canonical::canonical_sha256(
        &value,
    )?)?)
}

#[allow(clippy::too_many_arguments)]
pub fn agent_key_proof_signing_input_for_session_grant(
    principal_id: &Did,
    device_id: &DeviceId,
    requested_scope: &[String],
    agent_key_authorization_ref: &str,
    agent_scope_request: &SessionGrantAgentScopeRequest,
    dpop_binding_proof: &SessionGrantDpopBindingProof,
    verification_method: DidUrl,
    challenge: impl Into<String>,
    nonce: impl Into<String>,
    audience: Did,
    expires_at: DateTime<Utc>,
) -> crate::Result<AgentKeyProofSigningInput> {
    let challenge = challenge.into();
    let nonce = nonce.into();
    let mut body = agent_key_proof_unsigned_session_grant_request(
        principal_id.clone(),
        device_id.clone(),
        requested_scope.to_vec(),
        agent_key_authorization_ref,
        agent_scope_request.clone(),
        dpop_binding_proof.clone(),
        verification_method.clone(),
        challenge.clone(),
        nonce.clone(),
        audience.clone(),
        expires_at,
    )?;
    let request_canonical_digest = agent_key_proof_request_binding_digest(&body)?;
    body.proof.request_canonical_digest = request_canonical_digest.clone();
    Ok(AgentKeyProofSigningInput {
        audience,
        challenge,
        nonce: Some(nonce),
        expires_at,
        request_canonical_digest,
        verification_method,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn agent_key_proof_session_grant_request(
    principal_id: Did,
    device_id: DeviceId,
    requested_scope: Vec<String>,
    agent_key_authorization_ref: impl Into<String>,
    agent_scope_request: SessionGrantAgentScopeRequest,
    dpop_binding_proof: SessionGrantDpopBindingProof,
    verification_method: DidUrl,
    challenge: impl Into<String>,
    nonce: impl Into<String>,
    audience: Did,
    expires_at: DateTime<Utc>,
    signature: impl Into<String>,
) -> crate::Result<SessionGrantRequestBody> {
    let agent_key_authorization_ref = agent_key_authorization_ref.into();
    let challenge = challenge.into();
    let nonce = nonce.into();
    let signing_input = agent_key_proof_signing_input_for_session_grant(
        &principal_id,
        &device_id,
        &requested_scope,
        &agent_key_authorization_ref,
        &agent_scope_request,
        &dpop_binding_proof,
        verification_method.clone(),
        challenge.clone(),
        nonce.clone(),
        audience.clone(),
        expires_at,
    )?;
    let mut request = agent_key_proof_unsigned_session_grant_request(
        principal_id,
        device_id,
        requested_scope,
        agent_key_authorization_ref,
        agent_scope_request,
        dpop_binding_proof,
        verification_method,
        challenge,
        nonce,
        audience,
        expires_at,
    )?;
    request.proof.request_canonical_digest = signing_input.request_canonical_digest;
    request.proof.signature = signature.into();
    Ok(request)
}

#[allow(clippy::too_many_arguments)]
fn agent_key_proof_unsigned_session_grant_request(
    principal_id: Did,
    device_id: DeviceId,
    requested_scope: Vec<String>,
    agent_key_authorization_ref: impl Into<String>,
    agent_scope_request: SessionGrantAgentScopeRequest,
    dpop_binding_proof: SessionGrantDpopBindingProof,
    verification_method: DidUrl,
    challenge: impl Into<String>,
    nonce: impl Into<String>,
    audience: Did,
    expires_at: DateTime<Utc>,
) -> crate::Result<SessionGrantRequestBody> {
    let request_canonical_digest = Hash::new(format!("sha256:{}", "0".repeat(64)))?;
    Ok(SessionGrantRequestBody {
        principal_id,
        device_id: Some(device_id),
        requested_scope,
        agent_key_authorization_ref: Some(agent_key_authorization_ref.into()),
        agent_scope_request: Some(agent_scope_request),
        dpop_binding_proof: Some(dpop_binding_proof),
        applet_authority: None,
        proof: SessionGrantRequestProof {
            proof_kind: SessionGrantProofKind::AgentKeyProof,
            challenge: challenge.into(),
            request_canonical_digest,
            audience,
            expires_at: Some(expires_at),
            signature: String::new(),
            verification_method: Some(verification_method),
            issuer: None,
            client_id: None,
            redirect_uri: None,
            state: None,
            nonce: Some(nonce.into()),
            authorization_code: None,
            code_verifier: None,
        },
    })
}

/// Shared signature-carrying proof fields for the signature-based session-grant
/// proof kinds. Mirrors the `SessionGrantRequestProof` subset those kinds
/// populate; the OIDC-only fields (`issuer` / `client_id` / …) are left unset.
#[derive(Clone, Debug)]
pub struct SessionGrantProofFields {
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience: Did,
    pub expires_at: Option<DateTime<Utc>>,
    pub signature: String,
    pub verification_method: Option<DidUrl>,
}

impl SessionGrantProofFields {
    /// Lower these fields into a full `SessionGrantRequestProof` under the given
    /// proof kind, leaving the OIDC-only fields absent.
    pub fn into_request_proof(self, proof_kind: SessionGrantProofKind) -> SessionGrantRequestProof {
        SessionGrantRequestProof {
            proof_kind,
            challenge: self.challenge,
            request_canonical_digest: self.request_canonical_digest,
            audience: self.audience,
            expires_at: self.expires_at,
            signature: self.signature,
            verification_method: self.verification_method,
            issuer: None,
            client_id: None,
            redirect_uri: None,
            state: None,
            nonce: None,
            authorization_code: None,
            code_verifier: None,
        }
    }
}

/// Build a `paired_device_proof` (holder-key) session-grant request.
pub fn holder_proof_session_grant_request(
    principal_id: Did,
    device_id: Option<DeviceId>,
    requested_scope: Vec<String>,
    dpop_binding_proof: Option<SessionGrantDpopBindingProof>,
    applet_authority: Option<SessionGrantAppletDelegation>,
    proof: SessionGrantProofFields,
) -> SessionGrantRequestBody {
    SessionGrantRequestBody {
        principal_id,
        device_id,
        requested_scope,
        agent_key_authorization_ref: None,
        agent_scope_request: None,
        dpop_binding_proof,
        applet_authority,
        proof: proof.into_request_proof(SessionGrantProofKind::PairedDeviceProof),
    }
}

/// Build a `did_bound_signature` session-grant request.
pub fn did_proof_session_grant_request(
    principal_id: Did,
    device_id: DeviceId,
    requested_scope: Vec<String>,
    dpop_binding_proof: Option<SessionGrantDpopBindingProof>,
    applet_authority: Option<SessionGrantAppletDelegation>,
    proof: SessionGrantProofFields,
) -> SessionGrantRequestBody {
    SessionGrantRequestBody {
        principal_id,
        device_id: Some(device_id),
        requested_scope,
        agent_key_authorization_ref: None,
        agent_scope_request: None,
        dpop_binding_proof,
        applet_authority,
        proof: proof.into_request_proof(SessionGrantProofKind::DidBoundSignature),
    }
}

/// Build an `oidc_code_exchange` session-grant request for an existing principal.
#[allow(clippy::too_many_arguments)]
pub fn oidc_session_grant_request(
    principal_id: Did,
    device_id: Option<DeviceId>,
    requested_scope: Vec<String>,
    challenge: impl Into<String>,
    request_canonical_digest: Hash,
    audience: Did,
    issuer: impl Into<String>,
    client_id: impl Into<String>,
    redirect_uri: impl Into<String>,
    state: impl Into<String>,
    nonce: impl Into<String>,
    authorization_code: impl Into<String>,
    code_verifier: impl Into<String>,
) -> SessionGrantRequestBody {
    SessionGrantRequestBody {
        principal_id,
        device_id,
        requested_scope,
        agent_key_authorization_ref: None,
        agent_scope_request: None,
        dpop_binding_proof: None,
        applet_authority: None,
        proof: SessionGrantRequestProof {
            proof_kind: SessionGrantProofKind::OidcCodeExchange,
            challenge: challenge.into(),
            request_canonical_digest,
            audience,
            expires_at: None,
            signature: String::new(),
            verification_method: None,
            issuer: Some(issuer.into()),
            client_id: Some(client_id.into()),
            redirect_uri: Some(redirect_uri.into()),
            state: Some(state.into()),
            nonce: Some(nonce.into()),
            authorization_code: Some(authorization_code.into()),
            code_verifier: Some(code_verifier.into()),
        },
    }
}

/// Build the holder-signed session request used immediately after account
/// binding. The caller signs `request.proof.canonical_signing_bytes()` with
/// the same Ed25519 key used by the account-handoff DPoP credential.
pub fn pre_registration_handoff_session_grant_request(
    principal_id: Did,
    device_id: Option<DeviceId>,
    requested_scope: Vec<String>,
    challenge: impl Into<String>,
    audience: Did,
    expires_at: DateTime<Utc>,
) -> crate::Result<SessionGrantRequestBody> {
    let placeholder = Hash::new(format!("sha256:{}", "0".repeat(64)))?;
    let mut request = SessionGrantRequestBody {
        principal_id,
        device_id,
        requested_scope,
        agent_key_authorization_ref: None,
        agent_scope_request: None,
        dpop_binding_proof: None,
        applet_authority: None,
        proof: SessionGrantRequestProof {
            proof_kind: SessionGrantProofKind::PreRegistrationHandoff,
            challenge: challenge.into(),
            request_canonical_digest: placeholder,
            audience,
            expires_at: Some(expires_at),
            signature: String::new(),
            verification_method: None,
            issuer: None,
            client_id: None,
            redirect_uri: None,
            state: None,
            nonce: None,
            authorization_code: None,
            code_verifier: None,
        },
    };
    request.proof.request_canonical_digest = request.canonical_request_digest()?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn device_id() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn digest() -> Hash {
        Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
    }

    fn proof_fields() -> SessionGrantProofFields {
        SessionGrantProofFields {
            challenge: "session-grant-challenge-0001".to_owned(),
            request_canonical_digest: digest(),
            audience: Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
            expires_at: "2026-07-08T10:05:00.000Z".parse().ok(),
            signature: "proof-signature".to_owned(),
            verification_method: Some(
                DidUrl::new("did:webvh:z6mkfixture:alice.example#device-1").unwrap(),
            ),
        }
    }

    #[test]
    fn holder_proof_builds_paired_device_request() {
        let request = holder_proof_session_grant_request(
            did(),
            Some(device_id()),
            vec!["ak.self.account.query.viewer".to_owned()],
            Some(SessionGrantDpopBindingProof {
                proof_jwt: "holder-dpop-proof".to_owned(),
            }),
            None,
            proof_fields(),
        );
        assert_eq!(
            request.proof.proof_kind,
            SessionGrantProofKind::PairedDeviceProof
        );
        assert_eq!(request.principal_id, did());
        assert_eq!(request.device_id, Some(device_id()));
        assert_eq!(request.proof.signature, "proof-signature");
        assert!(request.agent_key_authorization_ref.is_none());
        assert!(request.proof.issuer.is_none());
    }

    #[test]
    fn did_proof_builds_did_bound_request() {
        let request = did_proof_session_grant_request(
            did(),
            device_id(),
            vec!["ak.self.events.stream.subscribe".to_owned()],
            None,
            None,
            proof_fields(),
        );
        assert_eq!(
            request.proof.proof_kind,
            SessionGrantProofKind::DidBoundSignature
        );
        assert_eq!(request.device_id, Some(device_id()));
        assert_eq!(
            request.proof.verification_method.as_deref(),
            Some("did:webvh:z6mkfixture:alice.example#device-1")
        );
    }

    #[test]
    fn oidc_builds_code_exchange_request() {
        let request = oidc_session_grant_request(
            did(),
            Some(device_id()),
            Vec::new(),
            "oidc-challenge",
            digest(),
            Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
            "https://issuer.example",
            "client-1",
            "https://app.example/callback",
            "state-1",
            "nonce-1",
            "code-1",
            "verifier-1",
        );
        assert_eq!(
            request.proof.proof_kind,
            SessionGrantProofKind::OidcCodeExchange
        );
        assert_eq!(request.principal_id, did());
        assert_eq!(
            request.proof.issuer.as_deref(),
            Some("https://issuer.example")
        );
        assert_eq!(request.proof.authorization_code.as_deref(), Some("code-1"));
        assert!(request.proof.signature.is_empty());
    }
}
