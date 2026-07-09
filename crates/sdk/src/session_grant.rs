//! Session-grant request builders for the human / OIDC login proof kinds.
//!
//! Parallels [`crate::agent::agent_key_proof_session_grant_request`] (the agent
//! runtime proof kind) so every signature-based `SessionGrantProofKind` has a
//! first-class SDK constructor and callers do not hand-assemble
//! `SessionGrantRequestBody`. The signature-based kinds
//! (`did_bound_signature`, `paired_device_proof`) share
//! [`SessionGrantProofFields`]; the first-sign-in OIDC kind
//! (`oidc_code_exchange`) uses [`oidc_session_grant_request`].

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{
    DeviceId, Did, Hash, SessionGrantAppletDelegation, SessionGrantDpopBindingProof,
    SessionGrantProofKind, SessionGrantRequestBody, SessionGrantRequestProof,
};

/// Shared signature-carrying proof fields for the signature-based session-grant
/// proof kinds. Mirrors the `SessionGrantRequestProof` subset those kinds
/// populate; the OIDC-only fields (`issuer` / `client_id` / …) are left unset.
#[derive(Clone, Debug)]
pub struct SessionGrantProofFields {
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub signature: String,
    pub verification_method: Option<String>,
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
    applet_delegation: Option<SessionGrantAppletDelegation>,
    proof: SessionGrantProofFields,
) -> SessionGrantRequestBody {
    SessionGrantRequestBody {
        principal_id: Some(principal_id),
        device_id,
        requested_scope,
        agent_key_authorization_ref: None,
        agent_scope_request: Value::Null,
        dpop_binding_proof,
        applet_delegation,
        proof: proof.into_request_proof(SessionGrantProofKind::PairedDeviceProof),
    }
}

/// Build a `did_bound_signature` session-grant request.
pub fn did_proof_session_grant_request(
    principal_id: Did,
    device_id: DeviceId,
    requested_scope: Vec<String>,
    dpop_binding_proof: Option<SessionGrantDpopBindingProof>,
    applet_delegation: Option<SessionGrantAppletDelegation>,
    proof: SessionGrantProofFields,
) -> SessionGrantRequestBody {
    SessionGrantRequestBody {
        principal_id: Some(principal_id),
        device_id: Some(device_id),
        requested_scope,
        agent_key_authorization_ref: None,
        agent_scope_request: Value::Null,
        dpop_binding_proof,
        applet_delegation,
        proof: proof.into_request_proof(SessionGrantProofKind::DidBoundSignature),
    }
}

/// Build an `oidc_code_exchange` first-sign-in session-grant request.
///
/// `principal_id` MAY be omitted for OIDC first sign-in — the Account Authority
/// derives and returns the principal DID (`SessionGrantOutcome.principal_id`).
#[allow(clippy::too_many_arguments)]
pub fn oidc_session_grant_request(
    principal_id: Option<Did>,
    device_id: Option<DeviceId>,
    requested_scope: Vec<String>,
    challenge: impl Into<String>,
    request_canonical_digest: Hash,
    audience: impl Into<String>,
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
        agent_scope_request: Value::Null,
        dpop_binding_proof: None,
        applet_delegation: None,
        proof: SessionGrantRequestProof {
            proof_kind: SessionGrantProofKind::OidcCodeExchange,
            challenge: challenge.into(),
            request_canonical_digest,
            audience: audience.into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn did() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn device_id() -> DeviceId {
        DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn digest() -> Hash {
        Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
    }

    fn proof_fields() -> SessionGrantProofFields {
        SessionGrantProofFields {
            challenge: "session-grant-challenge-0001".to_owned(),
            request_canonical_digest: digest(),
            audience: "did:webvh:z6mkfixture:service.example".to_owned(),
            expires_at: "2026-07-08T10:05:00Z".parse().ok(),
            signature: "proof-signature".to_owned(),
            verification_method: Some("did:webvh:z6mkfixture:alice.example#device-1".to_owned()),
        }
    }

    #[test]
    fn holder_proof_builds_paired_device_request() {
        let request = holder_proof_session_grant_request(
            did(),
            Some(device_id()),
            vec!["ck.self.account.query.viewer".to_owned()],
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
        assert_eq!(request.principal_id, Some(did()));
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
            vec!["ck.self.events.stream.subscribe".to_owned()],
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
            None,
            Some(device_id()),
            Vec::new(),
            "oidc-challenge",
            digest(),
            "did:webvh:z6mkfixture:service.example",
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
        assert_eq!(request.principal_id, None);
        assert_eq!(
            request.proof.issuer.as_deref(),
            Some("https://issuer.example")
        );
        assert_eq!(request.proof.authorization_code.as_deref(), Some("code-1"));
        assert!(request.proof.signature.is_empty());
    }
}
