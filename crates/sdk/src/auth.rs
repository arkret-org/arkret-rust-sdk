//! Auth shim.
//!
//! The authentication behavior (sessions, session grants, claims, passwords,
//! MFA, DID/OIDC/passkey proof verification) lives in the standalone
//! `arkret-auth` crate; this module re-exports it so `arkret::auth::*` is
//! unchanged for downstream consumers. The transport-bound one-shot
//! `login_did_proof` helper — which speaks the collaboration session-grant DTOs and
//! drives the reqwest client — stays in the SDK as the [`AuthManagerLoginExt`]
//! extension trait so `arkret-auth` carries only transport-free auth behavior.

pub use arkret_auth::*;
#[cfg(all(feature = "client", feature = "signer"))]
pub use login_ext::AuthManagerLoginExt;

#[cfg(all(feature = "client", feature = "signer"))]
mod login_ext {
    use arkret_models_collaboration::session_grant_bodies::{
        SessionGrantOutcome, SessionGrantRequestBody, SessionGrantRequestProof,
    };
    use arkret_models_identity::SessionGrantProofKind;
    use arkret_wire::MoveSigner;
    use chrono::{Duration, Utc};

    use super::AuthManager;
    use crate::{DeviceId, Did, Error, Hash, Result};

    /// Maximum `expires_at - issued_at` freshness window for a `ak.did.proof`
    /// (`identity-did.md` §5.1: window upper bound MUST be ≤ 300s).
    const DID_PROOF_FRESHNESS_WINDOW_SECS: i64 = 300;

    /// SDK-only extension over [`AuthManager`]: the one-shot DID-proof login
    /// strand that drives the single registered
    /// `POST /_arkret/gate/account/session-grants`
    /// (`ak.gate.account.command.issue_session_grant`) operation. Kept in the
    /// SDK rather than `arkret-auth` because it speaks the collaboration
    /// session-grant DTOs and the reqwest client.
    pub trait AuthManagerLoginExt {
        /// One-shot DID-proof login. Builds the `ak.did.proof` signing payload
        /// (`identity-did.md` §5.1), signs it with `signer`, and submits the
        /// spec-shaped `SessionGrantRequestBody` to the single registered
        /// issuance operation. The `challenge` is the server-issued one-time
        /// challenge obtained through the deployment-local channel.
        #[allow(async_fn_in_trait)]
        async fn login_did_proof<S>(
            &mut self,
            client: &arkret_http_client::Client,
            principal_id: Did,
            device_id: DeviceId,
            signer: &S,
            challenge: &str,
            audience: Did,
        ) -> Result<SessionGrantOutcome>
        where
            S: MoveSigner + ?Sized;
    }

    impl AuthManagerLoginExt for AuthManager {
        async fn login_did_proof<S>(
            &mut self,
            client: &arkret_http_client::Client,
            principal_id: Did,
            device_id: DeviceId,
            signer: &S,
            challenge: &str,
            audience: Did,
        ) -> Result<SessionGrantOutcome>
        where
            S: MoveSigner + ?Sized,
        {
            if challenge.len() < 16 {
                return Err(Error::Protocol(
                    "session grant challenge must be at least 16 characters".to_owned(),
                ));
            }

            let issued_at = Utc::now();
            let expires_at = issued_at + Duration::seconds(DID_PROOF_FRESHNESS_WINDOW_SECS);

            // Digest of the canonical request binding (request body without the
            // proof object) — bound into both the wire proof and the signed
            // payload so the proof cannot be replayed against a different body.
            let request_binding = serde_json::json!({
                "principal_id": principal_id.as_str(),
                "device_id": device_id.as_str(),
            });
            let request_canonical_digest = Hash::new(arkret_canonical::canonical::sha256_digest(
                &arkret_canonical::canonical::canonical_json_bytes(&request_binding)?,
            ))?;

            // `ak.did.proof` structured canonical-JSON signing payload per
            // `identity-did.md` §5.1 (device_id is signed-over for multi-device
            // principals; the SDK always supplies it).
            let signing_payload = serde_json::json!({
                "kind": "ak.did.proof",
                "purpose": "ak.session.grant",
                "did": principal_id.as_str(),
                "device_id": device_id.as_str(),
                "audience": audience.as_str(),
                "challenge": challenge,
                "request_canonical_digest": request_canonical_digest.as_str(),
                "issued_at": arkret_canonical::canonical::format_timestamp_canonical(issued_at),
                "expires_at": arkret_canonical::canonical::format_timestamp_canonical(expires_at),
            });
            let payload_bytes =
                arkret_canonical::canonical::canonical_json_bytes(&signing_payload)?;
            let move_sig = signer.sign_payload(&payload_bytes)?;

            client
                .auth_issue_session_grant(&SessionGrantRequestBody {
                    principal_id,
                    device_id: Some(device_id),
                    requested_scope: Vec::new(),
                    agent_key_authorization_ref: None,
                    agent_scope_request: None,
                    dpop_binding_proof: None,
                    applet_delegation: None,
                    proof: SessionGrantRequestProof {
                        proof_kind: SessionGrantProofKind::DidBoundSignature,
                        challenge: challenge.to_owned(),
                        request_canonical_digest,
                        audience,
                        expires_at: Some(expires_at),
                        signature: move_sig.jws,
                        verification_method: None,
                        issuer: None,
                        client_id: None,
                        redirect_uri: None,
                        state: None,
                        nonce: None,
                        authorization_code: None,
                        code_verifier: None,
                    },
                })
                .await
                .map_err(Error::from)
        }
    }
}
