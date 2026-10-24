//! Standard Account Authority SessionGrant revocation.

use arkret_models_collaboration::account_lifecycle::{
    SessionRevokeRequestBody, SessionRevokeResponseBody,
};
use arkret_wire::SessionGrantId;
use reqwest::Method;

use crate::{Auth, Client, DpopAuth, Error, Result};

const PATH: &str = "/_arkret/gate/account/session-grants/revoke";

/// One immutable revocation attempt, including its operation identity.
///
/// Retain this value to retry a lost response. Without an inner lifecycle
/// proof, the DPoP jti is the issuer's request identity and must remain fixed.
/// Creating another attempt starts another operation. This in-memory handle
/// does not provide persistence across a client process restart.
#[derive(Clone)]
pub struct SessionGrantRevokeAttempt {
    client: Client,
    request: SessionRevokeRequestBody,
    expected_grant: Option<SessionGrantId>,
}

impl std::fmt::Debug for SessionGrantRevokeAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionGrantRevokeAttempt")
            .finish_non_exhaustive()
    }
}

impl SessionGrantRevokeAttempt {
    /// Submit or replay this exact attempt at its original Account Authority.
    pub async fn send(&self) -> Result<SessionRevokeResponseBody> {
        let outcome: SessionRevokeResponseBody = self
            .client
            .post_protocol_replay_safe(PATH, &self.request)
            .await?;
        let ids = &outcome.revoked_session_grant_ids;
        let unique: std::collections::BTreeSet<_> = ids.iter().collect();
        if unique.len() != ids.len()
            || (!ids.is_empty() && ids.len() as u64 != outcome.revoked_count)
            || self.expected_grant.as_ref().is_some_and(|expected| {
                outcome.revoked_count > 1 || ids.iter().any(|id| id != expected)
            })
        {
            return Err(Error::Protocol(
                "session revoke outcome does not match its selector".into(),
            ));
        }
        Ok(outcome)
    }
}

impl Client {
    /// Freeze a revocation attempt on the already trusted Account Authority
    /// client. `authorizing_grant_id` identifies the presented credential,
    /// rather than a browser OAuth session or a device authorization.
    pub fn prepare_session_grant_revoke(
        &self,
        authorizing_grant_id: &SessionGrantId,
        request: &SessionRevokeRequestBody,
    ) -> Result<SessionGrantRevokeAttempt> {
        request.validate_shape()?;
        if self.service_signature_identity.is_some()
            || self.managed_device_signature_identity.is_some()
        {
            return Err(Error::Protocol(
                "session revoke cannot use a service or managed Device identity".into(),
            ));
        }
        let Some(Auth::Dpop(auth)) = &self.auth else {
            return Err(Error::Protocol(
                "session revoke requires a DPoP SessionGrant".into(),
            ));
        };
        let token = auth.access_token().ok_or_else(|| {
            Error::Protocol("session revoke requires a DPoP SessionGrant token".into())
        })?;
        let mut client = self.clone();
        if request.proof.is_none() {
            let target = self.base_url.join(PATH.trim_start_matches('/'))?;
            let proof = auth.proof_for(&Method::POST, &target)?;
            client.auth = Some(Auth::Dpop(DpopAuth::with_dpop_token(token, move |_| {
                Ok(proof.clone())
            })));
        }
        let expected_grant =
            if request.target_device_id.is_some() || request.all_sessions == Some(true) {
                None
            } else {
                Some(
                    request
                        .target_session_grant_id
                        .clone()
                        .unwrap_or_else(|| authorizing_grant_id.clone()),
                )
            };
        Ok(SessionGrantRevokeAttempt {
            client,
            request: request.clone(),
            expected_grant,
        })
    }

    /// Revoke with automatic exact-attempt transport retries. For an explicit
    /// retry after this call returns an uncertain error, retain an attempt
    /// created by `prepare_session_grant_revoke` instead.
    pub async fn session_grant_revoke(
        &self,
        authorizing_grant_id: &SessionGrantId,
        request: &SessionRevokeRequestBody,
    ) -> Result<SessionRevokeResponseBody> {
        self.prepare_session_grant_revoke(authorizing_grant_id, request)?
            .send()
            .await
    }
}
