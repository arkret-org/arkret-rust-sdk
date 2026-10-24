//! Real-time media endpoint methods on [`Client`].

use arkret_models_collaboration::objects::media::{
    CallMediaTokenExchangeRequestBody, CallMediaTokenExchangeResponseBody,
    MediaIceConfigurationRequestBody, MediaIceConfigurationResponseBody,
};

use crate::{Client, Result};

impl Client {
    pub async fn call_invitation_send(
        &self,
        request: &arkret_models_collaboration::call_invitation::CallInvitationSendRequestBody,
    ) -> Result<arkret_models_collaboration::call_invitation::CallInvitationSendResponseBody> {
        request
            .invitation
            .validate_for_envelope(&request.envelope)?;
        self.post("/_arkret/self/rtc/invitation", request).await
    }

    /// Structural transport only. Before editing, installation or permission
    /// decisions use `OwnStationStateClient::consent_current`, which binds an
    /// independent registered PCR and authority before verifying the JWS.
    pub async fn consent_current_read(
        &self,
        request: &arkret_models_collaboration::call_invitation::ConsentCurrentReadRequestBody,
    ) -> Result<arkret_models_collaboration::call_invitation::ConsentCurrentReadResponseBody> {
        request.validate()?;
        let outcome: arkret_models_collaboration::call_invitation::ConsentCurrentReadResponseBody =
            self.post("/_arkret/self/consent/current", request).await?;
        outcome.validate_for_request(request, outcome.governance_generation, chrono::Utc::now())?;
        Ok(outcome)
    }
    pub async fn media_ice_config(
        &self,
        request: &MediaIceConfigurationRequestBody,
    ) -> Result<MediaIceConfigurationResponseBody> {
        self.post("/_arkret/self/rtc/ice-config", request).await
    }

    /// AKP-0010 — exchange a committed `session_focus` for a backend media
    /// token + `participant_binding` via
    /// `ak.self.call.media.exchange.issue_token.v1` (`POST /_arkret/self/rtc/token`,
    /// `media-service-binding.md` §3).
    ///
    /// Returns the raw signed outcome; callers MUST verify the response against
    /// the realm media-service anchors and the issuing request before use (the
    /// `arkret` crate provides `verify_call_media_token_outcome`): check that
    /// `service_signature` / `participant_binding.issuer_kid` resolve to an
    /// anchored `service_id`, the TTL is ≤ 600s, and the binding tuple matches.
    pub async fn media_token_exchange(
        &self,
        request: &CallMediaTokenExchangeRequestBody,
    ) -> Result<CallMediaTokenExchangeResponseBody> {
        self.post("/_arkret/self/rtc/token", request).await
    }
}
