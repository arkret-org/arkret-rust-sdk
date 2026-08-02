//! Real-time media endpoint methods on [`Client`].

use arkret_models_collaboration::objects::media::{
    CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody, MediaIceConfigOutcome,
    MediaIceConfigRequestBody,
};

use crate::{Client, Result};

impl Client {
    pub async fn media_ice_config(
        &self,
        request: &MediaIceConfigRequestBody,
    ) -> Result<MediaIceConfigOutcome> {
        self.post("/_arkret/self/rtc/ice-config", request).await
    }

    /// AKP-0010 — exchange a committed `session_focus` for a backend media
    /// token + `participant_binding` via
    /// `ak.self.call.media.exchange.issue_token` (`POST /_arkret/self/rtc/token`,
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
    ) -> Result<CallMediaTokenExchangeOutcome> {
        self.post("/_arkret/self/rtc/token", request).await
    }
}
