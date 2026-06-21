//! Push, policy, media, moderation, mimi, applet, and the generic HTTP-verb
//! helper methods on [`Client`].

use cokret_core::{
    AppletActorView, AppletDescription, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletThirdPartyLocationList, AppletThirdPartyUserList, AppletTransactionOutcome,
    AppletTransactionRequestBody, CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody,
    MediaIceConfigOutcome, MediaIceConfigRequestBody, MimiProviderDirectory,
    MimiReportAbuseOutcome, MimiReportAbuseRequestBody, ModerationReportOutcome,
    ModerationReportRequestBody, OkOutcome, PolicyCheckOutcome, PolicyCheckRequestBody,
    PushNotifyOutcome, PushNotifyRequestBody, PushRegisterDeviceOutcome,
    PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody, Result,
};
use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Client, ClientRequestOptions, reject_path_segment};

impl Client {
    pub async fn push_register_device(
        &self,
        request: &PushRegisterDeviceRequestBody,
    ) -> Result<PushRegisterDeviceOutcome> {
        self.post("/_cokret/edge/push/register-device", request)
            .await
    }

    pub async fn push_unregister_device(
        &self,
        request: &PushUnregisterDeviceRequestBody,
    ) -> Result<OkOutcome> {
        self.post("/_cokret/edge/push/unregister-device", request)
            .await
    }

    pub async fn push_notify(&self, request: &PushNotifyRequestBody) -> Result<PushNotifyOutcome> {
        self.post("/_cokret/edge/push/notify", request).await
    }

    pub async fn policy_check(
        &self,
        request: &PolicyCheckRequestBody,
    ) -> Result<PolicyCheckOutcome> {
        self.post("/_cokret/self/policy/check", request).await
    }

    pub async fn media_ice_config(
        &self,
        request: &MediaIceConfigRequestBody,
    ) -> Result<MediaIceConfigOutcome> {
        self.post("/_cokret/self/rtc/ice-config", request).await
    }

    /// CKP-0010 — exchange a committed `session_focus` for a backend media
    /// token + `participant_binding` via
    /// `ck.self.call.media.exchange.issue_token` (`POST /_cokret/self/rtc/token`,
    /// `media-service-binding.md` §3).
    ///
    /// Returns the raw signed outcome; callers MUST verify the response against
    /// the realm media-service anchors and the issuing request before use (the
    /// `cokret` crate provides `verify_call_media_token_outcome`): check that
    /// `service_signature` / `participant_binding.issuer_kid` resolve to an
    /// anchored `service_id`, the TTL is ≤ 600s, and the binding tuple matches.
    pub async fn media_token_exchange(
        &self,
        request: &CallMediaTokenExchangeRequestBody,
    ) -> Result<CallMediaTokenExchangeOutcome> {
        self.post("/_cokret/self/rtc/token", request).await
    }

    pub async fn moderation_report(
        &self,
        request: &ModerationReportRequestBody,
    ) -> Result<ModerationReportOutcome> {
        self.post("/_cokret/self/moderation/report", request).await
    }

    pub async fn mimi_provider_directory(
        &self,
        provider_id: Option<&str>,
        features: &[String],
    ) -> Result<MimiProviderDirectory> {
        let mut builder = self.request(Method::GET, "/_cokret/open/mimi/provider-directory")?;
        if let Some(provider_id) = provider_id {
            builder = builder.query(&[("provider_id", provider_id)]);
        }
        for feature in features {
            builder = builder.query(&[("features", feature)]);
        }
        self.send_json(builder).await
    }

    pub async fn mimi_report_abuse(
        &self,
        request: &MimiReportAbuseRequestBody,
    ) -> Result<MimiReportAbuseOutcome> {
        self.post("/_cokret/open/mimi/report-abuse", request).await
    }

    pub async fn applet_ping(&self) -> Result<AppletPingOutcome> {
        self.get("/_cokret/edge/applet/ping").await
    }

    pub async fn applet_describe(&self) -> Result<AppletDescription> {
        self.get("/_cokret/edge/applet/describe").await
    }

    pub async fn applet_transaction(
        &self,
        idempotency_key: &str,
        request: &AppletTransactionRequestBody,
    ) -> Result<AppletTransactionOutcome> {
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options("/_cokret/edge/applet/transactions", request, &options)
            .await
    }

    pub async fn applet_actor(&self, actor_id: &str) -> Result<AppletActorView> {
        reject_path_segment(actor_id)?;
        let path = format!("/_cokret/edge/applet/actors/{actor_id}");
        self.get(&path).await
    }

    pub async fn applet_realm(&self, realm_id_or_alias: &str) -> Result<AppletRealmView> {
        reject_path_segment(realm_id_or_alias)?;
        let path = format!("/_cokret/edge/applet/realms/{realm_id_or_alias}");
        self.get(&path).await
    }

    pub async fn applet_protocol(&self, protocol: &str) -> Result<AppletProtocolMetadata> {
        reject_path_segment(protocol)?;
        let path = format!("/_cokret/edge/applet/protocols/{protocol}");
        self.get(&path).await
    }

    /// Query third-party users for an applet.
    pub async fn applet_third_party_users(&self) -> Result<AppletThirdPartyUserList> {
        self.get("/_cokret/edge/applet/third_party/users").await
    }

    /// Query third-party locations for an applet.
    pub async fn applet_third_party_locations(&self) -> Result<AppletThirdPartyLocationList> {
        self.get("/_cokret/edge/applet/third_party/locations").await
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let builder = self.request(Method::GET, path)?;
        self.send_json(builder).await
    }

    pub async fn get_with_options<T: DeserializeOwned>(
        &self,
        path: &str,
        options: &ClientRequestOptions,
    ) -> Result<T> {
        let builder = self.apply_request_options(self.request(Method::GET, path)?, options)?;
        self.send_json(builder).await
    }

    pub async fn post<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let builder = self.request(Method::POST, path)?.json(body);
        self.send_json(builder).await
    }

    pub async fn post_with_options<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        options: &ClientRequestOptions,
    ) -> Result<R> {
        let builder = self.apply_request_options(self.request(Method::POST, path)?, options)?;
        self.send_json(builder.json(body)).await
    }

    pub async fn put<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let builder = self.request(Method::PUT, path)?.json(body);
        self.send_json(builder).await
    }

    pub async fn put_with_options<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        options: &ClientRequestOptions,
    ) -> Result<R> {
        let builder = self.apply_request_options(self.request(Method::PUT, path)?, options)?;
        self.send_json(builder.json(body)).await
    }

    pub async fn delete<R: DeserializeOwned>(&self, path: &str) -> Result<R> {
        let builder = self.request(Method::DELETE, path)?;
        self.send_json(builder).await
    }
}
