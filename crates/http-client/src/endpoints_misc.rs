//! Push, policy, media, moderation, mimi, applet, and the generic HTTP-verb
//! helper methods on [`Client`].

use arkret_models_collaboration::account_lifecycle::AppletRevokeRequestBody;
use arkret_models_collaboration::event_sync::{
    EventsFrontierAccountClientState, EventsFrontierSelector,
};
use arkret_models_collaboration::governance::circle::{
    CircleCreateRequestBody, CircleLifecycleRequestBody, CircleList, CircleMemberRequestBody,
    CircleMembershipOutcome, CircleScopeRotateOutcome, CircleScopeRotateRequestBody, CircleView,
};
use arkret_models_collaboration::governance::moderation::{
    ModerationReportOutcome, ModerationReportRequestBody,
};
use arkret_models_collaboration::governance::policy_check::{
    PolicyCheckOutcome, PolicyCheckRequestBody,
};
use arkret_models_collaboration::http_bodies::{
    AppletTransactionRequestBody, MimiReportAbuseOutcome, MimiReportAbuseRequestBody,
};
use arkret_models_collaboration::objects::interop::ProviderDirectory;
use arkret_models_collaboration::objects::media::{
    CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody, MediaIceConfigOutcome,
    MediaIceConfigRequestBody,
};
use arkret_models_discovery::ServiceDescribe;
use arkret_models_integration::{
    AppletActorView, AppletInstallOutcome, AppletInstallPlan, AppletInstallPreviewRequestBody,
    AppletInstallRequestBody, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletRevokeOutcome, AppletThirdPartyLocationList, AppletThirdPartyUserList,
    AppletTransactionOutcome, OkOutcome, PushNotifyOutcome, PushNotifyRequestBody,
    PushRegisterDeviceOutcome, PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody,
};
use arkret_signatures::http_signature::{
    Component, ContentDigest, ContentDigestAlgorithm, Ed25519SigningKey, SignedRequestParts,
    canonical_message, format_signature_header, format_signature_input_component_list,
    parse_signature_input, sign_message,
};
use arkret_wire::{Did, canonical};
use reqwest::Method;
use reqwest::header::CONTENT_TYPE;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Client, ClientRequestOptions, Error, Result, reject_path_segment};

pub struct SignedAppletTransactionOptions<'a> {
    pub source_service_id: &'a Did,
    pub destination_service_id: &'a Did,
    pub key_id: &'a str,
    pub signing_key: &'a Ed25519SigningKey,
    pub created: Option<i64>,
    pub expires: Option<i64>,
}

impl Client {
    /// Fetch a selector-bound Event frontier and fail closed when the service
    /// returns a different union variant or scope.
    pub async fn events_frontier(
        &self,
        selector: &EventsFrontierSelector,
    ) -> Result<EventsFrontierAccountClientState> {
        let builder = self
            .request(Method::GET, "/_arkret/self/events/frontier")?
            .query(&selector.query_pairs());
        let state: EventsFrontierAccountClientState = self.send_json(builder).await?;
        selector.validate_response(&state.frontier)?;
        Ok(state)
    }

    pub async fn push_register_device(
        &self,
        request: &PushRegisterDeviceRequestBody,
    ) -> Result<PushRegisterDeviceOutcome> {
        self.post("/_arkret/edge/push/register-device", request)
            .await
    }

    pub async fn push_unregister_device(
        &self,
        request: &PushUnregisterDeviceRequestBody,
    ) -> Result<OkOutcome> {
        self.post("/_arkret/edge/push/unregister-device", request)
            .await
    }

    pub async fn push_notify(&self, request: &PushNotifyRequestBody) -> Result<PushNotifyOutcome> {
        self.post("/_arkret/edge/push/notify", request).await
    }

    pub async fn policy_check(
        &self,
        request: &PolicyCheckRequestBody,
    ) -> Result<PolicyCheckOutcome> {
        self.post("/_arkret/self/policy/check", request).await
    }

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

    pub async fn moderation_report(
        &self,
        request: &ModerationReportRequestBody,
    ) -> Result<ModerationReportOutcome> {
        self.post("/_arkret/self/moderation/report", request).await
    }

    pub async fn mimi_provider_directory(
        &self,
        provider_id: Option<&str>,
        features: &[String],
    ) -> Result<ProviderDirectory> {
        let mut builder = self.request(Method::GET, "/_arkret/open/mimi/provider-directory")?;
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
        self.post("/_arkret/open/mimi/report-abuse", request).await
    }

    pub async fn applet_ping(&self) -> Result<AppletPingOutcome> {
        self.get("/_arkret/edge/applet/ping").await
    }

    pub async fn applet_describe(&self) -> Result<ServiceDescribe> {
        self.get("/_arkret/edge/applet/describe").await
    }

    pub async fn applet_install_preview(
        &self,
        request: &AppletInstallPreviewRequestBody,
    ) -> Result<AppletInstallPlan> {
        self.post("/_arkret/self/applets/install/preview", request)
            .await
    }

    pub async fn applet_install(
        &self,
        idempotency_key: &str,
        request: &AppletInstallRequestBody,
    ) -> Result<AppletInstallOutcome> {
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options("/_arkret/self/applets/install", request, &options)
            .await
    }

    pub async fn applet_revoke(
        &self,
        applet_id: &str,
        request: &AppletRevokeRequestBody,
    ) -> Result<AppletRevokeOutcome> {
        reject_path_segment(applet_id)?;
        let path = format!("/_arkret/self/applets/{applet_id}/revoke");
        self.post(&path, request).await
    }

    pub async fn applet_transaction(
        &self,
        idempotency_key: &str,
        request: &AppletTransactionRequestBody,
    ) -> Result<AppletTransactionOutcome> {
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options("/_arkret/edge/applet/transactions", request, &options)
            .await
    }

    pub async fn applet_transaction_signed(
        &self,
        idempotency_key: &str,
        request: &AppletTransactionRequestBody,
        signature: SignedAppletTransactionOptions<'_>,
    ) -> Result<AppletTransactionOutcome> {
        if &request.source_service_id != signature.source_service_id {
            return Err(Error::Protocol(
                "applet transaction source_service_id must match signing source".to_owned(),
            ));
        }
        let path = "/_arkret/edge/applet/transactions";
        let url = self.base_url.join(path.trim_start_matches('/'))?;
        let target_uri = url.to_string();
        let authority = request_authority(&url)?;
        let body_bytes = canonical::canonical_json_bytes(request)?;
        let content_digest = ContentDigest::compute(&body_bytes, ContentDigestAlgorithm::Sha256);
        let created = signature
            .created
            .unwrap_or_else(|| chrono::Utc::now().timestamp());
        let expires = signature.expires.unwrap_or(created + 300);
        if expires < created || expires - created > 300 {
            return Err(Error::Protocol(
                "applet transaction signature validity window must be within 300 seconds"
                    .to_owned(),
            ));
        }
        let covered_components = vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
            Component::Header("content-digest".to_owned()),
            Component::Header("source-service-id".to_owned()),
            Component::Header("destination-service-id".to_owned()),
            Component::Header("idempotency-key".to_owned()),
        ];
        let signature_input_header =
            format_signature_input_component_list("sig1", &covered_components)
                .map_err(|error| Error::Protocol(format!("signature input: {error}")))?;
        let signature_input_header = format!(
            "{signature_input_header};created={created};expires={expires};keyid=\"{}\";alg=\"ed25519\"",
            signature.key_id
        );
        let signature_input = parse_signature_input(&signature_input_header)
            .map_err(|error| Error::Protocol(format!("signature input: {error}")))?;
        let headers = vec![
            (
                "source-service-id".to_owned(),
                signature.source_service_id.to_string(),
            ),
            (
                "destination-service-id".to_owned(),
                signature.destination_service_id.to_string(),
            ),
            ("idempotency-key".to_owned(), idempotency_key.to_owned()),
        ];
        let parts = SignedRequestParts {
            method: "POST".to_owned(),
            target_uri,
            authority,
            path: url.path().to_owned(),
            headers,
            body_digest: Some(content_digest.wire_value.clone()),
        };
        let message = canonical_message(&parts, &signature_input)
            .map_err(|error| Error::Protocol(format!("canonical signature message: {error}")))?;
        let signature_header =
            format_signature_header("sig1", &sign_message(&message, signature.signing_key))
                .map_err(|error| Error::Protocol(format!("signature header: {error}")))?;

        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        let builder = self.apply_request_options(self.request(Method::POST, path)?, &options)?;
        let builder = builder
            .header(CONTENT_TYPE, "application/json")
            .header("Content-Digest", content_digest.wire_value)
            .header("Source-Service-ID", signature.source_service_id.to_string())
            .header(
                "Destination-Service-ID",
                signature.destination_service_id.to_string(),
            )
            .header("Signature-Input", signature_input_header)
            .header("Signature", signature_header)
            .body(body_bytes);
        self.send_json(builder).await
    }

    pub async fn applet_actor(&self, actor_id: &str) -> Result<AppletActorView> {
        reject_path_segment(actor_id)?;
        let path = format!("/_arkret/edge/applet/actors/{actor_id}");
        self.get(&path).await
    }

    pub async fn applet_realm(&self, realm_id_or_alias: &str) -> Result<AppletRealmView> {
        reject_path_segment(realm_id_or_alias)?;
        let path = format!("/_arkret/edge/applet/realms/{realm_id_or_alias}");
        self.get(&path).await
    }

    pub async fn applet_protocol(&self, protocol: &str) -> Result<AppletProtocolMetadata> {
        reject_path_segment(protocol)?;
        let path = format!("/_arkret/edge/applet/protocols/{protocol}");
        self.get(&path).await
    }

    /// Query third-party users for an applet.
    pub async fn applet_third_party_users(&self) -> Result<AppletThirdPartyUserList> {
        self.get("/_arkret/edge/applet/third_party/users").await
    }

    /// Query third-party locations for an applet.
    pub async fn applet_third_party_locations(&self) -> Result<AppletThirdPartyLocationList> {
        self.get("/_arkret/edge/applet/third_party/locations").await
    }

    pub async fn circle_list(&self, realm_id: &str) -> Result<CircleList> {
        let builder = self
            .request(Method::GET, "/_arkret/self/circles")?
            .query(&[("realm_id", realm_id)]);
        self.send_json(builder).await
    }

    pub async fn circle_get(&self, circle_id: &str) -> Result<CircleView> {
        reject_path_segment(circle_id)?;
        self.get(&format!("/_arkret/self/circles/{circle_id}"))
            .await
    }

    pub async fn circle_create(&self, request: &CircleCreateRequestBody) -> Result<CircleView> {
        self.post("/_arkret/self/circles", request).await
    }

    pub async fn circle_member_add(
        &self,
        circle_id: &str,
        request: &CircleMemberRequestBody,
    ) -> Result<CircleMembershipOutcome> {
        reject_path_segment(circle_id)?;
        self.post(
            &format!("/_arkret/self/circles/{circle_id}/members"),
            request,
        )
        .await
    }

    pub async fn circle_member_remove(
        &self,
        circle_id: &str,
        actor_id: &str,
    ) -> Result<CircleMembershipOutcome> {
        reject_path_segment(circle_id)?;
        reject_path_segment(actor_id)?;
        self.delete(&format!(
            "/_arkret/self/circles/{circle_id}/members/{actor_id}"
        ))
        .await
    }

    async fn circle_lifecycle(
        &self,
        circle_id: &str,
        action: &str,
        request: &CircleLifecycleRequestBody,
    ) -> Result<CircleView> {
        reject_path_segment(circle_id)?;
        reject_path_segment(action)?;
        self.post(
            &format!("/_arkret/self/circles/{circle_id}/{action}"),
            request,
        )
        .await
    }

    pub async fn circle_archive(
        &self,
        circle_id: &str,
        request: &CircleLifecycleRequestBody,
    ) -> Result<CircleView> {
        self.circle_lifecycle(circle_id, "archive", request).await
    }

    pub async fn circle_restore(
        &self,
        circle_id: &str,
        request: &CircleLifecycleRequestBody,
    ) -> Result<CircleView> {
        self.circle_lifecycle(circle_id, "restore", request).await
    }

    pub async fn circle_tombstone(
        &self,
        circle_id: &str,
        request: &CircleLifecycleRequestBody,
    ) -> Result<CircleView> {
        self.circle_lifecycle(circle_id, "tombstone", request).await
    }

    pub async fn circle_scope_rotate(
        &self,
        circle_id: &str,
        idempotency_key: &str,
        request: &CircleScopeRotateRequestBody,
    ) -> Result<CircleScopeRotateOutcome> {
        reject_path_segment(circle_id)?;
        let path = format!("/_arkret/self/circles/{circle_id}/scope-rotate");
        let options = ClientRequestOptions::new()
            .request_id(idempotency_key)
            .idempotency_key(idempotency_key);
        self.post_with_options(&path, request, &options).await
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
        let builder = self.canonical_json_body(self.request(Method::POST, path)?, body)?;
        self.send_json(builder).await
    }

    pub async fn post_with_options<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        options: &ClientRequestOptions,
    ) -> Result<R> {
        let builder = self.apply_request_options(self.request(Method::POST, path)?, options)?;
        self.send_json(self.canonical_json_body(builder, body)?)
            .await
    }

    /// Replay a caller-persisted canonical JSON body without serializing it
    /// again. This is intended for immutable signed-envelope transport retry.
    pub async fn post_canonical_bytes_with_options<R: DeserializeOwned>(
        &self,
        path: &str,
        body: &[u8],
        options: &ClientRequestOptions,
    ) -> Result<R> {
        let builder = self.apply_request_options(self.request(Method::POST, path)?, options)?;
        self.send_json(
            builder
                .header(CONTENT_TYPE, "application/json")
                .body(body.to_vec()),
        )
        .await
    }

    pub async fn put<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let builder = self.canonical_json_body(self.request(Method::PUT, path)?, body)?;
        self.send_json(builder).await
    }

    pub async fn put_with_options<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        options: &ClientRequestOptions,
    ) -> Result<R> {
        let builder = self.apply_request_options(self.request(Method::PUT, path)?, options)?;
        self.send_json(self.canonical_json_body(builder, body)?)
            .await
    }

    pub async fn delete<R: DeserializeOwned>(&self, path: &str) -> Result<R> {
        let builder = self.request(Method::DELETE, path)?;
        self.send_json(builder).await
    }
}

fn request_authority(url: &url::Url) -> Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::Protocol("applet transaction URL has no host".to_owned()))?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}
