//! Applet endpoint methods on [`Client`].

use arkret_models_collaboration::account_lifecycle::AppletRevokeRequestBody;
use arkret_models_collaboration::http_bodies::AppletTransactionRequestBody;
use arkret_models_discovery::ServiceDescribe;
use arkret_models_integration::{
    AppletActorView, AppletInstallAuthorOutcome, AppletInstallAuthorRequestBody,
    AppletInstallOutcome, AppletInstallPreviewOutcome, AppletInstallPreviewRequestBody,
    AppletInstallRequestBody, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletRevokeOutcome, AppletRevokePreviewOutcome, AppletRevokePreviewRequestBody,
    AppletThirdPartyLocationList, AppletThirdPartyUserList, AppletTransactionOutcome,
};
use arkret_signatures::http_signature::{
    Component, ContentDigest, ContentDigestAlgorithm, SignedRequestParts, canonical_message,
    format_signature_header, format_signature_input_component_list, parse_signature_input,
    sign_message,
};
use arkret_wire::{DidCoreId, canonical};
use ed25519_dalek::SigningKey;
use reqwest::Method;
use reqwest::header::CONTENT_TYPE;
use url::Url;

use crate::{Client, ClientRequestOptions, Error, Result, reject_path_segment, validate_base_url};

pub struct SignedAppletTransactionOptions<'a> {
    pub source_service_id: &'a DidCoreId,
    pub destination_service_id: &'a DidCoreId,
    pub key_id: &'a str,
    pub signing_key: &'a SigningKey,
    pub created: Option<i64>,
    pub expires: Option<i64>,
}

impl Client {
    pub async fn applet_ping(&self) -> Result<AppletPingOutcome> {
        self.get("/_arkret/edge/applet/ping").await
    }

    pub async fn applet_describe(&self) -> Result<ServiceDescribe> {
        self.get("/_arkret/edge/applet/describe").await
    }

    pub async fn applet_install_preview(
        &self,
        request: &AppletInstallPreviewRequestBody,
    ) -> Result<AppletInstallPreviewOutcome> {
        self.post("/_arkret/self/applets/install/preview", request)
            .await
    }

    /// Relay a Principal-Server-signed authoring request to the Applet
    /// service without forwarding this client's Principal Server credentials.
    pub async fn applet_install_author_at(
        &self,
        applet_service_base_url: &Url,
        request: &AppletInstallAuthorRequestBody,
    ) -> Result<AppletInstallAuthorOutcome> {
        validate_base_url(applet_service_base_url, self.allow_insecure_localhost)?;
        let url = applet_author_url(applet_service_base_url)?;
        let mut builder = self
            .http
            .request(Method::POST, url)
            .header("Accept", "application/json")
            .header(CONTENT_TYPE, "application/json")
            .json(request);
        if let Some(user_agent) = &self.user_agent {
            builder = builder.header(reqwest::header::USER_AGENT, user_agent);
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(timeout) = self.default_timeout {
            builder = builder.timeout(timeout);
        }
        self.send_json(builder).await
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

    pub async fn applet_revoke_preview(
        &self,
        applet_id: &str,
        request: &AppletRevokePreviewRequestBody,
    ) -> Result<AppletRevokePreviewOutcome> {
        reject_path_segment(applet_id)?;
        let path = format!("/_arkret/self/applets/{applet_id}/revoke/preview");
        self.post(&path, request).await
    }

    pub async fn applet_revoke(
        &self,
        applet_id: &str,
        idempotency_key: &str,
        request: &AppletRevokeRequestBody,
    ) -> Result<AppletRevokeOutcome> {
        reject_path_segment(applet_id)?;
        let path = format!("/_arkret/self/applets/{applet_id}/revoke");
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options(&path, request, &options).await
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

fn applet_author_url(base_url: &Url) -> Result<Url> {
    base_url
        .join("/_arkret/edge/applet/install/author")
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::applet_author_url;

    #[test]
    fn author_endpoint_is_origin_absolute_even_when_base_url_has_a_path() {
        let base = url::Url::parse("https://applet.example/api/v1/").unwrap();
        assert_eq!(
            applet_author_url(&base).unwrap().as_str(),
            "https://applet.example/_arkret/edge/applet/install/author"
        );
    }
}
