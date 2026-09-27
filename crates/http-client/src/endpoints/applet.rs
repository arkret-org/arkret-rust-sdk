//! Applet endpoint methods on [`Client`].

use arkret_models_discovery::ServiceDescribe;
use arkret_models_integration::{
    AppletActorView, AppletInstallOutcome, AppletInstallPreviewOutcome,
    AppletInstallPreviewRequestBody, AppletInstallRequestBody, AppletManagedActorAuthorOutcome,
    AppletManagedActorAuthorRequestBody, AppletPingOutcome, AppletProtocolMetadata,
    AppletRealmView, AppletRevokeOutcome, AppletRevokePreviewOutcome,
    AppletRevokePreviewRequestBody, AppletRevokeRequestBody, AppletTransactionOutcome,
    AppletTransactionRequestBody, GhostActorProvisionOutcome, GhostActorProvisionRequestBody,
    GhostPreviewOutcome, GhostPreviewRequestBody,
};
use arkret_signatures::http_signature::HttpSignatureScenario;
use arkret_wire::DidCoreId;
use reqwest::Method;
use reqwest::header::CONTENT_TYPE;
use url::Url;

use crate::client_internals::validate_base_url;
use crate::{Client, ClientRequestOptions, Result, reject_path_segment};

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

    /// Relay a Station-signed authoring request to the Applet
    /// service without forwarding this client's Station credentials.
    pub async fn applet_managed_actor_author_at(
        &self,
        applet_service_base_url: &Url,
        request: &AppletManagedActorAuthorRequestBody,
    ) -> Result<AppletManagedActorAuthorOutcome> {
        validate_base_url(applet_service_base_url, self.allow_insecure_localhost)?;
        let url = applet_managed_actor_author_url(applet_service_base_url)?;
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

    /// Provision an Applet-managed Ghost actor through the canonical self
    /// operation `ak.self.applet.ghost.command.provision.v1`.
    pub async fn ghost_actor_provision(
        &self,
        applet_id: &str,
        idempotency_key: &str,
        request: &GhostActorProvisionRequestBody,
    ) -> Result<GhostActorProvisionOutcome> {
        let path = ghost_actor_provision_path(applet_id)?;
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options(&path, request, &options).await
    }

    pub async fn ghost_actor_preview(
        &self,
        applet_id: &str,
        request: &GhostPreviewRequestBody,
    ) -> Result<GhostPreviewOutcome> {
        reject_path_segment(applet_id)?;
        let path = format!("/_arkret/self/applets/{applet_id}/ghosts/provision/preview");
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

    /// Send the registered transaction with the exact two service identities
    /// and the generated service-to-service RFC 9421 signature scenario.
    pub async fn applet_transaction_from_service(
        &self,
        idempotency_key: &str,
        request: &AppletTransactionRequestBody,
        source_id: &DidCoreId,
        destination_id: &DidCoreId,
    ) -> Result<AppletTransactionOutcome> {
        request.validate()?;
        if request.source_id() != source_id {
            return Err(crate::Error::Protocol(
                "Applet body source differs from its authenticated service".to_owned(),
            ));
        }
        let body = arkret_canonical::canonical::canonical_json_bytes(request)?;
        let builder = self
            .service_request(Method::POST, "/_arkret/edge/applet/transactions")?
            .header(crate::HEADER_SOURCE_SERVICE_ID, source_id.as_str())
            .header(
                crate::HEADER_DESTINATION_SERVICE_ID,
                destination_id.as_str(),
            )
            .header(crate::HEADER_IDEMPOTENCY_KEY, idempotency_key)
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        self.send_json_protocol_replay_safe_for_scenario(
            builder,
            HttpSignatureScenario::ServiceToServiceV1,
        )
        .await
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
}

fn ghost_actor_provision_path(applet_id: &str) -> Result<String> {
    reject_path_segment(applet_id)?;
    Ok(format!(
        "/_arkret/self/applets/{applet_id}/ghosts/provision"
    ))
}

fn applet_managed_actor_author_url(base_url: &Url) -> Result<Url> {
    base_url
        .join("/_arkret/edge/applet/managed-actors/author")
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{applet_managed_actor_author_url, ghost_actor_provision_path};

    #[test]
    fn author_endpoint_is_origin_absolute_even_when_base_url_has_a_path() {
        let base = url::Url::parse("https://applet.example/api/v1/").unwrap();
        assert_eq!(
            applet_managed_actor_author_url(&base).unwrap().as_str(),
            "https://applet.example/_arkret/edge/applet/managed-actors/author"
        );
    }

    #[test]
    fn ghost_applet_id_is_one_safe_path_segment() {
        assert_eq!(
            ghost_actor_provision_path("ak:applet:01904100-0000-7000-8000-000000000001").unwrap(),
            "/_arkret/self/applets/ak:applet:01904100-0000-7000-8000-000000000001/ghosts/provision"
        );
        assert!(ghost_actor_provision_path("../other/ghosts").is_err());
        assert!(ghost_actor_provision_path("applet%2Fescape").is_err());
    }
}
