//! Applet endpoint methods on [`Client`].

use arkret_identity::VerifiedSubmission;
use arkret_models_discovery::ServiceDescribe;
use arkret_models_integration::{
    AppletActorView, AppletInstallPreviewRequestBody, AppletInstallPreviewResponseBody,
    AppletInstallRequestBody, AppletInstallResponseBody, AppletManagedActorAuthorRequestBody,
    AppletManagedActorAuthorResponseBody, AppletPingResponseBody, AppletProtocolMetadata,
    AppletRealmView, AppletRevokePreviewRequestBody, AppletRevokePreviewResponseBody,
    AppletRevokeRequestBody, AppletRevokeResponseBody, AppletTransactionRequestBody,
    AppletTransactionResponseBody, GhostPreviewRequestBody, GhostPreviewResponseBody,
};
use arkret_signatures::http_signature::HttpSignatureScenario;
use arkret_wire::DidCoreId;
use reqwest::Method;
use reqwest::header::CONTENT_TYPE;
use url::Url;

use crate::client_internals::validate_base_url;
use crate::{Client, ClientRequestOptions, Result, reject_path_segment};

struct MaterialCommitKeys<'a> {
    base: &'a (dyn arkret_identity::RealmAuthorityKeyDirectory + Sync),
    commit_key: Option<(
        arkret_wire::DidUrl,
        chrono::DateTime<chrono::Utc>,
        arkret_signatures::PublicKeyMaterial,
    )>,
}
impl arkret_identity::RealmAuthorityKeyDirectory for MaterialCommitKeys<'_> {
    fn public_key(
        &self,
        method: &arkret_wire::DidUrl,
    ) -> Option<arkret_signatures::PublicKeyMaterial> {
        self.base.public_key(method)
    }
    fn public_key_at(
        &self,
        method: &arkret_wire::DidUrl,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Option<arkret_signatures::PublicKeyMaterial> {
        self.commit_key
            .as_ref()
            .filter(|(kid, time, _)| kid == method && *time == at)
            .map(|(_, _, key)| key.clone())
            .or_else(|| self.base.public_key_at(method, at))
    }
}

impl Client {
    /// Forward an authenticated local Account's exact configuration request.
    /// This client must use the Account Station's Service HTTP signer.
    pub async fn peer_applet_configuration_submit(
        &self,
        destination: &DidCoreId,
        applet_id: &arkret_wire::AppletId,
        request: &arkret_models_integration::AppletConfigurationPeerRequestBody,
    ) -> Result<arkret_models_integration::AppletConfigurationResponseBody> {
        request.validate()?;
        reject_path_segment(applet_id.as_str())?;
        let path = format!("/_arkret/peer/applets/{applet_id}/configuration");
        let builder = self
            .service_request(Method::POST, &path)?
            .header(
                crate::HEADER_SOURCE_SERVICE_ID,
                request.requester_account_id.station_id.as_str(),
            )
            .header(crate::HEADER_DESTINATION_SERVICE_ID, destination.as_str())
            .header(CONTENT_TYPE, "application/json")
            .body(arkret_canonical::canonical_json_bytes(request)?);
        let outcome: arkret_models_integration::AppletConfigurationResponseBody = self
            .send_json_protocol_replay_safe_for_scenario(
                builder,
                HttpSignatureScenario::ServiceToServiceV1,
            )
            .await?;
        if outcome.request_id != request.request.intent.request_id
            || outcome.source_response_body.as_ref().is_some_and(|source| {
                source.request_id != outcome.request_id
                    || source.intent_digest != outcome.intent_digest
            })
        {
            return Err(crate::Error::Protocol(
                "peer configuration response differs from its request".into(),
            ));
        }
        Ok(outcome)
    }
    pub async fn applet_configuration_submit(
        &self,
        applet_id: &arkret_wire::AppletId,
        request: &arkret_models_integration::AppletConfigurationRequestBody,
    ) -> Result<arkret_models_integration::AppletConfigurationResponseBody> {
        request.validate()?;
        reject_path_segment(applet_id.as_str())?;
        let path = format!("/_arkret/self/applets/{applet_id}/configuration");
        let outcome: arkret_models_integration::AppletConfigurationResponseBody =
            self.post(&path, request).await?;
        if outcome.request_id != request.intent.request_id
            || outcome.source_response_body.as_ref().is_some_and(|source| {
                source.request_id != outcome.request_id
                    || source.intent_digest != outcome.intent_digest
            })
        {
            return Err(crate::Error::Protocol(
                "Applet configuration response differs from its request".into(),
            ));
        }
        Ok(outcome)
    }

    /// This client targets the independently resolved Applet Service origin.
    /// The returned source proof still requires verification against its
    /// authenticated Service identity before any candidate is submitted.
    pub async fn applet_configuration_execute(
        &self,
        idempotency_key: &str,
        request: &arkret_models_integration::AppletConfigurationExecutionRequestBody,
    ) -> Result<arkret_models_integration::AppletConfigurationExecutionResponseBody> {
        request.validate_at(chrono::Utc::now())?;
        let body = arkret_canonical::canonical_json_bytes(request)?;
        let builder = self
            .service_request(Method::POST, "/_arkret/edge/applet/configuration")?
            .header(
                crate::HEADER_SOURCE_SERVICE_ID,
                request.governance_station_id.as_str(),
            )
            .header(
                crate::HEADER_DESTINATION_SERVICE_ID,
                request.intent.service_id.as_str(),
            )
            .header(crate::HEADER_IDEMPOTENCY_KEY, idempotency_key)
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        let outcome: arkret_models_integration::AppletConfigurationExecutionResponseBody = self
            .send_json_protocol_replay_safe_for_scenario(
                builder,
                HttpSignatureScenario::ServiceToServiceV1,
            )
            .await?;
        outcome.validate_for(&request.intent)?;
        Ok(outcome)
    }

    /// Read this authenticated subject's effective grants at the governing Station.
    /// The response is a selection aid; Event admission revalidates all authority.
    pub async fn effective_grants(
        &self,
        realm: &arkret_wire::RealmId,
        subject: &arkret_wire::ActorId,
    ) -> Result<arkret_models_collaboration::governance::authorization::EffectiveGrantSnapshot>
    {
        let actor = String::from_utf8(arkret_canonical::canonical_json_bytes(subject)?)
            .map_err(|error| crate::Error::Protocol(error.to_string()))?;
        let request = self
            .request(Method::GET, "/_arkret/self/authz/effective-grants")?
            .query(&[
                ("realm_id", realm.as_str()),
                ("subject_actor_id", actor.as_str()),
            ]);
        self.send_json(request).await
    }

    pub async fn realm_actor_material(
        &self,
        request: &arkret_models_integration::RealmActorMaterialRequestBody,
        requester: &arkret_wire::ActorId,
        authority: &arkret_identity::VerifiedRealmAuthority,
        resolution: &arkret_models_identity::AuthenticatedServiceResolution,
        keys: &(dyn arkret_identity::RealmAuthorityKeyDirectory + Sync),
    ) -> Result<arkret_identity::VerifiedRealmActorMaterial> {
        request.validate()?;
        let outcome: arkret_models_integration::RealmActorMaterialResponseBody = self
            .post("/_arkret/self/realm-actors/material", request)
            .await?;
        outcome.validate_for_request(request, requester, chrono::Utc::now())?;
        let mut material_keys = MaterialCommitKeys {
            base: keys,
            commit_key: None,
        };
        if let arkret_models_integration::RealmActorMaterial::Event { commit, .. } =
            &outcome.material
        {
            let method = &commit.signature.verification_method;
            let did = arkret_identity::verification_method_did(method.as_str())
                .map_err(|e| crate::Error::Protocol(e.to_string()))?;
            let station = arkret_wire::project_did_to_core_id(&did)?;
            if !authority.authorizes_issuer_at(
                &station,
                Some(&commit.authority_ref),
                commit.committed_at,
            ) || authority.authority_service_at(commit.governance_generation) != Some(&station)
            {
                return Err(crate::Error::Protocol(
                    "private Event Commit has no verified issuing tenure".into(),
                ));
            }
            let history = if &station == authority.current_service_id() {
                resolution.clone()
            } else {
                self.resolve_service_from_did(&did, arkret_wire::ServiceKind::Station)
                    .await?
            };
            let document = arkret_identity::authenticated_service_document_at(
                &history,
                &station,
                commit.committed_at,
            )
            .map_err(|e| crate::Error::Protocol(e.to_string()))?;
            arkret_identity::validate_verification_method_relationship(
                &document,
                method,
                &document.id,
                arkret_identity::DidVerificationRelationship::AssertionMethod,
            )
            .map_err(|e| crate::Error::Protocol(e.to_string()))?;
            let key = arkret_identity::public_key_material_from_document(&document, method)
                .map_err(|e| crate::Error::Protocol(e.to_string()))?;
            material_keys.commit_key = Some((method.clone(), commit.signature.created_at, key));
        }
        arkret_identity::verify_realm_actor_material(
            outcome,
            request,
            requester,
            authority,
            resolution,
            &material_keys,
            chrono::Utc::now(),
        )
        .map_err(|error| crate::Error::Protocol(error.to_string()))
    }
    pub async fn applet_authority_material(
        &self,
        applet_id: &str,
        request: &arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialRequestBody,
    ) -> Result<
        arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialResponseBody,
    >{
        reject_path_segment(applet_id)?;
        let applet = arkret_wire::AppletId::new(applet_id.to_owned())?;
        request.validate()?;
        let (source, _) = self.service_signature_identity.as_ref().ok_or_else(|| {
            crate::Error::Protocol("Applet authority material requires a Service signer".into())
        })?;
        let material: arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialResponseBody = self.post(
            &format!("/_arkret/self/applets/{applet_id}/authority/material"),
            request,
        ).await?;
        material.validate_for_request(&applet, request)?;
        if &material.service_id != source {
            return Err(crate::Error::Protocol(
                "Applet material belongs to another authenticated Service".into(),
            ));
        }
        for result in &material.current_states {
            if let arkret_models_collaboration::exact_current_state::ExactCurrentStateReadResponseBody::Present {
                entry: arkret_models_collaboration::exact_current_state::ExactCurrentStateEntry::AppletRegistration(row), ..
            } = result {
                let _: arkret_models_integration::AppletRegistrationPayload =
                    serde_json::from_value(row.value.clone())?;
            }
        }
        let registration: arkret_models_integration::AppletRegistrationPayload =
            serde_json::from_value(serde_json::to_value(&material.registration.event.payload)?)?;
        if registration.applet_id != applet || registration.service_id != material.service_id {
            return Err(crate::Error::Protocol(
                "Applet material registration belongs to another Applet or Service".into(),
            ));
        }
        let service = arkret_wire::ActorId::service(registration.service_id.clone());
        for original in &material.grant_events {
            let payload: arkret_models_collaboration::events_payloads::capability::CapabilityGrantPayload =
                serde_json::from_value(serde_json::to_value(&original.event.payload)?)?;
            if !matches!(&payload.grant.subject, arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(subject) if subject == &service)
                || payload.grant.constraints.iter().filter(|constraint| {
                    constraint.constraint_kind == arkret_models_collaboration::governance::grant_constraint::GrantConstraintKind::AuthorityControl
                        && constraint.constraint_subkind == Some(arkret_models_collaboration::governance::grant_constraint::GrantConstraintSubkind::AppletAuthority)
                }).any(|binding| binding.registration_epoch.as_ref() != Some(&registration.registration_epoch))
            {
                return Err(crate::Error::Protocol("Applet material historical grants differ from their original registration Service or epoch".into()));
            }
        }
        Ok(material)
    }
    /// Configure a Service transport carrier; native Event proofs remain independent.
    pub fn with_service_http_signer(
        mut self,
        source: DidCoreId,
        destination: DidCoreId,
        signer: crate::HttpMessageSigner,
    ) -> Self {
        self.auth = None;
        self.own_station_context = None;
        self.realm_actor_control_signature_identity = None;
        self.mimi_provider_identity = None;
        self.http_message_signer = Some(signer);
        self.service_signature_identity = Some((source, destination));
        self.managed_device_signature_identity = None;
        self
    }
    /// Configure accepted Device transport. Every HTTP attempt, including an
    /// automatic retry, receives a fresh random nonce before signing.
    pub fn with_managed_device_http_signer(
        mut self,
        metadata: arkret_models_integration::AppletManagedDeviceMetadata,
        destination: DidCoreId,
        signer: crate::HttpMessageSigner,
    ) -> Result<Self> {
        metadata.validate()?;
        self.auth = None;
        self.own_station_context = None;
        self.realm_actor_control_signature_identity = None;
        self.mimi_provider_identity = None;
        self.http_message_signer = Some(signer);
        self.service_signature_identity = None;
        self.managed_device_signature_identity = Some((metadata, destination));
        Ok(self)
    }
    /// Configure only the registered Realm control HTTP scenario. This key
    /// cannot authenticate business content, Device inventory or login.
    pub fn with_realm_actor_control_http_signer(
        mut self,
        metadata: arkret_models_integration::RealmActorControlHttpMetadata,
        destination: DidCoreId,
        signer: crate::HttpMessageSigner,
    ) -> Result<Self> {
        metadata.validate()?;
        self.auth = None;
        self.own_station_context = None;
        self.http_message_signer = Some(signer);
        self.service_signature_identity = None;
        self.managed_device_signature_identity = None;
        self.mimi_provider_identity = None;
        self.realm_actor_control_signature_identity = Some((metadata, destination));
        Ok(self)
    }

    pub async fn applet_bot_preview(
        &self,
        applet_id: &str,
        request: &arkret_models_integration::AppletBotPreviewRequestBody,
    ) -> Result<arkret_models_integration::AppletBotPreviewResponseBody> {
        reject_path_segment(applet_id)?;
        self.post(
            &format!("/_arkret/self/applets/{applet_id}/bots/provision/preview"),
            request,
        )
        .await
    }
    pub async fn management_review_request(
        &self,
        request: &arkret_models_integration::ManagementReviewRequestBody,
    ) -> Result<arkret_models_integration::ManagementReviewResponseBody> {
        request.validate()?;
        self.post("/_arkret/self/management-reviews/requests", request)
            .await
    }
    pub async fn management_review_decide(
        &self,
        request: &arkret_models_integration::ManagementReviewDecisionRequestBody,
    ) -> Result<arkret_models_integration::ManagementReviewResponseBody> {
        request.validate()?;
        self.post("/_arkret/self/management-reviews/decisions", request)
            .await
    }
    pub async fn management_review_status(
        &self,
        request: &arkret_models_integration::ManagementReviewLookupRequestBody,
    ) -> Result<arkret_models_integration::ManagementReviewResponseBody> {
        self.post("/_arkret/self/management-reviews/status", request)
            .await
    }
    pub async fn applet_ping(&self) -> Result<AppletPingResponseBody> {
        self.get("/_arkret/edge/applet/ping").await
    }

    pub async fn applet_describe(&self) -> Result<ServiceDescribe> {
        self.get("/_arkret/edge/applet/describe").await
    }

    pub async fn applet_install_preview(
        &self,
        request: &AppletInstallPreviewRequestBody,
    ) -> Result<AppletInstallPreviewResponseBody> {
        self.post("/_arkret/self/applets/install/preview", request)
            .await
    }

    /// Relay a Station-signed authoring request to the Applet
    /// service without forwarding this client's Station credentials.
    pub async fn applet_managed_actor_author_at(
        &self,
        applet_service_base_url: &Url,
        request: &AppletManagedActorAuthorRequestBody,
    ) -> Result<AppletManagedActorAuthorResponseBody> {
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
        request: &VerifiedSubmission<AppletInstallRequestBody>,
    ) -> Result<AppletInstallResponseBody> {
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options("/_arkret/self/applets/install", request, &options)
            .await
    }

    pub async fn applet_revoke_preview(
        &self,
        applet_id: &str,
        request: &AppletRevokePreviewRequestBody,
    ) -> Result<AppletRevokePreviewResponseBody> {
        reject_path_segment(applet_id)?;
        let path = format!("/_arkret/self/applets/{applet_id}/revoke/preview");
        self.post(&path, request).await
    }

    pub async fn applet_revoke(
        &self,
        applet_id: &str,
        idempotency_key: &str,
        request: &VerifiedSubmission<AppletRevokeRequestBody>,
    ) -> Result<AppletRevokeResponseBody> {
        reject_path_segment(applet_id)?;
        let path = format!("/_arkret/self/applets/{applet_id}/revoke");
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options(&path, request, &options).await
    }

    pub async fn ghost_actor_preview(
        &self,
        applet_id: &str,
        request: &GhostPreviewRequestBody,
    ) -> Result<GhostPreviewResponseBody> {
        reject_path_segment(applet_id)?;
        let path = format!("/_arkret/self/applets/{applet_id}/ghosts/provision/preview");
        self.post(&path, request).await
    }

    pub async fn applet_transaction(
        &self,
        idempotency_key: &str,
        request: &VerifiedSubmission<AppletTransactionRequestBody>,
    ) -> Result<AppletTransactionResponseBody> {
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options("/_arkret/edge/applet/transactions", request, &options)
            .await
    }

    /// Send the registered transaction with the exact two service identities
    /// and the generated service-to-service RFC 9421 signature scenario.
    pub async fn applet_transaction_from_service(
        &self,
        idempotency_key: &str,
        request: &VerifiedSubmission<AppletTransactionRequestBody>,
        source_id: &DidCoreId,
        destination_id: &DidCoreId,
    ) -> Result<AppletTransactionResponseBody> {
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

    /// Query a known complete Realm actor as its current governing Station.
    /// The client must carry that Station's Service HTTP signer.
    pub async fn applet_actor(
        &self,
        source: &DidCoreId,
        destination: &DidCoreId,
        actor_id: &arkret_wire::ActorId,
    ) -> Result<AppletActorView> {
        actor_id.validate()?;
        if actor_id.as_realm_actor_id().is_none() {
            return Err(crate::Error::Protocol(
                "Applet lookup requires a Realm ActorId".into(),
            ));
        }
        let mut encoded = String::new();
        for byte in arkret_canonical::canonical_json_bytes(actor_id)? {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                encoded.push(char::from(byte));
            } else {
                use std::fmt::Write as _;
                let _ = write!(&mut encoded, "%{byte:02X}");
            }
        }
        let path = format!("/_arkret/edge/applet/actors/{encoded}");
        let request = self
            .service_request(Method::GET, &path)?
            .header(crate::HEADER_SOURCE_SERVICE_ID, source.as_str())
            .header(crate::HEADER_DESTINATION_SERVICE_ID, destination.as_str());
        let outcome: AppletActorView = self
            .send_json_protocol_replay_safe_for_scenario(
                request,
                HttpSignatureScenario::ServiceToServiceV1,
            )
            .await?;
        if !outcome.exists || outcome.actor_id.as_ref() != Some(actor_id) {
            return Err(crate::Error::Protocol(
                "Applet lookup returned another complete actor".into(),
            ));
        }
        Ok(outcome)
    }

    pub async fn applet_realm(
        &self,
        source: &DidCoreId,
        destination: &DidCoreId,
        realm_id_or_alias: &str,
    ) -> Result<AppletRealmView> {
        reject_path_segment(realm_id_or_alias)?;
        let path = format!("/_arkret/edge/applet/realms/{realm_id_or_alias}");
        let request = self
            .service_request(Method::GET, &path)?
            .header(crate::HEADER_SOURCE_SERVICE_ID, source.as_str())
            .header(crate::HEADER_DESTINATION_SERVICE_ID, destination.as_str());
        self.send_json_protocol_replay_safe_for_scenario(
            request,
            HttpSignatureScenario::ServiceToServiceV1,
        )
        .await
    }

    pub async fn applet_protocol(
        &self,
        source: &DidCoreId,
        destination: &DidCoreId,
        protocol: &str,
    ) -> Result<AppletProtocolMetadata> {
        reject_path_segment(protocol)?;
        let path = format!("/_arkret/edge/applet/protocols/{protocol}");
        let request = self
            .service_request(Method::GET, &path)?
            .header(crate::HEADER_SOURCE_SERVICE_ID, source.as_str())
            .header(crate::HEADER_DESTINATION_SERVICE_ID, destination.as_str());
        self.send_json_protocol_replay_safe_for_scenario(
            request,
            HttpSignatureScenario::ServiceToServiceV1,
        )
        .await
    }
}

fn applet_managed_actor_author_url(base_url: &Url) -> Result<Url> {
    base_url
        .join("/_arkret/edge/applet/managed-actors/author")
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::applet_managed_actor_author_url;

    #[test]
    fn author_endpoint_is_origin_absolute_even_when_base_url_has_a_path() {
        let base = url::Url::parse("https://applet.example/api/v1/").unwrap();
        assert_eq!(
            applet_managed_actor_author_url(&base).unwrap().as_str(),
            "https://applet.example/_arkret/edge/applet/managed-actors/author"
        );
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod authority_material_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod native_retry_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;

    use arkret_models_integration::AppletManagedDeviceMetadata;
    use arkret_signatures::http_signature::{
        HttpSignatureScenario, SignatureVerificationPolicy, verify_signed_canonical_json_message,
    };
    use arkret_signatures::{
        Ed25519DetachedJwsSigner, EventProofBuilder, PublicKeyMaterial, SignEventOptions,
        sign_event, verify_ed25519_detached_jws_proof_with_digest_suite,
    };
    use arkret_wire::{
        AccountId, ActorId, AppletId, AuthoredEvent, DeviceId, DidCoreId, Event,
        EventAdmissionSubmission, EventId, EventKind, ScopeRef, StrandId,
    };
    use ed25519_dalek::SigningKey;
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{Client, ClientRequestOptions, HttpMessageSigner, RetryConfig};

    async fn read_request(
        stream: &mut tokio::net::TcpStream,
    ) -> (String, Vec<(String, String)>, Vec<u8>) {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(offset) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break offset + 4;
            }
            assert!(bytes.len() < 64 * 1024);
        };
        let head = std::str::from_utf8(&bytes[..header_end]).unwrap();
        let mut lines = head.split("\r\n");
        let line = lines.next().unwrap().to_owned();
        let headers: Vec<_> = lines
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (name, value) = line.split_once(':').unwrap();
                (name.to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect();
        let length: usize = header(&headers, "content-length").parse().unwrap();
        while bytes.len() < header_end + length {
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&chunk[..count]);
        }
        assert_eq!(bytes.len(), header_end + length);
        (line, headers, bytes[header_end..].to_vec())
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
        let values: Vec<_> = headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .collect();
        assert_eq!(values.len(), 1, "exactly one {name}");
        values[0].1.as_str()
    }

    #[tokio::test]
    async fn realm_control_retry_refreshes_only_transport_nonce_and_rejects_business_operations() {
        use arkret_models_integration::{
            RealmActorControlHttpMetadata, RealmActorMaterialRequestBody,
        };
        use arkret_wire::{
            CommitStreamRef, CommittedEventRef, CurrentSelector, RealmActorId, RealmCommitId,
            RealmId,
        };
        let key = SigningKey::from_bytes(&[91; 32]);
        let method = "did:webvh:zcontrol:applet.example#managed-controller";
        let public = key.verifying_key();
        let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [92; 32]);
        let realm = RealmId::from_event_id(&event);
        let actor = ActorId::realm(RealmActorId {
            realm_id: realm.clone(),
            principal_id: DidCoreId::new("ak:did_core:webvh:zcontrol").unwrap(),
        });
        let station = DidCoreId::new("ak:did_core:webvh:zgovernor").unwrap();
        let metadata = RealmActorControlHttpMetadata {
            actor_id: actor.clone(),
            control_ref: CommittedEventRef {
                event_id: event,
                commit_id: RealmCommitId::from_digest([93; 32]),
                stream_ref: CommitStreamRef::RealmControl { realm_id: realm },
                stream_position: 7,
            },
            nonce: arkret_canonical::base64url_encode([94; 32]),
        };
        let body = RealmActorMaterialRequestBody::Current {
            actor_id: actor.clone(),
            request_nonce: arkret_canonical::base64url_encode([95; 32]),
            selectors: vec![CurrentSelector::RealmActorControl { actor_id: actor }],
        };
        let expected_body = arkret_canonical::canonical_json_bytes(&body).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let expected = metadata.clone();
        let receiver = tokio::spawn(async move {
            let path = "/_arkret/self/realm-actors/material";
            let target = format!("http://{address}{path}");
            let policy = SignatureVerificationPolicy::for_scenario(
                HttpSignatureScenario::RealmActorControlV1,
                &["content-digest", "idempotency-key"],
            )
            .unwrap();
            let mut nonces = BTreeSet::new();
            for attempt in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (line, headers, body) = read_request(&mut socket).await;
                assert_eq!(line, format!("POST {path} HTTP/1.1"));
                assert_eq!(body, expected_body);
                assert_eq!(header(&headers, "idempotency-key"), "exact-control-query");
                assert!(!headers.iter().any(|(name, _)| matches!(
                    name.as_str(),
                    "authorization" | "dpop" | "source-service-id" | "arkret-managed-device"
                )));
                let verified = verify_signed_canonical_json_message(
                    "POST",
                    &target,
                    &address.to_string(),
                    path,
                    headers.iter().map(|(name, value)| (name, value)),
                    false,
                    &body,
                    &public,
                    &policy,
                    chrono::Utc::now().timestamp(),
                )
                .unwrap();
                assert_eq!(verified.signature_input.key_id, method);
                let presented = RealmActorControlHttpMetadata::from_header_value(header(
                    &headers,
                    RealmActorControlHttpMetadata::HEADER,
                ))
                .unwrap();
                assert_eq!(presented.actor_id, expected.actor_id);
                assert_eq!(presented.control_ref, expected.control_ref);
                assert_ne!(presented.nonce, expected.nonce);
                assert!(nonces.insert(presented.nonce));
                let mut changed = headers.clone();
                changed
                    .iter_mut()
                    .find(|(name, _)| name == "destination-service-id")
                    .unwrap()
                    .1 = "ak:did_core:webvh:zanother".into();
                assert!(
                    verify_signed_canonical_json_message(
                        "POST",
                        &target,
                        &address.to_string(),
                        path,
                        changed.iter().map(|(name, value)| (name, value)),
                        false,
                        &body,
                        &public,
                        &policy,
                        chrono::Utc::now().timestamp()
                    )
                    .is_err()
                );
                let status = if attempt == 0 {
                    "503 Service Unavailable"
                } else {
                    "200 OK"
                };
                socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnull").as_bytes()).await.unwrap();
            }
        });
        let client = Client::builder(format!("http://{address}").parse().unwrap())
            .allow_insecure_localhost()
            .timeout(Duration::from_secs(5))
            .retry(
                RetryConfig {
                    base_delay: Duration::from_millis(1),
                    ..RetryConfig::standard(1)
                }
                .with_jitter(false),
            )
            .build()
            .unwrap()
            .with_realm_actor_control_http_signer(
                metadata,
                station,
                HttpMessageSigner::new(method, key),
            )
            .unwrap();
        for (method, path) in [
            (
                reqwest::Method::POST,
                "/_arkret/self/keys/keypackages/claim",
            ),
            (
                reqwest::Method::POST,
                "/_arkret/self/keys/keypackages/upload",
            ),
            (reqwest::Method::GET, "/_arkret/self/device_messages"),
        ] {
            assert!(
                arkret_wire::ServiceOperationId::from_http_request(method.as_str(), path).is_some()
            );
            assert!(
                client.request(method, path).is_err(),
                "control key must not authenticate {path}"
            );
        }
        let result: Value = client
            .post_with_options(
                "/_arkret/self/realm-actors/material",
                &body,
                &ClientRequestOptions::new().idempotency_key("exact-control-query"),
            )
            .await
            .unwrap();
        assert!(result.is_null());
        receiver.await.unwrap();
    }

    #[tokio::test]
    async fn managed_device_attempts_refresh_nonce_without_changing_original_event_or_idempotency()
    {
        for retries in [0, 1] {
            let device_key = SigningKey::from_bytes(&[81; 32]);
            let public_key = device_key.verifying_key();
            let fingerprint =
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(public_key.as_bytes());
            let method = format!("did:key:{fingerprint}#{fingerprint}");
            let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
            let account = AccountId::new(
                DidCoreId::new("ak:did_core:webvh:zmanaged").unwrap(),
                station.clone(),
            );
            let realm = arkret_wire::RealmId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [82; 32],
            ));
            let scope = ScopeRef::Realm {
                realm_id: realm.clone(),
            };
            let applet_id =
                AppletId::new("ak:applet:01964137-0000-7000-8000-000000000081").unwrap();
            let metadata = AppletManagedDeviceMetadata {
                actor_id: ActorId::realm(arkret_wire::RealmActorId {
                    realm_id: scope.realm_id().clone(),
                    principal_id: account.principal_id.clone(),
                }),
                device_id: DeviceId::new("ak:device:01964137-0000-7000-8000-000000000081").unwrap(),
                authorization_event_id: EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [83; 32],
                ),
                applet_id: applet_id.clone(),
                effective_scope: scope.clone(),
                nonce: arkret_canonical::base64url_encode([84; 16]),
            };
            let event = Event {
                event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [85; 32]),
                kind: EventKind::MessageCreate,
                realm_id: realm,
                scope_ref: scope,
                actor_id: metadata.actor_id.clone(),
                created_at: "2026-10-17T00:00:00.000Z".parse().unwrap(),
                semantic_refs: Vec::new(),
                payload: serde_json::from_value(json!({
                    "strand_id": StrandId::from_event_id(&EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [86; 32])),
                    "track_name": "discussion",
                    "content": {"kind": "ak.content.text", "body": "one immutable Device original"}
                })).unwrap(),
                executed_by: None,
                authorization_ref: Some(arkret_wire::GrantId::from_event_id(&EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [87; 32])).into()),
                applet_id: Some(applet_id),
                external_ref: None,
                producer_proof: None,
            };
            let mut authored = AuthoredEvent::finalize_with_digest_suite(
                event,
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();
            sign_event(
                &mut authored,
                &Ed25519DetachedJwsSigner::new(
                    device_key.clone(),
                    format!("did:webvh:zmanaged:managed.example#{}", metadata.device_id),
                ),
                SignEventOptions::new()
                    .with_created_at("2026-10-17T00:00:00.000Z".parse().unwrap()),
            )
            .unwrap();
            let submission = EventAdmissionSubmission::new(authored.into_event());
            let original = arkret_canonical::canonical::canonical_json_bytes(&submission).unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let target = format!("http://{address}/_arkret/self/events");
            let expected_station = station.clone();
            let expected_metadata = metadata.clone();
            let expected_body = original.clone();
            let expected_method = method.clone();
            // This receiver tests transport signatures and replay identity. It
            // does not fabricate Realm admission, Commit or authorization state.
            let receiver = tokio::spawn(async move {
                let mut nonces = BTreeSet::new();
                let mut originals = BTreeMap::new();
                let mut signatures = BTreeSet::new();
                let policy = SignatureVerificationPolicy::for_scenario(
                    HttpSignatureScenario::AppletManagedDeviceV1,
                    &["content-digest", "idempotency-key"],
                )
                .unwrap();
                for attempt in 0..=retries {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let (line, headers, body) = read_request(&mut stream).await;
                    assert_eq!(line, "POST /_arkret/self/events HTTP/1.1");
                    assert_eq!(body, expected_body);
                    assert_eq!(
                        header(&headers, "arkret-operation"),
                        "ak.self.events.command.submit.v1"
                    );
                    assert_eq!(
                        header(&headers, "destination-service-id"),
                        expected_station.as_str()
                    );
                    assert!(!headers.iter().any(|(name, _)| matches!(
                        name.as_str(),
                        "authorization" | "dpop" | "source-service-id"
                    )));
                    let verified = verify_signed_canonical_json_message(
                        "POST",
                        &target,
                        &address.to_string(),
                        "/_arkret/self/events",
                        headers.iter().map(|(name, value)| (name, value)),
                        false,
                        &body,
                        &public_key,
                        &policy,
                        chrono::Utc::now().timestamp(),
                    )
                    .unwrap();
                    assert_eq!(verified.signature_input.key_id, expected_method);
                    let presented = AppletManagedDeviceMetadata::from_header_value(header(
                        &headers,
                        AppletManagedDeviceMetadata::HEADER,
                    ))
                    .unwrap();
                    assert_ne!(presented.nonce, expected_metadata.nonce);
                    assert_eq!(
                        arkret_canonical::base64url_decode(&presented.nonce)
                            .unwrap()
                            .len(),
                        16
                    );
                    let mut identity = presented.clone();
                    identity.nonce = expected_metadata.nonce.clone();
                    assert_eq!(identity, expected_metadata);
                    assert!(
                        nonces.insert(presented.nonce.clone()),
                        "a consumed Device nonce cannot authenticate a retry"
                    );
                    assert!(signatures.insert(header(&headers, "signature").to_owned()));
                    let received: EventAdmissionSubmission = serde_json::from_slice(&body).unwrap();
                    let event = &received.event;
                    assert_eq!(event.actor_id, expected_metadata.actor_id);
                    assert!(
                        event
                            .producer_proof
                            .as_ref()
                            .unwrap()
                            .verification_method
                            .as_str()
                            .ends_with(expected_metadata.device_id.as_str())
                    );
                    verify_ed25519_detached_jws_proof_with_digest_suite(
                        event.producer_proof.as_ref().unwrap(),
                        &EventProofBuilder::new().envelope_bytes(event).unwrap(),
                        &event.actor_id,
                        &PublicKeyMaterial::Ed25519Raw {
                            bytes: public_key.to_bytes().to_vec(),
                        },
                        arkret_canonical::DigestSuite::Sha256,
                    )
                    .unwrap();
                    let key = header(&headers, "idempotency-key").to_owned();
                    if let Some(original) = originals.get(&key) {
                        assert_eq!(original, &body);
                    } else {
                        originals.insert(key, body.clone());
                    }
                    // Altering just the covered nonce invalidates this attempt.
                    let mut altered = headers.clone();
                    let mut altered_metadata = presented;
                    altered_metadata.nonce = expected_metadata.nonce.clone();
                    altered
                        .iter_mut()
                        .find(|(name, _)| {
                            name.eq_ignore_ascii_case(AppletManagedDeviceMetadata::HEADER)
                        })
                        .unwrap()
                        .1 = altered_metadata.to_header_value().unwrap();
                    assert!(
                        verify_signed_canonical_json_message(
                            "POST",
                            &target,
                            &address.to_string(),
                            "/_arkret/self/events",
                            altered.iter().map(|(name, value)| (name, value)),
                            false,
                            &body,
                            &public_key,
                            &policy,
                            chrono::Utc::now().timestamp()
                        )
                        .is_err()
                    );
                    let status = if attempt < retries {
                        "503 Service Unavailable"
                    } else {
                        "200 OK"
                    };
                    stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnull").as_bytes()).await.unwrap();
                }
                assert_eq!(nonces.len(), retries + 1);
                assert_eq!(originals.len(), 1);
            });
            let client = Client::builder(url::Url::parse(&format!("http://{address}/")).unwrap())
                .allow_insecure_localhost()
                .timeout(Duration::from_secs(10))
                .retry(
                    RetryConfig {
                        base_delay: Duration::from_millis(1),
                        ..RetryConfig::standard(retries)
                    }
                    .with_jitter(false),
                )
                .build()
                .unwrap()
                .with_managed_device_http_signer(
                    metadata,
                    station,
                    HttpMessageSigner::new(method, device_key),
                )
                .unwrap();
            let answer: Value = client
                .post_with_options(
                    "/_arkret/self/events",
                    &submission,
                    &ClientRequestOptions::new().idempotency_key("same-original-device-event"),
                )
                .await
                .unwrap();
            assert!(answer.is_null());
            receiver.await.unwrap();
            assert_eq!(
                arkret_canonical::canonical::canonical_json_bytes(&submission).unwrap(),
                original
            );
        }
    }
    #[tokio::test]
    async fn managed_device_claim_binds_original_transaction_id_across_real_http_attempts() {
        use arkret_models_crypto::{
            KeyPackagesClaimRequestBody, PeerKeyPackageRequesterAuthorization,
        };
        use ed25519_dalek::Signer as _;
        let key = SigningKey::from_bytes(&[92; 32]);
        let public = key.verifying_key();
        let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(public.as_bytes());
        let transport_method = format!("did:key:{fingerprint}#{fingerprint}");
        let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let account = AccountId::new(
            DidCoreId::new("ak:did_core:webvh:zmanaged").unwrap(),
            station.clone(),
        );
        let device = DeviceId::new("ak:device:01964137-0000-7000-8000-000000000092").unwrap();
        let authorization = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [93; 32]);
        let scope = ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [94; 32],
            )),
        };
        let metadata = AppletManagedDeviceMetadata {
            actor_id: ActorId::realm(arkret_wire::RealmActorId {
                realm_id: scope.realm_id().clone(),
                principal_id: account.principal_id.clone(),
            }),
            device_id: device.clone(),
            authorization_event_id: authorization.clone(),
            applet_id: AppletId::new("ak:applet:01964137-0000-7000-8000-000000000092").unwrap(),
            effective_scope: scope.clone(),
            nonce: arkret_canonical::base64url_encode([95; 16]),
        };
        let method = format!("did:webvh:zmanaged:managed.example#{device}");
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let mut entropy = [0u8; 32];
        getrandom::fill(&mut entropy).unwrap();
        let id = arkret_canonical::base64url_encode(entropy);
        let mut body:KeyPackagesClaimRequestBody=serde_json::from_value(json!({
            "claim_request_id":id,"target_actor_id":metadata.actor_id,"requester_actor_id":metadata.actor_id,"intended_realm_id":scope.realm_id(),"mls_group_id":scope.canonical_mls_group_id().unwrap(),"claim_purpose":"realm_membership","required_capabilities":["ak.content.v1"],
            "expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::Duration::minutes(1)),"target_device_ids":[device],"service_binding":{"source_id":station,"destination_id":station},
            "requester_authorization":{"kind":"realm_device","verification_method":method,"requester_device_id":device,"device_authorize_event_id":authorization,"signed_at":arkret_canonical::format_timestamp_canonical(at),"signature":{"kid":method,"signature_algorithm":"Ed25519","signature":"AA"}}
        })).unwrap();
        let input = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
            &body.unsigned_request(),
            &body.service_binding,
            &body.requester_authorization,
        )
        .unwrap();
        let PeerKeyPackageRequesterAuthorization::RealmDevice { signature, .. } =
            &mut body.requester_authorization
        else {
            unreachable!()
        };
        *signature = arkret_signatures::keypackages::keypackage_signature_from_bytes(
            &method,
            &key.sign(&input).to_bytes(),
        )
        .unwrap();
        body.validate_shape().unwrap();
        let original = arkret_canonical::canonical_json_bytes(&body).unwrap();
        let expected = original.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            let policy = SignatureVerificationPolicy::for_scenario(
                HttpSignatureScenario::AppletManagedDeviceV1,
                &["content-digest", "idempotency-key"],
            )
            .unwrap();
            let mut nonces = BTreeSet::new();
            // This receiver verifies the emitted request and signatures only.
            // It always refuses and never fabricates an accepted claim.
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (line, headers, bytes) = read_request(&mut stream).await;
                assert_eq!(line, "POST /_arkret/self/keys/keypackages/claim HTTP/1.1");
                assert_eq!(bytes, expected);
                assert_eq!(header(&headers, "idempotency-key"), id);
                assert!(!headers.iter().any(|(name, _)| matches!(
                    name.as_str(),
                    "authorization" | "dpop" | "source-service-id"
                )));
                assert_eq!(
                    header(&headers, "arkret-operation"),
                    "ak.self.keys.keypackages.command.claim.v1"
                );
                verify_signed_canonical_json_message(
                    "POST",
                    &format!("http://{address}/_arkret/self/keys/keypackages/claim"),
                    &address.to_string(),
                    "/_arkret/self/keys/keypackages/claim",
                    headers.iter().map(|(k, v)| (k, v)),
                    false,
                    &bytes,
                    &public,
                    &policy,
                    chrono::Utc::now().timestamp(),
                )
                .unwrap();
                let received: KeyPackagesClaimRequestBody = serde_json::from_slice(&bytes).unwrap();
                let input = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
                    &received.unsigned_request(),
                    &received.service_binding,
                    &received.requester_authorization,
                )
                .unwrap();
                let PeerKeyPackageRequesterAuthorization::RealmDevice {
                    verification_method,
                    signature,
                    ..
                } = &received.requester_authorization
                else {
                    unreachable!()
                };
                arkret_signatures::keypackages::verify_keypackage_signing_input(
                    public.as_bytes(),
                    verification_method.as_str(),
                    &input,
                    signature,
                )
                .unwrap();
                let metadata = AppletManagedDeviceMetadata::from_header_value(header(
                    &headers,
                    AppletManagedDeviceMetadata::HEADER,
                ))
                .unwrap();
                assert!(nonces.insert(metadata.nonce));
                let status = if attempt == 0 {
                    "503 Service Unavailable"
                } else {
                    "400 Bad Request"
                };
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/problem+json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").as_bytes()).await.unwrap();
            }
            assert_eq!(nonces.len(), 2);
        });
        let client = Client::builder(url::Url::parse(&format!("http://{address}/")).unwrap())
            .allow_insecure_localhost()
            .timeout(Duration::from_secs(10))
            .retry(
                RetryConfig {
                    base_delay: Duration::from_millis(1),
                    ..RetryConfig::standard(1)
                }
                .with_jitter(false),
            )
            .build()
            .unwrap()
            .with_managed_device_http_signer(
                metadata,
                station,
                HttpMessageSigner::new(transport_method, key),
            )
            .unwrap();
        assert!(client.keypackages_claim(&body).await.is_err());
        receiver.await.unwrap();
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&body).unwrap(),
            original
        );
    }
}
