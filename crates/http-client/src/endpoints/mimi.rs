//! Typed provider interoperability using the registered MIMI signature scene.
use arkret_models_collaboration::mimi_operations::{
    MimiIdentifierQueryRequestBody, MimiIdentifierQueryResponseBody, MimiNotifyRequestBody,
    MimiNotifyResponseBody, MimiProxyDownloadRequestBody, MimiProxyDownloadResponseBody,
    MimiReportAbuseRequestBody, MimiReportAbuseResponseBody, MimiRequestConsentRequestBody,
    MimiRequestConsentResponseBody, MimiRoomUpdateRequestBody, MimiRoomUpdateResponseBody,
    MimiSubmitMessageRequestBody, MimiSubmitMessageResponseBody, MimiUpdateConsentRequestBody,
    MimiUpdateConsentResponseBody,
};
use arkret_models_collaboration::objects::interop::ProviderDirectory;
use arkret_models_crypto::{KeyPackagesClaimRequestBody, PeerKeyPackagesClaimQueryResponseBody};
use arkret_signatures::http_signature::HttpSignatureScenario;
use arkret_wire::{DidCoreId, MimiRoomUri, MimiUri};
use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{
    Client, Error, HEADER_DESTINATION_SERVICE_ID, HEADER_SOURCE_SERVICE_ID, HttpMessageSigner,
    Result,
};

impl Client {
    /// Configure the actual provider Service identity, independently of actor
    /// operation proofs. Account and managed Device credentials are removed.
    /// The receiver still verifies the Service key's accepted authority.
    pub fn with_mimi_provider_http_signer(
        self,
        source: DidCoreId,
        destination: DidCoreId,
        provider_id: MimiUri,
        signer: HttpMessageSigner,
    ) -> Result<Self> {
        crate::client_internals::validate_header_value("Provider-ID", provider_id.as_str())?;
        arkret_wire::DidUrl::new(signer.key_id())
            .map_err(|error| Error::Protocol(error.to_owned()))?;
        let mut client = self.with_service_http_signer(source, destination, signer);
        client.mimi_provider_identity = Some((provider_id, None));
        Ok(client)
    }

    /// Bind room-scoped calls to the destination's canonical MIMI room URI.
    /// Source Provider-ID does not determine a destination room namespace.
    pub fn with_mimi_room(mut self, room: MimiRoomUri) -> Result<Self> {
        let (_, selected) = self.mimi_provider_identity.as_mut().ok_or_else(|| {
            Error::Protocol("MIMI room requires a configured provider Service signer".into())
        })?;
        *selected = Some(room);
        Ok(self)
    }

    async fn mimi_post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        request: &T,
        room_scoped: bool,
        replay_safe: bool,
    ) -> Result<R> {
        let (provider, room) = self.mimi_provider_identity.as_ref().ok_or_else(|| {
            Error::Protocol("MIMI operation requires a configured provider Service signer".into())
        })?;
        let (source, destination) = self.service_signature_identity.as_ref().ok_or_else(|| {
            Error::Protocol(
                "MIMI operation requires source and destination Service identities".into(),
            )
        })?;
        let mut builder = self
            .canonical_json_body(self.service_request(Method::POST, path)?, request)?
            .header(HEADER_SOURCE_SERVICE_ID, source.as_str())
            .header(HEADER_DESTINATION_SERVICE_ID, destination.as_str())
            .header("Provider-ID", provider.as_str());
        if room_scoped {
            let room = room.as_ref().ok_or_else(|| {
                Error::Protocol("room-scoped MIMI operation requires a canonical room URI".into())
            })?;
            builder = builder.header("MIMI-Room-URI", room.as_str());
        }
        if replay_safe {
            self.send_json_protocol_replay_safe_for_scenario(
                builder,
                HttpSignatureScenario::MimiProviderV1,
            )
            .await
        } else {
            self.send_json_for_scenario(builder, HttpSignatureScenario::MimiProviderV1)
                .await
        }
    }

    /// This creates an opaque correlation. An uncertain outcome requires
    /// manual confirmation; a second call is a new correlation, not recovery.
    pub async fn mimi_request_consent(
        &self,
        request: &MimiRequestConsentRequestBody,
    ) -> Result<MimiRequestConsentResponseBody> {
        request.validate()?;
        for proof in &request.proofs {
            request.proof_binding_bytes(proof)?;
        }
        self.mimi_post("/_arkret/open/mimi/consent/request", request, false, false)
            .await
    }

    /// Retry only the same caller-authored consent Event and its frozen proof.
    pub async fn mimi_update_consent(
        &self,
        request: &MimiUpdateConsentRequestBody,
    ) -> Result<MimiUpdateConsentResponseBody> {
        request.validate_consent_event()?;
        request.signature_binding_bytes()?;
        let outcome: MimiUpdateConsentResponseBody = self
            .mimi_post("/_arkret/open/mimi/consent/update", request, false, true)
            .await?;
        if outcome.consent_id != request.consent_id
            || outcome.decision != request.decision
            || outcome.event_ref != request.consent_event.event.event_id
        {
            return Err(Error::Protocol(
                "MIMI consent outcome does not match the exact carried Event".into(),
            ));
        }
        Ok(outcome)
    }

    /// Submit the original native claim to the MIMI adapter. Its identity,
    /// participant signature, ledger and receipt are shared with native claims.
    pub async fn mimi_request_key_material(
        &self,
        request: &KeyPackagesClaimRequestBody,
        source_trust_domain: &arkret_wire::TrustDomainId,
        destination_trust_domain: &arkret_wire::TrustDomainId,
    ) -> Result<PeerKeyPackagesClaimQueryResponseBody> {
        request
            .validate_shape()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if request.last_resort_allowed == Some(true)
            || !request
                .required_capabilities
                .iter()
                .any(|value| value.as_str() == "mimi.content.v1")
        {
            return Err(Error::Protocol(
                "MIMI requires single-use packages with mimi.content.v1".into(),
            ));
        }
        let (_, room) = self.mimi_provider_identity.as_ref().ok_or_else(|| {
            Error::Protocol("MIMI claim requires a configured source Station Service signer".into())
        })?;
        let room = room
            .as_ref()
            .ok_or_else(|| Error::Protocol("MIMI claim requires a canonical room URI".into()))?;
        let (source, destination) = self.service_signature_identity.as_ref().ok_or_else(|| {
            Error::Protocol("MIMI claim requires source and destination Station identities".into())
        })?;
        if source != &request.service_binding.source_id
            || destination != &request.service_binding.destination_id
        {
            return Err(Error::Protocol(
                "MIMI claim must retain its original source and destination Station".into(),
            ));
        }
        let builder = self
            .canonical_json_body(
                self.service_request(Method::POST, "/_arkret/open/mimi/key-material")?,
                request,
            )?
            .header(HEADER_SOURCE_SERVICE_ID, source.as_str())
            .header(HEADER_DESTINATION_SERVICE_ID, destination.as_str())
            .header("Provider-ID", source.as_str())
            .header("MIMI-Room-URI", room.as_str())
            .header(
                crate::HEADER_IDEMPOTENCY_KEY,
                request.claim_request_id.as_str(),
            )
            .header("Source-Trust-Domain", source_trust_domain.as_str())
            .header(
                "Destination-Trust-Domain",
                destination_trust_domain.as_str(),
            );
        let outcome: PeerKeyPackagesClaimQueryResponseBody = self
            .send_json_protocol_replay_safe_for_scenario(
                builder,
                HttpSignatureScenario::MimiProviderV1,
            )
            .await?;
        outcome
            .validate_command_shape()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if outcome.claim_request_id != request.claim_request_id {
            return Err(Error::Protocol(
                "MIMI result does not identify the original native claim".into(),
            ));
        }
        if let Some(claim) = &outcome.claim_outcome {
            let receipt = &claim.claim_receipt;
            if receipt.source_id != request.service_binding.source_id
                || receipt.destination_id != request.service_binding.destination_id
                || receipt.request_digest.as_str() != arkret_canonical::canonical_sha256(request)?
            {
                return Err(Error::Protocol(
                    "MIMI claim receipt does not bind the exact native request".into(),
                ));
            }
        }
        Ok(outcome)
    }

    pub async fn mimi_update_room(
        &self,
        room_id: &str,
        request: &MimiRoomUpdateRequestBody,
    ) -> Result<MimiRoomUpdateResponseBody> {
        crate::reject_path_segment(room_id)?;
        request.validate()?;
        let outcome: MimiRoomUpdateResponseBody = self
            .mimi_post(
                &format!("/_arkret/open/mimi/strands/{room_id}/update"),
                request,
                true,
                false,
            )
            .await?;
        if outcome.accepted
            && outcome.room_state_ref.as_ref()
                != request
                    .room_binding_event
                    .as_ref()
                    .map(|submission| &submission.event.event_id)
        {
            return Err(Error::Protocol(
                "MIMI room outcome does not match the exact carried Event".into(),
            ));
        }
        Ok(outcome)
    }

    pub async fn mimi_notify(
        &self,
        room_id: &str,
        request: &MimiNotifyRequestBody,
    ) -> Result<MimiNotifyResponseBody> {
        crate::reject_path_segment(room_id)?;
        self.mimi_post(
            &format!("/_arkret/open/mimi/strands/{room_id}/notify"),
            request,
            true,
            false,
        )
        .await
    }

    pub async fn mimi_identifier_query(
        &self,
        request: &MimiIdentifierQueryRequestBody,
    ) -> Result<MimiIdentifierQueryResponseBody> {
        request.validate()?;
        let outcome: MimiIdentifierQueryResponseBody = self
            .mimi_post(
                "/_arkret/open/mimi/identifiers/query",
                request,
                false,
                false,
            )
            .await?;
        // The contract binds every commitment, without imposing response order.
        let mut expected: Vec<_> = request
            .identifiers
            .iter()
            .map(|item| item.identifier_commitment.as_str())
            .collect();
        let mut actual: Vec<_> = outcome
            .matches
            .iter()
            .map(|item| item.identifier_commitment.as_str())
            .collect();
        expected.sort_unstable();
        actual.sort_unstable();
        if outcome.has_more
            || actual != expected
            || outcome.matches.iter().any(|found| {
                found.matched || found.mimi_uri.is_some() || found.subject_id.is_some()
            })
        {
            return Err(Error::Protocol(
                "MIMI identifier outcome violates the exact no-match contract".into(),
            ));
        }
        Ok(outcome)
    }

    pub async fn mimi_submit_message(
        &self,
        strand_id: &str,
        request: &MimiSubmitMessageRequestBody,
    ) -> Result<MimiSubmitMessageResponseBody> {
        crate::reject_path_segment(strand_id)?;
        let outcome: MimiSubmitMessageResponseBody = self
            .mimi_post(
                &format!("/_arkret/open/mimi/strands/{strand_id}/messages"),
                request,
                true,
                false,
            )
            .await?;
        outcome.validate()?;
        Ok(outcome)
    }

    pub async fn mimi_proxy_download(
        &self,
        request: &MimiProxyDownloadRequestBody,
    ) -> Result<MimiProxyDownloadResponseBody> {
        self.mimi_post("/_arkret/open/mimi/proxy-download", request, false, false)
            .await
    }

    /// Public discovery must not forward account, Device or provider credentials.
    pub async fn mimi_provider_directory(
        &self,
        authority: &crate::mimi_directory::MimiDirectoryAuthority,
        provider_id: Option<&MimiUri>,
        features: &[String],
    ) -> Result<crate::mimi_directory::VerifiedProviderDirectory> {
        authority.check_request_origin(self.base_url())?;
        let directory = self.read_mimi_directory_wire(provider_id, features).await?;
        authority.verify(directory, provider_id, features, chrono::Utc::now())
    }

    /// Consume a public result from the host's already accepted own Station.
    /// No DID resolution/history is fetched and this is not an independent
    /// provider proof. Current account/session UI guards remain the host's duty.
    pub async fn mimi_provider_directory_from_own_station(
        &self,
        binding: &arkret_models_discovery::StationConnectionBinding,
        provider_id: Option<&MimiUri>,
        features: &[String],
        max_age: chrono::Duration,
        egress: arkret_egress_policy::OutboundPolicy,
    ) -> Result<crate::mimi_directory::OwnStationProviderDirectory> {
        let context = crate::mimi_directory::OwnStationDirectoryRead::new(
            binding,
            self.base_url(),
            max_age,
            egress,
        )?;
        let directory = self.read_mimi_directory_wire(provider_id, features).await?;
        context.accept(directory, provider_id, features, chrono::Utc::now())
    }

    async fn read_mimi_directory_wire(
        &self,
        provider_id: Option<&MimiUri>,
        features: &[String],
    ) -> Result<ProviderDirectory> {
        let mut builder =
            self.public_request(Method::GET, "/_arkret/open/mimi/provider-directory")?;
        if let Some(provider_id) = provider_id {
            builder = builder.query(&[("provider_id", provider_id.as_str())]);
        }
        for feature in features {
            builder = builder.query(&[("features", feature)]);
        }
        self.send_json(builder).await
    }

    pub async fn mimi_report_abuse(
        &self,
        request: &MimiReportAbuseRequestBody,
    ) -> Result<MimiReportAbuseResponseBody> {
        request.validate()?;
        self.mimi_post("/_arkret/open/mimi/report-abuse", request, false, true)
            .await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod directory_transport_tests {
    use std::io::{Read, Write};

    use super::*;
    use crate::{Auth, DpopAuth};

    #[tokio::test]
    async fn shared_directory_get_never_forwards_account_or_provider_credentials() {
        for account in ["bearer", "dpop", "provider"] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let base = format!("http://{}/", listener.local_addr().unwrap());
            let captured = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(stream) => break stream,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && std::time::Instant::now() < deadline =>
                        {
                            std::thread::sleep(std::time::Duration::from_millis(2))
                        }
                        Err(error) => panic!("directory request did not arrive: {error}"),
                    }
                };
                // Accepted sockets can inherit nonblocking mode on macOS.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                while !bytes.windows(4).any(|v| v == b"\r\n\r\n") {
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]);
                }
                stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
                String::from_utf8(bytes).unwrap().to_ascii_lowercase()
            });
            let auth = if account == "dpop" {
                Auth::Dpop(DpopAuth::with_dpop_token("account-secret", |_| {
                    panic!("public directory must not request DPoP")
                }))
            } else {
                Auth::Bearer("account-secret".into())
            };
            let client = Client::builder(base.parse().unwrap())
                .allow_insecure_localhost()
                .auth(auth)
                .http_message_signer(HttpMessageSigner::new(
                    "did:web:source.example#key",
                    ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
                ))
                .build()
                .unwrap();
            let client = if account == "provider" {
                client
                    .with_mimi_provider_http_signer(
                        DidCoreId::new("ak:did_core:web:source.example").unwrap(),
                        DidCoreId::new("ak:did_core:web:destination.example").unwrap(),
                        MimiUri::new("mimi://source.example").unwrap(),
                        HttpMessageSigner::new(
                            "did:web:source.example#key",
                            ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
                        ),
                    )
                    .unwrap()
            } else {
                client
            };
            // Only the shared wire adapter is exercised over loopback HTTP;
            // both public directory APIs enforce HTTPS before calling it.
            assert!(client.read_mimi_directory_wire(None, &[]).await.is_err());
            let head = captured.join().unwrap();
            assert!(head.starts_with("get /_arkret/open/mimi/provider-directory "));
            for name in [
                "authorization",
                "dpop",
                "signature",
                "signature-input",
                "provider-id",
                "source-service-id",
                "destination-service-id",
            ] {
                assert!(
                    !head
                        .lines()
                        .any(|line| line.starts_with(&format!("{name}:"))),
                    "{name}"
                );
            }
        }
    }
}
