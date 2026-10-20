//! Typed provider interoperability using the registered MIMI signature scene.
use arkret_models_collaboration::mimi_operations::{
    MimiIdentifierQueryOutcome, MimiIdentifierQueryRequestBody, MimiKeyMaterialOutcome,
    MimiKeyMaterialRequestBody, MimiNotifyOutcome, MimiNotifyRequestBody, MimiProxyDownloadOutcome,
    MimiProxyDownloadRequestBody, MimiReportAbuseOutcome, MimiReportAbuseRequestBody,
    MimiRequestConsentOutcome, MimiRequestConsentRequestBody, MimiRoomUpdateOutcome,
    MimiRoomUpdateRequestBody, MimiSubmitMessageOutcome, MimiSubmitMessageRequestBody,
    MimiUpdateConsentOutcome, MimiUpdateConsentRequestBody,
};
use arkret_models_collaboration::objects::interop::ProviderDirectory;
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
    ) -> Result<MimiRequestConsentOutcome> {
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
    ) -> Result<MimiUpdateConsentOutcome> {
        request.validate_consent_event()?;
        request.signature_binding_bytes()?;
        let outcome: MimiUpdateConsentOutcome = self
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

    pub async fn mimi_request_key_material(
        &self,
        request: &MimiKeyMaterialRequestBody,
    ) -> Result<MimiKeyMaterialOutcome> {
        for proof in &request.proofs {
            request.proof_binding_bytes(proof)?;
        }
        let outcome: MimiKeyMaterialOutcome = self
            .mimi_post("/_arkret/open/mimi/key-material", request, false, false)
            .await?;
        outcome.validate()?;
        Ok(outcome)
    }

    pub async fn mimi_update_room(
        &self,
        room_id: &str,
        request: &MimiRoomUpdateRequestBody,
    ) -> Result<MimiRoomUpdateOutcome> {
        crate::reject_path_segment(room_id)?;
        request.validate()?;
        let outcome: MimiRoomUpdateOutcome = self
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
    ) -> Result<MimiNotifyOutcome> {
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
    ) -> Result<MimiIdentifierQueryOutcome> {
        request.validate()?;
        let outcome: MimiIdentifierQueryOutcome = self
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
    ) -> Result<MimiSubmitMessageOutcome> {
        crate::reject_path_segment(strand_id)?;
        let outcome: MimiSubmitMessageOutcome = self
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
    ) -> Result<MimiProxyDownloadOutcome> {
        self.mimi_post("/_arkret/open/mimi/proxy-download", request, false, false)
            .await
    }

    /// Public discovery must not forward account, Device or provider credentials.
    pub async fn mimi_provider_directory(
        &self,
        provider_id: Option<&str>,
        features: &[String],
    ) -> Result<ProviderDirectory> {
        let mut builder =
            self.public_request(Method::GET, "/_arkret/open/mimi/provider-directory")?;
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
        request.validate()?;
        self.mimi_post("/_arkret/open/mimi/report-abuse", request, false, true)
            .await
    }
}
