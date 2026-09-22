//! Push gateway endpoint methods on [`Client`].

use arkret_models_integration::{
    PushNotifyOutcome, PushNotifyRequestBody, PushRegisterDeviceOutcome,
    PushRegisterDeviceRequestBody, PushRegistrationHandoffOutcome,
    PushRegistrationHandoffRequestBody,
};
use arkret_signatures::http_signature::HttpSignatureScenario;
use arkret_wire::DidCoreId;
use reqwest::Method;
use reqwest::header::CONTENT_TYPE;

use crate::{Client, HEADER_DESTINATION_SERVICE_ID, HEADER_SOURCE_SERVICE_ID, Result};

impl Client {
    pub async fn push_register_device(
        &self,
        request: &PushRegisterDeviceRequestBody,
    ) -> Result<PushRegisterDeviceOutcome> {
        self.post("/_arkret/edge/push/register-device", request)
            .await
    }

    pub async fn push_notify(&self, request: &PushNotifyRequestBody) -> Result<PushNotifyOutcome> {
        self.post("/_arkret/edge/push/notify", request).await
    }

    /// Apply one complete active or revoked registration desired state to a
    /// trusted public Push Gateway.
    ///
    /// The client must be configured with [`crate::HttpMessageSigner`]. The
    /// call is signed with the generated service-to-service RFC 9421 scenario,
    /// including the exact source/destination service identities and body
    /// digest. Its body-owned registration identity makes exact transport
    /// replay safe under the operation registry contract.
    pub async fn push_apply_registration(
        &self,
        request: &PushRegistrationHandoffRequestBody,
        source_station_id: &DidCoreId,
        destination_gateway_id: &DidCoreId,
    ) -> Result<PushRegistrationHandoffOutcome> {
        request.validate()?;
        let body = arkret_canonical::canonical::canonical_json_bytes(request)?;
        let builder = self
            .service_request(Method::POST, "/_arkret/edge/push/registrations:apply")?
            .header(HEADER_SOURCE_SERVICE_ID, source_station_id.as_str())
            .header(
                HEADER_DESTINATION_SERVICE_ID,
                destination_gateway_id.as_str(),
            )
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        self.send_json_protocol_replay_safe_for_scenario(
            builder,
            HttpSignatureScenario::ServiceToServiceV1,
        )
        .await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use arkret_models_integration::{
        PushRegistrationHandoffState, PushRegistrationInstallationReceipt,
    };
    use arkret_signatures::http_signature::{
        SignatureVerificationPolicy, verify_signed_http_message,
    };
    use arkret_wire::{Audience, DidUrl, Hash, PayloadProof};
    use chrono::{DateTime, Utc};
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use url::Url;

    use super::*;
    use crate::{Auth, HttpMessageSigner};

    fn active_request() -> PushRegistrationHandoffRequestBody {
        serde_json::from_value(json!({
            "registration_id": "registration_0123456789abcdef",
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": "provider-secret",
            "platform": "apns",
            "visible_notification_opt_in": false
        }))
        .unwrap()
    }

    fn outcome(
        request: &PushRegistrationHandoffRequestBody,
        source: &DidCoreId,
        destination: &DidCoreId,
    ) -> PushRegistrationHandoffOutcome {
        let stored_at = DateTime::parse_from_rfc3339("2026-09-20T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut receipt = PushRegistrationInstallationReceipt {
            registration_id: request.registration_id().clone(),
            push_target_id: request.push_target_id().clone(),
            device_id: request.device_id().clone(),
            state: PushRegistrationHandoffState::Active,
            request_digest: request.request_digest().unwrap(),
            source_station_id: source.clone(),
            destination_gateway_id: destination.clone(),
            stored_at,
            proof: PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new("did:web:gateway.example#push-receipt-key")
                    .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: stored_at,
                domain: None,
                audience: Some(Audience::Single(source.as_str().to_owned())),
                proof_purpose: None,
                jws: "fixture..signature".to_owned(),
            },
        };
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        PushRegistrationHandoffOutcome { receipt }
    }

    async fn read_http_request(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut raw = Vec::new();
        let mut buffer = [0u8; 2048];
        loop {
            let count = socket.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            raw.extend_from_slice(&buffer[..count]);
            let Some(header_end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let headers = std::str::from_utf8(&raw[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                })
                .unwrap_or(0);
            if raw.len() >= header_end + 4 + content_length {
                break;
            }
        }
        raw
    }

    #[tokio::test]
    async fn apply_registration_uses_registered_service_signature_scenario() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let request = active_request();
        let source = DidCoreId::new("ak:did_core:web:source.example").unwrap();
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let response_body =
            serde_json::to_string(&outcome(&request, &source, &destination)).unwrap();
        let capture = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let raw = read_http_request(&mut socket).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.shutdown().await.ok();
            raw
        });

        let signing_key = SigningKey::from_bytes(&[71; 32]);
        let client = Client::builder(Url::parse(&format!("http://{addr}/")).unwrap())
            .allow_insecure_localhost()
            .http_message_signer(HttpMessageSigner::new(
                "did:web:source.example#service-key",
                signing_key.clone(),
            ))
            .auth(Auth::Bearer("must-not-forward-user-session".to_owned()))
            .build()
            .unwrap();
        let received = client
            .push_apply_registration(&request, &source, &destination)
            .await
            .unwrap();
        assert_eq!(
            received.receipt.request_digest,
            request.request_digest().unwrap()
        );

        let raw = capture.await.unwrap();
        let header_end = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        let head = std::str::from_utf8(&raw[..header_end]).unwrap();
        let body = &raw[header_end + 4..];
        let mut lines = head.lines();
        assert_eq!(
            lines.next().unwrap(),
            "POST /_arkret/edge/push/registrations:apply HTTP/1.1"
        );
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
            .collect::<Vec<_>>();
        let header = |name: &str| {
            headers
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
                .unwrap()
        };
        assert_eq!(
            header("Arkret-Operation"),
            "ak.edge.push.command.apply_registration.v1"
        );
        assert_eq!(header(HEADER_SOURCE_SERVICE_ID), source.as_str());
        assert_eq!(header(HEADER_DESTINATION_SERVICE_ID), destination.as_str());
        assert!(
            headers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("authorization")),
            "Gateway handoff must not forward account-client authorization"
        );

        let policy = SignatureVerificationPolicy::for_scenario(
            HttpSignatureScenario::ServiceToServiceV1,
            &["content-digest"],
        )
        .unwrap();
        verify_signed_http_message(
            "POST",
            &format!("http://{addr}/_arkret/edge/push/registrations:apply"),
            &addr.to_string(),
            "/_arkret/edge/push/registrations:apply",
            headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            body,
            &signing_key.verifying_key(),
            &policy,
            Utc::now().timestamp(),
        )
        .unwrap();
        let decoded: PushRegistrationHandoffRequestBody = serde_json::from_slice(body).unwrap();
        assert_eq!(decoded, request);
    }

    #[tokio::test]
    async fn apply_registration_fails_closed_without_http_message_signer() {
        let client = Client::builder(Url::parse("http://127.0.0.1:9/").unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();
        let error = client
            .push_apply_registration(
                &active_request(),
                &DidCoreId::new("ak:did_core:web:source.example").unwrap(),
                &DidCoreId::new("ak:did_core:web:gateway.example").unwrap(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("requires an HttpMessageSigner"));
    }
}
