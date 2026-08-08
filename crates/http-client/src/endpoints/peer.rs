//! Typed service-authenticated peer query endpoints.

use arkret_models_collaboration::account_lifecycle::{
    AccountStatusAuthoringBasisOutcome, AccountStatusAuthoringBasisRequestBody,
};
use arkret_models_collaboration::contact_operations::{
    DeviceBootstrapDecisionOutcome, DeviceBootstrapDecisionRequestBody,
};
use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialOutcome, MlsGroupStateMaterialRequestBody,
};
use arkret_wire::{
    PATH_PEER_ACCOUNT_STATUS_AUTHORING_BASIS, PATH_PEER_DEVICE_BOOTSTRAP_DECISIONS,
    PATH_PEER_MLS_GROUP_STATE_MATERIAL,
};

use crate::{Client, Result};

impl Client {
    /// `POST /_arkret/peer/device-bootstrap-decisions`
    /// (`ak.peer.device_bootstrap.command.decide`). The body is canonicalized
    /// once and reused byte-for-byte on transport retry; the HTTP Message
    /// Signature remains the service-authentication boundary.
    pub async fn peer_device_bootstrap_decide(
        &self,
        request: &DeviceBootstrapDecisionRequestBody,
    ) -> Result<DeviceBootstrapDecisionOutcome> {
        request.validate()?;
        let outcome: DeviceBootstrapDecisionOutcome = self
            .post_protocol_replay_safe(PATH_PEER_DEVICE_BOOTSTRAP_DECISIONS, request)
            .await?;
        outcome.validate_against(request)?;
        Ok(outcome)
    }

    /// `POST /_arkret/peer/account-status/authoring-basis`
    /// (`ak.peer.account_status.read.authoring_basis`).
    pub async fn peer_account_status_authoring_basis(
        &self,
        request: &AccountStatusAuthoringBasisRequestBody,
    ) -> Result<AccountStatusAuthoringBasisOutcome> {
        request.validate()?;
        let outcome: AccountStatusAuthoringBasisOutcome = self
            .post(PATH_PEER_ACCOUNT_STATUS_AUTHORING_BASIS, request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// `POST /_arkret/peer/mls/group-state-material`
    /// (`ak.peer.mls.read.group_state_material`). This validates selectors,
    /// content-addressed refs, raw-byte digests, and response bounds. Callers
    /// then pass the decoded bytes to `arkret_mls::validate_public_group_state`.
    pub async fn peer_mls_group_state_material(
        &self,
        request: &MlsGroupStateMaterialRequestBody,
    ) -> Result<MlsGroupStateMaterialOutcome> {
        request.validate()?;
        let outcome: MlsGroupStateMaterialOutcome = self
            .post(PATH_PEER_MLS_GROUP_STATE_MATERIAL, request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_request_and_outcome() -> (DeviceBootstrapDecisionRequestBody, String) {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/device-bootstrap-fixture.json")
                .unwrap();
        let fence = &fixture["decision_fence"];
        let request = serde_json::from_value(fence["request"].clone()).unwrap();
        let mut receipt = fence["receipt_core"].clone();
        let object = receipt.as_object_mut().unwrap();
        object.insert(
            "receipt_digest".to_owned(),
            fence["expected_receipt_digest"].clone(),
        );
        object.insert("proof".to_owned(), fence["proof"].clone());
        let outcome = serde_json::json!({
            "transaction_id": fence["request"]["transaction_id"],
            "decision": "cancelled",
            "receipt": receipt,
        });
        (request, outcome.to_string())
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn read_http_request(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt;

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

    #[cfg(not(target_arch = "wasm32"))]
    fn request_body(raw: &[u8]) -> &[u8] {
        let header_end = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        &raw[header_end + 4..]
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn decision_fence_timeout_replays_exact_canonical_body() {
        use std::time::Duration;

        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;
        use url::Url;

        let (request, success_body) = fixture_request_and_outcome();
        let expected_body = arkret_canonical::canonical_json_bytes(&request).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let first_raw = read_http_request(&mut first).await;
            tokio::time::sleep(Duration::from_millis(80)).await;
            drop(first);

            let (mut second, _) = listener.accept().await.unwrap();
            let second_raw = read_http_request(&mut second).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                success_body.len(),
                success_body
            );
            second.write_all(response.as_bytes()).await.unwrap();
            (first_raw, second_raw)
        });

        let client = Client::builder(Url::parse(&format!("http://{address}/")).unwrap())
            .allow_insecure_localhost()
            .timeout(Duration::from_millis(40))
            .retry(
                crate::RetryConfig::standard(1)
                    .with_base_delay(Duration::from_millis(1))
                    .with_jitter(false),
            )
            .build()
            .unwrap();
        client.peer_device_bootstrap_decide(&request).await.unwrap();

        let (first, second) = server.await.unwrap();
        assert!(
            std::str::from_utf8(&first)
                .unwrap()
                .starts_with("POST /_arkret/peer/device-bootstrap-decisions ")
        );
        assert_eq!(request_body(&first), expected_body);
        assert_eq!(request_body(&second), expected_body);
        assert_eq!(request_body(&first), request_body(&second));
    }
}
