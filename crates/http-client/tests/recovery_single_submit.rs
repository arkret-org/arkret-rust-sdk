//! Real transport binding; native authority authentication is verified separately.
#![cfg(not(target_arch = "wasm32"))]

use std::io::{Read, Write};

use arkret_http_client::{Auth, Client, DpopAuth};
use arkret_models_identity::RecoveryCompletionGrantRequestBody;
use serde_json::Value;

fn kat() -> Value {
    arkret_schema_conformance::spec_json_artifact(
        "fixtures/security-transaction-resilience-fixture.json",
    )
    .unwrap()["single_submit_recovery_kat"]
        .clone()
}

fn server(body: Value) -> (Client, std::thread::JoinHandle<Vec<u8>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut wire = Vec::new();
        let mut chunk = [0; 4096];
        let boundary = loop {
            let count = socket.read(&mut chunk).unwrap();
            assert!(count > 0);
            wire.extend_from_slice(&chunk[..count]);
            if let Some(index) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let head = String::from_utf8_lossy(&wire[..boundary]).to_ascii_lowercase();
        assert!(
            head.starts_with("post /_arkret/gate/account/recovery-session-grants/issue http/1.1")
        );
        assert!(head.contains(
            "arkret-operation: ak.gate.account.command.issue_recovery_completion_grant.v1"
        ));
        let length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        while wire.len() < boundary + length {
            let count = socket.read(&mut chunk).unwrap();
            assert!(count > 0);
            wire.extend_from_slice(&chunk[..count]);
        }
        let bytes = wire[boundary..boundary + length].to_vec();
        let body = body.to_string();
        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        bytes
    });
    let client = Client::builder(format!("http://{address}/").parse().unwrap())
        .allow_insecure_localhost()
        .auth(Auth::Dpop(DpopAuth::with_dpop_token(
            "fresh-bound-handoff",
            |_| Ok("transport-proof".into()),
        )))
        .build()
        .unwrap();
    (client, handle)
}

#[tokio::test]
async fn completion_issue_uses_original_receipt_and_fresh_holder_without_client_supplied_c() {
    let kat = kat();
    let request: RecoveryCompletionGrantRequestBody =
        serde_json::from_value(kat["completion_request"].clone()).unwrap();
    let (client, server) = server(kat["completion_expected_outcome"].clone());
    let response = client
        .issue_recovery_completion_grant(&request)
        .await
        .unwrap();
    assert_eq!(
        response.transaction_id,
        request.terminal_receipt.transaction_id
    );
    let sent = server.join().unwrap();
    assert_eq!(
        sent,
        arkret_canonical::canonical_json_bytes(&request).unwrap()
    );
    let sent: Value = serde_json::from_slice(&sent).unwrap();
    assert!(sent.get("completion_attestation").is_none());
    assert!(sent.get("transaction_request_digest").is_none());
}

#[tokio::test]
async fn completion_response_cannot_substitute_another_candidate() {
    let kat = kat();
    let request = serde_json::from_value(kat["completion_request"].clone()).unwrap();
    let mut response = kat["completion_expected_outcome"].clone();
    response["issued_session"]["device_id"] =
        Value::String("ak:device:019ba000-0000-7000-8000-000000000099".into());
    let (client, server) = server(response);
    assert!(
        client
            .issue_recovery_completion_grant(&request)
            .await
            .is_err()
    );
    server.join().unwrap();
}
