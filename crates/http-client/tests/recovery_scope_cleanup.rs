//! Exact registered transport and closed response bindings, not Native admission.
#![cfg(not(target_arch = "wasm32"))]

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use arkret_http_client::{Auth, Client, DpopAuth};
use arkret_models_crypto::{
    ContentRecoveryScopeCleanupAuthorization, ContentRecoveryScopeCleanupRequestBody,
};
use arkret_schema_conformance::spec_json_artifact;
use serde_json::{Value, json};

fn server(body: Value, request: Value) -> (String, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(error) => panic!("cleanup POST missing: {error}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 4096];
        let end = loop {
            if let Some(index) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                break index + 4;
            }
            let count = socket.read(&mut buffer).unwrap();
            assert!(count > 0 && bytes.len() < 65536);
            bytes.extend_from_slice(&buffer[..count]);
        };
        let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
        assert!(headers.starts_with("post /_arkret/self/mls/recovery-scope-cleanup http/1.1"));
        assert!(
            headers.contains("arkret-operation: ak.self.mls.command.reconcile_recovery_scope.v1")
        );
        assert!(headers.contains("authorization: dpop cleanup-session"));
        assert!(headers.contains("dpop: cleanup-proof"));
        let length = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .unwrap()
            .trim()
            .parse::<usize>()
            .unwrap();
        while bytes.len() < end + length {
            let count = socket.read(&mut buffer).unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&buffer[..count]);
        }
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes[end..end + length]).unwrap(),
            request
        );
        let body = body.to_string();
        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    });
    (base, handle)
}

#[tokio::test]
async fn cleanup_post_uses_full_request_and_refuses_wrong_proof_or_pending_disclosure() {
    let f = spec_json_artifact("fixtures/content-history-fixture.json").unwrap();
    let f = &f["scope_retirement"];
    let source: ContentRecoveryScopeCleanupAuthorization =
        serde_json::from_value(f["authorization"].clone()).unwrap();
    let request = ContentRecoveryScopeCleanupRequestBody {
        authorization_event_ref: source.replacement.authorization_event_ref,
        inventory_digest: source.inventory_digest,
        effective_scope: source.inventory_entry.effective_scope,
        genesis_event_ref: source.inventory_entry.genesis_event_ref,
        nonce_base64url: source.nonce_base64url,
        delivery_challenge_base64url: source.delivery_challenge_base64url,
    };
    let valid = f["self_deliveries"]["removed"].clone();
    let mut wrong_challenge = valid.clone();
    wrong_challenge["delivery"]["delivery_attestation"]["delivery_challenge_base64url"] =
        json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let mut wrong_digest = valid.clone();
    wrong_digest["attestor_signing_key"]["proof_digest"] =
        json!(format!("sha256:{}", "00".repeat(32)));
    let mut disclosed = json!({"delivery":{"state":"pending"}});
    disclosed["attestor_signing_key"] = valid["attestor_signing_key"].clone();
    for (body, accepted) in [
        (valid, true),
        (json!({"delivery":{"state":"pending"}}), true),
        (wrong_challenge, false),
        (wrong_digest, false),
        (disclosed, false),
    ] {
        let (base, server) = server(body, serde_json::to_value(&request).unwrap());
        let client = Client::builder(url::Url::parse(&base).unwrap())
            .allow_insecure_localhost()
            .auth(Auth::Dpop(DpopAuth::with_dpop_token(
                "cleanup-session",
                |request| {
                    assert_eq!(request.method, "POST");
                    Ok("cleanup-proof".into())
                },
            )))
            .build()
            .unwrap();
        assert_eq!(
            client
                .self_mls_reconcile_recovery_scope(&request)
                .await
                .is_ok(),
            accepted
        );
        server.join().unwrap();
    }
}
