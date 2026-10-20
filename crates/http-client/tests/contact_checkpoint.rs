//! Actual HTTP command dispatch and closed checkpoint outcome consumption.
#![cfg(not(target_arch = "wasm32"))]
use std::io::{Read, Write};

use arkret_http_client::{Auth, Client, DpopAuth};
use arkret_models_collaboration::contact_operations::*;
use serde_json::json;

#[tokio::test]
async fn checkpoint_posts_fixed_request_and_does_not_accept_uncommitted_success() {
    let holder = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    );
    let peer = ContactPeer::Human {
        account_id: arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            holder.station_id.clone(),
        ),
    };
    let request = ContactContinuityCheckpointRequestBody {
        idempotency_key: arkret_wire::IdempotencyKey::new("frozen-attempt").unwrap(),
        peer,
    };
    for (status, extra, valid) in [
        ("pending", json!({}), true),
        ("committed", json!({}), false),
        ("pending", json!({"continuity_evidence":null}), false),
        ("pending", json!({"invented":true}), false),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let expected = serde_json::to_value(&request).unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut buffer = [0; 4096];
                let n = socket.read(&mut buffer).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                    let length: usize = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    if bytes.len() < end + 4 + length {
                        continue;
                    }
                    assert!(
                        head.starts_with(
                            "post /_arkret/self/contacts/continuity-checkpoint http/1.1"
                        )
                    );
                    assert!(
                        head.contains("authorization: dpop session-token")
                            && head.contains("dpop: request-proof")
                    );
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&bytes[end + 4..]).unwrap(),
                        expected
                    );
                    break;
                }
            }
            let mut body =
                json!({"status":status,"checkpoint_digest":format!("sha256:{}","a".repeat(64))});
            body.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let body = body.to_string();
            write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        });
        let client = Client::builder(url::Url::parse(&format!("http://{address}")).unwrap())
            .allow_insecure_localhost()
            .auth(Auth::Dpop(DpopAuth::with_dpop_token(
                "session-token",
                |_| Ok("request-proof".into()),
            )))
            .build()
            .unwrap();
        let result = client.contacts_checkpoint(&holder, &request).await;
        server.join().unwrap();
        assert_eq!(result.is_ok(), valid, "{result:?}");
    }
}
