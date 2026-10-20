//! Real transport, closed response and register-identity checks for recovery reads.
#![cfg(not(target_arch = "wasm32"))]
use std::io::{Read, Write};

use arkret_http_client::{Auth, Client, DpopAuth};
use serde_json::json;

#[tokio::test]
async fn list_uses_authenticated_registered_get_and_rejects_incomplete_or_ambiguous_results() {
    let row = json!({"account_data_key":"ak.account.holder_quarantine","revision":7,
        "content":{"opaque":"service-owned"},"updated_at":"2026-10-20T00:00:00.000Z"});
    let mut invalid_key = row.clone();
    invalid_key["account_data_key"] = json!("bad/key");
    for (body, valid) in [
        (json!({"account_data_entries":[row.clone()]}), true),
        (json!({"account_data_entries":[]}), true),
        (json!({}), false),
        (
            json!({"account_data_entries":[],"next_cursor":"invented"}),
            false,
        ),
        (
            json!({"account_data_entries":[row.clone(),row.clone()]}),
            false,
        ),
        (json!({"account_data_entries":[invalid_key]}), false),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut bytes = Vec::new();
            while !bytes.windows(4).any(|v| v == b"\r\n\r\n") {
                let mut buffer = [0; 4096];
                let n = socket.read(&mut buffer).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
            }
            let head = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
            assert!(head.starts_with("get /_arkret/self/account_data http/1.1"));
            assert!(head.contains("authorization: dpop session-token"));
            assert!(head.contains("dpop: request-proof"));
            let body = body.to_string();
            write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        });
        let client = Client::builder(url::Url::parse(&format!("http://{address}/")).unwrap())
            .allow_insecure_localhost()
            .auth(Auth::Dpop(DpopAuth::with_dpop_token(
                "session-token",
                |request| {
                    assert_eq!(request.method, "GET");
                    assert!(request.htu.ends_with("/_arkret/self/account_data"));
                    Ok("request-proof".into())
                },
            )))
            .build()
            .unwrap();
        let outcome = client.account_data_list().await;
        server.join().unwrap();
        assert_eq!(outcome.is_ok(), valid, "{outcome:?}");
    }
}
