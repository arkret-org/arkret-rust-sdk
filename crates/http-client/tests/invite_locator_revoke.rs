//! Actual HTTP transport and response correlation for explicit revocation.
#![cfg(not(target_arch = "wasm32"))]
use std::io::{Read, Write};

use arkret_http_client::{Auth, Client, DpopAuth, Error};
use arkret_models_collaboration::governance::invite_addressing::*;

#[tokio::test]
async fn revoke_posts_typed_body_with_dpop_and_rejects_another_locator() {
    let id = "ak:invite_locator:0196419b-0000-7000-8000-000000000000";
    for returned_id in [id, "ak:invite_locator:0196419b-0000-7000-8000-000000000001"] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
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
                if let Some(end) = bytes.windows(4).position(|p| p == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                    let length: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    if bytes.len() < end + 4 + length {
                        continue;
                    }
                    assert!(
                        head.starts_with(&format!("post /{INVITE_LOCATOR_REVOKE_PATH} http/1.1"))
                    );
                    assert!(head.contains("authorization: dpop session-token"));
                    assert!(head.contains("dpop: request-proof"));
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&bytes[end + 4..]).unwrap(),
                        serde_json::json!({"locator_id": id})
                    );
                    break;
                }
            }
            let body = serde_json::json!({"locator_id":returned_id,"revoked_at":"2026-10-20T00:00:00.000Z"}).to_string();
            write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        });
        let client = Client::builder(url::Url::parse(&format!("http://{address}/")).unwrap())
            .allow_insecure_localhost()
            .auth(Auth::Dpop(DpopAuth::with_dpop_token(
                "session-token",
                |request| {
                    assert!(request.htu.ends_with(INVITE_LOCATOR_REVOKE_PATH));
                    Ok("request-proof".into())
                },
            )))
            .build()
            .unwrap();
        let result = client
            .revoke_invite_locator(&InviteLocatorRevokeRequestBody {
                locator_id: arkret_wire::InviteLocatorId::new(id).unwrap(),
            })
            .await;
        server.join().unwrap();
        if returned_id == id {
            assert_eq!(result.unwrap().locator_id.as_str(), id);
        } else {
            assert!(matches!(result, Err(Error::Protocol(_))));
        }
    }
}
