//! Transport coverage only; native recovery authority is the server's obligation.
#![cfg(not(target_arch = "wasm32"))]

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use arkret_http_client::{Auth, Client, DpopAuth};
use arkret_schema_conformance::spec_json_artifact;
use serde_json::json;

#[tokio::test]
async fn preparation_get_binds_registered_operation_path_and_closed_response() {
    let f = spec_json_artifact("fixtures/content-history-fixture.json").unwrap();
    let encoding = &f["recovery_preparation_encoding"];
    let authorization: arkret_wire::EventId =
        serde_json::from_value(encoding["authorization_event_ref"].clone()).unwrap();
    let mut wrong_authorization = encoding["prepared"].clone();
    let mut other = authorization.to_string();
    let end = other.len();
    other.replace_range(end - 1.., "D");
    wrong_authorization["replacement"]["authorization_event_ref"] = json!(other);
    let mut wrong_phase = encoding["prepared"].clone();
    wrong_phase["state"] = json!("pending");
    let mut explicit_null = encoding["pending"].clone();
    explicit_null["inventory_blob_ref"] = json!(null);
    let mut extra = encoding["prepared"].clone();
    extra["ready"] = json!(true);
    for (body, valid) in [
        (encoding["pending"].clone(), true),
        (encoding["prepared"].clone(), true),
        (wrong_authorization, false),
        (wrong_phase, false),
        (explicit_null, false),
        (extra, false),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let expected_path = format!("/_arkret/self/mls/content-recoveries/{authorization}");
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let (mut socket, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("preparation GET did not arrive: {error}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut bytes = Vec::new();
            while !bytes.windows(4).any(|v| v == b"\r\n\r\n") {
                let mut buffer = [0; 4096];
                let n = socket.read(&mut buffer).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
                assert!(bytes.len() <= 64 * 1024);
            }
            let head = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
            assert!(head.starts_with(&format!(
                "get {} http/1.1",
                expected_path.to_ascii_lowercase()
            )));
            assert!(
                head.contains("arkret-operation: ak.self.mls.content_recovery.resource.get.v1")
            );
            assert!(head.contains("authorization: dpop session-token"));
            assert!(head.contains("dpop: request-proof"));
            assert!(!head.contains("transfer-encoding:"));
            assert!(!head.contains("content-length:") || head.contains("content-length: 0\r\n"));
            let body = body.to_string();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        });
        let client = Client::builder(url::Url::parse(&format!("http://{address}/")).unwrap())
            .allow_insecure_localhost()
            .timeout(Duration::from_secs(15))
            .auth(Auth::Dpop(DpopAuth::with_dpop_token(
                "session-token",
                |request| {
                    assert_eq!(request.method, "GET");
                    assert!(
                        request
                            .htu
                            .contains("/_arkret/self/mls/content-recoveries/")
                    );
                    Ok("request-proof".into())
                },
            )))
            .build()
            .unwrap();
        let outcome = client.self_mls_content_recovery(&authorization).await;
        server.join().unwrap();
        assert_eq!(outcome.is_ok(), valid, "{outcome:?}");
    }
}
