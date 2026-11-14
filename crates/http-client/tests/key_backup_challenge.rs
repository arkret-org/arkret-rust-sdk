//! Received challenge validation on the real transport; no authority is inferred.
#![cfg(not(target_arch = "wasm32"))]

use std::io::{Read, Write};

use arkret_http_client::{Auth, Client, DpopAuth};
use arkret_models_crypto::{
    KeysBackupsIssueDeleteChallengeRequestBody, KeysBackupsIssueUnlockChallengeRequestBody,
};
use arkret_wire::BackupId;
use serde_json::{Value, json};

const BACKUP: &str = "ak:backup:01964137-1000-7000-8000-000000000001";

fn challenge(delete: bool) -> Value {
    let now = chrono::Utc::now();
    let mut value = json!({
        "challenge_id":"AAAAAAAAAAAAAAAAAAAAAA", "challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "operation": if delete {"ak.self.keys.backups.resource.delete.v1"} else {"ak.self.keys.backups.command.unlock.v1"},
        "account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:station.example"},
        "backup_id":BACKUP, "audience":null, "service_id":"ak:did_core:web:station.example",
        "request_id":"BBBBBBBBBBBBBBBBBBBBBB",
        "issued_at":arkret_canonical::canonical::format_timestamp_canonical(now),
        "expires_at":arkret_canonical::canonical::format_timestamp_canonical(now+chrono::Duration::seconds(300)),
    });
    if !delete {
        value["requesting_device_id"] = json!("ak:device:01964139-0000-7000-8000-000000000000");
        value["series_id"] = json!("ak:backup_series:01964137-1000-7000-8000-000000000000");
        value["ciphertext_digest"] = json!(format!("sha256:{}", "55".repeat(32)));
    }
    value
}

fn server(mut value: Value, delete: bool) -> (Client, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    if value["audience"].is_null() {
        value["audience"] = json!(origin);
    }
    let client = Client::builder(format!("{origin}/").parse().unwrap())
        .allow_insecure_localhost()
        .auth(Auth::Dpop(DpopAuth::with_dpop_token(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            |_| Ok("transport-proof".into()),
        )))
        .build()
        .unwrap();
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
            if let Some(index) = wire.windows(4).position(|value| value == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let head = String::from_utf8_lossy(&wire[..boundary]).to_ascii_lowercase();
        let suffix = if delete {
            "delete-challenge"
        } else {
            "unlock-challenge"
        };
        assert!(
            head.starts_with(
                &format!("post /_arkret/self/keys/backups/{BACKUP}/{suffix} http/1.1")
                    .to_ascii_lowercase()
            )
        );
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
        let request: Value = serde_json::from_slice(&wire[boundary..boundary + length]).unwrap();
        assert_eq!(request, json!({"request_id":"BBBBBBBBBBBBBBBBBBBBBB"}));
        let body = value.to_string();
        write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
    });
    (client, handle)
}

#[tokio::test]
async fn received_unlock_and_delete_challenges_are_closed_fresh_and_object_bound() {
    let backup = BackupId::new(BACKUP).unwrap();
    for delete in [false, true] {
        for mutation in [
            "valid",
            "retired_nonce",
            "noncanonical",
            "wrong_request",
            "wrong_backup",
            "wrong_origin",
            "wide_window",
            "expired",
        ] {
            let mut value = challenge(delete);
            match mutation {
                "retired_nonce" => value["nonce"] = json!("AAAAAAAAAAAAAAAAAAAAAA"),
                "noncanonical" => value["challenge"] = json!(format!("{}B", "A".repeat(42))),
                "wrong_request" => value["request_id"] = json!("CCCCCCCCCCCCCCCCCCCCCC"),
                "wrong_backup" => {
                    value["backup_id"] = json!("ak:backup:01964137-1000-7000-8000-000000000002")
                }
                "wrong_origin" => value["audience"] = json!("https://other.example"),
                "wide_window" => {
                    let issued: chrono::DateTime<chrono::Utc> =
                        value["issued_at"].as_str().unwrap().parse().unwrap();
                    value["expires_at"] =
                        json!(arkret_canonical::canonical::format_timestamp_canonical(
                            issued + chrono::Duration::milliseconds(300001)
                        ));
                }
                "expired" => {
                    let now = chrono::Utc::now();
                    value["issued_at"] =
                        json!(arkret_canonical::canonical::format_timestamp_canonical(
                            now - chrono::Duration::seconds(600)
                        ));
                    value["expires_at"] =
                        json!(arkret_canonical::canonical::format_timestamp_canonical(
                            now - chrono::Duration::seconds(300)
                        ));
                }
                _ => {}
            }
            let (client, server) = server(value, delete);
            let valid = if delete {
                let request: KeysBackupsIssueDeleteChallengeRequestBody =
                    serde_json::from_value(json!({"request_id":"BBBBBBBBBBBBBBBBBBBBBB"})).unwrap();
                client
                    .issue_key_backup_delete_challenge(&backup, &request)
                    .await
                    .is_ok()
            } else {
                let request: KeysBackupsIssueUnlockChallengeRequestBody =
                    serde_json::from_value(json!({"request_id":"BBBBBBBBBBBBBBBBBBBBBB"})).unwrap();
                client
                    .issue_key_backup_unlock_challenge(&backup, &request)
                    .await
                    .is_ok()
            };
            server.join().unwrap();
            assert_eq!(
                valid,
                mutation == "valid",
                "delete={delete},mutation={mutation}"
            );
        }
    }
}
