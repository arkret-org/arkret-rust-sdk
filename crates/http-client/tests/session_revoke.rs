//! Request identity and response binding on the real TCP transport.
#![cfg(not(target_arch = "wasm32"))]
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arkret_http_client::{Auth, Client, DpopAuth, RetryConfig};
use arkret_models_collaboration::account_lifecycle::{
    AccountLifecycleProof, AccountLifecycleProofKind, SessionRevokeRequestBody,
};
use arkret_wire::{DidCoreId, Hash, SessionGrantId};
use serde_json::{Value, json};

fn body() -> SessionRevokeRequestBody {
    serde_json::from_value(json!({})).unwrap()
}
fn proof() -> AccountLifecycleProof {
    let now = chrono::Utc::now();
    AccountLifecycleProof {
        proof_kind: AccountLifecycleProofKind::DidBoundSignature,
        challenge: "frozen-lifecycle-challenge".into(),
        request_canonical_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        audience_id: DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        issued_at: now,
        expires_at: now + chrono::Duration::minutes(4),
        verification_method: None,
        signature: "frozen-inner-signature".into(),
    }
}
fn server(
    responses: Vec<(u16, Value)>,
) -> (
    Client,
    std::thread::JoinHandle<Vec<(String, Vec<u8>)>>,
    Arc<AtomicUsize>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut captured = Vec::new();
        for (status, response) in responses {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0; 4096];
            let boundary = loop {
                let n = socket.read(&mut chunk).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(p) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                    break p + 4;
                }
            };
            let head = String::from_utf8(bytes[..boundary].to_vec())
                .unwrap()
                .to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|v| v.strip_prefix("content-length: "))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            while bytes.len() < boundary + length {
                let n = socket.read(&mut chunk).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
            }
            assert!(head.starts_with("post /_arkret/gate/account/session-grants/revoke http/1.1"));
            assert!(head.contains("arkret-operation: ak.gate.account.command.revoke_session.v1"));
            assert!(head.contains("authorization: dpop session-token"));
            let payload = bytes[boundary..boundary + length].to_vec();
            assert_eq!(
                arkret_canonical::canonical_json_bytes(
                    &serde_json::from_slice::<Value>(&payload).unwrap()
                )
                .unwrap(),
                payload
            );
            captured.push((head, payload));
            let response = response.to_string();
            write!(socket,"HTTP/1.1 {status} response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).unwrap();
        }
        captured
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let mut retry = RetryConfig::standard(1);
    retry.base_delay = std::time::Duration::ZERO;
    retry.max_delay = std::time::Duration::ZERO;
    retry.jitter = false;
    let client = Client::builder(base.parse().unwrap())
        .allow_insecure_localhost()
        .retry(retry)
        .auth(Auth::Dpop(DpopAuth::with_dpop_token(
            "session-token",
            move |_| Ok(format!("proof-{}", counter.fetch_add(1, Ordering::SeqCst))),
        )))
        .build()
        .unwrap();
    (client, handle, calls)
}
#[tokio::test]
async fn current_revoke_freezes_identity_across_transport_and_explicit_retry() {
    let id = SessionGrantId::from_issuance_digest([5; 32]);
    let response = json!({"revoked_count":1,"revoked_session_grant_ids":[id]});
    let (sdk, server, calls) = server(vec![
        (503, json!({})),
        (200, response.clone()),
        (200, response),
    ]);
    let attempt = sdk.prepare_session_grant_revoke(&id, &body()).unwrap();
    let first = attempt.send().await.unwrap();
    assert_eq!(attempt.send().await.unwrap(), first);
    let captured = server.join().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(captured.iter().all(|v| v == &captured[0]));
    assert!(!format!("{attempt:?}").contains("session-token"));
}
#[tokio::test]
async fn inner_challenge_preserves_body_with_fresh_outer_proofs() {
    let id = SessionGrantId::from_issuance_digest([5; 32]);
    let target = SessionGrantId::from_issuance_digest([6; 32]);
    let (sdk, server, _) = server(vec![
        (503, json!({})),
        (
            200,
            json!({"revoked_count":1,"revoked_session_grant_ids":[target]}),
        ),
    ]);
    let mut request = body();
    request.target_session_grant_id = Some(target);
    request.proof = Some(proof());
    sdk.session_grant_revoke(&id, &request).await.unwrap();
    let captured = server.join().unwrap();
    assert_eq!(captured[0].1, captured[1].1);
    assert_ne!(captured[0].0, captured[1].0);
}
#[tokio::test]
async fn outcome_rejects_substitution_duplicate_ids_counts_and_unknown_members() {
    let id = SessionGrantId::from_issuance_digest([5; 32]);
    let other = SessionGrantId::from_issuance_digest([6; 32]);
    for (response, valid) in [
        (json!({"revoked_count":1}), true),
        (
            json!({"revoked_count":1,"revoked_session_grant_ids":[id]}),
            true,
        ),
        (
            json!({"revoked_count":1,"revoked_session_grant_ids":[other]}),
            false,
        ),
        (
            json!({"revoked_count":2,"revoked_session_grant_ids":[id,id]}),
            false,
        ),
        (json!({"revoked_count":0}), true),
        (json!({"revoked_count":1,"invented":true}), false),
    ] {
        let (sdk, server, _) = server(vec![(200, response)]);
        assert_eq!(sdk.session_grant_revoke(&id, &body()).await.is_ok(), valid);
        server.join().unwrap();
    }
}
#[test]
fn invalid_selectors_proof_and_authentication_fail_before_network() {
    let id = SessionGrantId::from_issuance_digest([5; 32]);
    let sdk = Client::builder("http://127.0.0.1:1/".parse().unwrap())
        .allow_insecure_localhost()
        .build()
        .unwrap();
    assert!(sdk.prepare_session_grant_revoke(&id, &body()).is_err());
    let sdk = Client::builder("http://127.0.0.1:1/".parse().unwrap())
        .allow_insecure_localhost()
        .auth(Auth::Dpop(DpopAuth::with_dpop_token(
            "session-token",
            |_| Ok("frozen-proof".into()),
        )))
        .build()
        .unwrap();
    for request in [
        json!({"all_sessions":false}),
        json!({"all_sessions":true,"target_session_grant_id":id}),
    ] {
        assert!(
            sdk.prepare_session_grant_revoke(&id, &serde_json::from_value(request).unwrap())
                .is_err()
        );
    }
    let mut malformed = body();
    malformed.proof = Some(proof());
    malformed.proof.as_mut().unwrap().challenge.clear();
    assert!(sdk.prepare_session_grant_revoke(&id, &malformed).is_err());
    let mut deployment_selected = body();
    deployment_selected.all_sessions = Some(true);
    assert!(
        sdk.prepare_session_grant_revoke(&id, &deployment_selected)
            .is_ok()
    );
    deployment_selected.proof = Some(proof());
    deployment_selected.proof.as_mut().unwrap().proof_kind =
        AccountLifecycleProofKind::PasskeyAssertion;
    assert!(
        sdk.prepare_session_grant_revoke(&id, &deployment_selected)
            .is_ok()
    );
}
