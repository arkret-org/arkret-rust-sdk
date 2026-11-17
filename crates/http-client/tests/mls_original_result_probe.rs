//! Standard typed SDK publication and real loopback HTTP/RFC 9421 transport.
//! The source Event has a real independently checked Ed25519 proof. The
//! historical schema payload exercises SDK shape, not RFC MLS/G admission.
#![cfg(not(target_arch = "wasm32"))]

use arkret_http_client::{Client, ClientRequestOptions, HttpMessageSigner};
use arkret_identity::{ProducerVerificationContext, PublicationRequest, VerifiedSubmission};
use arkret_models_collaboration::authority_commit::{
    AuthorityForwardBranch, ForwardedAuthorityResponseBody, MlsGroupStateMaterial,
    PeerAuthorityForwardMlsRequestBody, PeerAuthorityForwardResponseBody,
    PeerAuthoritySubmitRequestBody, PeerAuthoritySubmitResponseBody,
};
use arkret_signatures::http_signature::{
    HttpSignatureScenario, SignatureVerificationPolicy, verify_signed_http_message,
};
use arkret_wire::{AccountId, ActorId, AuthoredEvent, DidUrl, Event, MlsCommitSubmission};
use ed25519_dalek::SigningKey;
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn original() -> (PeerAuthoritySubmitRequestBody, ProducerVerificationContext) {
    let fixture = arkret_schema_conformance::spec_json_artifact(
        "fixtures/mls-cross-station-welcome-replication-fixture.json",
    )
    .unwrap();
    let source = fixture["schema_validation_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "mls_commit_item_with_welcomes_valid")
        .unwrap();
    let mut event: Event =
        serde_json::from_value(source["instance"]["event_submission"]["event"].clone()).unwrap();
    event.actor_id = ActorId::account(AccountId::new(
        "ak:did_core:web:sdk.arkret.org".parse().unwrap(),
        "ak:did_core:web:relay.arkret.org".parse().unwrap(),
    ));
    event.producer_proof = None;
    let method =
        DidUrl::new("did:web:sdk.arkret.org#ak:device:0196419b-0000-7000-8000-000000000099")
            .unwrap();
    let key = SigningKey::from_bytes(&[137; 32]);
    let context = ProducerVerificationContext {
        actor: event.actor_id.clone(),
        verification_method: method.clone(),
        public_key: arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().as_bytes().to_vec(),
        },
        digest_suite: arkret_canonical::DigestSuite::Sha256,
    };
    let mut authored =
        AuthoredEvent::finalize_with_digest_suite(event, context.digest_suite).unwrap();
    let created = authored.created_at;
    arkret_signatures::sign_event(
        &mut authored,
        &arkret_signatures::Ed25519DetachedJwsSigner::new(key, method.as_str()),
        arkret_signatures::SignEventOptions::new().with_created_at(created),
    )
    .unwrap();
    let submission = MlsCommitSubmission {
        commit_event: authored.into_event(),
        welcomes: Vec::new(),
        idempotency_key: serde_json::from_value(json!("0196419b-0000-7000-8000-000000000099"))
            .unwrap(),
        recovery_source: None,
    };
    let request =
        PeerAuthoritySubmitRequestBody::AuthorityForwardMls(PeerAuthorityForwardMlsRequestBody {
            branch: AuthorityForwardBranch::AuthorityForward,
            mls_submission: submission.for_origin_forward(None),
            mls_group_state_material: MlsGroupStateMaterial::from_bytes(&[0, 1], &[2, 3]),
            content_backup_sources: None,
            producer_device_evidence: None,
            producer_agent_evidence: None,
        });
    (request, context)
}

#[test]
fn pure_probe_keeps_verified_producer_and_immutable_original_boundaries() {
    let (request, context) = original();
    assert!(
        request.validate().is_err(),
        "the result probe cannot first-admit an Account Event"
    );
    request.validate_publication_shape().unwrap();
    assert!(VerifiedSubmission::from_verified_events(request.clone(), &[]).is_err());
    let mut wrong = context.clone();
    wrong.public_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: SigningKey::from_bytes(&[138; 32])
            .verifying_key()
            .as_bytes()
            .to_vec(),
    };
    assert!(VerifiedSubmission::verify(request.clone(), |_| Ok(wrong.clone())).is_err());
    let bytes = arkret_canonical::canonical_json_bytes(&request).unwrap();
    let verified = VerifiedSubmission::verify(request, |_| Ok(context.clone())).unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&verified).unwrap(),
        bytes
    );
    let mut changed = verified.wire().clone();
    let PeerAuthoritySubmitRequestBody::AuthorityForwardMls(value) = &mut changed else {
        unreachable!()
    };
    value
        .mls_submission
        .commit_event
        .producer_proof
        .as_mut()
        .unwrap()
        .jws
        .push('A');
    assert!(verified.rebind(changed).is_err());
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&verified).unwrap(),
        bytes
    );
}

#[tokio::test]
async fn verified_original_probe_uses_the_standard_typed_peer_http_endpoint() {
    let (request, context) = original();
    let verified = VerifiedSubmission::verify(request, |_| Ok(context.clone())).unwrap();
    let expected = arkret_canonical::canonical_json_bytes(&verified).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base = format!("http://{address}/");
    let service_key = SigningKey::from_bytes(&[139; 32]);
    let public = service_key.verifying_key();
    let endpoint = format!("{base}_arkret/peer/events");
    let reply =
        PeerAuthoritySubmitResponseBody::AuthorityForward(PeerAuthorityForwardResponseBody {
            branch: AuthorityForwardBranch::AuthorityForward,
            response_body: ForwardedAuthorityResponseBody::Ordinary(
                arkret_wire::AuthoritySubmitResponseBody::Rejected {
                    status: arkret_wire::AuthorityRejectionStatus::Rejected,
                    reason_code: "governance_binding_mismatch".into(),
                },
            ),
        });
    let response = serde_json::to_vec(&reply).unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) =
            tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
        let read = async {
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 4096];
            let boundary = loop {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
                assert!(bytes.len() <= 1024 * 1024);
                if let Some(at) = bytes.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break at + 4;
                }
            };
            let head = std::str::from_utf8(&bytes[..boundary]).unwrap();
            let mut lines = head.lines();
            assert_eq!(lines.next().unwrap(), "POST /_arkret/peer/events HTTP/1.1");
            let headers: Vec<(String, String)> = lines
                .filter_map(|line| line.split_once(':'))
                .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
                .collect();
            let length: usize = headers
                .iter()
                .find(|(key, _)| key == "content-length")
                .unwrap()
                .1
                .parse()
                .unwrap();
            assert!(length <= 1024 * 1024);
            while bytes.len() < boundary + length {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
            }
            let body = bytes[boundary..boundary + length].to_vec();
            assert!(headers.iter().any(|(key, value)| key == "arkret-operation"
                && value == "ak.peer.events.command.submit.v1"));
            verify_signed_http_message(
                "POST",
                &endpoint,
                &address.to_string(),
                "/_arkret/peer/events",
                headers,
                &body,
                &public,
                &SignatureVerificationPolicy::for_scenario(
                    HttpSignatureScenario::ServiceToServiceV1,
                    &["content-digest"],
                )
                .unwrap(),
                chrono::Utc::now().timestamp(),
            )
            .unwrap();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len()).as_bytes()).await.unwrap();
            socket.write_all(&response).await.unwrap();
            socket.shutdown().await.unwrap();
            body
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), read)
            .await
            .unwrap()
    });
    let client = Client::builder(base.parse().unwrap())
        .allow_insecure_localhost()
        .build()
        .unwrap()
        .with_service_http_signer(
            "ak:did_core:web:relay.arkret.org".parse().unwrap(),
            "ak:did_core:web:authority.arkret.org".parse().unwrap(),
            HttpMessageSigner::new("did:web:relay.arkret.org#http-key", service_key),
        );
    assert_eq!(
        client
            .submit_to_peer_authority(&verified, &ClientRequestOptions::default())
            .await
            .unwrap(),
        reply
    );
    let sent = server.await.unwrap();
    assert_eq!(sent, expected);
    let sent: serde_json::Value = serde_json::from_slice(&sent).unwrap();
    assert!(sent.get("producer_device_evidence").is_none());
    assert!(sent.get("producer_agent_evidence").is_none());
}
