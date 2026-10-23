//! Real TCP transport signatures and retry boundaries; business admission is
//! independently covered by Cotest against Coland, TLS and PostgreSQL.
#![cfg(not(target_arch = "wasm32"))]
use std::io::{Read, Write};
use std::time::{Duration, Instant};

use arkret_http_client::{Auth, Client, HttpMessageSigner, RetryConfig};
use arkret_models_collaboration::mimi_operations::*;
use arkret_signatures::http_signature::{
    HttpSignatureScenario, SignatureVerificationPolicy, verify_signed_http_message,
};
use arkret_wire::{
    AccountId, ActorId, DidCoreId, EventAdmissionSubmission, EventId, EventKind, MimiRoomUri,
    PayloadProof, RealmId, ScopeRef,
};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
const STRAND: &str = "ak:strand:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0";
const CONSENT: &str = "ak:consent:0198ff00-0000-7000-8000-000000000001";
const PROVIDER: &str = "mimi://source.example";
const ROOM: &str = "mimi://destination.example/rooms/target";
fn core(name: &str) -> DidCoreId {
    DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap()
}
fn actor() -> ActorId {
    ActorId::account(AccountId::new(core("alice"), core("station")))
}
fn scope() -> ScopeRef {
    ScopeRef::Realm {
        realm_id: RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [3; 32],
        )),
    }
}
fn proof() -> PayloadProof {
    serde_json::from_value(json!({"kind":"detached_jws","verification_method":"did:web:alice.example#device-1", "payload_digest":format!("sha256:{}","0".repeat(64)),"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),"domain":"ak:trust_domain:station.example","audience":"ak:did_core:web:station.example","jws":"pending"})).unwrap()
}
fn trust_domain() -> arkret_wire::TrustDomainId {
    "ak:trust_domain:testing.example".parse().unwrap()
}
fn key_material_request() -> arkret_models_crypto::PeerKeyPackagesClaimRequestBody {
    key_material_request_at(chrono::Utc::now())
}
fn key_material_request_at(
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_models_crypto::PeerKeyPackagesClaimRequestBody {
    let device = "ak:device:0198ff00-0000-7000-8000-000000000001";
    let method = format!("did:web:alice.example#{device}");
    let mut request: arkret_models_crypto::PeerKeyPackagesClaimRequestBody = serde_json::from_value(json!({
        "claim_request_id":"AAAAAAAAAAAAAAAAAAAAAQ",
        "target_account_id":AccountId::new(core("bob"),core("destination")),
        "requester_account_id":AccountId::new(core("alice"),core("source")),
        "target_device_ids":["ak:device:0198ff00-0000-7000-8000-000000000002"],
        "intended_realm_id":scope().realm_id(), "mls_group_id":scope().canonical_mls_group_id().unwrap(),
        "claim_purpose":"realm_membership", "required_capabilities":["mimi.content.v1"],
        "expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::Duration::minutes(5)),
        "service_binding":{"source_id":core("source"),"destination_id":core("destination")},
        "requester_authorization":{"kind":"device","verification_method":method,"requester_device_id":device,
            "device_authorize_event_id":EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[2;32]),
            "signed_at":arkret_canonical::format_timestamp_canonical(at),"signature":{"kid":method,"sig":"AA"}}
    })).unwrap();
    let input = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &request.unsigned_request(),
        &request.service_binding,
        &request.requester_authorization,
    )
    .unwrap();
    let signature = SigningKey::from_bytes(&[4; 32]).sign(&input);
    let mut value = serde_json::to_value(&request).unwrap();
    value["requester_authorization"]["signature"]["sig"] =
        json!(arkret_canonical::base64url_encode(signature.to_bytes()));
    request = serde_json::from_value(value).unwrap();
    request.validate_shape().unwrap();
    request
}
#[test]
fn key_material_fixture_keeps_milliseconds_at_whole_seconds() {
    let at = arkret_canonical::parse_timestamp_canonical("2026-10-24T00:00:00.000Z").unwrap();
    let request = key_material_request_at(at);
    let value = serde_json::to_value(request).unwrap();
    assert_eq!(value["expires_at"], "2026-10-24T00:05:00.000Z");
    assert_eq!(
        value["requester_authorization"]["signed_at"],
        "2026-10-24T00:00:00.000Z"
    );
}
fn request_consent() -> MimiRequestConsentRequestBody {
    let mut v:MimiRequestConsentRequestBody=serde_json::from_value(json!({"requester_actor_id":actor(),"holder_account_id":AccountId::new(core("bob"),core("station")),"purpose":"voice_call","proofs":[proof()]})).unwrap();
    v.proofs[0].payload_digest = v.payload_digest().unwrap();
    v.proofs[0].jws = arkret_signatures::jws::sign_jws_ed25519(
        &v.unsigned_proof_binding_bytes(&v.proofs[0].unsigned())
            .unwrap(),
        &SigningKey::from_bytes(&[4; 32]),
    )
    .unwrap();
    v
}
fn update_consent() -> MimiUpdateConsentRequestBody {
    // A real producer signature supplies the transport fixture; authority admission is independent.
    let event = arkret_wire::test_support::raw_event(
        EventKind::ConsentReplace.as_str(),
        scope(),
        core("alice"),
        core("station"),
        json!({"peer":{"kind":"actor","actor_id":ActorId::account(AccountId::new(core("bob"),core("station")))},"expected_current":{"state":"never_written"},"permissions":[{"consent_scope":"voice_call"}]}),
    )
    .unwrap();
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        [4; 32],
        "did:web:alice.example".parse().unwrap(),
        arkret_wire::DidUrl::new("did:web:alice.example#device-1").unwrap(),
    );
    let event_at = authored.created_at;
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(event_at),
    )
    .unwrap();
    let event = authored.into_event();
    let mut v = MimiUpdateConsentRequestBody {
        consent_id: CONSENT.parse().unwrap(),
        decision: MimiConsentDecision::Accept,
        actor_id: actor(),
        consent_event: EventAdmissionSubmission::new(event),
        signature: proof(),
        reason: None,
        expires_at: None,
    };
    v.signature.payload_digest = v.payload_digest().unwrap();
    v.signature.jws = arkret_signatures::jws::sign_jws_ed25519(
        &v.unsigned_signature_binding_bytes(&v.signature.unsigned())
            .unwrap(),
        &SigningKey::from_bytes(&[4; 32]),
    )
    .unwrap();
    v
}
fn room_request() -> MimiRoomUpdateRequestBody {
    serde_json::from_value(json!({"mls_group_id":scope().canonical_mls_group_id().unwrap(),"update":{"kind":"m.room.name","payload":{"content_type":"application/json","payload_digest":format!("sha256:{}","0".repeat(64))}}})).unwrap()
}
#[derive(Clone, Debug)]
struct Captured {
    base: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
impl Captured {
    fn verify(&self, room: bool) -> bool {
        let conditions = if room { vec!["mimi-room-uri"] } else { vec![] };
        verify_signed_http_message(
            "POST",
            &format!("{}{}", self.base.trim_end_matches('/'), self.path),
            self.base
                .trim_start_matches("http://")
                .trim_end_matches('/'),
            &self.path,
            self.headers.clone(),
            &self.body,
            &SigningKey::from_bytes(&[9; 32]).verifying_key(),
            &SignatureVerificationPolicy::for_scenario(
                HttpSignatureScenario::MimiProviderV1,
                &conditions,
            )
            .unwrap(),
            chrono::Utc::now().timestamp(),
        )
        .is_ok()
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}
fn server(responses: Vec<(u16, Value)>) -> (Client, std::thread::JoinHandle<Vec<Captured>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap());
    let captured_base = base.clone();
    let handle = std::thread::spawn(move || {
        let mut captured = Vec::new();
        let mut deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let (mut socket, _) = match listener.accept() {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("{e}"),
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
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
            let head = String::from_utf8(bytes[..boundary].to_vec()).unwrap();
            let headers: Vec<(String, String)> = head
                .lines()
                .skip(1)
                .filter_map(|v| {
                    v.split_once(':')
                        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
                })
                .collect();
            let length: usize = headers
                .iter()
                .find(|(k, _)| k == "content-length")
                .map(|(_, v)| v.parse().unwrap())
                .unwrap_or(0);
            while bytes.len() < boundary + length {
                let n = socket.read(&mut chunk).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
            }
            let path = head
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .to_owned();
            let response = &responses[captured.len().min(responses.len() - 1)];
            captured.push(Captured {
                base: captured_base.clone(),
                path,
                headers,
                body: bytes[boundary..boundary + length].to_vec(),
            });
            let payload = response.1.to_string();
            write!(socket,"HTTP/1.1 {} response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",response.0,payload.len()).unwrap();
            deadline = Instant::now() + Duration::from_millis(300);
        }
        captured
    });
    let mut retry = RetryConfig::standard(2);
    retry.base_delay = Duration::ZERO;
    retry.max_delay = Duration::ZERO;
    retry.jitter = false;
    let client = Client::builder(base.parse().unwrap())
        .allow_insecure_localhost()
        .retry(retry)
        .auth(Auth::Bearer("account-secret".to_owned()))
        .build()
        .unwrap()
        .with_mimi_provider_http_signer(
            core("source"),
            core("destination"),
            arkret_wire::MimiUri::new(PROVIDER).unwrap(),
            HttpMessageSigner::new(
                "did:web:source.example#provider",
                SigningKey::from_bytes(&[9; 32]),
            ),
        )
        .unwrap();
    (client, handle)
}
#[tokio::test]
async fn non_replayable_operations_are_signed_once_even_on_transient_failure() {
    for operation in [0, 2, 3, 4, 5, 6] {
        let (client, handle) = server(vec![(503, json!({}))]);
        let client = client
            .with_mimi_room(MimiRoomUri::new(ROOM).unwrap())
            .unwrap();
        let failed=match operation {
            0=>client.mimi_request_consent(&request_consent()).await.is_err(),
            2=>client.mimi_update_room(STRAND,&room_request()).await.is_err(),
            3=>client.mimi_notify(STRAND,&serde_json::from_value(json!({"notification":{"kind":"delivery"}})).unwrap()).await.is_err(),
            4=>client.mimi_identifier_query(&serde_json::from_value(json!({"identifiers":[{"kind":"handle","identifier_commitment":format!("sha256:{}","1".repeat(64))}],"privacy_profile":"private_identifier_query"})).unwrap()).await.is_err(),
            5=>client.mimi_proxy_download(&serde_json::from_value(json!({"asset_ref":"opaque","requester_id":core("source")})).unwrap()).await.is_err(),
            _=>client.mimi_submit_message(STRAND,&serde_json::from_value(json!({"sender_actor_id":actor(),"device_id":"ak:device:0198ff00-0000-7000-8000-000000000001","ciphertext":{"content_type":"application/mimi-content","payload":"eA","ciphertext_digest":arkret_canonical::sha256_digest(b"x")}})).unwrap()).await.is_err(),
        };
        assert!(failed);
        let captured = handle.join().unwrap();
        assert_eq!(captured.len(), 1, "operation {operation}");
        let request = &captured[0];
        assert!(
            request.verify(matches!(operation, 2 | 3 | 6)),
            "operation {operation}: {request:?}"
        );
        assert_eq!(request.header("provider-id"), Some(PROVIDER));
        for name in [
            "authorization",
            "dpop",
            "device-id",
            "device-nonce",
            "content-encoding",
        ] {
            assert!(request.header(name).is_none(), "{name}");
        }
        assert_eq!(
            request.body,
            arkret_canonical::canonical_json_bytes(
                &serde_json::from_slice::<Value>(&request.body).unwrap()
            )
            .unwrap()
        );
    }
}
#[tokio::test]
async fn room_signature_authenticates_destination_namespace_and_exact_body() {
    let (client, handle) = server(vec![(200, json!({"accepted":true}))]);
    client
        .with_mimi_room(MimiRoomUri::new(ROOM).unwrap())
        .unwrap()
        .mimi_notify(
            STRAND,
            &serde_json::from_value(json!({"notification":{"kind":"delivery"}})).unwrap(),
        )
        .await
        .unwrap();
    let request = handle.join().unwrap().remove(0);
    assert!(request.verify(true));
    assert_eq!(request.header("mimi-room-uri"), Some(ROOM));
    for name in [
        "provider-id",
        "source-service-id",
        "destination-service-id",
        "mimi-room-uri",
        "arkret-operation",
    ] {
        let mut altered = request.clone();
        altered
            .headers
            .iter_mut()
            .find(|(k, _)| k == name)
            .unwrap()
            .1
            .push('x');
        assert!(!altered.verify(true), "{name}");
    }
    let mut altered = request;
    altered.body.push(b' ');
    assert!(!altered.verify(true));
}
#[tokio::test]
async fn exact_consent_retry_retains_caller_event_and_checks_response_binding() {
    let request = update_consent();
    let response = json!({"consent_id":request.consent_id,"decision":"accept","updated_at":"2026-10-20T00:00:00.000Z","event_ref":request.consent_event.event.event_id});
    let (client, handle) = server(vec![(503, json!({})), (200, response.clone())]);
    client.mimi_update_consent(&request).await.unwrap();
    let captured = handle.join().unwrap();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].body, captured[1].body);
    assert!(captured.iter().all(|r| r.verify(false)));
    for (field, value) in [
        (
            "consent_id",
            json!("ak:consent:0198ff00-0000-7000-8000-000000000002"),
        ),
        ("decision", json!("deny")),
        (
            "event_ref",
            json!(EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [6; 32]
            )),
        ),
    ] {
        let mut replaced = response.clone();
        replaced[field] = value;
        let (client, handle) = server(vec![(200, replaced)]);
        assert!(matches!(
            client.mimi_update_consent(&request).await,
            Err(arkret_http_client::Error::Protocol(_))
        ));
        assert_eq!(handle.join().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn invalid_provider_context_fails_before_connecting() {
    let client = Client::builder("http://127.0.0.1:1/".parse().unwrap())
        .allow_insecure_localhost()
        .build()
        .unwrap();
    let notify = serde_json::from_value(json!({"notification":{"kind":"delivery"}})).unwrap();
    assert!(matches!(
        client.mimi_notify(STRAND, &notify).await,
        Err(arkret_http_client::Error::Protocol(_))
    ));
    {
        let provider = "mimi://bad\0header";
        assert!(
            client
                .clone()
                .with_mimi_provider_http_signer(
                    core("source"),
                    core("destination"),
                    arkret_wire::MimiUri::new(provider).unwrap(),
                    HttpMessageSigner::new(
                        "did:web:source.example#provider",
                        SigningKey::from_bytes(&[9; 32])
                    )
                )
                .is_err()
        );
    }
    let client = client
        .with_mimi_provider_http_signer(
            core("source"),
            core("destination"),
            arkret_wire::MimiUri::new(PROVIDER).unwrap(),
            HttpMessageSigner::new(
                "did:web:source.example#provider",
                SigningKey::from_bytes(&[9; 32]),
            ),
        )
        .unwrap();
    assert!(matches!(
        client.mimi_notify(STRAND, &notify).await,
        Err(arkret_http_client::Error::Protocol(_))
    ));
}
#[tokio::test]
async fn own_station_directory_requires_https_before_any_authentication() {
    for account_context in [false, true] {
        let (provider_client, handle) = server(vec![(400, json!({}))]);
        let client = if account_context {
            Client::builder(provider_client.base_url().clone())
                .allow_insecure_localhost()
                .auth(Auth::Dpop(arkret_http_client::DpopAuth::with_dpop_token(
                    "account-secret",
                    |_| panic!("public directory must not request DPoP"),
                )))
                .http_message_signer(HttpMessageSigner::new(
                    "did:web:alice.example#device",
                    SigningKey::from_bytes(&[4; 32]),
                ))
                .build()
                .unwrap()
        } else {
            provider_client
        };
        let binding = arkret_models_discovery::StationConnectionBinding {
            service_id: core("destination"),
            base_url: client.base_url().to_string(),
            trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:destination.example")
                .unwrap(),
            auth_metadata: arkret_models_discovery::AuthMetadata::minimal(),
        };
        let result = client
            .mimi_provider_directory_from_own_station(
                &binding,
                None,
                &[],
                chrono::Duration::minutes(5),
                arkret_egress_policy::OutboundPolicy::local_development(),
            )
            .await;
        assert!(
            matches!(result, Err(arkret_http_client::Error::Protocol(message)) if message.contains("HTTPS"))
        );
        assert!(handle.join().unwrap().is_empty());
    }
}

#[tokio::test]
async fn malformed_successes_are_rejected() {
    let (client, handle) = server(vec![(200, json!({}))]);
    let request = key_material_request();
    let client = client
        .with_mimi_room(MimiRoomUri::new(ROOM).unwrap())
        .unwrap();
    assert!(
        client
            .mimi_request_key_material(&request, &trust_domain(), &trust_domain())
            .await
            .is_err()
    );
    assert_eq!(handle.join().unwrap().len(), 1);
    let (client, handle) = server(vec![(
        200,
        json!({"accepted":true,"room_state_ref":EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[6;32])}),
    )]);
    assert!(matches!(
        client
            .with_mimi_room(MimiRoomUri::new(ROOM).unwrap())
            .unwrap()
            .mimi_update_room(STRAND, &room_request())
            .await,
        Err(arkret_http_client::Error::Protocol(_))
    ));
    handle.join().unwrap();
    let digest = format!("sha256:{}", "1".repeat(64));
    let request=serde_json::from_value(json!({"identifiers":[{"kind":"handle","identifier_commitment":digest}],"privacy_profile":"private_identifier_query"})).unwrap();
    let (client, handle) = server(vec![(
        200,
        json!({"matches":[{"identifier_commitment":digest,"matched":true}],"has_more":false}),
    )]);
    assert!(matches!(
        client.mimi_identifier_query(&request).await,
        Err(arkret_http_client::Error::Protocol(_))
    ));
    handle.join().unwrap();
}

#[tokio::test]
async fn identifier_receipt_binds_commitment_multiplicity_without_imposing_order() {
    let a = format!("sha256:{}", "1".repeat(64));
    let b = format!("sha256:{}", "2".repeat(64));
    let request=serde_json::from_value(json!({"identifiers":[{"kind":"handle","identifier_commitment":a},{"kind":"handle","identifier_commitment":b}],"privacy_profile":"private_identifier_query"})).unwrap();
    for (values, valid) in [
        (vec![b.clone(), a.clone()], true),
        (vec![a.clone(), a.clone()], false),
    ] {
        let matches: Vec<_> = values
            .iter()
            .map(|v| json!({"identifier_commitment":v,"matched":false}))
            .collect();
        let (client, handle) = server(vec![(200, json!({"matches":matches,"has_more":false}))]);
        assert_eq!(client.mimi_identifier_query(&request).await.is_ok(), valid);
        handle.join().unwrap();
    }
}

#[tokio::test]
async fn key_material_retries_only_the_original_native_claim_and_signs_all_bindings() {
    let request = key_material_request();
    let pending =
        json!({"claim_request_id":request.claim_request_id,"state":"pending","retry_after_ms":1});
    let (client, handle) = server(vec![
        (503, json!({"error":"temporarily_unavailable"})),
        (200, pending),
    ]);
    let result = client
        .with_mimi_room(MimiRoomUri::new(ROOM).unwrap())
        .unwrap()
        .mimi_request_key_material(&request, &trust_domain(), &trust_domain())
        .await
        .unwrap();
    assert_eq!(
        result.state,
        arkret_models_crypto::PeerKeyPackagesClaimQueryState::Pending
    );
    let captured = handle.join().unwrap();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].body, captured[1].body);
    assert_eq!(
        serde_json::from_slice::<Value>(&captured[0].body).unwrap(),
        serde_json::to_value(&request).unwrap()
    );
    for sent in captured {
        assert!(sent.verify(true));
        assert_eq!(sent.header("provider-id"), Some(core("source").as_str()));
        assert_eq!(
            sent.header("idempotency-key"),
            Some(request.claim_request_id.as_str())
        );
        assert!(sent.header("authorization").is_none());
        for name in [
            "idempotency-key",
            "mimi-room-uri",
            "source-trust-domain",
            "destination-trust-domain",
        ] {
            assert!(
                sent.header("signature-input")
                    .unwrap()
                    .contains(&format!("\"{name}\""))
            );
        }
    }
}

#[tokio::test]
async fn key_material_rejects_provider_only_and_last_resort_requests_before_io() {
    for mutation in 0..3 {
        let (client, handle) = server(vec![]);
        let mut request = key_material_request();
        match mutation {
            0 => request.last_resort_allowed = Some(true),
            1 => {
                request.required_capabilities =
                    vec![arkret_wire::NonEmptyString::new("ak.content.v1").unwrap()]
            }
            _ => request.service_binding.source_id = core("another-station"),
        }
        assert!(
            client
                .with_mimi_room(MimiRoomUri::new(ROOM).unwrap())
                .unwrap()
                .mimi_request_key_material(&request, &trust_domain(), &trust_domain())
                .await
                .is_err()
        );
        assert!(handle.join().unwrap().is_empty());
    }
}
