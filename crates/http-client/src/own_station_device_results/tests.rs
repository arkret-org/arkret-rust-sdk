use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

struct Source(Mutex<OwnStationDeviceSnapshot>);
impl OwnStationDeviceSource for Source {
    fn snapshot(&self) -> Result<OwnStationDeviceSnapshot> {
        Ok(self.0.lock().unwrap().clone())
    }
}

fn native(base: &str) -> (Client, Arc<Source>) {
    let key = SigningKey::from_bytes(&[123; 32]);
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
    let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [124; 32]);
    let metadata = AppletManagedDeviceMetadata {
        account_id: AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:bot.example").unwrap(),
            station.clone(),
        ),
        device_id: DeviceId::new_v7_at(Utc::now().timestamp_millis().try_into().unwrap()),
        authorization_event_id: event.clone(),
        applet_id: AppletId::new("ak:applet:01964137-0000-7000-8000-000000000123").unwrap(),
        effective_scope: ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::from_event_id(&event),
        },
        nonce: arkret_canonical::base64url_encode([125; 16]),
    };
    let binding = OwnStationDeviceBinding {
        service_id: station.clone(),
        base_url: base.into(),
        trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:station.example").unwrap(),
    };
    let now = Utc::now();
    let snapshot = OwnStationDeviceSnapshot::new(
        binding,
        &metadata,
        key.verifying_key().to_bytes(),
        now - chrono::TimeDelta::minutes(1),
        now + chrono::TimeDelta::minutes(1),
        0,
        Default::default(),
    )
    .unwrap();
    let fingerprint =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let client = crate::ClientBuilder::new(url::Url::parse(base).unwrap())
        .allow_insecure_localhost()
        .retry(crate::RetryConfig::standard(0))
        .build()
        .unwrap()
        .with_managed_device_http_signer(
            metadata,
            station,
            crate::HttpMessageSigner::new(format!("did:key:{fingerprint}#{fingerprint}"), key),
        )
        .unwrap();
    (client, Arc::new(Source(Mutex::new(snapshot))))
}

#[test]
fn native_reader_binds_complete_transport_and_never_constructs_a_session() {
    let (client, source) = native("http://localhost:1234/");
    let own = OwnStationDeviceClient::new(client.clone(), source.clone()).unwrap();
    assert!(client.auth.is_none());
    assert!(client.own_station_context.is_none());
    let mut wrong = client.clone();
    wrong.auth = Some(crate::Auth::Bearer("borrowed-session".into()));
    assert!(OwnStationDeviceClient::new(wrong, source.clone()).is_err());
    let mut wrong = client.clone();
    wrong.base_url = url::Url::parse("http://localhost:1235/").unwrap();
    assert!(OwnStationDeviceClient::new(wrong, source.clone()).is_err());
    let mut wrong = client.clone();
    wrong
        .managed_device_signature_identity
        .as_mut()
        .unwrap()
        .0
        .authorization_event_id =
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [126; 32]);
    assert!(OwnStationDeviceClient::new(wrong, source.clone()).is_err());
    let mut wrong = client.clone();
    wrong.http_message_signer = Some(crate::HttpMessageSigner::new(
        "did:key:borrowed#borrowed",
        SigningKey::from_bytes(&[127; 32]),
    ));
    assert!(OwnStationDeviceClient::new(wrong, source.clone()).is_err());
    // Identical serialized coordinates from a new provider remain a new
    // incarnation; old results never acquire the replacement's lifetime.
    source.0.lock().unwrap().instance = Default::default();
    assert!(own.check_context().is_err());
    assert!(OwnStationDeviceClient::new(client, source).is_ok());
}

#[tokio::test]
async fn native_http_rejects_late_aba_and_invalidates_earlier_bound_results() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (raw, source) = native(&format!("http://{}/", listener.local_addr().unwrap()));
    let own = OwnStationDeviceClient::new(raw, source.clone()).unwrap();
    let server_source = source.clone();
    let server = tokio::spawn(async move {
        for ordinal in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                let count = stream.read(&mut chunk).await.unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&chunk[..count]);
                if bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                    break;
                }
                assert!(bytes.len() < 64 * 1024);
            }
            let request = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
            assert!(request.starts_with("get /_arkret/self/device_messages?"));
            assert!(!request.contains("authorization:"));
            assert!(request.contains("signature-input:"));
            assert!(request.contains("arkret-managed-device"));
            if ordinal == 1 {
                server_source.0.lock().unwrap().instance = Default::default();
            }
            let body = r#"{"deliveries":[],"has_more":false}"#;
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
        }
    });
    let response = own.receive_device_messages(None, Some(1)).await.unwrap();
    assert!(response.value().unwrap().deliveries.is_empty());
    assert!(own.receive_device_messages(None, Some(1)).await.is_err());
    server.await.unwrap();
    assert!(response.value().is_err());
}

#[test]
fn native_bound_results_expire_without_a_new_network_request() {
    let (raw, source) = native("http://localhost:1234/");
    let own = OwnStationDeviceClient::new(raw, source.clone()).unwrap();
    let response = own.bind((), ()).unwrap();
    source.0.lock().unwrap().expires_at = Utc::now() - chrono::TimeDelta::seconds(1);
    assert!(response.value().is_err());
    assert!(own.check_context().is_err());
}
