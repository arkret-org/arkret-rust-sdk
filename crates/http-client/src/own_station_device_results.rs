//! Original results from an accepted Station using a real managed Device.
//!
//! These local capabilities preserve the host's Device lifetime and exact
//! transport identity. They are not sessions or portable authorization facts.

use std::sync::Arc;

use arkret_models_collaboration::device_messages::DeviceMessagesGetOutcome;
use arkret_models_collaboration::exact_current_results::{
    ExactCurrentResultsReadOutcome, ExactCurrentResultsReadRequestBody,
};
use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialOutcome, MlsMemberGroupStateMaterialReadRequestBody,
};
use arkret_models_collaboration::mls_roster_authority::{
    MlsMemberRosterAuthorityReadRequestBody, MlsSelfRosterAuthorityReadOutcome,
};
use arkret_models_crypto::{KeyPackagesClaimOutcome, KeyPackagesClaimQueryRequestBody};
use arkret_models_discovery::StationConnectionBinding;
use arkret_models_identity::signer_key_operations::{
    SignerKeysQueryOutcome, SignerKeysQueryRequestBody,
};
use arkret_models_integration::AppletManagedDeviceMetadata;
use arkret_wire::{
    AccountId, AppletId, CommitStreamRef, CommittedEventView, DeviceId, EventId, ScopeRef,
    StreamScanOutcome, StreamScanRequest,
};
use chrono::{DateTime, Utc};

use crate::{Client, Error, Result};

/// Host incarnation, retained across clones but never recreated by replaying
/// serialized metadata. A replacement provider must use a new identity.
#[derive(Clone, Debug)]
pub struct OwnStationDeviceInstance(Arc<()>);

impl Default for OwnStationDeviceInstance {
    fn default() -> Self {
        Self(Arc::new(()))
    }
}

impl PartialEq for OwnStationDeviceInstance {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for OwnStationDeviceInstance {}

/// A host-confirmed accepted Device instance. The host must derive these
/// coordinates from its durable authorization, never from an inbound row.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnStationDeviceSnapshot {
    binding: StationConnectionBinding,
    account_id: AccountId,
    device_id: DeviceId,
    authorization_event_id: EventId,
    applet_id: AppletId,
    effective_scope: ScopeRef,
    public_key: [u8; 32],
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    epoch: u64,
    instance: OwnStationDeviceInstance,
}

impl std::fmt::Debug for OwnStationDeviceSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnStationDeviceSnapshot")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl OwnStationDeviceSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: StationConnectionBinding,
        metadata: &AppletManagedDeviceMetadata,
        public_key: [u8; 32],
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        epoch: u64,
        instance: OwnStationDeviceInstance,
    ) -> Result<Self> {
        metadata.validate()?;
        if binding.service_id != metadata.account_id.station_id || expires_at <= not_before {
            return Err(protocol("own Station Device binding or window is invalid"));
        }
        let snapshot = Self {
            binding,
            account_id: metadata.account_id.clone(),
            device_id: metadata.device_id.clone(),
            authorization_event_id: metadata.authorization_event_id.clone(),
            applet_id: metadata.applet_id.clone(),
            effective_scope: metadata.effective_scope.clone(),
            public_key,
            not_before,
            expires_at,
            epoch,
            instance,
        };
        snapshot.check_window()?;
        Ok(snapshot)
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }
    pub fn authorization_event_id(&self) -> &EventId {
        &self.authorization_event_id
    }
    pub fn effective_scope(&self) -> &ScopeRef {
        &self.effective_scope
    }
    pub fn binding(&self) -> &StationConnectionBinding {
        &self.binding
    }
    fn check_window(&self) -> Result<()> {
        let now = Utc::now();
        if now < self.not_before || now >= self.expires_at {
            return Err(protocol(
                "own Station Device authorization window is closed",
            ));
        }
        Ok(())
    }
    fn matches_metadata(&self, metadata: &AppletManagedDeviceMetadata) -> bool {
        self.account_id == metadata.account_id
            && self.device_id == metadata.device_id
            && self.authorization_event_id == metadata.authorization_event_id
            && self.applet_id == metadata.applet_id
            && self.effective_scope == metadata.effective_scope
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub trait OwnStationDeviceSource: Send + Sync {
    fn snapshot(&self) -> Result<OwnStationDeviceSnapshot>;
}

#[cfg(target_arch = "wasm32")]
pub trait OwnStationDeviceSource {
    fn snapshot(&self) -> Result<OwnStationDeviceSnapshot>;
}

/// A successful request from one captured native endpoint. No public
/// constructor, deserializer, mutable value or conversion from a wire flag.
#[derive(Clone)]
pub struct BoundOwnStationDeviceResponse<Q, T> {
    request: Q,
    value: T,
    context: OwnStationDeviceSnapshot,
    source: Arc<dyn OwnStationDeviceSource>,
}

impl<Q, T> BoundOwnStationDeviceResponse<Q, T> {
    pub fn request(&self) -> &Q {
        &self.request
    }
    pub fn context(&self) -> &OwnStationDeviceSnapshot {
        &self.context
    }
    pub fn value(&self) -> Result<&T> {
        self.context.check_window()?;
        if self.source.snapshot()? != self.context {
            return Err(protocol("late result belongs to a retired Device context"));
        }
        Ok(&self.value)
    }
    pub fn into_value(self) -> Result<T> {
        self.value()?;
        Ok(self.value)
    }
}

#[derive(Clone)]
pub struct OwnStationDeviceClient {
    client: Client,
    context: OwnStationDeviceSnapshot,
    source: Arc<dyn OwnStationDeviceSource>,
}

impl OwnStationDeviceClient {
    pub fn new(client: Client, source: Arc<dyn OwnStationDeviceSource>) -> Result<Self> {
        let context = source.snapshot()?;
        context.check_window()?;
        let (metadata, destination) = client
            .managed_device_signature_identity
            .as_ref()
            .ok_or_else(|| protocol("own Station reader requires actual Device transport"))?;
        let signer = client
            .http_message_signer
            .as_ref()
            .ok_or_else(|| protocol("own Station Device transport has no signing key"))?;
        let fingerprint =
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(&context.public_key);
        let expected_key_id = format!("did:key:{fingerprint}#{fingerprint}");
        if client.auth.is_some()
            || client.own_station_context.is_some()
            || client.service_signature_identity.is_some()
            || client.base_url.as_str() != context.binding.base_url
            || destination != &context.account_id.station_id
            || !context.matches_metadata(metadata)
            || signer.key_id() != expected_key_id
            || signer.signing_key().verifying_key().to_bytes() != context.public_key
        {
            return Err(protocol(
                "own Station reader differs from its accepted Device",
            ));
        }
        Ok(Self {
            client,
            context,
            source,
        })
    }

    pub fn context(&self) -> Result<&OwnStationDeviceSnapshot> {
        self.check_context()?;
        Ok(&self.context)
    }
    pub fn check_context(&self) -> Result<()> {
        self.context.check_window()?;
        if self.source.snapshot()? != self.context {
            return Err(protocol("own Station Device context changed"));
        }
        Ok(())
    }
    fn bind<Q, T>(&self, request: Q, value: T) -> Result<BoundOwnStationDeviceResponse<Q, T>> {
        self.check_context()?;
        Ok(BoundOwnStationDeviceResponse {
            request,
            value,
            context: self.context.clone(),
            source: self.source.clone(),
        })
    }

    pub async fn scan_commit_stream(
        &self,
        request: &StreamScanRequest,
    ) -> Result<BoundOwnStationDeviceResponse<StreamScanRequest, StreamScanOutcome>> {
        self.check_context()?;
        let expected = CommitStreamRef::from_scope(&self.context.effective_scope, None)?;
        if request.stream_ref != expected || &request.realm_id != expected.realm_id() {
            return Err(protocol(
                "native stream read differs from its exact authorized scope",
            ));
        }
        let value = self.client.scan_commit_stream(request).await?;
        value.validate_for_request(request)?;
        self.bind(request.clone(), value)
    }

    pub async fn exact_current_result(
        &self,
        request: &ExactCurrentResultsReadRequestBody,
        generation: u64,
    ) -> Result<
        BoundOwnStationDeviceResponse<
            (ExactCurrentResultsReadRequestBody, u64),
            ExactCurrentResultsReadOutcome,
        >,
    > {
        self.check_context()?;
        request.validate()?;
        if self.context.effective_scope.realm_id_opt() != Some(&request.realm_id) {
            return Err(protocol("native current request belongs to another Realm"));
        }
        let value = self
            .client
            .exact_current_result(request, generation)
            .await?;
        value.validate_for_request(request, generation)?;
        let stream = match &value {
            ExactCurrentResultsReadOutcome::Present {
                effective_stream_head,
                ..
            }
            | ExactCurrentResultsReadOutcome::NeverWritten {
                effective_stream_head,
                ..
            } => &effective_stream_head.stream_ref,
        };
        if stream != &CommitStreamRef::from_scope(&self.context.effective_scope, None)? {
            return Err(protocol(
                "native current result belongs to another exact scope",
            ));
        }
        self.bind((request.clone(), generation), value)
    }

    pub async fn committed_event_get(
        &self,
        event_id: &EventId,
    ) -> Result<BoundOwnStationDeviceResponse<EventId, CommittedEventView>> {
        self.check_context()?;
        let value = self.client.committed_event_get(event_id).await?;
        self.bind(event_id.clone(), value)
    }

    pub async fn signer_keys_query(
        &self,
        request: &SignerKeysQueryRequestBody,
    ) -> Result<BoundOwnStationDeviceResponse<SignerKeysQueryRequestBody, SignerKeysQueryOutcome>>
    {
        self.check_context()?;
        if request.recipient_account_id != self.context.account_id {
            return Err(protocol(
                "historical signer request belongs to another Account",
            ));
        }
        let value = self.client.signer_keys_query(request).await?;
        value.validate_for_request(request)?;
        self.bind(request.clone(), value)
    }

    pub async fn keypackages_claim_query(
        &self,
        request: &KeyPackagesClaimQueryRequestBody,
    ) -> Result<
        BoundOwnStationDeviceResponse<KeyPackagesClaimQueryRequestBody, KeyPackagesClaimOutcome>,
    > {
        self.check_context()?;
        let value = self.client.keypackages_claim_query(request).await?;
        value.validate_shape().map_err(protocol)?;
        if !value
            .claims
            .iter()
            .any(|claim| claim.claim_id == request.claim_id.as_str())
        {
            return Err(protocol("Device claim read answered for another claim"));
        }
        self.bind(request.clone(), value)
    }

    pub async fn self_mls_group_state_material(
        &self,
        request: &MlsMemberGroupStateMaterialReadRequestBody,
    ) -> Result<
        BoundOwnStationDeviceResponse<
            MlsMemberGroupStateMaterialReadRequestBody,
            MlsGroupStateMaterialOutcome,
        >,
    > {
        self.check_context()?;
        request.validate()?;
        if request.effective_scope != self.context.effective_scope
            || request.caller_actor_id
                != arkret_wire::ActorId::account(self.context.account_id.clone())
        {
            return Err(protocol(
                "MLS material request differs from its native reader",
            ));
        }
        let value = self.client.self_mls_group_state_material(request).await?;
        self.bind(request.clone(), value)
    }

    pub async fn self_mls_roster_authority(
        &self,
        request: &MlsMemberRosterAuthorityReadRequestBody,
    ) -> Result<
        BoundOwnStationDeviceResponse<
            MlsMemberRosterAuthorityReadRequestBody,
            MlsSelfRosterAuthorityReadOutcome,
        >,
    > {
        self.check_context()?;
        request.validate()?;
        if request.effective_scope != self.context.effective_scope
            || request.caller_actor_id
                != arkret_wire::ActorId::account(self.context.account_id.clone())
        {
            return Err(protocol(
                "MLS roster request differs from its native reader",
            ));
        }
        let value = self.client.self_mls_roster_authority(request).await?;
        self.bind(request.clone(), value)
    }

    pub async fn receive_device_messages(
        &self,
        after: Option<&str>,
        limit: Option<u32>,
    ) -> Result<
        BoundOwnStationDeviceResponse<(Option<String>, Option<u32>), DeviceMessagesGetOutcome>,
    > {
        self.check_context()?;
        let value = self.client.receive_device_messages(after, limit).await?;
        self.bind((after.map(str::to_owned), limit), value)
    }
}

fn protocol(message: impl std::fmt::Display) -> Error {
    Error::Protocol(message.to_string())
}

#[cfg(test)]
mod tests {
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
        let binding = StationConnectionBinding {
            service_id: station.clone(),
            base_url: base.into(),
            trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:station.example")
                .unwrap(),
            auth_metadata: arkret_models_discovery::AuthMetadata::minimal(),
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
}
