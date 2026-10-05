//! Ordinary-client consumption of original results from its accepted Station.
//!
//! These non-wire carriers bind an authenticated request to a live local
//! session. They are not portable governance proofs or Station audit evidence.

use std::sync::Arc;

use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
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
use arkret_wire::{
    AccountId, CommittedEventView, DidCoreId, EventId, RealmId, RealmSnapshotId,
    RealmStateSnapshot, SessionGrantId, StreamScanOutcome, StreamScanRequest,
};

use crate::{Auth, Client, ClientRequestOptions, Error, Result};

/// A host session provider implements this using its live, atomically captured
/// session state. The epoch changes on every replacement, including ABA login.
#[cfg(not(target_arch = "wasm32"))]
pub trait OwnStationSessionSource: Send + Sync {
    fn snapshot(&self) -> Result<OwnStationSessionSnapshot>;
}

#[cfg(target_arch = "wasm32")]
pub trait OwnStationSessionSource {
    fn snapshot(&self) -> Result<OwnStationSessionSnapshot>;
}

#[derive(Clone, PartialEq, Eq)]
pub struct OwnStationSessionSnapshot {
    binding: StationConnectionBinding,
    account_id: AccountId,
    grant_id: SessionGrantId,
    epoch: u64,
    credential: String,
    instance: Option<OwnStationSessionIdentity>,
}

/// Local provider lifetime identity. Clones retain identity; constructing a
/// new provider produces a different identity even for byte-identical grants.
#[derive(Clone, Debug)]
pub struct OwnStationSessionIdentity(Arc<()>);
impl Default for OwnStationSessionIdentity {
    fn default() -> Self {
        Self(Arc::new(()))
    }
}
impl PartialEq for OwnStationSessionIdentity {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for OwnStationSessionIdentity {}

impl std::fmt::Debug for OwnStationSessionSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnStationSessionSnapshot")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl OwnStationSessionSnapshot {
    /// Convert an already accepted connection and a formally validated live
    /// grant. This does not accept a wire `verified` assertion.
    pub fn new(
        binding: StationConnectionBinding,
        account_id: AccountId,
        audience_id: DidCoreId,
        grant_id: SessionGrantId,
        epoch: u64,
        credential: String,
    ) -> Result<Self> {
        if binding.service_id != account_id.station_id
            || audience_id != binding.service_id
            || credential.is_empty()
        {
            return Err(protocol(
                "own Station session account, audience or credential mismatch",
            ));
        }
        Ok(Self {
            binding,
            account_id,
            grant_id,
            epoch,
            credential,
            instance: None,
        })
    }

    pub fn with_provider_identity(mut self, identity: OwnStationSessionIdentity) -> Self {
        self.instance = Some(identity);
        self
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }
    pub fn grant_id(&self) -> &SessionGrantId {
        &self.grant_id
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn binding(&self) -> &StationConnectionBinding {
        &self.binding
    }
}

/// Only successful authenticated operations below can construct this carrier.
/// It deliberately has no deserializer, public constructor or mutable value.
#[derive(Clone)]
pub struct BoundOwnStationResponse<Q, T> {
    request: Q,
    value: T,
    session: OwnStationSessionSnapshot,
    source: Arc<dyn OwnStationSessionSource>,
}

impl<Q: std::fmt::Debug, T: std::fmt::Debug> std::fmt::Debug for BoundOwnStationResponse<Q, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundOwnStationResponse")
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

impl<Q, T> BoundOwnStationResponse<Q, T> {
    pub fn request(&self) -> &Q {
        &self.request
    }
    pub fn value(&self) -> Result<&T> {
        if self.source.snapshot()? != self.session {
            return Err(protocol(
                "late own Station response belongs to an inactive session",
            ));
        }
        Ok(&self.value)
    }
    pub fn into_value(self) -> Result<T> {
        self.value()?;
        Ok(self.value)
    }
    pub fn session(&self) -> &OwnStationSessionSnapshot {
        &self.session
    }
}

#[derive(Clone)]
pub struct OwnStationResultClient {
    client: Client,
    binding: StationConnectionBinding,
    session: OwnStationSessionSnapshot,
    source: Arc<dyn OwnStationSessionSource>,
}

impl OwnStationResultClient {
    pub fn new(
        client: Client,
        accepted_binding: StationConnectionBinding,
        source: Arc<dyn OwnStationSessionSource>,
    ) -> Result<Self> {
        let session = source.snapshot()?;
        if session.binding != accepted_binding
            || client.base_url.as_str() != accepted_binding.base_url
        {
            return Err(protocol(
                "own Station client is not at the accepted session origin",
            ));
        }
        let credential = match &client.auth {
            Some(Auth::Bearer(value)) => Some(value.as_str()),
            Some(Auth::Dpop(value)) => value.access_token(),
            _ => None,
        };
        if credential != Some(session.credential.as_str()) {
            return Err(protocol(
                "own Station client credential differs from live session",
            ));
        }
        Ok(Self {
            client,
            binding: accepted_binding,
            session,
            source,
        })
    }

    pub fn session(&self) -> Result<&OwnStationSessionSnapshot> {
        self.check_session()?;
        Ok(&self.session)
    }
    pub fn binding(&self) -> &StationConnectionBinding {
        &self.binding
    }
    pub fn check_session(&self) -> Result<()> {
        if self.source.snapshot()? != self.session {
            return Err(protocol("own Station client session changed"));
        }
        Ok(())
    }
    fn bind<Q, T>(&self, request: Q, value: T) -> Result<BoundOwnStationResponse<Q, T>> {
        self.check_session()?;
        Ok(BoundOwnStationResponse {
            request,
            value,
            session: self.session.clone(),
            source: self.source.clone(),
        })
    }
    pub async fn scan_commit_stream(
        &self,
        request: &StreamScanRequest,
    ) -> Result<BoundOwnStationResponse<StreamScanRequest, StreamScanOutcome>> {
        self.check_session()?;
        let value = self.client.scan_commit_stream(request).await?;
        self.bind(request.clone(), value)
    }
    pub async fn committed_event_get(
        &self,
        event_id: &EventId,
    ) -> Result<BoundOwnStationResponse<EventId, CommittedEventView>> {
        self.check_session()?;
        let value = self.client.committed_event_get(event_id).await?;
        self.bind(event_id.clone(), value)
    }
    pub async fn snapshot_head(
        &self,
        realm_id: &RealmId,
    ) -> Result<BoundOwnStationResponse<RealmId, RealmStateSnapshot>> {
        self.check_session()?;
        let value = self.client.realm_state_snapshot_head(realm_id).await?;
        self.bind(realm_id.clone(), value)
    }
    pub async fn snapshot_by_ref(
        &self,
        realm_id: &RealmId,
        snapshot_id: &RealmSnapshotId,
    ) -> Result<BoundOwnStationResponse<(RealmId, RealmSnapshotId), RealmStateSnapshot>> {
        self.check_session()?;
        let value = self
            .client
            .realm_state_snapshot_by_ref(realm_id, snapshot_id)
            .await?;
        self.bind((realm_id.clone(), snapshot_id.clone()), value)
    }
    pub async fn signer_keys_query(
        &self,
        request: &SignerKeysQueryRequestBody,
    ) -> Result<BoundOwnStationResponse<SignerKeysQueryRequestBody, SignerKeysQueryOutcome>> {
        self.check_session()?;
        if &request.recipient_account_id != self.session.account_id() {
            return Err(protocol(
                "historical signer request uses another full Account",
            ));
        }
        let value = self.client.signer_keys_query(request).await?;
        self.bind(request.clone(), value)
    }
    pub async fn keypackages_claim_query(
        &self,
        request: &KeyPackagesClaimQueryRequestBody,
    ) -> Result<BoundOwnStationResponse<KeyPackagesClaimQueryRequestBody, KeyPackagesClaimOutcome>>
    {
        self.check_session()?;
        let value = self.client.keypackages_claim_query(request).await?;
        value
            .validate_shape()
            .map_err(|error| protocol(&error.to_string()))?;
        if !value
            .claims
            .iter()
            .any(|claim| claim.claim_id == request.claim_id.as_str())
        {
            return Err(protocol(
                "own Station claim query answered for another claim",
            ));
        }
        self.bind(request.clone(), value)
    }
    pub async fn self_mls_group_state_material(
        &self,
        request: &MlsMemberGroupStateMaterialReadRequestBody,
    ) -> Result<
        BoundOwnStationResponse<
            MlsMemberGroupStateMaterialReadRequestBody,
            MlsGroupStateMaterialOutcome,
        >,
    > {
        self.check_session()?;
        let value = self.client.self_mls_group_state_material(request).await?;
        self.bind(request.clone(), value)
    }
    pub async fn self_mls_roster_authority(
        &self,
        request: &MlsMemberRosterAuthorityReadRequestBody,
    ) -> Result<
        BoundOwnStationResponse<
            MlsMemberRosterAuthorityReadRequestBody,
            MlsSelfRosterAuthorityReadOutcome,
        >,
    > {
        self.check_session()?;
        let value = self.client.self_mls_roster_authority(request).await?;
        self.bind(request.clone(), value)
    }
    pub async fn exact_current_result(
        &self,
        request: &ExactCurrentResultsReadRequestBody,
        generation: u64,
    ) -> Result<
        BoundOwnStationResponse<
            (ExactCurrentResultsReadRequestBody, u64),
            ExactCurrentResultsReadOutcome,
        >,
    > {
        self.check_session()?;
        let value = self
            .client
            .exact_current_result(request, generation)
            .await?;
        self.bind((request.clone(), generation), value)
    }
    pub async fn submit_to_realm_authority(
        &self,
        request: &SelfAuthoritySubmitRequest,
        options: &ClientRequestOptions,
    ) -> Result<BoundOwnStationResponse<SelfAuthoritySubmitRequest, SelfAuthoritySubmitOutcome>>
    {
        self.check_session()?;
        let value = self
            .client
            .submit_to_realm_authority(request, options)
            .await?;
        self.bind(request.clone(), value)
    }
}

fn protocol(message: &str) -> Error {
    Error::Protocol(message.into())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    struct Source(Mutex<OwnStationSessionSnapshot>);
    impl OwnStationSessionSource for Source {
        fn snapshot(&self) -> Result<OwnStationSessionSnapshot> {
            Ok(self.0.lock().unwrap().clone())
        }
    }
    fn session(base: String) -> OwnStationSessionSnapshot {
        let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let binding = StationConnectionBinding {
            service_id: station.clone(),
            base_url: base,
            trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:station.example")
                .unwrap(),
            auth_metadata: arkret_models_discovery::AuthMetadata::minimal(),
        };
        OwnStationSessionSnapshot::new(
            binding,
            AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                station.clone(),
            ),
            station,
            SessionGrantId::from_issuance_digest([1; 32]),
            0,
            "session-token".into(),
        )
        .unwrap()
        .with_provider_identity(Default::default())
    }

    #[tokio::test]
    async fn own_station_actual_http_rejects_late_session_and_preserves_original() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source = Arc::new(Source(Mutex::new(session(format!(
            "http://{}/",
            listener.local_addr().unwrap()
        )))));
        let captured = source.snapshot().unwrap();
        let raw = crate::ClientBuilder::new(url::Url::parse(&captured.binding.base_url).unwrap())
            .allow_insecure_localhost()
            .auth(Auth::Bearer("session-token".into()))
            .build()
            .unwrap();
        let client =
            OwnStationResultClient::new(raw.clone(), captured.binding.clone(), source.clone())
                .unwrap();
        let server_source = source.clone();
        let server = tokio::spawn(async move {
            for ordinal in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = vec![0; 8192];
                let count = stream.read(&mut bytes).await.unwrap();
                let request = String::from_utf8_lossy(&bytes[..count]);
                assert!(request.contains("/_arkret/self/streams/scan"));
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer session-token")
                );
                if ordinal == 1 {
                    server_source.0.lock().unwrap().epoch += 1;
                }
                let body = r#"{"committed_events":[],"truncated":false}"#;
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
            }
        });
        let realm =
            arkret_wire::RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO")
                .unwrap();
        let request = StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: arkret_wire::CommitStreamRef::Realm { realm_id: realm },
            direction: arkret_wire::StreamScanDirection::After(None),
            limit: 1,
        };
        let response = client.scan_commit_stream(&request).await.unwrap();
        assert_eq!(response.request(), &request);
        assert!(response.value().unwrap().committed_events.is_empty());
        assert!(
            client.scan_commit_stream(&request).await.is_err(),
            "session replaced while HTTP response was in flight"
        );
        server.await.unwrap();
        assert!(response.value().is_err());
        assert!(client.check_session().is_err());
        assert!(
            OwnStationResultClient::new(
                raw.with_base_url(url::Url::parse("http://localhost:1/").unwrap())
                    .unwrap(),
                captured.binding.clone(),
                source.clone()
            )
            .is_err()
        );
        assert!(
            OwnStationResultClient::new(
                crate::ClientBuilder::new(url::Url::parse(&captured.binding.base_url).unwrap())
                    .allow_insecure_localhost()
                    .auth(Auth::Bearer("another-token".into()))
                    .build()
                    .unwrap(),
                captured.binding,
                source
            )
            .is_err()
        );
    }

    #[test]
    fn own_station_full_account_audience_and_provider_instance_are_exact() {
        let original = session("https://station.example/".into());
        let another_instance = session("https://station.example/".into());
        assert_ne!(original, another_instance);
        let wrong_station = DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(
            OwnStationSessionSnapshot::new(
                original.binding.clone(),
                AccountId::new(original.account_id.principal_id.clone(), wrong_station),
                original.binding.service_id.clone(),
                original.grant_id.clone(),
                0,
                "session-token".into()
            )
            .is_err()
        );
    }
}
