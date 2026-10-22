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
use arkret_models_discovery::{ServiceDescribe, TransportBinding};
use arkret_models_identity::signer_key_operations::{
    SignerKeysQueryOutcome, SignerKeysQueryRequestBody,
};
use arkret_models_integration::AppletManagedDeviceMetadata;
use arkret_wire::{
    ActorId, AppletId, CommitStreamRef, CommittedEventView, DeviceId, EventId, RealmId,
    RealmSnapshotId, RealmStateSnapshot, ScopeRef, StreamScanOutcome, StreamScanRequest,
    TypedCurrentRow,
};
use chrono::{DateTime, Utc};

use crate::{Client, Error, Result};

/// Shape/data-scope check only. Authorization still comes from the bound
/// native response and the accepted Station's current delivery barriers.
pub fn validate_device_snapshot_scope(
    snapshot: &RealmStateSnapshot,
    scope: &ScopeRef,
) -> Result<()> {
    if !matches!(scope, ScopeRef::Realm { .. } | ScopeRef::Circle { .. }) {
        return Err(protocol("native snapshot requires a Realm or Circle"));
    }
    let expected = CommitStreamRef::from_scope(scope, None)?;
    if &snapshot.realm_id != expected.realm_id()
        || snapshot.visible_stream_heads.len() != 1
        || snapshot.visible_stream_heads[0].stream_ref != expected
        || snapshot.retention_and_history_floor.stream_floors.len() != 1
        || snapshot.retention_and_history_floor.stream_floors[0].stream_ref != expected
        || snapshot.current_state_entries.iter().any(|row| match row {
            // Circle object data cannot piggyback on its Realm authorization
            // stream; that Realm source is outside a Circle-only cut as well.
            TypedCurrentRow::Value {
                source_stream_ref,
                selector,
                ..
            } => {
                source_stream_ref != &expected
                    || matches!(selector, arkret_wire::CurrentSelector::Circle { .. })
            }
        })
    {
        return Err(protocol(
            "native snapshot differs from its exact authorized scope",
        ));
    }
    Ok(())
}

/// Local Station identity for an already accepted Device. Login and Gate
/// enrollment metadata are outside this native transport capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnStationDeviceBinding {
    service_id: arkret_wire::DidCoreId,
    base_url: String,
    trust_domain: arkret_wire::TrustDomainId,
}

impl OwnStationDeviceBinding {
    pub fn from_description(
        selected_base: &url::Url,
        description: &ServiceDescribe,
    ) -> Result<Self> {
        arkret_models_discovery::validate_connection_url(selected_base, false)?;
        description.validate()?;
        if description.service_kind != arkret_wire::ServiceKind::Station
            || !selected_base.as_str().ends_with('/')
        {
            return Err(protocol(
                "native connection requires the exact Station base",
            ));
        }
        let bases = description
            .transport_bindings
            .iter()
            .filter_map(|binding| match binding {
                TransportBinding::HttpJson { base_url, .. } => Some(base_url.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        if bases != [selected_base.as_str()] {
            return Err(protocol(
                "Station describe does not confirm the selected native base",
            ));
        }
        Ok(Self {
            service_id: description.service_id.clone(),
            base_url: selected_base.as_str().to_owned(),
            trust_domain: description.trust_domain.clone(),
        })
    }
    pub fn service_id(&self) -> &arkret_wire::DidCoreId {
        &self.service_id
    }
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    pub fn trust_domain(&self) -> &arkret_wire::TrustDomainId {
        &self.trust_domain
    }
}

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
    binding: OwnStationDeviceBinding,
    actor_id: ActorId,
    governance_generation: u64,
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
        binding: OwnStationDeviceBinding,
        governance: &arkret_identity::VerifiedRealmAuthority,
        metadata: &AppletManagedDeviceMetadata,
        public_key: [u8; 32],
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        epoch: u64,
        instance: OwnStationDeviceInstance,
    ) -> Result<Self> {
        metadata.validate()?;
        if &binding.service_id != governance.current_service_id()
            || metadata
                .actor_id
                .as_realm_actor_id()
                .is_none_or(|actor| &actor.realm_id != governance.realm_id())
            || expires_at <= not_before
        {
            return Err(protocol("own Station Device binding or window is invalid"));
        }
        let snapshot = Self {
            binding,
            actor_id: metadata.actor_id.clone(),
            governance_generation: governance.current_generation(),
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

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
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
    pub fn binding(&self) -> &OwnStationDeviceBinding {
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
        self.actor_id == metadata.actor_id
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
            || destination != &context.binding.service_id
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

    fn check_snapshot_scope(&self, realm: &RealmId, snapshot: &RealmStateSnapshot) -> Result<()> {
        if &snapshot.realm_id != realm {
            return Err(protocol("native snapshot request differs from its Realm"));
        }
        validate_device_snapshot_scope(snapshot, &self.context.effective_scope)
    }

    pub async fn snapshot_head(
        &self,
        realm: &RealmId,
    ) -> Result<BoundOwnStationDeviceResponse<RealmId, RealmStateSnapshot>> {
        self.check_context()?;
        if self.context.effective_scope.realm_id() != realm {
            return Err(protocol("native snapshot request belongs to another Realm"));
        }
        let value = self.client.realm_state_snapshot_head(realm).await?;
        self.check_snapshot_scope(realm, &value)?;
        self.bind(realm.clone(), value)
    }

    pub async fn snapshot_by_ref(
        &self,
        realm: &RealmId,
        reference: &RealmSnapshotId,
    ) -> Result<BoundOwnStationDeviceResponse<(RealmId, RealmSnapshotId), RealmStateSnapshot>> {
        self.check_context()?;
        if self.context.effective_scope.realm_id() != realm {
            return Err(protocol(
                "native snapshot reference belongs to another Realm",
            ));
        }
        let value = self
            .client
            .realm_state_snapshot_by_ref(realm, reference)
            .await?;
        self.check_snapshot_scope(realm, &value)?;
        if &value.snapshot_id != reference {
            return Err(protocol(
                "native snapshot response differs from its exact reference",
            ));
        }
        self.bind((realm.clone(), reference.clone()), value)
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
        if request.recipient_actor_id.as_ref() != Some(&self.context.actor_id)
            || request.recipient_account_id.is_some()
        {
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
            || request.caller_actor_id != self.context.actor_id
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
            || request.caller_actor_id != self.context.actor_id
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
        value.validate_realm_device_recipient(
            &self.context.actor_id,
            &self.context.device_id,
            &self.context.effective_scope,
        )?;
        self.bind((after.map(str::to_owned), limit), value)
    }
}

fn protocol(message: impl std::fmt::Display) -> Error {
    Error::Protocol(message.to_string())
}

#[cfg(test)]
mod tests;
