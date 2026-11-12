//! Original results from an accepted Station using a real managed Device.
//!
//! These local capabilities preserve the host's Device lifetime and exact
//! transport identity. They are not sessions or portable authorization facts.

use std::sync::Arc;

use arkret_models_collaboration::device_messages::DeviceMessagesGetResponseBody;
use arkret_models_collaboration::exact_current_state::{
    ExactCurrentStateReadRequestBody, ExactCurrentStateReadResponseBody,
};
use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialResponseBody, MlsMemberGroupStateMaterialReadRequestBody,
};
use arkret_models_collaboration::mls_roster_authority::{
    MlsMemberRosterAuthorityReadRequestBody, MlsSelfRosterAuthorityReadResponseBody,
};
use arkret_models_crypto::{KeyPackagesClaimQueryRequestBody, KeyPackagesClaimResponseBody};
use arkret_models_discovery::{ServiceDescribe, TransportBinding};
use arkret_models_identity::signer_key_operations::{
    SignerKeyQueryResponseBody, SignerKeysQueryRequestBody,
};
use arkret_models_integration::AppletManagedDeviceMetadata;
use arkret_wire::{
    ActorId, AppletId, CommitStreamRef, CommittedEventView, CurrentState, DeviceId, EventId,
    RealmId, RealmSnapshotId, RealmStateSnapshot, ScopeRef, StreamScanRequestBody,
    StreamScanResponseBody,
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
            CurrentState::Value {
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
        request: &StreamScanRequestBody,
    ) -> Result<BoundOwnStationDeviceResponse<StreamScanRequestBody, StreamScanResponseBody>> {
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

    pub async fn exact_current_state(
        &self,
        request: &ExactCurrentStateReadRequestBody,
        generation: u64,
    ) -> Result<
        BoundOwnStationDeviceResponse<
            (ExactCurrentStateReadRequestBody, u64),
            ExactCurrentStateReadResponseBody,
        >,
    > {
        self.check_context()?;
        request.validate()?;
        if self.context.effective_scope.realm_id_opt() != Some(&request.realm_id) {
            return Err(protocol("native current request belongs to another Realm"));
        }
        let value = self.client.exact_current_state(request, generation).await?;
        value.validate_for_request(request, generation)?;
        let stream = match &value {
            ExactCurrentStateReadResponseBody::Present {
                effective_stream_head,
                ..
            }
            | ExactCurrentStateReadResponseBody::NeverWritten {
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
    ) -> Result<BoundOwnStationDeviceResponse<SignerKeysQueryRequestBody, SignerKeyQueryResponseBody>>
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
        BoundOwnStationDeviceResponse<
            KeyPackagesClaimQueryRequestBody,
            KeyPackagesClaimResponseBody,
        >,
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
            MlsGroupStateMaterialResponseBody,
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
            MlsSelfRosterAuthorityReadResponseBody,
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
        BoundOwnStationDeviceResponse<(Option<String>, Option<u32>), DeviceMessagesGetResponseBody>,
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

    /// Submit the exact immutable original. This deliberately does not refresh
    /// prepare input or re-evaluate today's business cut before a fixed retry.
    /// The server authenticates the original requester and distinguishes replay
    /// from first acceptance transactionally.
    pub async fn put_native_key_backup(
        &self,
        packet: &arkret_models_crypto::KeyBackup,
        idempotency_key: &str,
    ) -> Result<
        BoundOwnStationDeviceResponse<
            arkret_models_crypto::KeyBackup,
            arkret_models_crypto::RealmActorBackupPutResponseBody,
        >,
    > {
        self.check_context()?;
        packet.validate()?;
        if packet.actor_id != self.context.actor_id
            || packet.device_id.as_ref() != Some(&self.context.device_id)
            || packet.signature_proof.device_authorize_event_id.as_ref()
                != Some(&self.context.authorization_event_id)
            || packet
                .contents
                .first()
                .and_then(|i| i.root_context.as_ref())
                .map(|c| &c.effective_scope)
                != Some(&self.context.effective_scope)
        {
            return Err(protocol(
                "native PUT differs from its exact original requester or scope",
            ));
        }
        let value: arkret_models_crypto::RealmActorBackupPutResponseBody = self
            .client
            .put_with_options(
                &format!("/_arkret/self/keys/backups/{}", packet.backup_id),
                packet,
                &crate::ClientRequestOptions::new().idempotency_key(idempotency_key),
            )
            .await?;
        if value.backup_id != packet.backup_id
            || value.ciphertext_digest != packet.ciphertext_digest
        {
            return Err(protocol("native PUT ACK differs from its immutable packet"));
        }
        self.validate_native_packet_result(packet, &value.admission)?;
        self.bind(packet.clone(), value)
    }

    pub async fn realm_actor_backup_prepare_input(
        &self,
        request_nonce: String,
        authority: &arkret_identity::VerifiedRealmAuthority,
        resolution: &arkret_models_identity::AuthenticatedServiceResolution,
        keys: &(dyn arkret_identity::RealmAuthorityKeyDirectory + Sync),
    ) -> Result<
        BoundOwnStationDeviceResponse<
            arkret_models_integration::RealmActorMaterialRequestBody,
            arkret_models_crypto::ContentBackupNextPrepareInput,
        >,
    > {
        self.check_context()?;
        if &self.context.binding.service_id != authority.current_service_id()
            || self.context.governance_generation != authority.current_generation()
            || self.context.effective_scope.realm_id_opt() != Some(authority.realm_id())
        {
            return Err(protocol(
                "native prepare input authority differs from captured Device context",
            ));
        }
        let request = arkret_models_integration::RealmActorMaterialRequestBody::Current {
            actor_id: self.context.actor_id.clone(),
            request_nonce,
            selectors: vec![
                arkret_wire::CurrentSelector::RealmActorRecovery {
                    actor_id: self.context.actor_id.clone(),
                },
                arkret_wire::CurrentSelector::RealmActorKeyBackupActiveSeries {
                    actor_id: self.context.actor_id.clone(),
                    effective_scope: self.context.effective_scope.clone(),
                    backup_kind: arkret_wire::RealmActorBackupKind::SecretStorage,
                },
            ],
        };
        let material = self
            .client
            .realm_actor_material(
                &request,
                &self.context.actor_id,
                authority,
                resolution,
                keys,
            )
            .await?;
        let input = material
            .material()
            .content_backup_prepare_input(&self.context.actor_id, &self.context.effective_scope)?
            .clone();
        self.bind(request, input)
    }

    /// Only the selected series' exact current head metadata is returned.
    pub async fn native_key_backup_head(
        &self,
        query: &arkret_models_crypto::RealmActorBackupHeadQuery,
    ) -> Result<
        BoundOwnStationDeviceResponse<
            arkret_models_crypto::RealmActorBackupHeadQuery,
            arkret_models_crypto::RealmActorBackupSeriesHeadResponseBody,
        >,
    > {
        self.check_context()?;
        if self.context.actor_id.as_realm_actor_id() != Some(&query.realm_actor_id)
            || self.context.effective_scope != query.effective_scope()
        {
            return Err(protocol(
                "native backup head request differs from its Device scope",
            ));
        }
        let pairs = arkret_models_crypto::KeysBackupsListParameters::Device(query.clone())
            .to_query_pairs()?;
        let value: arkret_models_crypto::RealmActorBackupSeriesHeadResponseBody = self
            .client
            .send_json(
                self.client
                    .request(reqwest::Method::GET, "/_arkret/self/keys/backups")?
                    .query(&pairs),
            )
            .await?;
        if value.realm_actor_id != query.realm_actor_id
            || value.effective_scope != query.effective_scope()
            || value.active_series.realm_actor_id != query.realm_actor_id
            || value.active_series.effective_scope != value.effective_scope
            || value.items.len() > 1
        {
            return Err(protocol(
                "native backup head response changed its actor, scope or cardinality",
            ));
        }
        for item in &value.items {
            if item.metadata.actor_id != self.context.actor_id
                || item.admission.realm_actor_id != query.realm_actor_id
                || item.admission.effective_scope != query.effective_scope()
                || item.metadata.backup_id != item.admission.backup_id
                || item.metadata.ciphertext_digest != item.admission.ciphertext_digest
                || item.metadata.device_id != item.admission.device_id
                || item.metadata.auth_binding.manager_ref != item.admission.manager_ref
                || item.metadata.auth_binding.recovery_ref != item.admission.recovery_ref
                || item.metadata.auth_binding.recipient_ref != item.admission.recipient_ref
                || item.metadata.auth_binding.device_generation != item.admission.device_generation
                || item.admission.signature.context
                    != arkret_wire::DetachedSignatureContext::RealmActorContentBackupAdmission
                || item.admission.signature.created_at != item.admission.accepted_at
                || value.active_series.secret_storage.series_id() != Some(&item.metadata.series_id)
            {
                return Err(protocol(
                    "native head metadata differs from its immutable admission or selected series",
                ));
            }
        }
        self.bind(query.clone(), value)
    }

    pub async fn issue_native_key_backup_unlock_challenge(
        &self,
        backup_id: &arkret_wire::BackupId,
        request: &arkret_models_crypto::RealmActorBackupIssueUnlockChallengeRequestBody,
    ) -> Result<
        BoundOwnStationDeviceResponse<
            (
                arkret_wire::BackupId,
                arkret_models_crypto::RealmActorBackupIssueUnlockChallengeRequestBody,
            ),
            arkret_models_crypto::RealmActorBackupUnlockChallenge,
        >,
    > {
        use arkret_models_crypto::{
            RealmActorBackupUnlockChallengeKind as Kind,
            RealmActorBackupUnlockChallengePurpose as Purpose,
        };
        self.check_context()?;
        if request.kind != Kind::RealmActorDevice
            || request.purpose != Purpose::SeriesPredecessor
            || self.context.actor_id.as_realm_actor_id() != Some(&request.realm_actor_id)
            || self.context.effective_scope != request.effective_scope
        {
            return Err(protocol(
                "native challenge must select this Device's exact head scope",
            ));
        }
        let value: arkret_models_crypto::RealmActorBackupUnlockChallenge = self
            .client
            .post(
                &format!("/_arkret/self/keys/backups/{backup_id}/unlock-challenge"),
                request,
            )
            .await?;
        value.validate_for_native_request(request, backup_id)?;
        if value.audience.as_str() != self.client.base_url.origin().ascii_serialization() {
            return Err(protocol(
                "native unlock challenge changed the bound service origin",
            ));
        }
        if value.requesting_device_id.as_ref() != Some(&self.context.device_id)
            || value.device_authorize_event_id.as_ref()
                != Some(&self.context.authorization_event_id)
            || value.service_id != self.context.binding.service_id
        {
            return Err(protocol(
                "native challenge changed its current requester or bound Station",
            ));
        }
        self.bind((backup_id.clone(), request.clone()), value)
    }

    /// Independently verifies the complete original packet with the immutable
    /// original Device key supplied by this bound Station. A sibling author is
    /// legitimate; it is never impersonated as a PUT requester.
    pub async fn unlock_native_key_backup(
        &self,
        challenge: &BoundOwnStationDeviceResponse<
            (
                arkret_wire::BackupId,
                arkret_models_crypto::RealmActorBackupIssueUnlockChallengeRequestBody,
            ),
            arkret_models_crypto::RealmActorBackupUnlockChallenge,
        >,
    ) -> Result<
        BoundOwnStationDeviceResponse<
            arkret_models_crypto::RealmActorDeviceKeyBackupUnlockProof,
            arkret_models_crypto::RealmActorBackupUnlockResponseBody,
        >,
    > {
        use ed25519_dalek::Signer as _;
        self.check_context()?;
        if challenge.context != self.context {
            return Err(protocol(
                "unlock challenge belongs to another Device incarnation",
            ));
        }
        let challenge = challenge.value()?;
        let signer = self
            .client
            .http_message_signer
            .as_ref()
            .ok_or_else(|| protocol("native unlock lacks its actual signer"))?;
        let fingerprint =
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(&self.context.public_key);
        let method = arkret_wire::DidUrl::new(format!("did:key:{fingerprint}#{fingerprint}"))
            .map_err(protocol)?;
        let proof = challenge.sign_device_unlock_proof(method, |bytes| {
            Ok(signer.signing_key().sign(bytes).to_bytes().to_vec())
        })?;
        let request = arkret_models_crypto::KeysBackupsUnlockOperationRequestBody {
            proof: arkret_models_crypto::KeyBackupUnlockProofBody::Device(proof.clone()),
        };
        let value: arkret_models_crypto::RealmActorBackupUnlockResponseBody = self
            .client
            .post(
                &format!("/_arkret/self/keys/backups/{}/unlock", proof.backup_id),
                &request,
            )
            .await?;
        self.validate_native_packet_result(&value.backup, &value.admission)?;
        if value.backup.backup_id != proof.backup_id
            || value.admission.envelope_digest != proof.envelope_digest
            || value.backup.ciphertext_digest != proof.ciphertext_digest
            || value.backup.series_id != proof.series_id
        {
            return Err(protocol("native unlock returned another exact packet"));
        }
        self.bind(proof, value)
    }

    fn validate_native_packet_result(
        &self,
        packet: &arkret_models_crypto::KeyBackup,
        admission: &arkret_models_crypto::RealmActorContentBackupAdmission,
    ) -> Result<()> {
        if packet.actor_id != self.context.actor_id
            || admission.effective_scope != self.context.effective_scope
        {
            return Err(protocol(
                "native packet result differs from its bound Device scope",
            ));
        }
        arkret_signatures::realm_actor_content_backup::verify_realm_actor_backup_packet(
            packet, admission,
        )
        .map_err(protocol)
    }
}

fn protocol(message: impl std::fmt::Display) -> Error {
    Error::Protocol(message.to_string())
}

#[cfg(test)]
mod tests;
