//! Closed recoverable-content models and local shape invariants.
//! Native authority, accepted history and durable custody are caller obligations.

use std::collections::BTreeSet;

use arkret_canonical::{base64url_decode, base64url_encode};
use arkret_wire::{Result, WireError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

include!("generated/content_history_contracts.rs");

mod scope_cleanup;

/// Local unsigned signing input, never a wire authorization or storage proof.
#[derive(Clone, Debug)]
pub struct ContentBackupSourceDraft {
    pub event_ref: arkret_wire::EventId,
    pub event_original_digest: arkret_wire::Hash,
    pub producer: ContentEndpoint,
    pub effective_scope: arkret_wire::ScopeRef,
    pub destination_service_id: arkret_wire::DidCoreId,
    pub protections_digest: arkret_wire::Hash,
    pub verification_method: arkret_wire::DidUrl,
    pub attested_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
struct UnsignedContentBackupSource<'a> {
    event_ref: &'a arkret_wire::EventId,
    event_original_digest: &'a arkret_wire::Hash,
    producer: &'a ContentEndpoint,
    effective_scope: &'a arkret_wire::ScopeRef,
    destination_service_id: &'a arkret_wire::DidCoreId,
    protections_digest: &'a arkret_wire::Hash,
    verification_method: &'a arkret_wire::DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    attested_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl From<&ContentBackupSourceAttestation> for ContentBackupSourceDraft {
    fn from(source: &ContentBackupSourceAttestation) -> Self {
        Self {
            event_ref: source.event_ref.clone(),
            event_original_digest: source.event_original_digest.clone(),
            producer: source.producer.clone(),
            effective_scope: source.effective_scope.clone(),
            destination_service_id: source.destination_service_id.clone(),
            protections_digest: source.protections_digest.clone(),
            verification_method: source.verification_method.clone(),
            attested_at: source.attested_at,
            expires_at: source.expires_at,
        }
    }
}

impl ContentBackupSourceDraft {
    pub fn validate(&self) -> Result<()> {
        self.producer.validate()?;
        self.effective_scope.canonical_mls_group_id()?;
        sha256_ref(&self.event_original_digest)?;
        sha256_ref(&self.protections_digest)?;
        if self.producer.actor_id.as_account_id().is_none()
            || self.expires_at <= self.attested_at
            || self.expires_at - self.attested_at > chrono::Duration::seconds(300)
        {
            return protocol("invalid unsigned backup-source binding or observation window");
        }
        Ok(())
    }

    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let unsigned = UnsignedContentBackupSource {
            event_ref: &self.event_ref,
            event_original_digest: &self.event_original_digest,
            producer: &self.producer,
            effective_scope: &self.effective_scope,
            destination_service_id: &self.destination_service_id,
            protections_digest: &self.protections_digest,
            verification_method: &self.verification_method,
            attested_at: self.attested_at,
            expires_at: self.expires_at,
        };
        let mut bytes = b"ak.content.backup_source.v1\n".to_vec();
        bytes.extend(arkret_canonical::canonical_json_bytes(&unsigned)?);
        Ok(bytes)
    }

    /// Attach the actual Service signer result after signing the exact draft.
    /// Native issuer role and durable first-PUT custody are caller obligations.
    pub fn into_attestation(
        self,
        signature: crate::KeyOperationSignature,
    ) -> Result<ContentBackupSourceAttestation> {
        self.validate()?;
        let source = ContentBackupSourceAttestation {
            event_ref: self.event_ref,
            event_original_digest: self.event_original_digest,
            producer: self.producer,
            effective_scope: self.effective_scope,
            destination_service_id: self.destination_service_id,
            protections_digest: self.protections_digest,
            verification_method: self.verification_method,
            attested_at: self.attested_at,
            expires_at: self.expires_at,
            signature,
        };
        source.validate()?;
        Ok(source)
    }
}

impl ContentBackupSourceAttestation {
    /// Closed byte invariants; native storage and owning-Service role are separate.
    pub fn validate(&self) -> Result<()> {
        ContentBackupSourceDraft::from(self).validate()?;
        if self.signature.kid.as_str() != self.verification_method.as_str()
            || self
                .signature
                .signature_algorithm
                .as_ref()
                .is_some_and(|a| a.as_str() != "Ed25519")
        {
            return protocol("invalid original backup-source binding or observation window");
        }
        Ok(())
    }

    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        ContentBackupSourceDraft::from(self).signing_payload_bytes()
    }

    pub fn validate_at(&self, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
        self.validate()?;
        if now < self.attested_at || now >= self.expires_at {
            return protocol("backup source is outside its observation window");
        }
        Ok(())
    }

    /// Original-byte integrity only; each supplied fact is independently qualified.
    pub fn validate_original_binding(
        &self,
        event: &arkret_wire::Event,
        actual_producer: &ContentEndpoint,
        destination: &arkret_wire::DidCoreId,
        registered_protections_digest: &arkret_wire::Hash,
    ) -> Result<()> {
        self.validate()?;
        if self.producer != *actual_producer
            || &actual_producer.actor_id != event.executed_by.as_ref().unwrap_or(&event.actor_id)
            || self.event_ref != event.event_id
            || self.event_original_digest.as_str() != arkret_canonical::canonical_sha256(event)?
            || self.effective_scope != event.scope_ref
            || &self.destination_service_id != destination
            || &self.protections_digest != registered_protections_digest
        {
            return protocol(
                "backup source differs from its complete original Event or actual producer",
            );
        }
        Ok(())
    }
}

/// A serialized recovery root is secret material, including in a decrypted keybag.
#[derive(Clone, PartialEq, Eq)]
pub struct ContentRootSecret(Zeroizing<[u8; 32]>);

impl ContentRootSecret {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for ContentRootSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContentRootSecret(<redacted>)")
    }
}

impl Serialize for ContentRootSecret {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64url_encode(self.0.as_ref()))
    }
}

impl<'de> Deserialize<'de> for ContentRootSecret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        let decoded = Zeroizing::new(base64url_decode(&encoded).map_err(serde::de::Error::custom)?);
        let bytes = decoded
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("content root must be exactly 32 bytes"))?;
        if base64url_encode(decoded.as_slice()) != *encoded {
            return Err(serde::de::Error::custom("noncanonical content root"));
        }
        Ok(Self::new(bytes))
    }
}

pub(crate) fn required_nullable<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn protocol<T>(message: &str) -> Result<T> {
    Err(WireError::Protocol(message.to_owned()))
}

pub(crate) fn bytes32(encoded: &str) -> Result<[u8; 32]> {
    let bytes =
        base64url_decode(encoded).map_err(|error| WireError::Protocol(error.to_string()))?;
    if base64url_encode(&bytes) != encoded {
        return protocol("noncanonical 32-byte content field");
    }
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| WireError::Protocol("content field must be exactly 32 bytes".to_owned()))
}

pub(crate) fn sha256_ref(value: &arkret_wire::Hash) -> Result<()> {
    if !value.as_str().starts_with("sha256:") {
        return protocol("content commitment must use SHA-256");
    }
    Ok(())
}

impl ContentRootContext {
    pub fn validate(&self) -> Result<()> {
        if self.cipher_suite != "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519" {
            return protocol("unsupported content-root MLS ciphersuite");
        }
        self.effective_scope.canonical_mls_group_id()?;
        Ok(())
    }
}

impl ContentEndpoint {
    pub fn validate(&self) -> Result<()> {
        bytes32(&self.signature_key_base64url)?;
        if let arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method,
        } = &self.endpoint
            && verification_method.as_str().is_empty()
        {
            return protocol("Agent content endpoint requires its native method");
        }
        Ok(())
    }
}

impl HistoryRequest {
    pub fn validate(&self) -> Result<()> {
        self.recipient.validate()?;
        bytes32(&self.recipient_hpke_key_base64url)?;
        Ok(())
    }

    /// Validate the signed request window for new issuance or delivery.
    /// Native signer/leaf binding and current read permission are checked separately.
    pub fn validate_at(
        &self,
        created_at: chrono::DateTime<chrono::Utc>,
        evaluated_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        self.validate()?;
        let ttl = self.expires_at - created_at;
        if ttl <= chrono::Duration::zero()
            || ttl > chrono::Duration::seconds(900)
            || evaluated_at < created_at
            || evaluated_at >= self.expires_at
        {
            return protocol("history request is outside its bounded validity window");
        }
        Ok(())
    }
}

impl HistoryKeySelector {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::ContentKey { content_path, .. } => {
                if !content_path.starts_with('/') || content_path.chars().count() > 1024 {
                    return protocol("history content selector requires a bounded JSON pointer");
                }
                let mut chars = content_path.chars();
                while let Some(c) = chars.next() {
                    if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
                        return protocol(
                            "history content selector has an invalid JSON pointer escape",
                        );
                    }
                }
                Ok(())
            }
            Self::EpochRoot {
                root_context,
                root_ref,
                ..
            } => {
                root_context.validate()?;
                sha256_ref(root_ref)
            }
        }
    }
}

impl HistoryGrant {
    /// Match the exact independently accepted request, without asserting native authority.
    /// Current read/disclosure, selection and request freshness remain caller obligations.
    pub fn validate_for_request(
        &self,
        request_event_ref: &arkret_wire::EventId,
        request: &HistoryRequest,
    ) -> Result<()> {
        self.validate()?;
        request.validate()?;
        if self.recipient_key_event_ref != *request_event_ref
            || self.recipient != request.recipient
            || self.recipient_hpke_key_base64url != request.recipient_hpke_key_base64url
            || self.history_cut != request.history_cut
            || self.expires_at != request.expires_at
        {
            return protocol("history grant differs from its exact accepted request");
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.recipient.validate()?;
        bytes32(&self.recipient_hpke_key_base64url)?;
        if self.entries.is_empty() || self.entries.len() > 256 {
            return protocol("history grant requires one to 256 entries");
        }
        let mut entries = BTreeSet::new();
        for entry in &self.entries {
            entry.selector.validate()?;
            if !matches!(entry.sealed_key_base64url.len(), 86 | 107) {
                return protocol("history grant has an invalid packed HPKE width");
            }
            let encoded = base64url_decode(&entry.sealed_key_base64url)
                .map_err(|error| WireError::Protocol(error.to_string()))?;
            if !matches!(encoded.len(), 64 | 80)
                || base64url_encode(&encoded) != entry.sealed_key_base64url
                || matches!(entry.selector, HistoryKeySelector::EpochRoot { .. })
                    && encoded.len() != 80
                || !entries.insert(arkret_canonical::canonical_json_bytes(entry)?)
            {
                return protocol(
                    "history grant contains a duplicate, noncanonical or wrong-width secret entry",
                );
            }
        }
        Ok(())
    }
}

impl ContentContext {
    pub fn validate(&self) -> Result<()> {
        self.root_context.validate()?;
        self.producer.validate()?;
        sha256_ref(&self.root_ref)?;
        bytes32(&self.content_key_salt)?;
        Ok(())
    }
}

fn unique<T: Ord>(values: &[T]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

impl ContentProtection {
    pub fn validate(&self) -> Result<()> {
        if self.root_refs.is_empty()
            || self.backup_refs.is_empty()
            || self.root_refs.len() > 256
            || self.blob_refs.len() > 256
            || self.backup_refs.len() > 256
            || !unique(&self.root_refs)
            || !unique(&self.blob_refs)
            || !unique(&self.backup_refs)
        {
            return protocol("content protection dependencies must be bounded and unique");
        }
        for root in &self.root_refs {
            sha256_ref(root)?;
        }
        Ok(())
    }
}

impl ContentRecoveryBinding {
    pub fn validate(&self) -> Result<()> {
        self.replacement.validate()?;
        sha256_ref(&self.inventory_digest)?;
        if self.authorization_event_ref != self.replacement.authorization_event_ref {
            return protocol("recovery binding differs from replacement authorization");
        }
        Ok(())
    }
}

impl ContentHistoryBackupAccess {
    pub fn validate(&self) -> Result<()> {
        if self.root_refs.is_empty() || self.root_refs.len() > 256 || !unique(&self.root_refs) {
            return protocol("history access roots must be nonempty, bounded and unique");
        }
        for root in &self.root_refs {
            sha256_ref(root)?;
        }
        Ok(())
    }
}

impl ContentRecoveryCheckpoint {
    pub fn validate(&self) -> Result<()> {
        self.replacement.validate()?;
        sha256_ref(&self.coverage_head_digest)?;
        match self.state {
            ContentRecoveryState::Pending
                if !self.cleanup_completed
                    && self.cleanup_blob_ref.is_none()
                    && self.cleanup_inventory_digest.is_none() =>
            {
                Ok(())
            }
            ContentRecoveryState::Ready
                if self.cleanup_completed
                    && self.cleanup_blob_ref.is_some()
                    && self.cleanup_inventory_digest.is_some() =>
            {
                sha256_ref(
                    self.cleanup_inventory_digest
                        .as_ref()
                        .expect("checked present"),
                )
            }
            _ => protocol("recovery checkpoint state and cleanup evidence disagree"),
        }
    }
}

impl ContentRecoveryInventory {
    pub fn validate(&self) -> Result<()> {
        self.replacement.validate()?;
        if self.actor_id != self.replacement.actor_id
            || self.authorization_event_ref != self.replacement.authorization_event_ref
        {
            return protocol("recovery inventory subject and replacement differ");
        }
        let mut previous: Option<Vec<u8>> = None;
        for entry in &self.entries {
            #[derive(Serialize)]
            struct Key<'a> {
                effective_scope: &'a arkret_wire::ScopeRef,
                genesis_event_ref: &'a arkret_wire::EventId,
            }
            let key = arkret_canonical::canonical_json_bytes(&Key {
                effective_scope: &entry.effective_scope,
                genesis_event_ref: &entry.genesis_event_ref,
            })?;
            if previous.as_ref().is_some_and(|value| value >= &key) {
                return protocol("recovery inventory is not unique canonical scope order");
            }
            previous = Some(key);
            let mut indices = BTreeSet::new();
            let mut prior_index = None;
            for leaf in &entry.old_leaves {
                leaf.endpoint.validate()?;
                if !indices.insert(leaf.leaf_index)
                    || prior_index.is_some_and(|i| i >= leaf.leaf_index)
                    || leaf.endpoint.actor_id != self.actor_id
                    || leaf.endpoint.signature_key_base64url
                        == self.replacement.signature_key_base64url
                {
                    return protocol(
                        "recovery inventory has duplicate, foreign or reused endpoint",
                    );
                }
                prior_index = Some(leaf.leaf_index);
            }
        }
        Ok(())
    }
}

impl ContentRecoveryPreparation {
    /// Validate the closed progress shape, not native authority or history readiness.
    pub fn validate(&self) -> Result<()> {
        self.replacement.validate()?;
        if !matches!(
            self.replacement.actor_id,
            arkret_wire::ActorId::Account { .. }
        ) {
            return protocol("recovery preparation requires an Account replacement");
        }
        match self.state {
            ContentRecoveryPreparationState::Pending if self.inventory_blob_ref.is_none() => Ok(()),
            ContentRecoveryPreparationState::Prepared if self.inventory_blob_ref.is_some() => {
                Ok(())
            }
            _ => protocol("recovery preparation state and inventory reference disagree"),
        }
    }

    pub fn validate_for_authorization(&self, authorization: &arkret_wire::EventId) -> Result<()> {
        self.validate()?;
        if &self.replacement.authorization_event_ref != authorization {
            return protocol("recovery preparation differs from the requested authorization");
        }
        Ok(())
    }

    /// Bind progress to independently qualified native source coordinates.
    /// This does not prove complete census, current holder, Blob contents or decryption.
    pub fn validate_for_episode(
        &self,
        authorization: &arkret_wire::EventId,
        replacement: &ContentEndpoint,
        pcr_cut: &arkret_wire::CommittedEventRef,
        previous: Option<&Self>,
    ) -> Result<()> {
        self.validate_for_authorization(authorization)?;
        if &self.replacement != replacement || &self.pcr_cut != pcr_cut {
            return protocol("recovery preparation differs from the original episode");
        }
        if let Some(previous) = previous {
            previous.validate_for_episode(authorization, replacement, pcr_cut, None)?;
            if previous.state == ContentRecoveryPreparationState::Prepared
                && (self.state != ContentRecoveryPreparationState::Prepared
                    || self.inventory_blob_ref != previous.inventory_blob_ref)
            {
                return protocol("prepared recovery inventory cannot roll back or rebind");
            }
        }
        Ok(())
    }
}

impl ContentCleanupInventory {
    /// Compare every result to an independently frozen inventory, including empty census.
    /// Native completeness, retirement signatures, first qualification and
    /// current delivery authority remain independent caller obligations.
    pub fn validate_for_inventory(
        &self,
        inventory: &ContentRecoveryInventory,
        inventory_digest: &arkret_wire::Hash,
    ) -> Result<()> {
        inventory.validate()?;
        sha256_ref(inventory_digest)?;
        if &self.inventory_digest != inventory_digest
            || self.scope_cleanups.len() != inventory.entries.len()
        {
            return protocol("cleanup differs from its frozen inventory");
        }
        for (cleanup, entry) in self.scope_cleanups.iter().zip(&inventory.entries) {
            let (scope, genesis) = match cleanup {
                ContentScopeCleanup::Rekeyed {
                    effective_scope,
                    genesis_event_ref,
                    ..
                }
                | ContentScopeCleanup::Removed {
                    effective_scope,
                    genesis_event_ref,
                    ..
                }
                | ContentScopeCleanup::Terminated {
                    effective_scope,
                    genesis_event_ref,
                    ..
                } => (effective_scope, genesis_event_ref),
            };
            if scope != &entry.effective_scope || genesis != &entry.genesis_event_ref {
                return protocol("missing, reordered or unfinished scope cleanup");
            }
            match cleanup {
                ContentScopeCleanup::Rekeyed {
                    winning_commit,
                    remaining_old_leaf_count,
                    root_refs,
                    backup_refs,
                    ..
                } => {
                    if *remaining_old_leaf_count != 0
                        || !(1..=256).contains(&root_refs.len())
                        || !(1..=256).contains(&backup_refs.len())
                        || !unique(root_refs)
                        || !unique(backup_refs)
                        || winning_commit.stream_ref
                            != arkret_wire::CommitStreamRef::from_scope(scope, None)?
                    {
                        return protocol(
                            "rekeyed cleanup lacks its exact scope or sufficient unique references",
                        );
                    }
                    for root in root_refs {
                        sha256_ref(root)?;
                    }
                }
                ContentScopeCleanup::Removed {
                    retirement_proof, ..
                } if matches!(
                    retirement_proof,
                    ContentScopeRetirementProof::Removed { .. }
                ) =>
                {
                    retirement_proof.validate_binding(
                        &inventory.replacement,
                        entry,
                        inventory_digest,
                    )?;
                }
                ContentScopeCleanup::Terminated {
                    retirement_proof, ..
                } if matches!(
                    retirement_proof,
                    ContentScopeRetirementProof::Terminated { .. }
                ) =>
                {
                    retirement_proof.validate_binding(
                        &inventory.replacement,
                        entry,
                        inventory_digest,
                    )?;
                }
                _ => return protocol("cleanup state differs from its original retirement proof"),
            }
        }
        Ok(())
    }
}

impl ContentScopeRetirementProof {
    /// Local shape and byte binding only; this does not qualify a governor,
    /// grant migration rights or verify a native terminal/fence transaction.
    fn validate_binding(
        &self,
        replacement_endpoint: &ContentEndpoint,
        entry: &ContentRecoveryInventoryEntry,
        expected_digest: &arkret_wire::Hash,
    ) -> Result<()> {
        self.validate_shape()?;
        match self {
            Self::Removed {
                remaining_old_leaf_count,
                ..
            } if *remaining_old_leaf_count != 0 => {
                return protocol("removed proof retains a displaced endpoint");
            }
            Self::Terminated {
                terminal_source_digest,
                ..
            } => sha256_ref(terminal_source_digest)?,
            _ => {}
        }
        let (Self::Removed {
            replacement,
            inventory_digest,
            inventory_entry_digest,
            request_digest,
            effective_scope,
            genesis_event_ref,
            scope_cut,
            epoch,
            nonce_base64url,
            ..
        }
        | Self::Terminated {
            replacement,
            inventory_digest,
            inventory_entry_digest,
            request_digest,
            effective_scope,
            genesis_event_ref,
            scope_cut,
            epoch,
            nonce_base64url,
            ..
        }) = self;
        sha256_ref(inventory_entry_digest)?;
        sha256_ref(request_digest)?;
        bytes32(nonce_base64url)?;
        if replacement != replacement_endpoint
            || inventory_digest != expected_digest
            || inventory_entry_digest.as_str() != arkret_canonical::canonical_sha256(entry)?
            || effective_scope != &entry.effective_scope
            || genesis_event_ref != &entry.genesis_event_ref
            || scope_cut.stream_ref
                != arkret_wire::CommitStreamRef::from_scope(effective_scope, None)?
            || *epoch < entry.epoch
        {
            return protocol("retirement proof differs from the frozen subject or scope inventory");
        }
        Ok(())
    }
}
