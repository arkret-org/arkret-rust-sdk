//! Local crypto bookkeeping records and the aggregate crypto store binding.

use std::collections::BTreeMap;

use arkret_models_crypto::encrypted_envelope::EncryptedPayload;
use arkret_wire::{BlobRef, DeviceId, DidCoreId, EncryptedPayloadScheme, EventId, Hash, RealmId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::device::{DeviceKeyBundle, DeviceTrustState};
use crate::errors::{
    Error, MAX_ALGORITHM_NAME_LEN, MAX_IDENTIFIER_LEN, MAX_KEY_FIELD_LEN, MAX_REASON_LEN, Result,
    validate_max_length, validate_nonempty_key,
};

/// Lifecycle state of a Realm E2EE session key tracked locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoSessionState {
    /// Session keys received but no message decrypted yet.
    Pending,
    /// In active use for inbound / outbound payloads.
    Active,
    /// Sender deliberately withheld the key (see `UnableToDecryptReason::Withheld`).
    Withheld,
    /// Session age / message count exceeded its rotation budget.
    Expired,
    /// Session was revoked (e.g. on device removal).
    Revoked,
}

/// Local record of a single Realm session — key id, sender device key,
/// algorithm, current state and replay watermark.
///
/// Boundary: this is **local bookkeeping only**. It is not the MLS group
/// state (Arkret has no per-sender ratchet session; group key material
/// evolves with the MLS group state and epoch — see
/// `guides/migrating-from-matrix.md` §4.5.3), not the HPKE to-device
/// secret-transfer path (`crate::secret_share`, `ak.secret.request` /
/// `ak.secret.send`), and not the realm_key history delivery
/// (`arkret_models_collaboration::events_payloads::realm_key`,
/// `ak.realm_key.request` / `ak.realm_key.share`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoSessionRecord {
    pub realm_id: RealmId,
    pub session_id: String,
    pub sender_key: String,
    pub algorithm: String,
    pub state: CryptoSessionState,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub last_used_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_index_high_watermark: Option<u64>,
}

impl CryptoSessionRecord {
    pub fn validate(&self) -> Result<()> {
        if self.session_id.trim().is_empty()
            || self.sender_key.trim().is_empty()
            || self.algorithm.trim().is_empty()
        {
            return Err(Error::Protocol(
                "crypto session requires id, sender key and algorithm".to_owned(),
            ));
        }
        validate_max_length("crypto session id", &self.session_id, MAX_IDENTIFIER_LEN)?;
        validate_max_length(
            "crypto session sender_key",
            &self.sender_key,
            MAX_KEY_FIELD_LEN,
        )?;
        validate_max_length(
            "crypto session algorithm",
            &self.algorithm,
            MAX_ALGORITHM_NAME_LEN,
        )?;
        Ok(())
    }

    pub fn accept_message_index(&mut self, index: u64, now: DateTime<Utc>) -> Result<()> {
        if self
            .message_index_high_watermark
            .is_some_and(|seen| index <= seen)
        {
            return Err(Error::Protocol(
                "encrypted session replay detected".to_owned(),
            ));
        }
        self.message_index_high_watermark = Some(index);
        self.last_used_at = now;
        Ok(())
    }
}

/// Lifecycle state of the principal's secret-storage backup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackupState {
    /// Backup not configured.
    Disabled,
    /// Backup active and accepting writes.
    Enabled,
    /// Mid-rotation to a new recovery key / public key.
    Rotating,
    /// Restore in progress from a recovery key.
    Recovering,
}

/// Public descriptor of the principal's secret-storage backup
/// (`ak.schema.key_backup.v1`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBackupDescriptor {
    pub backup_id: String,
    pub state: SecretBackupState,
    pub algorithm: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub last_recovery_at: Option<DateTime<Utc>>,
}

impl SecretBackupDescriptor {
    pub fn validate(&self) -> Result<()> {
        if self.backup_id.trim().is_empty()
            || self.algorithm.trim().is_empty()
            || self.public_key.trim().is_empty()
        {
            return Err(Error::Protocol(
                "secret backup descriptor requires id, algorithm and public key".to_owned(),
            ));
        }
        validate_max_length("secret backup id", &self.backup_id, MAX_IDENTIFIER_LEN)?;
        validate_max_length(
            "secret backup algorithm",
            &self.algorithm,
            MAX_ALGORITHM_NAME_LEN,
        )?;
        validate_max_length(
            "secret backup public_key",
            &self.public_key,
            MAX_KEY_FIELD_LEN,
        )?;
        Ok(())
    }
}

/// Discrete phase in a key's lifecycle journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyLifecyclePhase {
    /// Material generated locally.
    Created,
    /// Public half published to the server.
    Uploaded,
    /// One-time key claimed by a peer.
    Claimed,
    /// Session key delivered to authorized recipients.
    Shared,
    /// Replaced as part of a rotation cadence.
    Rotated,
    /// Captured into secret backup.
    BackedUp,
    /// Restored from secret backup.
    Recovered,
    /// Revoked / blacklisted.
    Revoked,
}

/// Lifecycle-journal row emitted whenever a key transitions phases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyLifecycleEvent {
    /// Stable reference identifying the key (kid / session id / backup id).
    pub key_ref: String,
    /// Phase the key moved into.
    pub phase: KeyLifecyclePhase,
    /// Principal that performed the transition.
    pub actor: DidCoreId,
    /// Device that performed the transition.
    pub device_id: DeviceId,
    /// Wall-clock time of the transition.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub occurred_at: DateTime<Utc>,
    /// Free-form reason / context string.
    pub reason: String,
}

impl KeyLifecycleEvent {
    /// Validate the structural invariants beyond what `serde` enforces.
    pub fn validate(&self) -> Result<()> {
        validate_nonempty_key("key lifecycle key_ref", &self.key_ref)?;
        validate_max_length("key lifecycle key_ref", &self.key_ref, MAX_IDENTIFIER_LEN)?;
        validate_max_length("key lifecycle reason", &self.reason, MAX_REASON_LEN)?;
        Ok(())
    }
}

/// Decryption metadata bound to an encrypted media blob.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaEncryptionInfo {
    pub blob_ref: BlobRef,
    pub scheme: EncryptedPayloadScheme,
    pub key_ref: String,
    pub plaintext_sha256: Hash,
    pub ciphertext_sha256: Hash,
}

impl MediaEncryptionInfo {
    pub fn validate_plaintext(&self, plaintext: &[u8]) -> Result<()> {
        let actual = Hash::new(sha256_prefixed(plaintext))?;
        if actual == self.plaintext_sha256 {
            Ok(())
        } else {
            Err(Error::Protocol(
                "encrypted media plaintext digest mismatch".to_owned(),
            ))
        }
    }
}

/// Classification of why an encrypted event failed to decrypt locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnableToDecryptReason {
    /// No session key recorded for the session id.
    NoSession,
    /// Sender DID is not known to the local store.
    UnknownSender,
    /// Sender device key is not known to the local store.
    UnknownDevice,
    /// Per-message decryption key material for the session is missing.
    MissingMessageKey,
    /// Ciphertext failed MAC / shape validation.
    BadCiphertext,
    /// Sender withheld the session key.
    Withheld,
}

/// Inbound record kept on the local store when an encrypted event
/// could not be decrypted; renderers display it as a placeholder until
/// retry succeeds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UnableToDecryptRecord {
    pub event_id: EventId,
    pub realm_id: RealmId,
    pub sender: DidCoreId,
    pub reason: UnableToDecryptReason,
    pub encrypted_content: EncryptedPayload,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub first_seen_at: DateTime<Utc>,
}

/// Aggregate local cache of every per-device crypto fact this client
/// has observed (device keys, trust verdicts, sessions, secret backup,
/// UTD records, lifecycle journal).
///
/// Interactive device verification (SAS) is not tracked here — it lives
/// in `crate::key_verification` (`ak.key.verification.*`), which inkson
/// consumes directly.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CryptoStoreBinding {
    pub device_keys: BTreeMap<DeviceId, DeviceKeyBundle>,
    pub device_trust: BTreeMap<DeviceId, DeviceTrustState>,
    pub sessions: BTreeMap<String, CryptoSessionRecord>,
    pub backup: Option<SecretBackupDescriptor>,
    pub unable_to_decrypt: BTreeMap<EventId, UnableToDecryptRecord>,
    pub lifecycle: Vec<KeyLifecycleEvent>,
}

impl CryptoStoreBinding {
    pub fn record_device_keys(&mut self, bundle: DeviceKeyBundle) -> Result<()> {
        bundle.validate()?;
        self.device_keys.insert(bundle.device_id.clone(), bundle);
        Ok(())
    }

    pub fn set_device_trust(&mut self, device_id: DeviceId, trust: DeviceTrustState) {
        self.device_trust.insert(device_id, trust);
    }

    pub fn record_session(&mut self, session: CryptoSessionRecord) -> Result<()> {
        session.validate()?;
        self.sessions
            .insert(session_key(&session.realm_id, &session.session_id), session);
        Ok(())
    }

    pub fn session_mut(
        &mut self,
        realm_id: &RealmId,
        session_id: &str,
    ) -> Option<&mut CryptoSessionRecord> {
        self.sessions.get_mut(&session_key(realm_id, session_id))
    }

    pub fn record_unable_to_decrypt(&mut self, record: UnableToDecryptRecord) {
        self.unable_to_decrypt
            .insert(record.event_id.clone(), record);
    }
}

pub(crate) fn session_key(realm_id: &RealmId, session_id: &str) -> String {
    format!("{}|{}", realm_id.as_str(), session_id)
}

pub(crate) fn sha256_prefixed(bytes: &[u8]) -> String {
    // Delegate to the authoritative `sha256:<lowercase-hex>` formatter in
    // the `arkret` umbrella so the prefix/encoding lives in a single place.
    arkret_canonical::canonical::sha256_digest(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_backup_descriptor_omitted_last_recovery_at_round_trip() {
        let descriptor = SecretBackupDescriptor {
            backup_id: "backup-1".to_owned(),
            state: SecretBackupState::Enabled,
            algorithm: "x25519-xsalsa20poly1305".to_owned(),
            public_key: "base64-public-key".to_owned(),
            last_recovery_at: None,
        };

        let serialized = serde_json::to_value(&descriptor).unwrap();
        assert!(
            !serialized
                .as_object()
                .unwrap()
                .contains_key("last_recovery_at")
        );

        let restored: SecretBackupDescriptor = serde_json::from_value(serialized).unwrap();
        assert_eq!(restored, descriptor);
    }
}
