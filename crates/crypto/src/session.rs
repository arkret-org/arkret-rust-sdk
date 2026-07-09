//! Realm session records, request/response bodies, the plan queue, and the
//! aggregate crypto store binding.

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Utc};
use cokret_core::{
    BlobRef, DeviceId, Did, EncryptedPayload, EncryptedPayloadScheme, Error, EventId, Hash,
    RealmId, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::device::{DeviceKeyBundle, DeviceTrustState, DeviceVerificationStrand};
use crate::errors::{
    MAX_ALGORITHM_NAME_LEN, MAX_IDENTIFIER_LEN, MAX_KEY_FIELD_LEN, MAX_ONE_TIME_KEY_CLAIM_COUNT,
    MAX_REASON_LEN, validate_max_length, validate_nonempty_key,
};

/// Discriminator for the request variants the crypto-machine plan
/// queue dispatches on. One variant per `CryptoMachineRequestBody` arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoMachineRequestKind {
    /// `ck.keys.upload_device_keys` — publish this device's keys.
    UploadDeviceKeys,
    /// `ck.keys.query_device_keys` — fetch peers' keys.
    QueryDeviceKeys,
    /// `ck.keys.claim_one_time_keys` — claim peers' one-time keys.
    ClaimOneTimeKeys,
    /// `ck.event.encrypt` — encrypt an event into a Realm session.
    EncryptEvent,
    /// `ck.event.decrypt` — decrypt a received encrypted event.
    DecryptEvent,
    /// `ck.keys.share_room_key` — distribute a Realm session key.
    ShareRoomKey,
    /// `ck.keys.request_room_key` — request a missing session key.
    RequestRoomKey,
    /// `ck.keys.backup_secrets` — push to secret backup storage.
    BackupSecrets,
    /// `ck.keys.restore_secrets` — pull from secret backup storage.
    RestoreSecrets,
}

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoSessionRecord {
    pub realm_id: RealmId,
    pub session_id: String,
    pub sender_key: String,
    pub algorithm: String,
    pub state: CryptoSessionState,
    pub created_at: DateTime<Utc>,
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

/// Sender-explicit refusal to share a Realm session key with this
/// device (e.g. via `m.blacklisted` or recipient-not-trusted).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithheldKeyRecord {
    /// Realm the withheld session belongs to.
    pub realm_id: RealmId,
    /// Session that the sender refused to share.
    pub session_id: String,
    /// Sending principal.
    pub sender: Did,
    /// Wire `code` (e.g. `m.blacklisted`).
    pub code: String,
    /// Mapped `UnableToDecryptReason` for renderer convenience.
    pub reason: UnableToDecryptReason,
    /// Time the withheld notice was observed locally.
    pub received_at: DateTime<Utc>,
}

impl WithheldKeyRecord {
    /// Validate the structural invariants beyond what `serde` enforces.
    pub fn validate(&self) -> Result<()> {
        validate_nonempty_key("withheld session id", &self.session_id)?;
        validate_max_length("withheld session id", &self.session_id, MAX_IDENTIFIER_LEN)?;
        validate_nonempty_key("withheld code", &self.code)?;
        validate_max_length("withheld code", &self.code, MAX_IDENTIFIER_LEN)?;
        Ok(())
    }
}

/// Inbound device-to-device secret-gossip request body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretGossipRequestBody {
    pub request_id: String,
    pub name: String,
    pub requesting_device: DeviceId,
    pub recipient_device: DeviceId,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl SecretGossipRequestBody {
    pub fn validate(&self) -> Result<()> {
        validate_nonempty_key("secret gossip request_id", &self.request_id)?;
        validate_max_length(
            "secret gossip request_id",
            &self.request_id,
            MAX_IDENTIFIER_LEN,
        )?;
        validate_nonempty_key("secret gossip name", &self.name)?;
        validate_max_length("secret gossip name", &self.name, MAX_IDENTIFIER_LEN)?;
        if self.requesting_device == self.recipient_device {
            return Err(Error::Protocol(
                "secret gossip request requires distinct devices".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Request to claim `count` one-time keys for a (user, device) pair on a
/// specific algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimeKeyClaim {
    /// Target principal.
    pub user_id: Did,
    /// Target device.
    pub device_id: DeviceId,
    /// One-time key algorithm (e.g. `signed_curve25519`).
    pub algorithm: String,
    /// How many keys to claim in this batch.
    pub count: u32,
}

impl OneTimeKeyClaim {
    pub fn validate(&self) -> Result<()> {
        validate_nonempty_key("one-time key algorithm", &self.algorithm)?;
        validate_max_length(
            "one-time key algorithm",
            &self.algorithm,
            MAX_ALGORITHM_NAME_LEN,
        )?;
        if self.count == 0 {
            return Err(Error::Protocol(
                "one-time key claim count must be non-zero".to_owned(),
            ));
        }
        if self.count > MAX_ONE_TIME_KEY_CLAIM_COUNT {
            return Err(Error::Protocol(format!(
                "one-time key claim count {} exceeds {}",
                self.count, MAX_ONE_TIME_KEY_CLAIM_COUNT
            )));
        }
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
/// (`ck.schema.key_backup.v1`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBackupDescriptor {
    pub backup_id: String,
    pub state: SecretBackupState,
    pub algorithm: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    /// Session key shared via `share_room_key`.
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
    pub actor: Did,
    /// Device that performed the transition.
    pub device_id: DeviceId,
    /// Wall-clock time of the transition.
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
    /// Olm/Megolm message-index key is missing.
    MissingMegolmKey,
    /// Ciphertext failed MAC / shape validation.
    BadCiphertext,
    /// Sender withheld the session key (`m.withheld`).
    Withheld,
}

/// Inbound record kept on the local store when an encrypted event
/// could not be decrypted; renderers display it as a placeholder until
/// retry succeeds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UnableToDecryptRecord {
    pub event_id: EventId,
    pub realm_id: RealmId,
    pub sender: Did,
    pub reason: UnableToDecryptReason,
    pub encrypted_content: EncryptedPayload,
    pub first_seen_at: DateTime<Utc>,
}

/// Request body the crypto-machine plan queue dispatches on. Each
/// variant corresponds 1:1 with a [`CryptoMachineRequestKind`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoMachineRequestBody {
    UploadDeviceKeys(DeviceKeyBundle),
    QueryDeviceKeys {
        users: Vec<Did>,
    },
    ClaimOneTimeKeys(Vec<OneTimeKeyClaim>),
    EncryptEvent {
        realm_id: RealmId,
        event_kind: String,
        content: Value,
    },
    DecryptEvent {
        event_id: EventId,
        payload: EncryptedPayload,
    },
    /// Matrix/MIMI compat name. The v1 concept is sharing a Realm
    /// E2EE session key — the `ShareRoomKey` variant name maps to the
    /// `ck.keys.room_key` interop device-message kind.
    ShareRoomKey {
        realm_id: RealmId,
        session_id: String,
        recipients: Vec<DeviceId>,
    },
    /// Matrix/MIMI compat name. Requests a Realm E2EE session key
    /// re-share from peers; maps to the interop `ck.keys.room_key`
    /// device-message kind.
    RequestRoomKey {
        event_id: EventId,
        realm_id: RealmId,
        session_id: String,
        requesting_device_id: DeviceId,
    },
    BackupSecrets(SecretBackupDescriptor),
    RestoreSecrets {
        backup_id: String,
    },
}

impl CryptoMachineRequestBody {
    pub fn kind(&self) -> CryptoMachineRequestKind {
        match self {
            Self::UploadDeviceKeys(_) => CryptoMachineRequestKind::UploadDeviceKeys,
            Self::QueryDeviceKeys { .. } => CryptoMachineRequestKind::QueryDeviceKeys,
            Self::ClaimOneTimeKeys(_) => CryptoMachineRequestKind::ClaimOneTimeKeys,
            Self::EncryptEvent { .. } => CryptoMachineRequestKind::EncryptEvent,
            Self::DecryptEvent { .. } => CryptoMachineRequestKind::DecryptEvent,
            Self::ShareRoomKey { .. } => CryptoMachineRequestKind::ShareRoomKey,
            Self::RequestRoomKey { .. } => CryptoMachineRequestKind::RequestRoomKey,
            Self::BackupSecrets(_) => CryptoMachineRequestKind::BackupSecrets,
            Self::RestoreSecrets { .. } => CryptoMachineRequestKind::RestoreSecrets,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::UploadDeviceKeys(bundle) => bundle.validate(),
            Self::QueryDeviceKeys { users } if users.is_empty() => Err(Error::Protocol(
                "device-key query must include users".to_owned(),
            )),
            Self::ClaimOneTimeKeys(claims) if claims.is_empty() => Err(Error::Protocol(
                "one-time key claim must include requests".to_owned(),
            )),
            Self::ClaimOneTimeKeys(claims) => {
                for claim in claims {
                    claim.validate()?;
                }
                Ok(())
            }
            Self::EncryptEvent { event_kind, .. } if event_kind.trim().is_empty() => Err(
                Error::Protocol("encrypt event request must include event kind".to_owned()),
            ),
            Self::ShareRoomKey {
                session_id,
                recipients,
                ..
            } => {
                if session_id.trim().is_empty() || recipients.is_empty() {
                    Err(Error::Protocol(
                        "share room key request requires session id and recipients".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            }
            Self::RequestRoomKey { session_id, .. } if session_id.trim().is_empty() => Err(
                Error::Protocol("room key request requires session id".to_owned()),
            ),
            Self::BackupSecrets(descriptor) => descriptor.validate(),
            Self::RestoreSecrets { backup_id } if backup_id.trim().is_empty() => Err(
                Error::Protocol("restore request must include backup id".to_owned()),
            ),
            _ => Ok(()),
        }
    }
}

/// Response body the crypto-machine plan returns once a request is
/// processed (or queued for processing).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CryptoMachineResponseBody {
    /// Request accepted and queued for asynchronous processing.
    Queued {
        request_id: String,
        kind: CryptoMachineRequestKind,
    },
    /// `UploadDeviceKeys` accepted.
    DeviceKeysUploaded { device_id: DeviceId },
    /// `QueryDeviceKeys` result set.
    DeviceKeys(Vec<DeviceKeyBundle>),
    /// `ClaimOneTimeKeys` result set (one per claimed device).
    OneTimeKeysClaimed(Vec<DeviceKeyBundle>),
    /// `EncryptEvent` produced this payload.
    Encrypted(EncryptedPayload),
    /// `DecryptEvent` resolved to this plaintext value.
    Decrypted(Value),
    /// `DecryptEvent` could not decrypt — caller should display a placeholder.
    UnableToDecrypt(UnableToDecryptRecord),
    /// `ShareRoomKey` fanned out to this many recipients.
    RoomKeyShared {
        realm_id: RealmId,
        session_id: String,
        recipients: usize,
    },
    /// `RequestRoomKey` was emitted on the wire.
    RoomKeyRequested {
        event_id: EventId,
        session_id: String,
    },
    /// `BackupSecrets` flushed this descriptor to storage.
    BackupReady(SecretBackupDescriptor),
    /// `RestoreSecrets` pulled the named backup and recovered this many secrets.
    Restored {
        backup_id: String,
        recovered_secrets: usize,
    },
}

/// In-memory FIFO queue of pending crypto-machine requests.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CryptoMachinePlan {
    queue: VecDeque<(String, CryptoMachineRequestBody)>,
}

impl CryptoMachinePlan {
    pub fn push(
        &mut self,
        request_id: impl Into<String>,
        request: CryptoMachineRequestBody,
    ) -> Result<CryptoMachineResponseBody> {
        request.validate()?;
        let request_id = request_id.into();
        if request_id.trim().is_empty() {
            return Err(Error::Protocol(
                "crypto request id must not be empty".to_owned(),
            ));
        }
        let kind = request.kind();
        self.queue.push_back((request_id.clone(), request));
        Ok(CryptoMachineResponseBody::Queued { request_id, kind })
    }

    pub fn pop(&mut self) -> Option<(String, CryptoMachineRequestBody)> {
        self.queue.pop_front()
    }

    pub fn pending_len(&self) -> usize {
        self.queue.len()
    }

    pub fn pending_kinds(&self) -> Vec<CryptoMachineRequestKind> {
        self.queue
            .iter()
            .map(|(_, request)| request.kind())
            .collect()
    }
}

/// Aggregate local cache of every per-device crypto fact this client
/// has observed (device keys, trust verdicts, verification strands,
/// sessions, secret backup, withheld notices, UTD records, lifecycle
/// journal).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CryptoStoreBinding {
    pub device_keys: BTreeMap<DeviceId, DeviceKeyBundle>,
    pub device_trust: BTreeMap<DeviceId, DeviceTrustState>,
    pub verification_strands: BTreeMap<String, DeviceVerificationStrand>,
    pub sessions: BTreeMap<String, CryptoSessionRecord>,
    pub backup: Option<SecretBackupDescriptor>,
    pub withheld_keys: BTreeMap<String, WithheldKeyRecord>,
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

    pub fn record_verification_strand(&mut self, strand: DeviceVerificationStrand) -> Result<()> {
        strand.validate()?;
        self.verification_strands
            .insert(strand.transaction_id.clone(), strand);
        Ok(())
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

    pub fn record_withheld_key(&mut self, record: WithheldKeyRecord) {
        self.withheld_keys
            .insert(session_key(&record.realm_id, &record.session_id), record);
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
    // `arkret-core` so the prefix/encoding lives in a single place.
    cokret_core::canonical::sha256_digest(bytes)
}
