//! Protocol crypto machine contracts.

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Utc};
use contrix_core::{
    BlobRef, DeviceId, Did, EncryptedPayload, EncryptedPayloadScheme, Error, EventId, Hash, Result,
    SpaceId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use contrix_signatures::{DetachedSignature, DetachedSignatureBinding, DetachedVerifier};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoMachineRequestKind {
    UploadDeviceKeys,
    QueryDeviceKeys,
    ClaimOneTimeKeys,
    EncryptEvent,
    DecryptEvent,
    ShareRoomKey,
    RequestRoomKey,
    BackupSecrets,
    RestoreSecrets,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceKeyBundle {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub signing_key: String,
    pub identity_key: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub algorithms: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<DetachedSignature>,
}

impl DeviceKeyBundle {
    pub fn validate(&self) -> Result<()> {
        if self.signing_key.trim().is_empty() || self.identity_key.trim().is_empty() {
            return Err(Error::Protocol("device key bundle keys must not be empty".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrustState {
    Unverified,
    LocallyTrusted,
    CrossSigned,
    Verified,
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFlowState {
    Requested,
    Ready,
    SasStarted,
    QrScanned,
    Done,
    Cancelled,
    TimedOut,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceVerificationFlow {
    pub transaction_id: String,
    pub user_id: Did,
    pub from_device: DeviceId,
    pub to_device: DeviceId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    pub state: VerificationFlowState,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl DeviceVerificationFlow {
    pub fn validate(&self) -> Result<()> {
        if self.transaction_id.trim().is_empty() {
            return Err(Error::Protocol(
                "verification transaction id must not be empty".to_owned(),
            ));
        }
        if self.from_device == self.to_device {
            return Err(Error::Protocol("verification requires two distinct devices".to_owned()));
        }
        Ok(())
    }

    pub fn advance(&mut self, next: VerificationFlowState) -> Result<()> {
        let allowed = matches!(
            (self.state, next),
            (VerificationFlowState::Requested, VerificationFlowState::Ready)
                | (VerificationFlowState::Ready, VerificationFlowState::SasStarted)
                | (VerificationFlowState::Ready, VerificationFlowState::QrScanned)
                | (VerificationFlowState::SasStarted, VerificationFlowState::Done)
                | (VerificationFlowState::QrScanned, VerificationFlowState::Done)
                | (_, VerificationFlowState::Cancelled)
                | (_, VerificationFlowState::TimedOut)
        );
        if allowed {
            self.state = next;
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "invalid verification transition from {:?} to {:?}",
                self.state, next
            )))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoSessionState {
    Pending,
    Active,
    Withheld,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoSessionRecord {
    pub space_id: SpaceId,
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
        Ok(())
    }

    pub fn accept_message_index(&mut self, index: u64, now: DateTime<Utc>) -> Result<()> {
        if self.message_index_high_watermark.is_some_and(|seen| index <= seen) {
            return Err(Error::Protocol("encrypted session replay detected".to_owned()));
        }
        self.message_index_high_watermark = Some(index);
        self.last_used_at = now;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithheldKeyRecord {
    pub space_id: SpaceId,
    pub session_id: String,
    pub sender: Did,
    pub code: String,
    pub reason: UnableToDecryptReason,
    pub received_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretGossipRequest {
    pub request_id: String,
    pub name: String,
    pub requesting_device: DeviceId,
    pub recipient_device: DeviceId,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl SecretGossipRequest {
    pub fn validate(&self) -> Result<()> {
        if self.request_id.trim().is_empty() || self.name.trim().is_empty() {
            return Err(Error::Protocol("secret gossip request requires id and name".to_owned()));
        }
        if self.requesting_device == self.recipient_device {
            return Err(Error::Protocol(
                "secret gossip request requires distinct devices".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimeKeyClaim {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub algorithm: String,
    pub count: u32,
}

impl OneTimeKeyClaim {
    pub fn validate(&self) -> Result<()> {
        if self.algorithm.trim().is_empty() {
            return Err(Error::Protocol("one-time key algorithm must not be empty".to_owned()));
        }
        if self.count == 0 {
            return Err(Error::Protocol("one-time key claim count must be non-zero".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackupState {
    Disabled,
    Enabled,
    Rotating,
    Recovering,
}

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
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyLifecyclePhase {
    Created,
    Uploaded,
    Claimed,
    Shared,
    Rotated,
    BackedUp,
    Recovered,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyLifecycleEvent {
    pub key_ref: String,
    pub phase: KeyLifecyclePhase,
    pub actor: Did,
    pub device_id: DeviceId,
    pub occurred_at: DateTime<Utc>,
    pub reason: String,
}

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
            Err(Error::Protocol("encrypted media plaintext digest mismatch".to_owned()))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnableToDecryptReason {
    NoSession,
    UnknownSender,
    UnknownDevice,
    MissingMegolmKey,
    BadCiphertext,
    Withheld,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UnableToDecryptRecord {
    pub event_id: EventId,
    pub space_id: SpaceId,
    pub sender: Did,
    pub reason: UnableToDecryptReason,
    pub encrypted_payload: EncryptedPayload,
    pub first_seen_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CryptoMachineRequest {
    UploadDeviceKeys(DeviceKeyBundle),
    QueryDeviceKeys {
        users: Vec<Did>,
    },
    ClaimOneTimeKeys(Vec<OneTimeKeyClaim>),
    EncryptEvent {
        space_id: SpaceId,
        event_kind: String,
        content: Value,
    },
    DecryptEvent {
        event_id: EventId,
        payload: EncryptedPayload,
    },
    ShareRoomKey {
        space_id: SpaceId,
        session_id: String,
        recipients: Vec<DeviceId>,
    },
    RequestRoomKey {
        event_id: EventId,
        space_id: SpaceId,
        session_id: String,
        requesting_device_id: DeviceId,
    },
    BackupSecrets(SecretBackupDescriptor),
    RestoreSecrets {
        backup_id: String,
    },
}

impl CryptoMachineRequest {
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
            Self::QueryDeviceKeys { users } if users.is_empty() => {
                Err(Error::Protocol("device-key query must include users".to_owned()))
            }
            Self::ClaimOneTimeKeys(claims) if claims.is_empty() => {
                Err(Error::Protocol("one-time key claim must include requests".to_owned()))
            }
            Self::ClaimOneTimeKeys(claims) => {
                for claim in claims {
                    claim.validate()?;
                }
                Ok(())
            }
            Self::EncryptEvent { event_kind, .. } if event_kind.trim().is_empty() => {
                Err(Error::Protocol("encrypt event request must include event kind".to_owned()))
            }
            Self::ShareRoomKey { session_id, recipients, .. } => {
                if session_id.trim().is_empty() || recipients.is_empty() {
                    Err(Error::Protocol(
                        "share room key request requires session id and recipients".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            }
            Self::RequestRoomKey { session_id, .. } if session_id.trim().is_empty() => {
                Err(Error::Protocol("room key request requires session id".to_owned()))
            }
            Self::BackupSecrets(descriptor) => descriptor.validate(),
            Self::RestoreSecrets { backup_id } if backup_id.trim().is_empty() => {
                Err(Error::Protocol("restore request must include backup id".to_owned()))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CryptoMachineResponse {
    Queued { request_id: String, kind: CryptoMachineRequestKind },
    DeviceKeysUploaded { device_id: DeviceId },
    DeviceKeys(Vec<DeviceKeyBundle>),
    OneTimeKeysClaimed(Vec<DeviceKeyBundle>),
    Encrypted(EncryptedPayload),
    Decrypted(Value),
    UnableToDecrypt(UnableToDecryptRecord),
    RoomKeyShared { space_id: SpaceId, session_id: String, recipients: usize },
    RoomKeyRequested { event_id: EventId, session_id: String },
    BackupReady(SecretBackupDescriptor),
    Restored { backup_id: String, recovered_secrets: usize },
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CryptoMachinePlan {
    queue: VecDeque<(String, CryptoMachineRequest)>,
}

impl CryptoMachinePlan {
    pub fn push(
        &mut self,
        request_id: impl Into<String>,
        request: CryptoMachineRequest,
    ) -> Result<CryptoMachineResponse> {
        request.validate()?;
        let request_id = request_id.into();
        if request_id.trim().is_empty() {
            return Err(Error::Protocol("crypto request id must not be empty".to_owned()));
        }
        let kind = request.kind();
        self.queue.push_back((request_id.clone(), request));
        Ok(CryptoMachineResponse::Queued { request_id, kind })
    }

    pub fn pop(&mut self) -> Option<(String, CryptoMachineRequest)> {
        self.queue.pop_front()
    }

    pub fn pending_len(&self) -> usize {
        self.queue.len()
    }

    pub fn pending_kinds(&self) -> Vec<CryptoMachineRequestKind> {
        self.queue.iter().map(|(_, request)| request.kind()).collect()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CryptoStoreBinding {
    pub device_keys: BTreeMap<DeviceId, DeviceKeyBundle>,
    pub device_trust: BTreeMap<DeviceId, DeviceTrustState>,
    pub verification_flows: BTreeMap<String, DeviceVerificationFlow>,
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

    pub fn record_verification_flow(&mut self, flow: DeviceVerificationFlow) -> Result<()> {
        flow.validate()?;
        self.verification_flows.insert(flow.transaction_id.clone(), flow);
        Ok(())
    }

    pub fn record_session(&mut self, session: CryptoSessionRecord) -> Result<()> {
        session.validate()?;
        self.sessions.insert(session_key(&session.space_id, &session.session_id), session);
        Ok(())
    }

    pub fn session_mut(
        &mut self,
        space_id: &SpaceId,
        session_id: &str,
    ) -> Option<&mut CryptoSessionRecord> {
        self.sessions.get_mut(&session_key(space_id, session_id))
    }

    pub fn record_withheld_key(&mut self, record: WithheldKeyRecord) {
        self.withheld_keys.insert(session_key(&record.space_id, &record.session_id), record);
    }

    pub fn record_unable_to_decrypt(&mut self, record: UnableToDecryptRecord) {
        self.unable_to_decrypt.insert(record.event_id.clone(), record);
    }
}

fn session_key(space_id: &SpaceId, session_id: &str) -> String {
    format!("{}|{}", space_id.as_str(), session_id)
}

pub fn encrypted_payload_digest(payload: &EncryptedPayload) -> Result<Hash> {
    let bytes = contrix_core::canonical::canonical_json_bytes(payload)?;
    Hash::new(sha256_prefixed(&bytes)).map_err(Into::into)
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", base16_lower(&Sha256::digest(bytes)))
}

fn base16_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn device() -> DeviceId {
        DeviceId::new("cx:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    #[test]
    fn crypto_machine_plan_validates_and_orders_requests() {
        let mut plan = CryptoMachinePlan::default();
        let queued = plan
            .push("r1", CryptoMachineRequest::QueryDeviceKeys { users: vec![did("alice")] })
            .unwrap();
        assert_eq!(
            queued,
            CryptoMachineResponse::Queued {
                request_id: "r1".to_owned(),
                kind: CryptoMachineRequestKind::QueryDeviceKeys
            }
        );
        assert_eq!(plan.pending_kinds(), vec![CryptoMachineRequestKind::QueryDeviceKeys]);
        assert!(matches!(
            plan.push("bad", CryptoMachineRequest::QueryDeviceKeys { users: Vec::new() }),
            Err(Error::Protocol(_))
        ));
        plan.push(
            "share",
            CryptoMachineRequest::ShareRoomKey {
                space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-6c355fb9dada").unwrap(),
                session_id: "sess1".to_owned(),
                recipients: vec![device()],
            },
        )
        .unwrap();
        assert_eq!(
            plan.pending_kinds(),
            vec![CryptoMachineRequestKind::QueryDeviceKeys, CryptoMachineRequestKind::ShareRoomKey]
        );
    }

    #[test]
    fn store_binding_records_device_keys_and_unable_to_decrypt() {
        let mut binding = CryptoStoreBinding::default();
        let bundle = DeviceKeyBundle {
            user_id: did("alice"),
            device_id: device(),
            signing_key: "ed25519:abc".to_owned(),
            identity_key: "curve25519:def".to_owned(),
            algorithms: BTreeMap::new(),
            signatures: Vec::new(),
        };
        binding.record_device_keys(bundle).unwrap();
        assert_eq!(binding.device_keys.len(), 1);

        let payload = EncryptedPayload {
            scheme: EncryptedPayloadScheme::MlsRfc9420,
            group_id: "group".to_owned(),
            epoch: 1,
            content_type: "application/json".to_owned(),
            ciphertext: "abc".to_owned(),
            aad: None,
            payload_digest: Hash::new(sha256_prefixed(b"abc")).unwrap(),
            key_ref: None,
        };
        binding.record_unable_to_decrypt(UnableToDecryptRecord {
            event_id: EventId::new("cx:event:01904100-0000-7000-8000-4e7fda181f9f").unwrap(),
            space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-6c355fb9dada").unwrap(),
            sender: did("alice"),
            reason: UnableToDecryptReason::NoSession,
            encrypted_payload: payload,
            first_seen_at: Utc::now(),
        });
        assert_eq!(binding.unable_to_decrypt.len(), 1);
    }

    #[test]
    fn verification_session_and_withheld_key_state_are_tracked() {
        let mut binding = CryptoStoreBinding::default();
        let mut flow = DeviceVerificationFlow {
            transaction_id: "verif1".to_owned(),
            user_id: did("alice"),
            from_device: DeviceId::new("cx:device:01904100-0000-7000-8000-000000000001").unwrap(),
            to_device: DeviceId::new("cx:device:01904100-0000-7000-8000-000000000004").unwrap(),
            methods: vec!["sas".to_owned(), "qr".to_owned()],
            state: VerificationFlowState::Requested,
            created_at: Utc::now(),
            expires_at: None,
        };
        flow.advance(VerificationFlowState::Ready).unwrap();
        flow.advance(VerificationFlowState::SasStarted).unwrap();
        flow.advance(VerificationFlowState::Done).unwrap();
        binding.record_verification_flow(flow).unwrap();
        binding.set_device_trust(
            DeviceId::new("cx:device:01904100-0000-7000-8000-000000000004").unwrap(),
            DeviceTrustState::Verified,
        );
        assert_eq!(
            binding
                .device_trust
                .get(&DeviceId::new("cx:device:01904100-0000-7000-8000-000000000004").unwrap()),
            Some(&DeviceTrustState::Verified)
        );

        let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-6c355fb9dada").unwrap();
        binding
            .record_session(CryptoSessionRecord {
                space_id: space_id.clone(),
                session_id: "sess1".to_owned(),
                sender_key: "curve25519:def".to_owned(),
                algorithm: "cx.mls.v1".to_owned(),
                state: CryptoSessionState::Active,
                created_at: Utc::now(),
                last_used_at: Utc::now(),
                message_index_high_watermark: None,
            })
            .unwrap();
        let session = binding.session_mut(&space_id, "sess1").unwrap();
        session.accept_message_index(7, Utc::now()).unwrap();
        assert!(matches!(session.accept_message_index(7, Utc::now()), Err(Error::Protocol(_))));

        binding.record_withheld_key(WithheldKeyRecord {
            space_id,
            session_id: "sess1".to_owned(),
            sender: did("alice"),
            code: "m.blacklisted".to_owned(),
            reason: UnableToDecryptReason::Withheld,
            received_at: Utc::now(),
        });
        assert_eq!(binding.withheld_keys.len(), 1);
    }

    #[test]
    fn media_encryption_info_validates_plaintext_digest() {
        let plaintext = b"hello media";
        let info = MediaEncryptionInfo {
            blob_ref: BlobRef::from_bytes(plaintext),
            scheme: EncryptedPayloadScheme::MlsRfc9420,
            key_ref: "media-key-1".to_owned(),
            plaintext_sha256: Hash::new(sha256_prefixed(plaintext)).unwrap(),
            ciphertext_sha256: Hash::new(sha256_prefixed(b"ciphertext")).unwrap(),
        };
        info.validate_plaintext(plaintext).unwrap();
        assert!(matches!(info.validate_plaintext(b"changed"), Err(Error::Protocol(_))));
    }
}
