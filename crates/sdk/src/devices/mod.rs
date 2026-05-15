//! Device list, to-device messaging, verification and key backup helpers.

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use contrix_crypto::{
    CrossSigningBinding, CrossSigningKeyKind, CrossSigningKeyRecord, CrossSigningPublishContent,
    CrossSigningResetContent, CrossSigningResetProof, DeviceBootstrapBinding,
    DeviceQuorumSignature, DeviceTrustBinding, DeviceTrustChainOutcome, SignedCrossSigningKey,
};

use crate::{DeviceId, DeviceVerificationState, Did, Error, Result, canonical};

mod backup;
mod manager;
#[cfg(test)]
mod tests;

pub use backup::*;
pub use manager::*;

/// User-visible device metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceMetadata {
    /// Device display name.
    pub name: Option<String>,
    /// Hardware model.
    pub model: Option<String>,
    /// Operating system name/version.
    pub os: Option<String>,
    /// Last seen time.
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Device record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Owning user.
    pub user_id: Did,
    /// Device ID.
    pub device_id: DeviceId,
    /// Metadata.
    pub metadata: DeviceMetadata,
    /// Verification state.
    pub verification: DeviceVerificationState,
    /// Public verify_key of the device. SDK-side mirror of `cx:device:`
    /// record `verify_key` (`crypto-media/device-lifecycle.md` §4); used as
    /// the canonical input to the SSK trust binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_public_key: Option<String>,
    /// Per-device trust binding produced by SSK (spec §5.2). When present,
    /// the device participates in the cross-signed trust chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_signing_binding: Option<DeviceTrustBinding>,
    /// First-device bootstrap binding (spec §5.3). Mutually exclusive with
    /// `cross_signing_binding`; only valid before the first cross-signing
    /// publish.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_binding: Option<DeviceBootstrapBinding>,
    /// Last local update time.
    pub updated_at: DateTime<Utc>,
}

/// Device-list change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceChange {
    /// Changed user.
    pub user_id: Did,
    /// Changed device.
    pub device_id: DeviceId,
    /// True when the device was removed.
    pub removed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceVerificationChallenge {
    pub transaction_id: String,
    pub user_id: Did,
    pub device_id: DeviceId,
    pub method: String,
    pub challenge: String,
    pub commitment: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// QR payload shown to scanners during device verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QrVerificationPayload {
    pub version: u32,
    pub transaction_id: String,
    pub user_id: Did,
    pub device_id: DeviceId,
    pub method: String,
    pub commitment: String,
}

/// To-device message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToDeviceEnvelope {
    /// Sender user.
    pub sender: Did,
    /// Recipient user.
    pub recipient: Did,
    /// Recipient device.
    pub device_id: DeviceId,
    /// Message type.
    #[serde(rename = "type")]
    pub message_type: String,
    /// Message body.
    pub content: Value,
    /// Local receive/enqueue time.
    pub queued_at: DateTime<Utc>,
}

/// Spec-aligned device message envelope facade from `cx.schema.device_message.v1`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceMessageEnvelope {
    pub kind: String,
    pub sender_principal_id: Did,
    pub sender_device_id: DeviceId,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub sent_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub content: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_proof: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<Value>,
}

/// Known `cx.key.verification.*` device message kinds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceVerificationMessageKind {
    Request,
    Ready,
    Start,
    Accept,
    Key,
    Mac,
    Done,
    Cancel,
}

impl DeviceVerificationMessageKind {
    pub fn as_event_kind(&self) -> &'static str {
        match self {
            Self::Request => "cx.key.verification.request",
            Self::Ready => "cx.key.verification.ready",
            Self::Start => "cx.key.verification.start",
            Self::Accept => "cx.key.verification.accept",
            Self::Key => "cx.key.verification.key",
            Self::Mac => "cx.key.verification.mac",
            Self::Done => "cx.key.verification.done",
            Self::Cancel => "cx.key.verification.cancel",
        }
    }
}

/// Schema-aligned verification message content scaffold.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceVerificationMessageContent {
    pub transaction_id: String,
    pub from_device: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_agreement_protocols: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub message_authentication_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub short_authentication_string: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
