//! Device list, to-device messaging, verification and key backup helpers.

use std::collections::{BTreeMap, VecDeque};

use arkret_core::CrossSigningPublish;
pub use arkret_core::{
    CrossSigningResetPayload, CrossSigningResetProof, CrossSigningResetReason,
    DeviceMessageEnvelope, DeviceQuorumSignature, DeviceQuorumThreshold,
};
pub use arkret_crypto::{
    DeviceCrossSigningChainVerification, DeviceTrustBinding, DeviceTrustChainOutcome,
    DeviceTrustState, cross_signing_publish_cell_subject, verify_device_cross_signing_chain,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{DeviceId, DeviceVerificationState, Did, Error, Result, canonical};

mod authoring;
mod backup;
mod manager;
#[cfg(test)]
mod tests;

pub use authoring::*;
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
    /// Public verify_key of the device. SDK-side mirror of `ak:device:`
    /// record `verify_key` (`crypto-media/device-lifecycle.md` §4); used as
    /// the canonical input to the SSK trust binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_public_key: Option<String>,
    /// Device HPKE sealing key mirrored from the `ak:device:` record
    /// (`crypto-media/device-lifecycle.md` §4/§5.2). Enters the SSK trust
    /// binding transcript together with `device_public_key` and `algorithms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hpke_key: Option<String>,
    /// Canonical sorted unique algorithm ids declared by the device record;
    /// part of the §5.2 trust binding transcript.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<String>>,
    /// Per-device trust binding produced by SSK (spec §5.2). When present,
    /// the device participates in the cross-signed trust chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_signing_binding: Option<DeviceTrustBinding>,
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

/// Known `ak.key.verification.*` device message kinds.
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
            Self::Request => "ak.key.verification.request",
            Self::Ready => "ak.key.verification.ready",
            Self::Start => "ak.key.verification.start",
            Self::Accept => "ak.key.verification.accept",
            Self::Key => "ak.key.verification.key",
            Self::Mac => "ak.key.verification.mac",
            Self::Done => "ak.key.verification.done",
            Self::Cancel => "ak.key.verification.cancel",
        }
    }
}
