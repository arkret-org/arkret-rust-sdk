use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{DeviceId, Did};

/// Initiator's first message: agree on protocols + commit to a SAS code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVerificationStart {
    pub transaction_id: String,
    pub from_user: Did,
    pub from_device: DeviceId,
    pub method: String,
    /// Supported key-agreement protocols (e.g. `curve25519-hkdf-sha256`).
    pub key_agreement_protocols: Vec<String>,
    /// Supported MAC algorithms (e.g. `hkdf-hmac-sha256`).
    pub message_authentication_codes: Vec<String>,
    /// Supported short-authentication-string forms (`decimal`, `emoji`).
    pub short_authentication_string: Vec<String>,
    /// Wall-clock send time.
    pub sent_at: DateTime<Utc>,
}

/// Responder's reply to `start`: pick one protocol/MAC/SAS combo and
/// commit to the responder's keying material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVerificationAccept {
    pub transaction_id: String,
    pub from_user: Did,
    pub from_device: DeviceId,
    pub method: String,
    pub key_agreement_protocol: String,
    pub message_authentication_code: String,
    pub short_authentication_string: Vec<String>,
    /// SHA-256 commitment over the responder's public key.
    pub commitment: String,
    pub sent_at: DateTime<Utc>,
}

/// Public key exchange (one per side, both must arrive before MAC).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVerificationKey {
    pub transaction_id: String,
    pub from_user: Did,
    pub from_device: DeviceId,
    /// Multibase-encoded public key contributed to the SAS DH.
    pub key: String,
    pub sent_at: DateTime<Utc>,
}

/// MAC over each side's keys binding to the agreed transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVerificationMac {
    pub transaction_id: String,
    pub from_user: Did,
    pub from_device: DeviceId,
    /// MAC over the entire keys block, keyed with HKDF-derived key.
    pub keys: String,
    /// Per-key MACs keyed by `key_id`.
    pub mac: BTreeMap<String, String>,
    pub sent_at: DateTime<Utc>,
}

/// Final ack closing the transaction successfully.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVerificationDone {
    pub transaction_id: String,
    pub from_user: Did,
    pub from_device: DeviceId,
    pub sent_at: DateTime<Utc>,
}

/// Cancellation envelope (may arrive at any state and aborts the strand).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVerificationCancel {
    pub transaction_id: String,
    pub from_user: Did,
    pub from_device: DeviceId,
    pub code: String,
    pub reason: String,
    pub sent_at: DateTime<Utc>,
}

/// Strict state machine state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyVerificationState {
    /// No envelopes accepted yet.
    Idle,
    /// `start` received; waiting for `accept`.
    Started,
    /// `accept` received; waiting for both sides' `key` exchange.
    Accepted,
    /// First side's `key` accepted; waiting for the other side's.
    KeyHalfExchanged,
    /// Both sides' `key` exchanged; waiting for both `mac` envelopes.
    KeysExchanged,
    /// First side's `mac` accepted; waiting for the other.
    MacHalfReceived,
    /// Both `mac` envelopes verified; waiting for `done` from each.
    MacsReceived,
    /// First `done` accepted; waiting for the second.
    DoneHalfReceived,
    /// Strand completed successfully.
    Done,
    /// Strand cancelled or aborted.
    Cancelled,
}

impl KeyVerificationState {
    /// Whether the strand has reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Done | Self::Cancelled)
    }
}
