//! Per-device key bundles, trust state, and interactive verification strands.

use std::collections::BTreeMap;

use arkret_core::{DeviceId, Did, Error, Result};
use arkret_signatures::DetachedSignature;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::errors::{
    MAX_ALGORITHM_NAME_LEN, MAX_ALGORITHM_VALUE_LEN, MAX_ALGORITHMS_PER_BUNDLE, MAX_IDENTIFIER_LEN,
    MAX_KEY_FIELD_LEN, MAX_VERIFICATION_METHODS, validate_max_length, validate_nonempty_key,
};

/// Per-device public key bundle published via
/// `ck.keys.upload_device_keys`.
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
        validate_nonempty_key("signing_key", &self.signing_key)?;
        validate_nonempty_key("identity_key", &self.identity_key)?;
        validate_max_length("signing_key", &self.signing_key, MAX_KEY_FIELD_LEN)?;
        validate_max_length("identity_key", &self.identity_key, MAX_KEY_FIELD_LEN)?;
        if self.algorithms.len() > MAX_ALGORITHMS_PER_BUNDLE {
            return Err(Error::Protocol(format!(
                "device key bundle algorithms count {} exceeds {}",
                self.algorithms.len(),
                MAX_ALGORITHMS_PER_BUNDLE
            )));
        }
        for (name, value) in &self.algorithms {
            validate_max_length("algorithm name", name, MAX_ALGORITHM_NAME_LEN)?;
            validate_max_length("algorithm value", value, MAX_ALGORITHM_VALUE_LEN)?;
        }
        Ok(())
    }
}

/// Per-device cross-signing trust verdict tracked alongside the
/// device-key bundle in `CryptoStoreBinding::device_trust`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrustState {
    /// No verification path is yet established.
    Unverified,
    /// User has marked the device trusted on this client only.
    LocallyTrusted,
    /// Device key is signed by the principal's SSK.
    CrossSigned,
    /// Verified end-to-end (cross-signed plus an interactive verification).
    Verified,
    /// After a cross-signing reset (spec §14.2), trust state drops here and
    /// the device must be re-verified before it can be treated as
    /// `cross_signed` or `verified` again.
    NeedsReverification,
    Blocked,
}

/// Interactive verification-strand state machine
/// (`ck.device.verification.v1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStrandState {
    /// Initial state — request sent, awaiting peer ready.
    Requested,
    /// Peer accepted; negotiation can start.
    Ready,
    /// SAS (short-authentication-string) leg started.
    SasStarted,
    /// QR-code leg scanned.
    QrScanned,
    /// Verification completed successfully.
    Done,
    /// Either party cancelled.
    Cancelled,
    /// Window expired before completion.
    TimedOut,
}

/// Active interactive-verification strand between two of the principal's
/// own devices (or a peer and a verifier).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceVerificationStrand {
    pub transaction_id: String,
    pub user_id: Did,
    pub from_device: DeviceId,
    pub to_device: DeviceId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    pub state: VerificationStrandState,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl DeviceVerificationStrand {
    pub fn validate(&self) -> Result<()> {
        validate_nonempty_key("verification transaction id", &self.transaction_id)?;
        validate_max_length(
            "verification transaction id",
            &self.transaction_id,
            MAX_IDENTIFIER_LEN,
        )?;
        if self.from_device == self.to_device {
            return Err(Error::Protocol(
                "verification requires two distinct devices".to_owned(),
            ));
        }
        if self.methods.len() > MAX_VERIFICATION_METHODS {
            return Err(Error::Protocol(format!(
                "verification methods count {} exceeds {}",
                self.methods.len(),
                MAX_VERIFICATION_METHODS
            )));
        }
        for method in &self.methods {
            validate_nonempty_key("verification method", method)?;
            validate_max_length("verification method", method, MAX_IDENTIFIER_LEN)?;
        }
        Ok(())
    }

    pub fn advance(&mut self, next: VerificationStrandState) -> Result<()> {
        let allowed = matches!(
            (self.state, next),
            (
                VerificationStrandState::Requested,
                VerificationStrandState::Ready
            ) | (
                VerificationStrandState::Ready,
                VerificationStrandState::SasStarted
            ) | (
                VerificationStrandState::Ready,
                VerificationStrandState::QrScanned
            ) | (
                VerificationStrandState::SasStarted,
                VerificationStrandState::Done
            ) | (
                VerificationStrandState::QrScanned,
                VerificationStrandState::Done
            ) | (_, VerificationStrandState::Cancelled)
                | (_, VerificationStrandState::TimedOut)
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
