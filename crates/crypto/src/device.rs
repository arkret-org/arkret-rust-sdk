//! Per-device key bundles and trust state.

use std::collections::BTreeMap;

use arkret_signatures::DetachedSignature;
use arkret_wire::{DeviceId, DidCoreId};
use serde::{Deserialize, Serialize};

use crate::errors::{
    Error, MAX_ALGORITHM_NAME_LEN, MAX_ALGORITHM_VALUE_LEN, MAX_ALGORITHMS_PER_BUNDLE,
    MAX_KEY_FIELD_LEN, Result, validate_max_length, validate_nonempty_key,
};

/// Per-device public key bundle cached locally alongside the trust
/// verdict (`CryptoStoreBinding::device_keys`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceKeyBundle {
    pub user_id: DidCoreId,
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

/// Per-device verification verdict tracked alongside the
/// device-key bundle in `CryptoStoreBinding::device_trust`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrustState {
    /// No verification path is yet established.
    Unverified,
    /// User has marked the device trusted on this client only.
    LocallyTrusted,
    /// Device key is covered by the accepted PCR authorization chain.
    Authorized,
    /// Verified end-to-end (PCR-authorized plus an interactive verification).
    Verified,
    /// After a root-anchored device re-entry, trust state drops here and
    /// the device must be re-verified before it can be treated as
    /// `authorized` or `verified` again.
    NeedsReverification,
    Blocked,
}
