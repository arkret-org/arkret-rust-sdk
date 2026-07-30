//! MLS record wire shapes: KeyPackage lifecycle + published-KeyPackage record,
//! and the provider-opaque MLS group-state snapshot record.
//!
//! These record shapes moved here so the MLS behavior layer can consume them
//! without depending on the higher crates that previously owned them:
//! `MlsKeyPackageState` from `arkret-models-collaboration`,
//! `MlsKeyPackageRecord` from the `arkret` umbrella, and `MlsGroupStateRecord` from the
//! SDK crypto store. The original owners keep re-export shims so downstream
//! paths are unchanged.

use arkret_wire::{DeviceId, Did, Hash, Proof};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Lifecycle of a published KeyPackage per `device-lifecycle.md` §2 /
/// `encryption-and-audit.md` §2.6. Once a KeyPackage is `claimed` it
/// MUST NOT be re-claimed; once `consumed` it MUST NOT return to
/// `published`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MlsKeyPackageState {
    #[default]
    Published,
    Claimed,
    Consumed,
    Revoked,
    Retired,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlsKeyPackageRecord {
    /// Globally unique identifier (`ak:mls:kp:<uuid>`, RFC 9562 UUIDv7).
    pub keypackage_id: String,
    pub principal_id: Did,
    pub device_id: DeviceId,
    /// MLS KeyPackage material (base64url).
    pub key_package: String,
    /// Canonical hash of `key_package`.
    pub keypackage_ref: Hash,
    pub cipher_suites: Vec<String>,
    /// Content / MLS profile capabilities (e.g. `mimi.content.v1`).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Lifecycle state.
    #[serde(default)]
    pub state: MlsKeyPackageState,
    /// Bound `claim_id` once `state = claimed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<Proof>,
    /// Whether this is a reusable last-resort KeyPackage. Last-resort
    /// KeyPackages are NOT consumed on claim (the server keeps them
    /// claimable), so a member is always (re-)addable even after its
    /// single-use KeyPackages are exhausted. The init-key forward-secrecy
    /// trade-off is the standard MLS last-resort guarantee. The KeyPackage
    /// material MUST itself carry the OpenMLS `last_resort` extension (built
    /// via `mark_as_last_resort`) so the holder retains the init private key
    /// across repeated Welcome processing.
    #[serde(default)]
    pub last_resort: bool,
}

impl MlsKeyPackageRecord {
    /// Schema id for `ak.mls.keypackage` events / records.
    pub const SCHEMA: &'static str = "ak.schema.mls_keypackage.v1";

    /// Whether the record is currently usable for a Welcome.
    pub fn is_usable(&self) -> bool {
        !matches!(
            self.state,
            MlsKeyPackageState::Revoked
                | MlsKeyPackageState::Consumed
                | MlsKeyPackageState::Retired
        )
    }
}

#[cfg(test)]
mod tests {
    use super::MlsKeyPackageState;

    #[test]
    fn keypackage_wire_state_accepts_retired_and_rejects_expired() {
        let retired: MlsKeyPackageState = serde_json::from_str("\"retired\"").unwrap();
        assert_eq!(retired, MlsKeyPackageState::Retired);
        assert_eq!(serde_json::to_string(&retired).unwrap(), "\"retired\"");
        assert!(serde_json::from_str::<MlsKeyPackageState>("\"expired\"").is_err());
    }
}

/// Provider-opaque MLS group-state snapshot record.
///
/// Applications serialize provider-specific MLS state into
/// `serialized_state` while using the typed Arkret envelopes for KeyPackages,
/// Welcomes and Commits. The SDK crypto store keeps this layer independent
/// from OpenMLS internals.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsGroupStateRecord {
    pub group_id: String,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub epoch: u64,
    pub serialized_state: Vec<u8>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub updated_at: DateTime<Utc>,
}

// `serialized_state` is the full OpenMLS group snapshot (ratchet secrets +
// retained history secrets): render it redacted so a stray `{record:?}` in a
// log line can never leak decryptable key material.
impl std::fmt::Debug for MlsGroupStateRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsGroupStateRecord")
            .field("group_id", &self.group_id)
            .field("principal_id", &self.principal_id)
            .field("device_id", &self.device_id)
            .field("epoch", &self.epoch)
            .field(
                "serialized_state",
                &format_args!("<redacted {} bytes>", self.serialized_state.len()),
            )
            .field("updated_at", &self.updated_at)
            .finish()
    }
}
