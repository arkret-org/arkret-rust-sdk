//! Seal-transparency log wire shapes.

use arkret_wire::{Hash, PayloadProof, RealmId, SchemaId, SealId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Counterpart for
/// `spec/v1/artifacts/schemas/seal-transparency.schema.json#/$defs/auditor_attestation/properties/
/// checks`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealTransparencyVerifiedCheck;

impl Serialize for SealTransparencyVerifiedCheck {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for SealTransparencyVerifiedCheck {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "seal transparency auditor checks must be true",
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealTransparencyChecks {
    pub append_only: SealTransparencyVerifiedCheck,
    pub seal_signatures: SealTransparencyVerifiedCheck,
    pub dag_edges_verified: SealTransparencyVerifiedCheck,
    pub set_root_monotonic: SealTransparencyVerifiedCheck,
}

/// Counterpart for `spec/v1/artifacts/schemas/seal-transparency.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealTransparency {
    pub log_id: String,
    pub log_index: u64,
    pub realm_id: RealmId,
    pub seal_id: SealId,
    pub control_event_set_root: Hash,
    pub state_root: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_entry_digest: Option<Hash>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub logged_at: DateTime<Utc>,
    pub log_signature: PayloadProof,
}

impl SealTransparency {
    pub const SCHEMA: &'static str = SchemaId::SEAL_TRANSPARENCY_V1;
}

#[cfg(test)]
mod seal_transparency_tests {
    use super::*;

    #[test]
    fn auditor_checks_require_every_registered_true_value() {
        let valid = serde_json::json!({
            "append_only": true,
            "seal_signatures": true,
            "dag_edges_verified": true,
            "set_root_monotonic": true
        });
        assert!(serde_json::from_value::<SealTransparencyChecks>(valid).is_ok());

        let missing = serde_json::json!({
            "append_only": true,
            "seal_signatures": true,
            "set_root_monotonic": true
        });
        assert!(serde_json::from_value::<SealTransparencyChecks>(missing).is_err());

        let false_check = serde_json::json!({
            "append_only": true,
            "seal_signatures": true,
            "dag_edges_verified": false,
            "set_root_monotonic": true
        });
        assert!(serde_json::from_value::<SealTransparencyChecks>(false_check).is_err());
    }
}
