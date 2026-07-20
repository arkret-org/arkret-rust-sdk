//! Inclusion-list and seal-transparency log wire shapes.
//!
//! Counterparts for `spec/v1/artifacts/schemas/inclusion-list.schema.json`
//! and `spec/v1/artifacts/schemas/seal-transparency.schema.json`. Migrated
//! from `arkret-core` (`models::artifacts::self_ops`).

use arkret_wire::{Did, Hash, PayloadProof, RealmId, SealId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Counterpart for `spec/v1/artifacts/schemas/inclusion-list.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionList {
    pub realm_id: RealmId,
    pub signer_id: Did,
    pub list_seq: u64,
    pub event_digests: Vec<Hash>,
    pub expiry_seal_count: u64,
    pub created_at: DateTime<Utc>,
    pub signature: PayloadProof,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/seal-transparency.schema.json#/$defs/auditor_attestation/checks`.
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
    pub completeness_monotonic: SealTransparencyVerifiedCheck,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/seal-transparency.schema.json#/$defs/auditor_attestation`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealTransparencyAuditorAttestation {
    pub log_id: String,
    pub realm_id: RealmId,
    pub from_index: u64,
    pub to_index: u64,
    pub head_entry_digest: Hash,
    pub auditor_id: Did,
    pub checks: SealTransparencyChecks,
    pub attested_at: DateTime<Utc>,
    pub signature: PayloadProof,
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
    pub completeness_root: Hash,
    pub state_root: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_entry_digest: Option<Hash>,
    pub logged_at: DateTime<Utc>,
    pub log_signature: PayloadProof,
}

#[cfg(test)]
mod seal_transparency_tests {
    use super::*;

    #[test]
    fn auditor_checks_require_dag_edges_and_true_values() {
        let valid = serde_json::json!({
            "append_only": true,
            "seal_signatures": true,
            "dag_edges_verified": true,
            "set_root_monotonic": true,
            "completeness_monotonic": true
        });
        assert!(serde_json::from_value::<SealTransparencyChecks>(valid).is_ok());

        let missing = serde_json::json!({
            "append_only": true,
            "seal_signatures": true,
            "set_root_monotonic": true,
            "completeness_monotonic": true
        });
        assert!(serde_json::from_value::<SealTransparencyChecks>(missing).is_err());

        let false_check = serde_json::json!({
            "append_only": true,
            "seal_signatures": true,
            "dag_edges_verified": false,
            "set_root_monotonic": true,
            "completeness_monotonic": true
        });
        assert!(serde_json::from_value::<SealTransparencyChecks>(false_check).is_err());
    }
}
