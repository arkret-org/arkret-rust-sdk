//! Shared authority proof family for high-risk material destruction.
//!
//! Exactly one closed branch — `recovery_unlock`, `device_quorum` or
//! `trusted_recovery_service` — discriminated by `kind`. Every branch reuses the
//! common detached-JWS leaf over the consuming operation's single canonical
//! intent transcript; branches never restate the leaf fields. An ordinary
//! current-device session proof is deliberately not a branch of this family.
//!
//! The transcript context belongs to the consuming operation, never to the
//! leaf: a signature made under another consumer's context must be rejected
//! even when it verifies cryptographically.

use arkret_wire::{DeviceId, DidCoreId, PayloadProof, RecoverySessionId, Result, WireError};
use serde::{Deserialize, Serialize};

use crate::recovery_session::{
    DeviceQuorumProofKind, RecoveryUnlockProofKind, TrustedRecoveryServiceProofKind,
};

/// The only registered consumer context in v1: active-series key backup tail
/// deletion.
pub const KEY_BACKUP_DELETE_PROOF_CONTEXT: &str = "ak.key_backup_delete_proof.v1";

// Field declaration order is byte-for-byte the properties order of
// high-risk-authority-proof.schema.json#/$defs/recovery_unlock_proof.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighRiskRecoveryUnlockProofBody {
    pub kind: RecoveryUnlockProofKind,
    /// Verified, unexpired recovery session for the transcript's exact account
    /// whose accepted proof summary is `recovery_unlock`.
    pub recovery_session_id: RecoverySessionId,
    pub proof: PayloadProof,
}

// Field declaration order is byte-for-byte the properties order of
// high-risk-authority-proof.schema.json#/$defs/device_quorum_signature.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighRiskDeviceQuorumSignature {
    pub device_id: DeviceId,
    /// Detached-JWS leaf whose verification method must resolve, at
    /// `proof.created_at`, to an authorized non-revoked device key of exactly
    /// this `device_id`. Every quorum member signs the same transcript bytes.
    pub proof: PayloadProof,
}

// Field declaration order is byte-for-byte the properties order of
// high-risk-authority-proof.schema.json#/$defs/device_quorum_proof.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighRiskDeviceQuorumProofBody {
    pub kind: DeviceQuorumProofKind,
    /// The quorum threshold the issuer claims to satisfy. It must equal the
    /// principal's currently accepted recovery-policy device-quorum `k`; a
    /// smaller issuer-supplied threshold is rejected as failed precondition.
    pub threshold: u32,
    /// Schema floor only: receivers require the deduplicated valid signature
    /// count to reach `threshold`.
    pub signatures: Vec<HighRiskDeviceQuorumSignature>,
}

// Field declaration order is byte-for-byte the properties order of
// high-risk-authority-proof.schema.json#/$defs/trusted_recovery_service_proof.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighRiskTrustedRecoveryServiceProofBody {
    pub kind: TrustedRecoveryServiceProofKind,
    pub service_id: DidCoreId,
    /// Verified, unexpired, unconsumed recovery session established by
    /// `recovery_unlock` or `device_quorum`. A service-only session is never a
    /// second factor.
    pub recovery_session_id: RecoverySessionId,
    pub proof: PayloadProof,
}

/// The closed high-risk authority proof family.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HighRiskAuthorityProof {
    RecoveryUnlock(HighRiskRecoveryUnlockProofBody),
    DeviceQuorum(HighRiskDeviceQuorumProofBody),
    TrustedRecoveryService(HighRiskTrustedRecoveryServiceProofBody),
}

impl HighRiskAuthorityProof {
    /// The recovery session this proof is bound to. Every branch names one.
    pub fn recovery_session_id(&self) -> Option<&RecoverySessionId> {
        match self {
            Self::RecoveryUnlock(body) => Some(&body.recovery_session_id),
            Self::DeviceQuorum(_) => None,
            Self::TrustedRecoveryService(body) => Some(&body.recovery_session_id),
        }
    }

    pub fn validate_shape(&self) -> Result<()> {
        match self {
            Self::RecoveryUnlock(body) => body.proof.validate(),
            Self::DeviceQuorum(body) => {
                if body.threshold < 2 {
                    return Err(WireError::Protocol(
                        "high-risk device quorum threshold is at least two".to_owned(),
                    ));
                }
                if body.signatures.is_empty() {
                    return Err(WireError::Protocol(
                        "high-risk device quorum carries at least one signature".to_owned(),
                    ));
                }
                for signature in &body.signatures {
                    signature.proof.validate()?;
                }
                Ok(())
            }
            Self::TrustedRecoveryService(body) => body.proof.validate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SESSION_ID: &str = "ak:recovery_session:0198ff00-0000-7000-8000-00000000000c";
    const DEVICE_ID: &str = "ak:device:0198ff00-0000-7000-8000-00000000000a";

    fn payload_proof_value() -> serde_json::Value {
        json!({
            "kind": "detached_jws",
            "verification_method": "did:webvh:z6mkfixture:alice.example#device-1",
            "payload_digest": format!("sha256:{}", "ab".repeat(32)),
            "created_at": "2026-08-01T00:00:00.000Z",
            "jws": "eyJhbGciOiJFZERTQSJ9..c2ln"
        })
    }

    #[test]
    fn recovery_unlock_branch_round_trips_and_is_closed() {
        let value = json!({
            "kind": "recovery_unlock",
            "recovery_session_id": SESSION_ID,
            "proof": payload_proof_value()
        });
        let parsed: HighRiskAuthorityProof =
            serde_json::from_value(value.clone()).expect("closed branch");
        parsed.validate_shape().expect("valid proof");
        assert_eq!(
            parsed.recovery_session_id().map(|id| id.as_str()),
            Some(SESSION_ID)
        );
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("seal_ref".to_owned(), json!("x"));
        assert!(serde_json::from_value::<HighRiskAuthorityProof>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("proof");
        assert!(serde_json::from_value::<HighRiskAuthorityProof>(missing).is_err());
    }

    #[test]
    fn device_quorum_branch_enforces_its_threshold_floor() {
        let value = json!({
            "kind": "device_quorum",
            "threshold": 2,
            "signatures": [{"device_id": DEVICE_ID, "proof": payload_proof_value()}]
        });
        let parsed: HighRiskAuthorityProof =
            serde_json::from_value(value.clone()).expect("closed branch");
        parsed
            .validate_shape()
            .expect("schema floor is one signature");
        assert!(parsed.recovery_session_id().is_none());
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut below_floor = value.clone();
        below_floor["threshold"] = json!(1);
        let parsed: HighRiskAuthorityProof =
            serde_json::from_value(below_floor).expect("shape parses");
        assert!(parsed.validate_shape().is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("signatures");
        assert!(serde_json::from_value::<HighRiskAuthorityProof>(missing).is_err());
    }

    #[test]
    fn trusted_recovery_service_branch_round_trips_and_is_closed() {
        let value = json!({
            "kind": "trusted_recovery_service",
            "service_id": "ak:did_core:web:recovery.example",
            "recovery_session_id": SESSION_ID,
            "proof": payload_proof_value()
        });
        let parsed: HighRiskAuthorityProof =
            serde_json::from_value(value.clone()).expect("closed branch");
        parsed.validate_shape().expect("valid proof");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("audience".to_owned(), json!("x"));
        assert!(serde_json::from_value::<HighRiskAuthorityProof>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("service_id");
        assert!(serde_json::from_value::<HighRiskAuthorityProof>(missing).is_err());
    }
}
