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

use arkret_wire::{RecoverySessionId, Result, WireError};

/// The only registered consumer context in v1: active-series key backup tail
/// deletion.
pub const KEY_BACKUP_DELETE_PROOF_CONTEXT: &str =
    arkret_wire::ProofContextId::KEY_BACKUP_DELETE_PROOF_V1;

pub use crate::generated::high_risk_authority_proof::{
    HighRiskAuthorityProof, HighRiskDeviceQuorumProofBody, HighRiskDeviceQuorumSignature,
    HighRiskRecoveryUnlockProofBody, HighRiskTrustedRecoveryServiceProofBody,
};

impl HighRiskAuthorityProof {
    /// The bound recovery session, absent for the device-quorum branch.
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

    #[test]
    fn backup_delete_reuses_exact_shared_authority_family_without_legacy_branches() {
        let proof = payload_proof_value();
        let branches = [
            json!({"kind":"recovery_unlock","recovery_session_id":SESSION_ID,"proof":proof}),
            json!({"kind":"device_quorum","threshold":2,"signatures":[{"device_id":DEVICE_ID,"proof":proof}]}),
            json!({"kind":"trusted_recovery_service","service_id":"ak:did_core:web:recovery.example","recovery_session_id":SESSION_ID,"proof":proof}),
        ];
        for branch in branches {
            let value = json!({"request_id":"AAAAAAAAAAAAAAAAAAAAAA","challenge_id":"BBBBBBBBBBBBBBBBBBBBBB","proof":branch});
            let request: crate::KeysBackupsDeleteRequestBody =
                serde_json::from_value(value.clone()).unwrap();
            request.validate().unwrap();
            assert_eq!(serde_json::to_value(request).unwrap(), value);
        }
        for branch in [
            json!({"kind":"current_device","proof":proof}),
            json!({"kind":"recovery_session","recovery_session_id":SESSION_ID,"proof":proof}),
        ] {
            assert!(serde_json::from_value::<crate::KeysBackupsDeleteRequestBody>(json!({"request_id":"AAAAAAAAAAAAAAAAAAAAAA","challenge_id":"BBBBBBBBBBBBBBBBBBBBBB","proof":branch})).is_err());
        }
    }

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
