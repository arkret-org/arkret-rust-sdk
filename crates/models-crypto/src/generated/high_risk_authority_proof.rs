//! @generated; do not edit by hand.
//! Generator: tools/generate-closed-models.py
//!
//! Input: schemas/high-risk-authority-proof.schema.json
//! sha256=6d932f6f09136f8e1f0abba560eb99392ba91396e3213f2c79a1bcd98b1fe239
//!
//! Input: schemas/event-envelope.schema.json
//! sha256=2a3f8d112bfec45b9ba80a8a1dc4d6c4dbf336c02a866133f84530da585a52a1
//!
//! Input: schemas/common-ids.schema.json
//! sha256=81b18acd21f4382860d5cab2384d9bb78ee5dbc23629752a6cc74ce384186149
//!
//! Bindings: tools/closed-model-bindings.json
//! sha256=3bfe22afd0deee9b00a0fd4b2c1e2c7eee318ee6752681d944e4cc4b38492100

/// Counterpart: `high-risk-authority-proof.schema.json#/$defs/recovery_unlock_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighRiskRecoveryUnlockProofBody {
    pub kind: crate::recovery_session::RecoveryUnlockProofKind,
    pub recovery_session_id: arkret_wire::RecoverySessionId,
    pub proof: arkret_wire::PayloadProof,
}

/// Counterpart: `high-risk-authority-proof.schema.json#/$defs/device_quorum_signature`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighRiskDeviceQuorumSignature {
    pub device_id: arkret_wire::DeviceId,
    pub proof: arkret_wire::PayloadProof,
}

/// Counterpart: `high-risk-authority-proof.schema.json#/$defs/device_quorum_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighRiskDeviceQuorumProofBody {
    pub kind: crate::recovery_session::DeviceQuorumProofKind,
    pub min_device_count: u32,
    pub signatures: Vec<HighRiskDeviceQuorumSignature>,
}

/// Counterpart: `high-risk-authority-proof.schema.json#/$defs/trusted_recovery_service_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighRiskTrustedRecoveryServiceProofBody {
    pub kind: crate::recovery_session::TrustedRecoveryServiceProofKind,
    pub service_id: arkret_wire::DidCoreId,
    pub recovery_session_id: arkret_wire::RecoverySessionId,
    pub proof: arkret_wire::PayloadProof,
}

/// Counterpart: `high-risk-authority-proof.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum HighRiskAuthorityProof {
    RecoveryUnlock(HighRiskRecoveryUnlockProofBody),
    DeviceQuorum(HighRiskDeviceQuorumProofBody),
    TrustedRecoveryService(HighRiskTrustedRecoveryServiceProofBody),
}
