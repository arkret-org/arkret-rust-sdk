//! @generated; do not edit by hand.
//! Generator: tools/generate-closed-models.py
//!
//! Input: schemas/high-risk-authority-proof.schema.json
//! sha256=4acda127c256d66797a837628cc785a36d2bb23f197e263e2f385e5d83db2a54
//!
//! Bindings: tools/closed-model-bindings.json
//! sha256=13aff1fc7ba8bd04dc6586b917faf46593a6d0e4beeadb69db75284c9e17a6f7

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
    pub threshold: u32,
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
