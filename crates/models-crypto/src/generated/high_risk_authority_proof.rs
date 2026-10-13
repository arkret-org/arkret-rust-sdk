//! @generated; do not edit by hand.
//! Generator: tools/generate-closed-models.py
//!
//! Input: schemas/high-risk-authority-proof.schema.json
//! sha256=3608c6f7fea8dcfc1baaf0f1fe557e9999a2ea49eeaca662ae0bb93bea8e22de
//!
//! Bindings: tools/closed-model-bindings.json
//! sha256=c5c717d42040392233cf38e4f3236cfeed2d38c2b642d4cf765ba04cf371a3ee

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
