//! Device recovery session state machine and its canonical proof transcripts.
//!
//! A session freezes the exact account, the replacement device identity key,
//! the accepted PCR recovery policy and the server-evaluated publication
//! authority before any factor is verified. Completion is not owned here: the
//! bound RecoveryTransaction is terminal only when the re-anchor Event and the
//! replacement device authorization Event take two consecutive
//! [`arkret_wire::CommittedEventRef`] values in the same PCR Realm stream, as
//! carried by [`arkret_wire::RecoveryCompletionAttestation`].

use arkret_wire::{
    AccountId, Base64UrlString, CommitStreamHead, DeviceId, DidCoreId, DidKey, DidUrl, Hash,
    PolicyId, RealmCommitId, RecoverySessionId, RequestId, Result, SchemaId, ScopeRef,
    SessionGrantId, TransactionId, TrustDomainId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::authority_set_policy::AuthoritySetPolicy;
use crate::recovery_policy::{RecoveryPolicyRef, RecoverySignatureAlgorithm};
use crate::security_transaction::{RecoveryIdentityModel, RecoveryProofKind};

/// Default recovery session TTL. Deployments MAY shorten it and MUST NOT
/// lengthen it.
pub const RECOVERY_SESSION_DEFAULT_TTL_SECONDS: i64 = 900;

/// The single action a recovery publication authority context may allow.
pub const RECOVERY_PUBLICATION_ALLOWED_ACTION: &str = "ak.device.reanchor";

/// Signature domain of the create-time replacement identity-key possession
/// transcript.
pub const RECOVERY_DEVICE_POSSESSION_DOMAIN: &str = "ak.identity.recovery_device_possession.v1";

/// Schema constant of every canonical recovery proof transcript.
pub const RECOVERY_PROOF_TRANSCRIPT_SCHEMA: &str = "ak.identity.recovery_proof.v1";

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/session_state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoverySessionState {
    Pending,
    Verified,
    Completed,
    Rejected,
    Expired,
}

/// Closed rejection reasons a recovery session may terminate with.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoverySessionRejectionReasonCode {
    ProofFailed,
    OperatorRejected,
    RiskPolicy,
    Superseded,
}

/// Reducer-managed PCR device generation status snapshotted at session
/// creation.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDeviceGenerationStatus {
    Active,
    Conflicted,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/proof_summary.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionProofSummary {
    pub kind: RecoveryProofKind,
    /// Digest of the canonical recovery proof transcript that satisfied this
    /// session.
    pub proof_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<DidUrl>,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/publication_authority_context.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationAuthorityContext {
    pub authority_commit_id: RealmCommitId,
    pub scope_ref: ScopeRef,
    pub authority_set_policy: AuthoritySetPolicy,
    pub allowed_actions: Vec<String>,
}

impl PublicationAuthorityContext {
    pub fn validate_shape(&self) -> Result<()> {
        self.authority_set_policy.validate_shape()?;
        if self.allowed_actions.len() != 1
            || self.allowed_actions[0] != RECOVERY_PUBLICATION_ALLOWED_ACTION
        {
            return Err(WireError::Protocol(
                "recovery publication authority allows exactly ak.device.reanchor".to_owned(),
            ));
        }
        Ok(())
    }
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/recovery_session_state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySession {
    pub schema: String,
    pub request_id: RequestId,
    pub recovery_session_id: RecoverySessionId,
    pub session_grant_id: SessionGrantId,
    pub session_grant_cnf_jkt: Base64UrlString,
    pub account_id: AccountId,
    pub requesting_device_id: DeviceId,
    pub requesting_device_public_key_did: DidKey,
    pub trust_domain: TrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub identity_model: RecoveryIdentityModel,
    pub current_device_generation_ref: u64,
    pub device_generation_status: RecoveryDeviceGenerationStatus,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub realm_stream_head: CommitStreamHead,
    pub publication_authority_context: PublicationAuthorityContext,
    /// SHA-256 of JCS(publication_authority_context). Proof transcripts and the
    /// RecoveryTransaction session snapshot bind this exact digest.
    pub publication_authority_context_digest: Hash,
    pub challenge: Base64UrlString,
    pub state: RecoverySessionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_summary: Option<RecoverySessionProofSummary>,
    /// Durable RecoveryTransaction bound by CAS after verification. Absent
    /// until transaction create succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<TransactionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason_code: Option<RecoverySessionRejectionReasonCode>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    /// Session creation/signing time; this is the `created_at` bound into the
    /// recovery proof transcript.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

impl RecoverySession {
    pub fn validate_shape(&self) -> Result<()> {
        if self.schema != SchemaId::RECOVERY_SESSION_V1 {
            return Err(WireError::Protocol(
                "recovery session schema is invalid".to_owned(),
            ));
        }
        if self.policy_version == 0 || self.current_device_generation_ref == 0 {
            return Err(WireError::Protocol(
                "recovery session policy version and device generation start at 1".to_owned(),
            ));
        }
        self.publication_authority_context.validate_shape()?;
        if matches!(
            self.state,
            RecoverySessionState::Verified | RecoverySessionState::Completed
        ) && self.proof_summary.is_none()
        {
            return Err(WireError::Protocol(
                "a verified or completed recovery session carries its proof summary".to_owned(),
            ));
        }
        if self.state == RecoverySessionState::Rejected && self.rejection_reason_code.is_none() {
            return Err(WireError::Protocol(
                "a rejected recovery session carries its rejection reason code".to_owned(),
            ));
        }
        Ok(())
    }
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/recovery_session_create_request_body.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionCreateRequestBody {
    pub request_id: RequestId,
    pub account_id: AccountId,
    pub requesting_device_id: DeviceId,
    pub requesting_device_public_key_did: DidKey,
    /// Ed25519 proof of possession over
    /// `UTF8("ak.identity.recovery_device_possession.v1\n") || JCS(transcript)`.
    pub requesting_device_signature: Base64UrlString,
    pub trust_domain: TrustDomainId,
    /// Client CAS hint. When present and different from the server-snapshotted
    /// accepted policy the request fails with `recovery_policy_mismatch`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_recovery_policy_ref: Option<RecoveryPolicyRef>,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/recovery_device_possession_transcript.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDevicePossessionTranscript {
    pub schema: String,
    pub request_id: RequestId,
    pub session_grant_id: SessionGrantId,
    pub session_grant_cnf_jkt: Base64UrlString,
    pub account_id: AccountId,
    pub requesting_device_id: DeviceId,
    pub requesting_device_public_key_did: DidKey,
    pub trust_domain: TrustDomainId,
    /// Included exactly when the create request includes it; an omitted hint is
    /// never normalized to null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_recovery_policy_ref: Option<RecoveryPolicyRef>,
}

impl RecoveryDevicePossessionTranscript {
    /// Canonical signing bytes: the domain line, then RFC 8785 JCS of the
    /// closed transcript.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        if self.schema != RECOVERY_DEVICE_POSSESSION_DOMAIN {
            return Err(WireError::Protocol(
                "recovery device possession transcript schema is invalid".to_owned(),
            ));
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(RECOVERY_DEVICE_POSSESSION_DOMAIN.as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(&arkret_canonical::canonical::canonical_json_bytes(self)?);
        Ok(bytes)
    }
}

/// Closed `kind` discriminator of the `did_root` recovery proof branch.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DidRootProofKind {
    #[serde(rename = "did_root")]
    DidRoot,
}

/// Closed `kind` discriminator of the `recovery_unlock` recovery proof branch.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoveryUnlockProofKind {
    #[serde(rename = "recovery_unlock")]
    RecoveryUnlock,
}

/// Closed `kind` discriminator of the `device_quorum` recovery proof branch.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeviceQuorumProofKind {
    #[serde(rename = "device_quorum")]
    DeviceQuorum,
}

/// Closed `kind` discriminator of the `trusted_recovery_service` recovery proof
/// branch.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustedRecoveryServiceProofKind {
    #[serde(rename = "trusted_recovery_service")]
    TrustedRecoveryService,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/did_root_proof.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidRootProofBody {
    pub kind: DidRootProofKind,
    pub challenge: Base64UrlString,
    /// Current DID-root verification method, accepted only when the frozen PCR
    /// recovery policy explicitly enables this revocable factor.
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
    pub signature: Base64UrlString,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/recovery_unlock_proof.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryUnlockProofBodyWithSignature {
    pub kind: RecoveryUnlockProofKind,
    pub challenge: Base64UrlString,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
    pub signature: Base64UrlString,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/device_quorum_proof/properties/
// signatures/items.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuorumSignature {
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
    pub signature: Base64UrlString,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/device_quorum_proof.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuorumProofBodyWithSignatures {
    pub kind: DeviceQuorumProofKind,
    pub challenge: Base64UrlString,
    pub threshold: u32,
    pub signatures: Vec<DeviceQuorumSignature>,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/trusted_recovery_service_proof.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRecoveryServiceProofBodyWithSignature {
    pub kind: TrustedRecoveryServiceProofKind,
    pub challenge: Base64UrlString,
    pub service_id: DidCoreId,
    pub audience: String,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
    pub signature: Base64UrlString,
}

/// Kind-specific recovery proof submitted against a pending session. Receivers
/// rebuild the canonical transcript from stored session state plus this body,
/// then require the frozen policy to allow this kind and the proof to satisfy
/// that entry exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecoverySessionProof {
    DidRoot(DidRootProofBody),
    RecoveryUnlock(RecoveryUnlockProofBodyWithSignature),
    DeviceQuorum(DeviceQuorumProofBodyWithSignatures),
    TrustedRecoveryService(TrustedRecoveryServiceProofBodyWithSignature),
}

impl RecoverySessionProof {
    pub fn proof_kind(&self) -> RecoveryProofKind {
        match self {
            Self::DidRoot(_) => RecoveryProofKind::DidRoot,
            Self::RecoveryUnlock(_) => RecoveryProofKind::RecoveryUnlock,
            Self::DeviceQuorum(_) => RecoveryProofKind::DeviceQuorum,
            Self::TrustedRecoveryService(_) => RecoveryProofKind::TrustedRecoveryService,
        }
    }

    pub fn challenge(&self) -> &Base64UrlString {
        match self {
            Self::DidRoot(body) => &body.challenge,
            Self::RecoveryUnlock(body) => &body.challenge,
            Self::DeviceQuorum(body) => &body.challenge,
            Self::TrustedRecoveryService(body) => &body.challenge,
        }
    }

    pub fn validate_shape(&self) -> Result<()> {
        if let Self::DeviceQuorum(body) = self {
            if body.threshold < 2 || body.signatures.len() < 2 {
                return Err(WireError::Protocol(
                    "device quorum recovery proof carries at least two signatures".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/recovery_session_proof_submit_request_body.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionProofSubmitRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub proof: RecoverySessionProof,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/recovery_session_proof_submit_outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionProofSubmitOutcome {
    pub recovery_session_id: RecoverySessionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_summary: Option<RecoverySessionProofSummary>,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/did_root_transcript.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidRootRecoveryTranscript {
    pub schema: String,
    pub kind: RecoveryProofKind,
    pub request_id: RequestId,
    pub session_grant_id: SessionGrantId,
    pub session_grant_cnf_jkt: Base64UrlString,
    pub account_id: AccountId,
    pub requesting_device_id: DeviceId,
    pub requesting_device_public_key_did: DidKey,
    pub trust_domain: TrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub identity_model: RecoveryIdentityModel,
    /// Accepted PCR generation fenced by this recovery. DID method versioning
    /// is orthogonal and is never carried here.
    pub model_generation_ref: u64,
    pub publication_authority_context_digest: Hash,
    pub challenge: Base64UrlString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    /// Session creation/signing time, not client proof creation time.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/recovery_unlock_proof_body.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryUnlockProofBody {
    pub kind: RecoveryUnlockProofKind,
    pub challenge: Base64UrlString,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/device_quorum_proof_body/properties/
// signatures/items.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuorumSignatureBody {
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/device_quorum_proof_body.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuorumProofBody {
    pub kind: DeviceQuorumProofKind,
    pub challenge: Base64UrlString,
    pub threshold: u32,
    pub signatures: Vec<DeviceQuorumSignatureBody>,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/trusted_recovery_service_proof_body.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRecoveryServiceProofBody {
    pub kind: TrustedRecoveryServiceProofKind,
    pub challenge: Base64UrlString,
    pub service_id: DidCoreId,
    pub audience: String,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
}

/// Closed signature-independent projection selected by `kind`. Carrier
/// signatures are deleted, never replaced by null, before transcript
/// canonicalization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecoveryTranscriptProofBody {
    RecoveryUnlock(RecoveryUnlockProofBody),
    DeviceQuorum(DeviceQuorumProofBody),
    TrustedRecoveryService(TrustedRecoveryServiceProofBody),
}

impl RecoveryTranscriptProofBody {
    pub fn proof_kind(&self) -> RecoveryProofKind {
        match self {
            Self::RecoveryUnlock(_) => RecoveryProofKind::RecoveryUnlock,
            Self::DeviceQuorum(_) => RecoveryProofKind::DeviceQuorum,
            Self::TrustedRecoveryService(_) => RecoveryProofKind::TrustedRecoveryService,
        }
    }
}

/// Canonical transcript shared by `recovery_unlock`, `device_quorum` and
/// `trusted_recovery_service` proofs. Producers and receivers bind exactly this
/// session tuple.
// Field declaration order is byte-for-byte the properties order of
// recovery-session.schema.json#/$defs/generic_recovery_transcript.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericRecoveryTranscript {
    pub schema: String,
    pub kind: RecoveryProofKind,
    pub request_id: RequestId,
    pub session_grant_id: SessionGrantId,
    pub session_grant_cnf_jkt: Base64UrlString,
    pub account_id: AccountId,
    pub requesting_device_id: DeviceId,
    pub requesting_device_public_key_did: DidKey,
    pub trust_domain: TrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub identity_model: RecoveryIdentityModel,
    /// PCR-local monotonic device generation accepted for this recovery
    /// session; it is never a DID method versionId.
    pub model_generation_ref: u64,
    pub publication_authority_context_digest: Hash,
    pub challenge: Base64UrlString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub proof_body: RecoveryTranscriptProofBody,
}

impl GenericRecoveryTranscript {
    pub fn validate_shape(&self) -> Result<()> {
        if self.schema != RECOVERY_PROOF_TRANSCRIPT_SCHEMA {
            return Err(WireError::Protocol(
                "recovery proof transcript schema is invalid".to_owned(),
            ));
        }
        if self.kind == RecoveryProofKind::DidRoot {
            return Err(WireError::Protocol(
                "did_root recovery proofs use the did_root transcript".to_owned(),
            ));
        }
        if self.kind != self.proof_body.proof_kind() {
            return Err(WireError::Protocol(
                "recovery transcript kind must select its proof body branch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::recovery_policy::fixtures;

    const CHALLENGE: &str = "Q2hhbGxlbmdlRml4dHVyZVZhbHVlMDAwMDAwMDAwMDAwMDAwMDA";
    const CNF_JKT: &str = "Q25mSmt0Rml4dHVyZVZhbHVlMDAwMDAwMDAwMDAwMDAwMDAwMA";
    const DEVICE_ID: &str = "ak:device:0198ff00-0000-7000-8000-00000000000a";
    const REQUEST_ID: &str = "ak:request:0198ff00-0000-7000-8000-00000000000b";
    const SESSION_ID: &str = "ak:recovery_session:0198ff00-0000-7000-8000-00000000000c";
    const DEVICE_KEY: &str = "did:key:z6MkfixtureDeviceKeyAbc";

    fn digest(byte: u8) -> String {
        format!("sha256:{}", format!("{byte:02x}").repeat(32))
    }

    fn session_grant_id() -> SessionGrantId {
        SessionGrantId::from_issuance_digest([4; 32])
    }

    fn realm_id() -> arkret_wire::RealmId {
        arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [7; 32],
        ))
    }

    fn publication_authority_context_value() -> serde_json::Value {
        json!({
            "authority_commit_id": RealmCommitId::from_digest([9; 32]),
            "scope_ref": {"kind": "realm", "realm_id": realm_id()},
            "authority_set_policy": {
                "schema": "ak.schema.authority_set_policy.v1",
                "authority_set_id": "ak.authority_set.principal_control.v1",
                "policy_kind": "principal_control",
                "scope_ref": {"kind": "realm", "realm_id": realm_id()},
                "source_commit_id": RealmCommitId::from_digest([9; 32]),
                "authorization_rules": [{
                    "rule_id": "identity_recovery",
                    "issuer_role": "identity_recovery",
                    "allowed_actions": ["ak.device.reanchor"],
                    "issuers": [{
                        "verification_method": fixtures::RECOVERY_METHOD_URL
                    }],
                    "threshold": 1
                }]
            },
            "allowed_actions": ["ak.device.reanchor"]
        })
    }

    fn session_value() -> serde_json::Value {
        json!({
            "schema": "ak.schema.recovery_session.v1",
            "request_id": REQUEST_ID,
            "recovery_session_id": SESSION_ID,
            "session_grant_id": session_grant_id(),
            "session_grant_cnf_jkt": CNF_JKT,
            "account_id": fixtures::account_id(),
            "requesting_device_id": DEVICE_ID,
            "requesting_device_public_key_did": DEVICE_KEY,
            "trust_domain": fixtures::TRUST_DOMAIN,
            "policy_id": fixtures::POLICY_ID,
            "policy_version": 1,
            "identity_model": "pcr_policy",
            "current_device_generation_ref": 3,
            "device_generation_status": "active",
            "realm_stream_head": {
                "stream_ref": {"kind": "realm", "realm_id": realm_id()},
                "stream_position": 12,
                "commit_id": RealmCommitId::from_digest([9; 32])
            },
            "publication_authority_context": publication_authority_context_value(),
            "publication_authority_context_digest": digest(0xab),
            "challenge": CHALLENGE,
            "state": "pending",
            "expires_at": "2026-08-01T00:15:00.000Z",
            "created_at": "2026-08-01T00:00:00.000Z",
            "updated_at": "2026-08-01T00:00:00.000Z"
        })
    }

    #[test]
    fn recovery_session_round_trips_and_is_closed() {
        let value = session_value();
        let parsed: RecoverySession =
            serde_json::from_value(value.clone()).expect("closed session");
        parsed.validate_shape().expect("valid session");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("cas_revision".to_owned(), json!(1));
        assert!(serde_json::from_value::<RecoverySession>(unknown).is_err());

        let mut missing = value;
        missing
            .as_object_mut()
            .unwrap()
            .remove("publication_authority_context_digest");
        assert!(serde_json::from_value::<RecoverySession>(missing).is_err());
    }

    #[test]
    fn verified_session_requires_a_proof_summary() {
        let mut value = session_value();
        value["state"] = json!("verified");
        let parsed: RecoverySession = serde_json::from_value(value.clone()).expect("shape parses");
        assert!(parsed.validate_shape().is_err());

        value["proof_summary"] = json!({
            "kind": "recovery_unlock",
            "proof_digest": digest(0xcd),
            "verification_method": fixtures::RECOVERY_METHOD_URL
        });
        let parsed: RecoverySession = serde_json::from_value(value).expect("shape parses");
        parsed.validate_shape().expect("verified session is valid");
    }

    #[test]
    fn rejected_session_requires_a_reason_code() {
        let mut value = session_value();
        value["state"] = json!("rejected");
        let parsed: RecoverySession = serde_json::from_value(value.clone()).expect("shape parses");
        assert!(parsed.validate_shape().is_err());

        value["rejection_reason_code"] = json!("proof_failed");
        let parsed: RecoverySession = serde_json::from_value(value).expect("shape parses");
        parsed.validate_shape().expect("rejected session is valid");
    }

    #[test]
    fn publication_authority_context_allows_only_reanchor() {
        let mut value = publication_authority_context_value();
        value["allowed_actions"] = json!(["ak.device.reanchor", "ak.device.revoke"]);
        let parsed: PublicationAuthorityContext =
            serde_json::from_value(value).expect("shape parses");
        assert!(parsed.validate_shape().is_err());
    }

    fn create_request_value() -> serde_json::Value {
        json!({
            "request_id": REQUEST_ID,
            "account_id": fixtures::account_id(),
            "requesting_device_id": DEVICE_ID,
            "requesting_device_public_key_did": DEVICE_KEY,
            "requesting_device_signature": "c2lnbmF0dXJlLWZpeHR1cmU",
            "trust_domain": fixtures::TRUST_DOMAIN
        })
    }

    #[test]
    fn create_request_round_trips_and_is_closed() {
        let value = create_request_value();
        let parsed: RecoverySessionCreateRequestBody =
            serde_json::from_value(value.clone()).expect("closed body");
        assert!(parsed.expected_recovery_policy_ref.is_none());
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("head_eq".to_owned(), json!(1));
        assert!(serde_json::from_value::<RecoverySessionCreateRequestBody>(unknown).is_err());

        let mut missing = value;
        missing
            .as_object_mut()
            .unwrap()
            .remove("requesting_device_signature");
        assert!(serde_json::from_value::<RecoverySessionCreateRequestBody>(missing).is_err());
    }

    #[test]
    fn possession_transcript_signs_under_its_own_domain() {
        let value = json!({
            "schema": "ak.identity.recovery_device_possession.v1",
            "request_id": REQUEST_ID,
            "session_grant_id": session_grant_id(),
            "session_grant_cnf_jkt": CNF_JKT,
            "account_id": fixtures::account_id(),
            "requesting_device_id": DEVICE_ID,
            "requesting_device_public_key_did": DEVICE_KEY,
            "trust_domain": fixtures::TRUST_DOMAIN
        });
        let parsed: RecoveryDevicePossessionTranscript =
            serde_json::from_value(value.clone()).expect("closed transcript");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
        let bytes = parsed.signing_bytes().expect("signing bytes");
        assert!(bytes.starts_with(b"ak.identity.recovery_device_possession.v1\n"));

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("challenge".to_owned(), json!(CHALLENGE));
        assert!(serde_json::from_value::<RecoveryDevicePossessionTranscript>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("account_id");
        assert!(serde_json::from_value::<RecoveryDevicePossessionTranscript>(missing).is_err());
    }

    #[test]
    fn proof_submit_body_selects_one_closed_branch() {
        let value = json!({
            "proof": {
                "kind": "recovery_unlock",
                "challenge": CHALLENGE,
                "verification_method": fixtures::RECOVERY_METHOD_URL,
                "signature_algorithm": "Ed25519",
                "signature": "cHJvb2Ytc2lnbmF0dXJl"
            }
        });
        let parsed: RecoverySessionProofSubmitRequestBody =
            serde_json::from_value(value.clone()).expect("closed submit body");
        assert_eq!(parsed.proof.proof_kind(), RecoveryProofKind::RecoveryUnlock);
        parsed.proof.validate_shape().expect("valid proof");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown["proof"]
            .as_object_mut()
            .unwrap()
            .insert("seal_ref".to_owned(), json!("x"));
        assert!(serde_json::from_value::<RecoverySessionProofSubmitRequestBody>(unknown).is_err());

        for (field, legacy_value) in [
            ("recovery_secret_ref", json!("recovery-key-fixture")),
            ("unlock_commitment", json!(digest(0xef))),
        ] {
            let mut legacy = value.clone();
            legacy["proof"]
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), legacy_value);
            assert!(
                serde_json::from_value::<RecoverySessionProofSubmitRequestBody>(legacy).is_err()
            );
        }
    }

    #[test]
    fn device_quorum_proof_requires_two_signatures() {
        let proof: RecoverySessionProof = serde_json::from_value(json!({
            "kind": "device_quorum",
            "challenge": CHALLENGE,
            "threshold": 2,
            "signatures": [
                {
                    "device_id": DEVICE_ID,
                    "verification_method": fixtures::RECOVERY_METHOD_URL,
                    "signature_algorithm": "Ed25519",
                    "signature": "cXVvcnVtLW9uZQ"
                },
                {
                    "device_id": "ak:device:0198ff00-0000-7000-8000-00000000000d",
                    "verification_method": fixtures::RECOVERY_METHOD_URL,
                    "signature_algorithm": "Ed25519",
                    "signature": "cXVvcnVtLXR3bw"
                }
            ]
        }))
        .expect("quorum proof");
        proof.validate_shape().expect("two signatures satisfy");

        let single: RecoverySessionProof = serde_json::from_value(json!({
            "kind": "device_quorum",
            "challenge": CHALLENGE,
            "threshold": 2,
            "signatures": [{
                "device_id": DEVICE_ID,
                "verification_method": fixtures::RECOVERY_METHOD_URL,
                "signature_algorithm": "Ed25519",
                "signature": "cXVvcnVtLW9uZQ"
            }]
        }))
        .expect("shape parses");
        assert!(single.validate_shape().is_err());
    }

    fn generic_transcript_value() -> serde_json::Value {
        json!({
            "schema": "ak.identity.recovery_proof.v1",
            "kind": "recovery_unlock",
            "request_id": REQUEST_ID,
            "session_grant_id": session_grant_id(),
            "session_grant_cnf_jkt": CNF_JKT,
            "account_id": fixtures::account_id(),
            "requesting_device_id": DEVICE_ID,
            "requesting_device_public_key_did": DEVICE_KEY,
            "trust_domain": fixtures::TRUST_DOMAIN,
            "policy_id": fixtures::POLICY_ID,
            "policy_version": 1,
            "recovery_session_id": SESSION_ID,
            "identity_model": "pcr_policy",
            "model_generation_ref": 4,
            "publication_authority_context_digest": digest(0xab),
            "challenge": CHALLENGE,
            "expires_at": "2026-08-01T00:15:00.000Z",
            "created_at": "2026-08-01T00:00:00.000Z",
            "proof_body": {
                "kind": "recovery_unlock",
                "challenge": CHALLENGE,
                "verification_method": fixtures::RECOVERY_METHOD_URL,
                "signature_algorithm": "Ed25519"
            }
        })
    }

    #[test]
    fn generic_transcript_round_trips_and_binds_its_branch() {
        let value = generic_transcript_value();
        let parsed: GenericRecoveryTranscript =
            serde_json::from_value(value.clone()).expect("closed transcript");
        parsed.validate_shape().expect("valid transcript");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut mismatched = value.clone();
        mismatched["kind"] = json!("trusted_recovery_service");
        let parsed: GenericRecoveryTranscript =
            serde_json::from_value(mismatched).expect("shape parses");
        assert!(parsed.validate_shape().is_err());

        let mut unknown = value.clone();
        unknown["proof_body"]
            .as_object_mut()
            .unwrap()
            .insert("signature".to_owned(), json!("x"));
        assert!(serde_json::from_value::<GenericRecoveryTranscript>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("proof_body");
        assert!(serde_json::from_value::<GenericRecoveryTranscript>(missing).is_err());
    }

    #[test]
    fn did_root_transcript_round_trips_and_is_closed() {
        let mut value = generic_transcript_value();
        value.as_object_mut().unwrap().remove("proof_body");
        value["kind"] = json!("did_root");
        let parsed: DidRootRecoveryTranscript =
            serde_json::from_value(value.clone()).expect("closed transcript");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("proof_body".to_owned(), json!({}));
        assert!(serde_json::from_value::<DidRootRecoveryTranscript>(unknown).is_err());

        let mut missing = value;
        missing
            .as_object_mut()
            .unwrap()
            .remove("model_generation_ref");
        assert!(serde_json::from_value::<DidRootRecoveryTranscript>(missing).is_err());
    }

    #[test]
    fn proof_submit_outcome_round_trips_and_is_closed() {
        let value = json!({"recovery_session_id": SESSION_ID});
        let parsed: RecoverySessionProofSubmitOutcome =
            serde_json::from_value(value.clone()).expect("closed outcome");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        assert!(
            serde_json::from_value::<RecoverySessionProofSubmitOutcome>(
                json!({"state": "verified"})
            )
            .is_err()
        );
    }
}
