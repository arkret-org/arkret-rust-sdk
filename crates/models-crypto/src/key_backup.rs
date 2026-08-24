//! Key backup envelope, recovery policy, and recovery receipt wire models.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::{
    decode_multibase_base58btc, decode_multicodec_varint, encode_multibase_base58btc,
};
use arkret_wire::{
    AttestationId, AuthoritySetIssuer, AuthoritySetIssuerRole, AuthorizationLease, BackupId,
    BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupSeriesId, Base64UrlString,
    CbaProofBundle, ControlProposalAck, Cursor, DeviceId, DidCoreId, DidUrl, EpochRange, Event,
    EventId, EventInitialSubmission, EventKind, HPKE_SUITE_X25519_CHACHA20POLY1305_V1, HPKE_SUITES,
    Hash, HistoryEffectiveScope, LeaseBasisRef, NonEmptyString, PayloadProof, PolicyId,
    ProofContextId, RECOVERY_POLICY_SIGNATURE_TYPE, RealmId, ReasonCode, ReceiptId,
    RecoverySessionId, Result, SchemaId, ServiceOperationId, TransactionId, TrustDomainId,
    WireError, XExtensionMap,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::artifacts_keys::{
    KeyBackupUnlockProof, RecoveryIdentityModel, RecoveryPolicyRef, ShareShareCommitment,
};

fn is_false(value: &bool) -> bool {
    !*value
}

/// Backup class for key backup envelopes (key-management.md §7.1).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupKind {
    SecretStorage,
    MlsHistory,
}

impl BackupKind {
    /// Canonical snake_case wire token used by `ak.schema.key_backup.v1`.
    pub const fn as_str(self) -> &'static str {
        match self {
            BackupKind::SecretStorage => "secret_storage",
            BackupKind::MlsHistory => "mls_history",
        }
    }

    /// HKDF info string per key-management.md §7.2.
    pub fn hkdf_info(self, subdomain: &str) -> String {
        let class = match self {
            BackupKind::SecretStorage => "secret_storage",
            BackupKind::MlsHistory => "mls_history",
        };
        format!("arkret-key-backup/{class}/{subdomain}/v1")
    }
}

/// Parse a `ak.schema.key_backup.v1` backup_kind wire token.
impl TryFrom<&str> for BackupKind {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "secret_storage" => Ok(Self::SecretStorage),
            "mls_history" => Ok(Self::MlsHistory),
            other => Err(format!("unsupported backup_kind {other}")),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupsListQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub series_id: Option<BackupSeriesId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_kind: Option<BackupKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysBackupsList {
    #[serde(default)]
    pub backups: Vec<KeyBackupSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
}

/// Conformance-vector id of the key-backup unlock-proof KAT
/// (`zh/conformance/conformance-vectors.md`).
pub const VECTOR_ID_KEY_BACKUP_UNLOCK_PROOF: &str = "ak.vector.key_backup.unlock_proof.v1";

/// Signing context of the canonical delete-intent transcript
/// (`key-management.md` §7.8.1). `high-risk-authority-proof.schema.json` is one
/// wire leaf shared by several consumers, so the leaf itself owns no context:
/// this row is registered with
/// `consumer_operation = ak.self.keys.backups.resource.delete`, and reusing
/// another consumer's context MUST fail closed even when the JWS verifies.
pub const KEY_BACKUP_DELETE_TRANSCRIPT_CONTEXT: &str = ProofContextId::KEY_BACKUP_DELETE_PROOF_V1;

/// High-risk authority proof over the canonical delete-intent transcript
/// (`high-risk-authority-proof.schema.json`).
///
/// Exactly three closed branches, discriminated by `kind`. An ordinary current
/// device session proof is deliberately **not** a fourth branch: a caller
/// holding only one is limited to envelopes that are already expired and outside
/// the active series (`key-management.md` §7.8). The previous open
/// `serde(untagged)` shape — which also carried a `Development` variant whose
/// "proof" was an unauthenticated string — is judged dead by the same section.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyBackupDeleteProof {
    /// Principal-control-key proof. The proof's `verification_method` MUST be a
    /// principal-grade DID control method whose controller DID is byte-identical
    /// to the transcript's `principal_id`, and that key MUST be a currently
    /// accepted principal control key at `created_at`. Device, service and
    /// retired keys are rejected.
    PrincipalSigning { proof: PayloadProof },
    /// Device-quorum proof. The wire shape only floors the quorum
    /// (`threshold >= 2`); the receiver verifies every signature over the same
    /// canonical transcript, deduplicates by `device_id`, and requires the
    /// deduplicated valid count to reach `threshold` — which MUST itself equal
    /// the principal's currently accepted recovery-policy `k`.
    DeviceQuorum {
        threshold: u32,
        signatures: Vec<KeyBackupDeleteQuorumSignature>,
    },
    /// Trusted recovery service proof. The service is never a sufficient factor
    /// on its own: the referenced recovery session MUST be unexpired, unconsumed
    /// and established by principal signing, recovery unlock or device quorum.
    TrustedRecoveryService {
        service_id: DidCoreId,
        recovery_session_id: RecoverySessionId,
        #[serde(skip_serializing_if = "Option::is_none")]
        attestation_ref: Option<AttestationId>,
        proof: PayloadProof,
    },
}

/// One device signature inside a [`KeyBackupDeleteProof::DeviceQuorum`].
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupDeleteQuorumSignature {
    pub device_id: DeviceId,
    /// Its `verification_method` MUST resolve, at `created_at`, to an authorized
    /// non-revoked key of exactly this `device_id` under the transcript's
    /// principal.
    pub proof: PayloadProof,
}

/// Request body of `ak.self.keys.backups.command.issue_delete_challenge`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsIssueDeleteChallengeRequestBody {
    /// While a challenge for the same `(principal_id, backup_id, request_id)` is
    /// still valid the service returns that same challenge; a different
    /// `request_id` mints a new one.
    pub request_id: Base64UrlString,
}

/// The server-issued, durable, single-use delete challenge
/// (`keys-operations.schema.json#/$defs/keys_backups_delete_challenge`).
///
/// Every field is materialized by the service — §7.8.1 forbids accepting a
/// caller-minted nonce — and every one of them is embedded verbatim in the
/// canonical transcript, so replay, expiry, a different path, a different
/// audience or a different service all fail closed at signature verification as
/// well as at challenge lookup.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsDeleteChallenge {
    pub challenge_id: Base64UrlString,
    pub challenge: Base64UrlString,
    /// Distinct from `challenge` so the transcript binds two independent
    /// freshness values.
    pub nonce: Base64UrlString,
    pub operation: String,
    pub principal_id: DidCoreId,
    pub backup_id: BackupId,
    /// The service base origin this challenge is valid against.
    pub audience: NonEmptyString,
    pub service_id: DidCoreId,
    pub request_id: Base64UrlString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl KeysBackupsDeleteChallenge {
    /// The single canonical delete-intent transcript every proof branch signs —
    /// including every individual signature of a device quorum.
    ///
    /// `reason` is encoded as JSON `null` when absent rather than omitted: §7.8.1
    /// fixes the key set, so an omitted key would make an absent reason and a
    /// tampered-away reason produce different bytes on different implementations.
    pub fn delete_intent_transcript(&self, reason: Option<&str>) -> Value {
        json!({
            "context": KEY_BACKUP_DELETE_TRANSCRIPT_CONTEXT,
            "operation": ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_DELETE,
            "request_id": self.request_id.as_str(),
            "principal_id": self.principal_id.as_str(),
            "backup_id": self.backup_id.as_str(),
            "reason": reason,
            "challenge_id": self.challenge_id.as_str(),
            "challenge": self.challenge.as_str(),
            "nonce": self.nonce.as_str(),
            "audience": self.audience.as_str(),
            "service_id": self.service_id.as_str(),
            "issued_at": arkret_canonical::canonical::format_timestamp_canonical(self.issued_at),
            "expires_at": arkret_canonical::canonical::format_timestamp_canonical(self.expires_at),
        })
    }

    /// `payload_digest` of the canonical delete-intent transcript.
    pub fn delete_intent_digest(&self, reason: Option<&str>) -> Result<Hash> {
        let bytes = arkret_canonical::canonical::canonical_json_bytes(
            &self.delete_intent_transcript(reason),
        )
        .map_err(|error| WireError::Protocol(error.to_string()))?;
        Hash::new(arkret_canonical::canonical::sha256_digest(bytes))
            .map_err(|error| WireError::Protocol(error.to_string()))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsDeleteRequestBody {
    pub request_id: Base64UrlString,
    /// Exact echo of the server-issued `challenge_id` being consumed.
    pub challenge_id: Base64UrlString,
    pub proof: KeyBackupDeleteProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<NonEmptyString>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysBackupsDeleteOutcome {
    pub deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<BackupId>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupSeriesEraseStatus {
    Complete,
    Partial,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupSeriesEraseResultStatus {
    Erased,
    Pending,
    FailedRetryable,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSeriesEraseRequestBody {
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub erase_confirmation_digest: Hash,
    pub series: Vec<BackupRotationBinding>,
    pub authorization_lease: AuthorizationLease,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cba_proof_bundles: Vec<CbaProofBundle>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSeriesEraseResult {
    pub backup_kind: BackupRotationKind,
    pub previous_series_id: BackupSeriesId,
    pub new_series_id: BackupSeriesId,
    pub status: BackupSeriesEraseResultStatus,
    pub erased_backups: Vec<BackupObjectRef>,
    pub remaining_backups: Vec<BackupObjectRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCode>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSeriesEraseConfirmation {
    pub schema: SchemaId,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub series: Vec<BackupRotationBinding>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSeriesEraseOutcome {
    pub transaction_id: TransactionId,
    pub request_digest: Hash,
    pub status: BackupSeriesEraseStatus,
    pub series_results: Vec<BackupSeriesEraseResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<BackupSeriesEraseConfirmation>,
}

fn validate_backup_object_refs(refs: &[BackupObjectRef], label: &str) -> Result<()> {
    if refs.len() > 512 {
        return Err(WireError::Protocol(format!(
            "{label} exceeds 512 backup object references"
        )));
    }
    let mut backup_ids = BTreeSet::new();
    if refs
        .iter()
        .any(|object| !backup_ids.insert(object.backup_id.clone()))
    {
        return Err(WireError::Protocol(format!(
            "{label} backup object references must be unique"
        )));
    }
    Ok(())
}

fn validate_canonical_backup_object_refs(refs: &[BackupObjectRef], label: &str) -> Result<()> {
    validate_backup_object_refs(refs, label)?;
    if refs
        .windows(2)
        .any(|pair| pair[0].backup_id.as_str() >= pair[1].backup_id.as_str())
    {
        return Err(WireError::Protocol(format!(
            "{label} must be canonical backup-id sorted"
        )));
    }
    Ok(())
}

fn validate_rotation_bindings(series: &[BackupRotationBinding]) -> Result<()> {
    let expected_kinds = [
        BackupRotationKind::SecretStorage,
        BackupRotationKind::MlsHistory,
    ];
    if series.len() != expected_kinds.len()
        || series
            .iter()
            .map(|binding| binding.backup_kind)
            .ne(expected_kinds)
    {
        return Err(WireError::Protocol(
            "backup-series erase requires exactly secret_storage then mls_history".to_owned(),
        ));
    }
    for binding in series {
        if binding.previous_series_id == binding.new_series_id
            || binding.new_backups.is_empty()
            || binding.old_backups.is_empty()
        {
            return Err(WireError::Protocol(
                "backup-series erase bindings require distinct series and non-empty backup sets"
                    .to_owned(),
            ));
        }
        validate_backup_object_refs(&binding.new_backups, "new_backups")?;
        validate_backup_object_refs(&binding.old_backups, "old_backups")?;
    }
    Ok(())
}

impl BackupSeriesEraseRequestBody {
    pub fn validate_structural(&self) -> Result<()> {
        validate_rotation_bindings(&self.series)?;
        if self.erase_confirmation_digest
            != arkret_wire::security_rotation_erase_confirmation_digest(
                &self.transaction_id,
                &self.series,
            )?
        {
            return Err(WireError::Protocol(
                "backup-series erase confirmation digest changed its fixed projection".to_owned(),
            ));
        }
        self.authorization_lease.validate_structural()?;
        if self.authorization_lease.action
            != arkret_wire::CapabilityActionId::SELF_KEYS_BACKUP_SERIES_COMMAND_ERASE
        {
            return Err(WireError::Protocol(
                "backup-series erase requires the exact erase authorization action".to_owned(),
            ));
        }
        if self.cba_proof_bundles.len() > 64 {
            return Err(WireError::Protocol(
                "backup-series erase exceeds 64 CBA proof bundles".to_owned(),
            ));
        }
        for bundle in &self.cba_proof_bundles {
            bundle.validate_structural()?;
        }
        Ok(())
    }
}

impl BackupSeriesEraseConfirmation {
    pub fn validate_structural(&self) -> Result<()> {
        if self.schema != SchemaId::BackupSeriesEraseConfirmationV1 {
            return Err(WireError::Protocol(
                "backup-series erase confirmation schema is invalid".to_owned(),
            ));
        }
        validate_rotation_bindings(&self.series)
    }
}

impl BackupSeriesEraseOutcome {
    pub fn validate_structural(&self) -> Result<()> {
        let expected_kinds = [
            BackupRotationKind::SecretStorage,
            BackupRotationKind::MlsHistory,
        ];
        if self.series_results.len() != expected_kinds.len()
            || self
                .series_results
                .iter()
                .map(|result| result.backup_kind)
                .ne(expected_kinds)
        {
            return Err(WireError::Protocol(
                "backup-series erase outcome requires exactly secret_storage then mls_history"
                    .to_owned(),
            ));
        }

        let mut has_incomplete = false;
        for result in &self.series_results {
            if result.previous_series_id == result.new_series_id {
                return Err(WireError::Protocol(
                    "backup-series erase result must change the active series".to_owned(),
                ));
            }
            validate_canonical_backup_object_refs(&result.erased_backups, "erased_backups")?;
            validate_canonical_backup_object_refs(&result.remaining_backups, "remaining_backups")?;
            match result.status {
                BackupSeriesEraseResultStatus::Erased if !result.remaining_backups.is_empty() => {
                    return Err(WireError::Protocol(
                        "erased backup series cannot retain remaining backups".to_owned(),
                    ));
                }
                BackupSeriesEraseResultStatus::Erased if result.reason_code.is_some() => {
                    return Err(WireError::Protocol(
                        "erased backup series cannot carry a reason code".to_owned(),
                    ));
                }
                BackupSeriesEraseResultStatus::Pending if result.reason_code.is_some() => {
                    return Err(WireError::Protocol(
                        "pending backup series cannot carry a reason code".to_owned(),
                    ));
                }
                BackupSeriesEraseResultStatus::FailedRetryable if result.reason_code.is_none() => {
                    return Err(WireError::Protocol(
                        "failed-retryable backup series requires a reason code".to_owned(),
                    ));
                }
                BackupSeriesEraseResultStatus::Pending
                | BackupSeriesEraseResultStatus::FailedRetryable => {
                    has_incomplete = true;
                }
                BackupSeriesEraseResultStatus::Erased => {}
            }
        }
        if (self.status == BackupSeriesEraseStatus::Partial) != has_incomplete {
            return Err(WireError::Protocol(
                "backup-series erase status does not match its per-series states".to_owned(),
            ));
        }
        match (self.status, self.confirmation.as_ref()) {
            (BackupSeriesEraseStatus::Complete, Some(confirmation)) => {
                confirmation.validate_structural()?;
            }
            (BackupSeriesEraseStatus::Partial, None) => {}
            _ => {
                return Err(WireError::Protocol(
                    "only a complete erase outcome carries one confirmation".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn validate_for_request(&self, request: &BackupSeriesEraseRequestBody) -> Result<()> {
        self.validate_structural()?;
        request.validate_structural()?;
        let request_digest = arkret_canonical::canonical::canonical_sha256(request)?;
        if self.transaction_id != request.transaction_id
            || self.request_digest.as_str() != request_digest
            || self
                .series_results
                .iter()
                .zip(&request.series)
                .any(|(result, binding)| {
                    let mut reported_backups = result.erased_backups.clone();
                    reported_backups.extend(result.remaining_backups.clone());
                    reported_backups.sort_by(|left, right| {
                        left.backup_id.as_str().cmp(right.backup_id.as_str())
                    });
                    let mut planned_backups = binding.old_backups.clone();
                    planned_backups.sort_by(|left, right| {
                        left.backup_id.as_str().cmp(right.backup_id.as_str())
                    });
                    result.backup_kind != binding.backup_kind
                        || result.previous_series_id != binding.previous_series_id
                        || result.new_series_id != binding.new_series_id
                        || reported_backups != planned_backups
                })
        {
            return Err(WireError::Protocol(
                "backup-series erase outcome changed the transaction, request, or target binding"
                    .to_owned(),
            ));
        }
        if let Some(confirmation) = &self.confirmation {
            if confirmation.transaction_id != request.transaction_id
                || confirmation.transaction_request_digest != request.transaction_request_digest
                || confirmation.prepared_plan_digest != request.prepared_plan_digest
                || confirmation.series != request.series
            {
                return Err(WireError::Protocol(
                    "backup-series erase confirmation changed the reserved transaction plan"
                        .to_owned(),
                ));
            }
            if request.erase_confirmation_digest
                != arkret_wire::security_rotation_erase_confirmation_digest(
                    &confirmation.transaction_id,
                    &confirmation.series,
                )?
            {
                return Err(WireError::Protocol(
                    "backup-series erase confirmation does not match its reserved digest"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysBackupsUnlockRequestBody {
    pub proof: KeyBackupUnlockProof,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupPutStatus {
    Accepted,
    Duplicate,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysBackupsReplaceOutcome {
    pub status: KeyBackupPutStatus,
    pub backup_id: BackupId,
    pub ciphertext_digest: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupSummary {
    pub backup_id: BackupId,
    pub actor_id: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub backup_kind: BackupKind,
    pub backup_version: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    pub ciphertext_digest: String,
    /// Non-secret recipient metadata so the client can categorize a backup
    /// (recovery_public_key vs passphrase_kdf vs secret_storage_key) without
    /// downloading the ciphertext. The aead/kdf material is withheld here.
    pub encryption: KeyBackupSummaryEncryption,
    pub series_id: BackupSeriesId,
    pub series_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_policy_ref: Option<RecoveryPolicyRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contents: Vec<KeyBackupContentItem>,
}

/// The list-summary projection of [`KeyBackupEncryption`]: only the non-secret
/// recipient fields survive into `ak.self.keys.backups.list` responses.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupSummaryEncryption {
    pub recipient_method: KeyBackupRecipientMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_key_ref: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackup {
    pub backup_id: BackupId,
    pub actor_id: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub backup_kind: BackupKind,
    #[serde(default, skip_serializing_if = "is_false")]
    pub mixed_secret_storage: bool,
    pub backup_version: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    pub encryption: KeyBackupEncryption,
    pub domain_separation: KeyBackupDomainSeparation,
    pub contents: Vec<KeyBackupContentItem>,
    pub ciphertext: String,
    pub ciphertext_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_data: Option<KeyBackupAuthData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention: Option<KeyBackupRetention>,
    /// Key-backup hardening (B-C, spec head 37ce729) — series chain identifier.
    /// Every envelope in a backup chain shares the same `series_id`; the chain
    /// is ordered by `series_seq`. Genesis vs successor are distinguished by
    /// `series_seq == 0` (genesis) vs `series_seq > 0` (successor with
    /// `supersedes` + `supersedes_digest` REQUIRED).
    pub series_id: BackupSeriesId,
    /// Key-backup hardening — monotonically increasing chain sequence number.
    /// `0` for the genesis envelope; reducer MUST reject non-monotonic
    /// successors with `series_seq_not_monotonic`.
    pub series_seq: u64,
    /// Key-backup hardening — `backup_id` of the immediate predecessor in
    /// the chain. REQUIRED on every successor (`series_seq >= 1`); MUST be
    /// absent on genesis. Reducer MUST reject mismatches with
    /// `series_chain_broken` or `series_predecessor_not_found`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<BackupId>,
    /// Key-backup hardening — canonical SHA-256 of the predecessor envelope,
    /// excluding `auth_data.signature`, mixed into the signing transcript on
    /// successor envelopes. REQUIRED whenever `supersedes` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes_digest: Option<String>,
    /// Key-backup hardening — opaque reference to the originating-key
    /// frontier the backup encrypts (e.g. recovery key frontier, MLS group
    /// epoch frontier). Reducer rejects stale frontiers with
    /// `backup_frontier_stale`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<serde_json::Value>))
    )]
    pub frontier_ref: Option<KeyBackupFrontierRef>,
    /// Recovery policy tuple under which this envelope was produced. Required
    /// by the MLS-history profile and when using a recovery public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_policy_ref: Option<RecoveryPolicyRef>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

/// Signing identity for a key-backup envelope before its detached signature is
/// available. The signature is deliberately absent from this type, so an
/// unsigned envelope cannot be mistaken for an uploadable [`KeyBackup`].
#[derive(Clone, Debug)]
pub struct UnsignedKeyBackupAuthData {
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub device_authorize_event_id: EventId,
    pub extra: XExtensionMap,
}

impl UnsignedKeyBackupAuthData {
    pub fn new(
        device_id: DeviceId,
        verification_method: DidUrl,
        signature_algorithm: KeyBackupSignatureAlgorithm,
        device_authorize_event_id: EventId,
    ) -> Result<Self> {
        validate_key_backup_signature_algorithm(signature_algorithm)?;
        Ok(Self {
            device_id,
            verification_method,
            signature_algorithm,
            device_authorize_event_id,
            extra: XExtensionMap::default(),
        })
    }
}

/// Validated key-backup authoring state whose signature transcript is stable,
/// but which cannot be serialized as a signed wire envelope yet.
#[derive(Clone, Debug)]
pub struct UnsignedKeyBackup {
    envelope: KeyBackup,
    auth_data: UnsignedKeyBackupAuthData,
}

impl UnsignedKeyBackup {
    /// Close the unsigned authoring boundary and validate every cross-field
    /// invariant that participates in the signature or AEAD domain.
    pub fn new(envelope: KeyBackup, auth_data: UnsignedKeyBackupAuthData) -> Result<Self> {
        if envelope.auth_data.is_some() {
            return Err(WireError::Protocol(
                "unsigned key backup must not already carry auth_data".to_owned(),
            ));
        }
        envelope.validate_envelope_fields()?;
        validate_key_backup_signature_algorithm(auth_data.signature_algorithm)?;
        if envelope
            .device_id
            .as_ref()
            .is_some_and(|device_id| device_id != &auth_data.device_id)
        {
            return Err(WireError::Protocol(
                "key backup auth_data.device_id does not match envelope device_id".to_owned(),
            ));
        }
        Ok(Self {
            envelope,
            auth_data,
        })
    }

    pub fn envelope(&self) -> &KeyBackup {
        &self.envelope
    }

    /// Canonical bytes signed by the author. These bytes include all auth
    /// metadata except the not-yet-existing signature.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        let unsigned = self.unsigned_wire_value()?;
        Ok(arkret_canonical::canonical_json_bytes(&unsigned)?)
    }

    /// Attach the detached signature and cross the only boundary that produces
    /// an uploadable signed [`KeyBackup`].
    pub fn attach_signature(mut self, signature: Base64UrlString) -> Result<KeyBackup> {
        self.envelope.auth_data = Some(KeyBackupAuthData {
            device_id: self.auth_data.device_id,
            verification_method: self.auth_data.verification_method,
            signature_algorithm: self.auth_data.signature_algorithm,
            signature,
            device_authorize_event_id: self.auth_data.device_authorize_event_id,
            extra: self.auth_data.extra,
        });
        self.envelope.validate()?;
        Ok(self.envelope)
    }

    fn unsigned_wire_value(&self) -> Result<Value> {
        let mut value = serde_json::to_value(&self.envelope).map_err(|error| {
            WireError::Protocol(format!("failed to serialize unsigned key backup: {error}"))
        })?;
        let object = value.as_object_mut().ok_or_else(|| {
            WireError::Protocol("key backup envelope must serialize as an object".to_owned())
        })?;
        let mut auth_data = serde_json::Map::new();
        auth_data.insert(
            "device_id".to_owned(),
            serde_json::to_value(&self.auth_data.device_id)?,
        );
        auth_data.insert(
            "verification_method".to_owned(),
            serde_json::to_value(&self.auth_data.verification_method)?,
        );
        auth_data.insert(
            "signature_algorithm".to_owned(),
            serde_json::to_value(self.auth_data.signature_algorithm)?,
        );
        auth_data.insert(
            "device_authorize_event_id".to_owned(),
            serde_json::to_value(&self.auth_data.device_authorize_event_id)?,
        );
        for (key, value) in self.auth_data.extra.iter() {
            auth_data.insert(key.clone(), value.clone());
        }
        object.insert("auth_data".to_owned(), Value::Object(auth_data));
        Ok(value)
    }
}

impl KeyBackup {
    pub const SCHEMA: &'static str = SchemaId::KEY_BACKUP_V1;

    /// Validate a fully signed key-backup envelope at the typed wire boundary.
    pub fn validate(&self) -> Result<()> {
        self.validate_envelope_fields()?;
        let auth_data = self.auth_data.as_ref().ok_or_else(|| {
            WireError::Protocol("signed key backup auth_data is required".to_owned())
        })?;
        validate_key_backup_signature_algorithm(auth_data.signature_algorithm)?;
        if self
            .device_id
            .as_ref()
            .is_some_and(|device_id| device_id != &auth_data.device_id)
        {
            return Err(WireError::Protocol(
                "key backup auth_data.device_id does not match envelope device_id".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate the signature-independent envelope fields. Authoring code
    /// reaches this through [`UnsignedKeyBackup::new`]; receiver code should
    /// normally call [`Self::validate`] so auth metadata is checked too.
    pub fn validate_envelope_fields(&self) -> Result<()> {
        self.encryption.validate()?;
        if self
            .backup_version
            .strip_prefix("kb_")
            .is_none_or(|suffix| {
                suffix.is_empty()
                    || !suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            })
        {
            return Err(WireError::Protocol(
                "key backup backup_version must match ^kb_[A-Za-z0-9_-]+$".to_owned(),
            ));
        }
        if self.contents.is_empty() {
            return Err(WireError::Protocol(
                "key backup contents must not be empty".to_owned(),
            ));
        }
        match self.backup_kind {
            BackupKind::SecretStorage => {
                for item in &self.contents {
                    let Some(index) = item.secret_storage() else {
                        return Err(WireError::Protocol(
                            "secret_storage key backup must not index history secret ranges"
                                .to_owned(),
                        ));
                    };
                    if index.secret_version == Some(0) {
                        return Err(WireError::Protocol(
                            "key backup content secret_version must be at least 1".to_owned(),
                        ));
                    }
                }
            }
            BackupKind::MlsHistory => {
                let [KeyBackupContentItem::HistorySecretRanges(index)] = self.contents.as_slice()
                else {
                    return Err(WireError::Protocol(
                        "mls_history key backup contents must be exactly one history_secret_ranges index"
                            .to_owned(),
                    ));
                };
                index.validate()?;
            }
        }
        if self.ciphertext.trim().is_empty() {
            return Err(WireError::Protocol(
                "key backup ciphertext must not be empty".to_owned(),
            ));
        }
        let ciphertext = arkret_canonical::base64url_decode(&self.ciphertext).map_err(|error| {
            WireError::Protocol(format!("invalid key backup ciphertext base64url: {error}"))
        })?;
        let ciphertext_digest = Hash::new(self.ciphertext_digest.clone()).map_err(|error| {
            WireError::Protocol(format!("invalid key backup ciphertext_digest: {error}"))
        })?;
        let digest_suite = self
            .ciphertext_digest
            .split_once(':')
            .and_then(|(suite, _)| arkret_canonical::digest_suite(suite).ok())
            .ok_or_else(|| {
                WireError::Protocol("unsupported key backup ciphertext digest suite".to_owned())
            })?;
        if arkret_canonical::digest(digest_suite, &ciphertext) != ciphertext_digest.as_str() {
            return Err(WireError::Protocol(
                "key backup ciphertext_digest does not match ciphertext".to_owned(),
            ));
        }
        if let Some(plaintext_commitment) = &self.plaintext_commitment {
            Hash::new(plaintext_commitment.clone()).map_err(|error| {
                WireError::Protocol(format!("invalid key backup plaintext_commitment: {error}"))
            })?;
        }

        match self.series_seq {
            0 if self.supersedes.is_some() || self.supersedes_digest.is_some() => {
                return Err(WireError::Protocol(
                    "key backup genesis forbids supersedes and supersedes_digest".to_owned(),
                ));
            }
            0 => {}
            _ if self.supersedes.is_none() || self.supersedes_digest.is_none() => {
                return Err(WireError::Protocol(
                    "key backup successor requires supersedes and supersedes_digest".to_owned(),
                ));
            }
            _ => {
                if self.supersedes.as_ref() == Some(&self.backup_id) {
                    return Err(WireError::Protocol(
                        "key backup successor cannot supersede itself".to_owned(),
                    ));
                }
                if let Some(supersedes_digest) = &self.supersedes_digest {
                    Hash::new(supersedes_digest.clone()).map_err(|error| {
                        WireError::Protocol(format!(
                            "invalid key backup supersedes_digest: {error}"
                        ))
                    })?;
                }
            }
        }

        if self.encryption.recipient_method == KeyBackupRecipientMethod::RecoveryPublicKey
            && self.recovery_policy_ref.is_none()
        {
            return Err(WireError::Protocol(
                "recovery-public-key key backup requires recovery_policy_ref".to_owned(),
            ));
        }
        if self
            .frontier_ref
            .as_ref()
            .is_some_and(|frontier| frontier.device_generation_ref == 0)
        {
            return Err(WireError::Protocol(
                "key backup device_generation_ref must be positive".to_owned(),
            ));
        }

        self.validate_encryption_profile()?;

        let domain = &self.domain_separation;
        let aad = &domain.aead_aad;
        if domain.subdomain.trim().is_empty()
            || domain.hkdf_info != self.backup_kind.hkdf_info(&domain.subdomain)
        {
            return Err(WireError::Protocol(
                "key backup domain separation mismatch".to_owned(),
            ));
        }
        let device_id = self.device_id.as_ref().map(|device_id| device_id.as_str());
        let item_kinds = self
            .contents
            .iter()
            .map(|item| item.item_kind().to_owned())
            .collect::<Vec<_>>();
        if aad.schema != Self::SCHEMA
            || aad.actor_id != self.actor_id
            || aad.device_id.as_deref() != device_id
            || aad.backup_kind != self.backup_kind
            || aad.backup_version != self.backup_version
            || aad.created_at != self.created_at
            || aad.item_kinds != item_kinds
            || aad.recipient_method != Some(self.encryption.recipient_method)
            || aad.recipient_key_ref != self.encryption.recipient_key_ref
        {
            return Err(WireError::Protocol(
                "key backup authenticated domain metadata mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_encryption_profile(&self) -> Result<()> {
        let encryption = &self.encryption;
        let aead = &encryption.aead;
        match encryption.recipient_method {
            KeyBackupRecipientMethod::PassphraseKdf => {
                if self.backup_kind == BackupKind::MlsHistory {
                    return Err(WireError::Protocol(
                        "passphrase_kdf is valid only for secret_storage backups".to_owned(),
                    ));
                }
                if aead.enc.is_some() {
                    return Err(WireError::Protocol(
                        "passphrase_kdf forbids encryption.aead.enc".to_owned(),
                    ));
                }
                let nonce_salt = aead.nonce_salt.as_ref().ok_or_else(|| {
                    WireError::Protocol(
                        "passphrase_kdf requires encryption.aead.nonce_salt".to_owned(),
                    )
                })?;
                if !(16..=128).contains(&nonce_salt.as_str().len()) {
                    return Err(WireError::Protocol(
                        "passphrase_kdf nonce_salt must contain 16 to 128 base64url characters"
                            .to_owned(),
                    ));
                }
                let key_commitment = encryption.key_commitment.as_ref().ok_or_else(|| {
                    WireError::Protocol("passphrase_kdf requires key_commitment".to_owned())
                })?;
                Hash::new(key_commitment.clone()).map_err(|error| {
                    WireError::Protocol(format!("invalid key backup key_commitment: {error}"))
                })?;
                let kdf = encryption.kdf.as_ref().ok_or_else(|| {
                    WireError::Protocol("passphrase_kdf requires encryption.kdf".to_owned())
                })?;
                if self.mixed_secret_storage
                    && (kdf.name != KeyBackupKdfName::Argon2id
                        || kdf.params.memory_kib.is_none_or(|value| value < 262_144)
                        || kdf.params.iterations.is_none_or(|value| value < 4)
                        || kdf.params.parallelism.is_none_or(|value| value < 1))
                {
                    return Err(WireError::Protocol(
                        "mixed secret-storage backups require the strengthened Argon2id profile"
                            .to_owned(),
                    ));
                }
            }
            KeyBackupRecipientMethod::SecretStorageKey => {
                if !matches!(
                    self.backup_kind,
                    BackupKind::SecretStorage | BackupKind::MlsHistory
                ) {
                    return Err(WireError::Protocol(
                        "secret_storage_key is valid only for secret_storage or mls_history backups"
                            .to_owned(),
                    ));
                }
                if aead.nonce_salt.is_some()
                    || aead.enc.is_some()
                    || encryption.key_commitment.is_some()
                {
                    return Err(WireError::Protocol(
                        "secret_storage_key forbids nonce_salt, enc, and key_commitment".to_owned(),
                    ));
                }
            }
            KeyBackupRecipientMethod::RecoveryPublicKey => {
                if aead.nonce.is_some()
                    || aead.nonce_salt.is_some()
                    || encryption.key_commitment.is_some()
                {
                    return Err(WireError::Protocol(
                        "recovery_public_key forbids nonce, nonce_salt, and key_commitment"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Canonical signature input for a fully formed backup envelope.
    ///
    /// The wire signature covers the entire envelope, including the remaining
    /// `auth_data` metadata, with only `auth_data.signature` omitted.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        self.signature_independent_payload_bytes()
    }

    /// Validate a signed wire envelope and compute its exact signature input
    /// without normalizing optional-field presence through a deserialize /
    /// reserialize round trip.
    pub fn signing_payload_bytes_from_wire(wire: &Value) -> Result<Vec<u8>> {
        let envelope = serde_json::from_value::<Self>(wire.clone()).map_err(|error| {
            WireError::Protocol(format!("invalid signed key backup envelope: {error}"))
        })?;
        envelope.validate()?;
        key_backup_signature_independent_wire_bytes(wire, true)
    }

    /// Canonical envelope bytes with a present signature omitted. This is also
    /// defined for an unsigned envelope and is the stable predecessor-digest
    /// input used by backup-series chaining.
    pub fn signature_independent_payload_bytes(&self) -> Result<Vec<u8>> {
        self.validate_envelope_fields()?;
        let mut unsigned = serde_json::to_value(self).map_err(|error| {
            WireError::Protocol(format!("failed to serialize key backup envelope: {error}"))
        })?;
        if let Some(auth_data) = unsigned.get_mut("auth_data").and_then(Value::as_object_mut) {
            auth_data.remove("signature");
        }
        Ok(arkret_canonical::canonical_json_bytes(&unsigned)?)
    }

    /// Compute a predecessor digest from its exact wire shape after validating
    /// that it is a key-backup envelope.
    pub fn signature_independent_digest_from_wire(wire: &Value) -> Result<String> {
        let envelope = serde_json::from_value::<Self>(wire.clone()).map_err(|error| {
            WireError::Protocol(format!("invalid key backup predecessor envelope: {error}"))
        })?;
        envelope.validate_envelope_fields()?;
        Ok(arkret_canonical::sha256_digest(
            key_backup_signature_independent_wire_bytes(wire, false)?,
        ))
    }

    pub fn summary(&self) -> KeyBackupSummary {
        KeyBackupSummary {
            backup_id: self.backup_id.clone(),
            actor_id: self.actor_id.clone(),
            device_id: self.device_id.clone(),
            backup_kind: self.backup_kind,
            backup_version: self.backup_version.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            expires_at: self.expires_at,
            ciphertext_digest: self.ciphertext_digest.clone(),
            encryption: KeyBackupSummaryEncryption {
                recipient_method: self.encryption.recipient_method,
                recipient_key_ref: self.encryption.recipient_key_ref.clone(),
            },
            series_id: self.series_id.clone(),
            series_seq: self.series_seq,
            recovery_policy_ref: self.recovery_policy_ref.clone(),
            contents: self.contents.clone(),
        }
    }
}

fn key_backup_signature_independent_wire_bytes(
    wire: &Value,
    require_signature: bool,
) -> Result<Vec<u8>> {
    let mut unsigned = wire.clone();
    let auth_data = unsigned.get_mut("auth_data").and_then(Value::as_object_mut);
    if require_signature && auth_data.is_none() {
        return Err(WireError::Protocol(
            "key backup auth_data is required".to_owned(),
        ));
    }
    if let Some(auth_data) = auth_data {
        let signature = auth_data.remove("signature");
        if require_signature && signature.is_none() {
            return Err(WireError::Protocol(
                "key backup auth_data signature is required".to_owned(),
            ));
        }
    }
    Ok(arkret_canonical::canonical_json_bytes(&unsigned)?)
}

fn validate_key_backup_signature_algorithm(algorithm: KeyBackupSignatureAlgorithm) -> Result<()> {
    if algorithm == KeyBackupSignatureAlgorithm::Es256 {
        return Err(WireError::Protocol(
            "key backup auth_data.signature_algorithm must be Ed25519 or ML-DSA-65".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupFrontierRef {
    pub frontier_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<String>,
    pub device_generation_ref: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupRecipientMethod {
    PassphraseKdf,
    RecoveryPublicKey,
    SecretStorageKey,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "KeyBackupEncryptionWire")]
pub struct KeyBackupEncryption {
    pub recipient_method: KeyBackupRecipientMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_key_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf: Option<KeyBackupKdf>,
    pub aead: KeyBackupAead,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_commitment: Option<String>,
    /// Registered active HPKE suite selector (key-backup.schema.json
    /// `encryption.hpke_suite`). Applies only to
    /// `recipient_method=recovery_public_key`; absent denotes the default-MUST
    /// row `ak.hpke_x25519_aead_chacha20poly1305.v1`. Optional/ignored for the
    /// symmetric methods (passphrase_kdf / secret_storage_key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hpke_suite: Option<String>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Deserialize)]
struct KeyBackupEncryptionWire {
    recipient_method: KeyBackupRecipientMethod,
    recipient_key_ref: Option<String>,
    kdf: Option<KeyBackupKdf>,
    aead: KeyBackupAead,
    key_commitment: Option<String>,
    hpke_suite: Option<String>,
    #[serde(default, flatten)]
    extra: XExtensionMap,
}

impl TryFrom<KeyBackupEncryptionWire> for KeyBackupEncryption {
    type Error = String;

    fn try_from(wire: KeyBackupEncryptionWire) -> std::result::Result<Self, Self::Error> {
        let encryption = Self {
            recipient_method: wire.recipient_method,
            recipient_key_ref: wire.recipient_key_ref,
            kdf: wire.kdf,
            aead: wire.aead,
            key_commitment: wire.key_commitment,
            hpke_suite: wire.hpke_suite,
            extra: wire.extra,
        };
        // Fail closed at parse time: a wire envelope whose recipient_method /
        // hpke_suite / per-method field set violates key-backup.schema.json's
        // `encryption.allOf[].if/then` conditions never materialises into a typed
        // value, so downstream code cannot operate on an illegal combination.
        encryption.validate().map_err(|error| error.to_string())?;
        Ok(encryption)
    }
}

impl KeyBackupEncryption {
    /// Validate the `recipient_method` / `hpke_suite` / per-method field-set
    /// conditional constraints from `key-backup.schema.json`
    /// (`properties.encryption.allOf[].if/then`), and enforce that a present
    /// `hpke_suite` names an `active` row of the embedded
    /// `hpke-suite-registry.json` (fail-closed `unsupported_hpke_suite`).
    ///
    /// Runs automatically on deserialization via the `KeyBackupEncryptionWire`
    /// `try_from`; constructors that assemble the struct directly SHOULD call it
    /// before signing / submitting an envelope.
    pub fn validate(&self) -> Result<()> {
        match self.recipient_method {
            KeyBackupRecipientMethod::PassphraseKdf => {
                // `if recipient_method==passphrase_kdf then required kdf; aead
                // requires nonce + nonce_salt`.
                let Some(kdf) = self.kdf.as_ref() else {
                    return Err(WireError::Protocol(
                        "key backup encryption: passphrase_kdf requires `kdf`".to_owned(),
                    ));
                };
                kdf.validate().map_err(WireError::Protocol)?;
                if self.aead.nonce.is_none() {
                    return Err(WireError::Protocol(
                        "key backup encryption: passphrase_kdf requires `aead.nonce`".to_owned(),
                    ));
                }
                if self.aead.nonce_salt.is_none() {
                    return Err(WireError::Protocol(
                        "key backup encryption: passphrase_kdf requires `aead.nonce_salt`"
                            .to_owned(),
                    ));
                }
                // hpke_suite applies only to recovery_public_key.
                if self.hpke_suite.is_some() {
                    return Err(WireError::Protocol(
                        "key backup encryption: hpke_suite applies only to recovery_public_key"
                            .to_owned(),
                    ));
                }
            }
            KeyBackupRecipientMethod::SecretStorageKey => {
                // `then not kdf; required recipient_key_ref; aead requires nonce`.
                if self.kdf.is_some() {
                    return Err(WireError::Protocol(
                        "key backup encryption: secret_storage_key forbids `kdf`".to_owned(),
                    ));
                }
                if self.recipient_key_ref.as_deref().is_none_or(str::is_empty) {
                    return Err(WireError::Protocol(
                        "key backup encryption: secret_storage_key requires `recipient_key_ref`"
                            .to_owned(),
                    ));
                }
                if self.aead.nonce.is_none() {
                    return Err(WireError::Protocol(
                        "key backup encryption: secret_storage_key requires `aead.nonce`"
                            .to_owned(),
                    ));
                }
                if self.hpke_suite.is_some() {
                    return Err(WireError::Protocol(
                        "key backup encryption: hpke_suite applies only to recovery_public_key"
                            .to_owned(),
                    ));
                }
            }
            KeyBackupRecipientMethod::RecoveryPublicKey => {
                // `then not kdf; required recipient_key_ref; aead requires enc`.
                if self.kdf.is_some() {
                    return Err(WireError::Protocol(
                        "key backup encryption: recovery_public_key forbids `kdf`".to_owned(),
                    ));
                }
                if self.recipient_key_ref.as_deref().is_none_or(str::is_empty) {
                    return Err(WireError::Protocol(
                        "key backup encryption: recovery_public_key requires `recipient_key_ref`"
                            .to_owned(),
                    ));
                }
                if self.aead.enc.is_none() {
                    return Err(WireError::Protocol(
                        "key backup encryption: recovery_public_key requires `aead.enc`".to_owned(),
                    ));
                }
                // An explicit hpke_suite (when present) MUST be an active
                // registry row, and the AEAD MUST equal the selected suite's
                // aead. Absent selector denotes HPKE_SUITE_X25519_CHACHA20POLY1305_V1.
                let suite_id = self
                    .hpke_suite
                    .as_deref()
                    .unwrap_or(HPKE_SUITE_X25519_CHACHA20POLY1305_V1);
                let suite_aead = active_hpke_suite_aead(suite_id)?.ok_or_else(|| {
                    WireError::Protocol(format!(
                        "key backup encryption: hpke_suite `{suite_id}` is not an active \
                         hpke-suite-registry row (unsupported_hpke_suite)"
                    ))
                })?;
                if self.aead.name.as_str() != suite_aead {
                    return Err(WireError::Protocol(format!(
                        "key backup encryption: aead.name `{}` does not equal hpke_suite \
                         `{suite_id}` aead `{suite_aead}` (schema_violation)",
                        self.aead.name.as_str()
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Return the AEAD name of an `active` HPKE suite registry row, or
/// `Ok(None)` when the suite id is absent / `status != "active"`. The active
/// set comes from the generated `hpke-suite-registry.json` snapshot embedded
/// in `arkret_wire::HPKE_SUITES`; the per-suite AEAD binding mirrors the
/// registry's `aead` column and fails closed on any active row it does not
/// know, so a registry addition cannot silently pass validation here.
fn active_hpke_suite_aead(suite_id: &str) -> Result<Option<String>> {
    let is_active = HPKE_SUITES
        .iter()
        .any(|suite| suite.canonical_id == suite_id && suite.status == "active");
    if !is_active {
        return Ok(None);
    }
    let aead = match suite_id {
        arkret_wire::HpkeSuiteId::P256_AEAD_AES256GCM_V1
        | arkret_wire::HpkeSuiteId::X25519_AEAD_AES256GCM_V1 => "aes_256_gcm",
        arkret_wire::HpkeSuiteId::X25519_AEAD_CHACHA20POLY1305_V1 => "chacha20_poly1305",
        other => {
            return Err(WireError::Protocol(format!(
                "key backup encryption: active hpke_suite `{other}` has no known aead binding \
                 (unsupported_hpke_suite)"
            )));
        }
    };
    Ok(Some(aead.to_owned()))
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupDomainSeparation {
    pub hkdf_info: String,
    pub subdomain: String,
    pub aead_aad: KeyBackupDomainSeparationAad,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupDomainSeparationAad {
    pub schema: String,
    pub actor_id: DidCoreId,
    /// The envelope's `device_id`, or `null` when it was sealed without an
    /// originating device (the top-level `device_id` is optional). The key is
    /// always present — never skipped, never an empty string — so the AAD
    /// transcript keeps a fixed field set and sealer/opener reconstruct it
    /// byte-identically (key-management.md §7.2).
    pub device_id: Option<String>,
    pub backup_kind: BackupKind,
    pub backup_version: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub item_kinds: Vec<String>,
    /// SEC-04: the envelope's `encryption.recipient_method` bound into the AEAD
    /// AAD (key-backup.schema.json `domain_separation.aead_aad.recipient_method`)
    /// so a ciphertext can never be cross-opened under the wrong recipient
    /// interpretation. Sealer and opener reconstruct it byte-identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_method: Option<KeyBackupRecipientMethod>,
    /// SEC-04: the envelope's `encryption.recipient_key_ref` bound into the AEAD
    /// AAD (key-backup.schema.json `domain_separation.aead_aad.recipient_key_ref`)
    /// so the recipient key / verification method is part of the authenticated
    /// context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_key_ref: Option<String>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupKdfName {
    Argon2id,
    Pbkdf2,
}

impl KeyBackupKdfName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Argon2id => "argon2id",
            Self::Pbkdf2 => "pbkdf2",
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyBackupKdfDigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KeyBackupKdfParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_kib: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iterations: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_algorithm: Option<KeyBackupKdfDigestAlgorithm>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "KeyBackupKdfWire")]
pub struct KeyBackupKdf {
    pub name: KeyBackupKdfName,
    pub salt: Base64UrlString,
    pub params: KeyBackupKdfParams,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded_profile_reason: Option<String>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Deserialize)]
struct KeyBackupKdfWire {
    name: KeyBackupKdfName,
    salt: Base64UrlString,
    params: KeyBackupKdfParams,
    degraded_profile_reason: Option<String>,
    #[serde(default, flatten)]
    extra: XExtensionMap,
}

impl TryFrom<KeyBackupKdfWire> for KeyBackupKdf {
    type Error = String;

    fn try_from(wire: KeyBackupKdfWire) -> std::result::Result<Self, Self::Error> {
        let kdf = Self {
            name: wire.name,
            salt: wire.salt,
            params: wire.params,
            degraded_profile_reason: wire.degraded_profile_reason,
            extra: wire.extra,
        };
        kdf.validate()?;
        Ok(kdf)
    }
}

impl KeyBackupKdf {
    pub fn validate(&self) -> std::result::Result<(), String> {
        match self.name {
            KeyBackupKdfName::Argon2id => {
                if self.params.memory_kib.is_none_or(|value| value < 65_536) {
                    return Err("argon2id params.memory_kib must be >= 65536".to_owned());
                }
                if self.params.iterations.is_none_or(|value| value < 3) {
                    return Err("argon2id params.iterations must be >= 3".to_owned());
                }
                if self.params.parallelism.is_none_or(|value| value < 1) {
                    return Err("argon2id params.parallelism must be >= 1".to_owned());
                }
            }
            KeyBackupKdfName::Pbkdf2 => {
                if self.params.iterations.is_none_or(|value| value < 600_000) {
                    return Err("pbkdf2 params.iterations must be >= 600000".to_owned());
                }
                if self.params.digest_algorithm.is_none() {
                    return Err("pbkdf2 params.digest_algorithm is required".to_owned());
                }
                if self
                    .degraded_profile_reason
                    .as_deref()
                    .is_none_or(str::is_empty)
                {
                    return Err("pbkdf2 degraded_profile_reason is required".to_owned());
                }
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupAeadName {
    Xchacha20Poly1305,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl KeyBackupAeadName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Xchacha20Poly1305 => "xchacha20_poly1305",
            Self::Aes256Gcm => "aes_256_gcm",
            Self::Chacha20Poly1305 => "chacha20_poly1305",
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupAead {
    pub name: KeyBackupAeadName,
    /// AEAD profile selector binding algorithm version, nonce/tag/key lengths
    /// and AAD construction (key-management.md §7.2). Receivers MUST fail
    /// closed on an unsupported profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aead_profile: Option<String>,
    /// Producer-generated random value (>=128 bits) mixed into the
    /// deterministic nonce derivation transcript for `passphrase_kdf`
    /// envelopes (key-management.md §7.2). REQUIRED on `passphrase_kdf`
    /// envelopes; receivers MUST reject a missing `nonce_salt` as
    /// `schema_violation`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_salt: Option<Base64UrlString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Base64UrlString>,
    /// HPKE KEM encapsulated key for `recipient_method=recovery_public_key`
    /// (key-backup.schema.json `encryption.aead.enc`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc: Option<Base64UrlString>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

/// Counterpart for the six non-history `item_kind` values shared by
/// `key-backup.schema.json#/properties/contents/items` and
/// `key-backup-plaintext.schema.json#/$defs/secret_storage_item`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretStorageItemKind {
    RecoveryKeyShare,
    AccountDataNamespaceKey,
    MlsAccountSecret,
    MlsPrivatePlaintext,
    MlsGroupSecretsBackupKey,
    PrivateAccountState,
}

impl SecretStorageItemKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecoveryKeyShare => "recovery_key_share",
            Self::AccountDataNamespaceKey => "account_data_namespace_key",
            Self::MlsAccountSecret => "mls_account_secret",
            Self::MlsPrivatePlaintext => "mls_private_plaintext",
            Self::MlsGroupSecretsBackupKey => "mls_group_secrets_backup_key",
            Self::PrivateAccountState => "private_account_state",
        }
    }
}

/// The `history_secret_ranges` discriminator of
/// `key-backup.schema.json#/properties/contents/items`. It is the only
/// `item_kind` a `backup_kind=mls_history` envelope may index
/// (key-management.md §7.1).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistorySecretRangesItemKind {
    #[serde(rename = "history_secret_ranges")]
    Value,
}

/// The public index of one secret-storage keybag item. `additionalProperties`
/// is closed: the `history_secret_ranges` branch fields (`effective_scope`,
/// `ranges`) cannot appear here, and neither can active MLS state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretStorageContentIndex {
    pub item_kind: SecretStorageItemKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    /// Monotonic version of the backed-up secret (e.g. `mls_account_secret`),
    /// used for deterministic preferred-backup selection and anti-rollback
    /// ordering (key-management.md §9.1). Present on versioned secret items;
    /// absent on share-style items (e.g. `recovery_key_share`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_version: Option<u32>,
    #[serde(default, flatten, skip_serializing_if = "XExtensionMap::is_empty")]
    pub extra: XExtensionMap,
}

/// The public range index of a `backup_kind=mls_history` envelope: exact
/// effective scope plus the canonical epoch ranges whose packed secrets live
/// in the encrypted keybag. Secret bytes never appear here.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistorySecretRangeIndex {
    pub item_kind: HistorySecretRangesItemKind,
    pub effective_scope: HistoryEffectiveScope,
    pub ranges: Vec<EpochRange>,
    #[serde(default, flatten, skip_serializing_if = "XExtensionMap::is_empty")]
    pub extra: XExtensionMap,
}

/// Maximum `ranges` entries per `key-backup.schema.json` (`maxItems: 64`).
pub const KEY_BACKUP_MAX_HISTORY_RANGES: usize = 64;

impl HistorySecretRangeIndex {
    pub fn validate(&self) -> Result<()> {
        arkret_wire::validate_canonical_ranges(&self.ranges, KEY_BACKUP_MAX_HISTORY_RANGES)
    }
}

/// Counterpart for `key-backup.schema.json#/properties/contents/items`: the
/// closed union its `allOf` if/then imposes on `item_kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyBackupContentItem {
    SecretStorage(SecretStorageContentIndex),
    HistorySecretRanges(HistorySecretRangeIndex),
}

impl KeyBackupContentItem {
    /// The wire `item_kind` string this index carries.
    pub const fn item_kind(&self) -> &'static str {
        match self {
            Self::SecretStorage(index) => index.item_kind.as_str(),
            Self::HistorySecretRanges(_) => "history_secret_ranges",
        }
    }

    pub fn secret_id(&self) -> Option<&str> {
        match self {
            Self::SecretStorage(index) => index.secret_id.as_deref(),
            Self::HistorySecretRanges(_) => None,
        }
    }

    pub const fn secret_version(&self) -> Option<u32> {
        match self {
            Self::SecretStorage(index) => index.secret_version,
            Self::HistorySecretRanges(_) => None,
        }
    }

    pub const fn secret_storage(&self) -> Option<&SecretStorageContentIndex> {
        match self {
            Self::SecretStorage(index) => Some(index),
            Self::HistorySecretRanges(_) => None,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupAuthData {
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: Base64UrlString,
    pub device_authorize_event_id: EventId,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyBackupSignatureAlgorithm {
    Ed25519,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

impl KeyBackupSignatureAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Es256 => "ES256",
            Self::MlDsa65 => "ML-DSA-65",
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupRetention {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub delete_after: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<bool>,
    /// Open retention metadata permitted by
    /// `key-backup.schema.json#/properties/retention`.
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

/// REC-1 (spec head, `recovery-policy.schema.json`) — Rust shape for
/// `ak.schema.recovery_policy.v1`. A principal's signed recovery policy,
/// versioned and bound to the Principal Control Realm via publish / rotate /
/// revoke control events.
///
/// Required surface: `schema`, `policy_id`, `principal_id`, `version`,
/// `supersedes`, `trust_domain`, `allowed_proof_kinds`, `issued_at`,
/// `auth_data`. The proof-family configuration sub-objects
/// (`threshold` / `device_quorum` / `trusted_recovery_services`) are required
/// by `allOf` when the matching `allowed_proof_kinds` entry is present;
/// full conditional / signed-fields enforcement stays with schema validation.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryPolicy {
    /// Schema id (`ak.schema.recovery_policy.v1`).
    pub schema: String,
    pub policy_id: PolicyId,
    pub principal_id: DidCoreId,
    /// Monotonically increasing counter scoped by `principal_id`.
    pub version: u64,
    /// Predecessor `policy_id`; `None` only for the genesis policy.
    pub supersedes: Option<PolicyId>,
    pub trust_domain: TrustDomainId,
    pub allowed_proof_kinds: Vec<RecoveryProofKind>,
    pub publication_authorization_rules: Vec<RecoveryPublicationAuthorizationRule>,
    /// Threshold-recovery config; required when `allowed_proof_kinds`
    /// contains `threshold_recovery`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<RecoveryThresholdConfig>,
    /// Device-quorum config; required when `allowed_proof_kinds` contains
    /// `device_quorum`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_quorum: Option<RecoveryDeviceQuorumConfig>,
    /// Declared recovery services; required when `allowed_proof_kinds`
    /// contains `trusted_recovery_service`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_recovery_services: Option<Vec<RecoveryTrustedService>>,
    /// Recovery signing keys a `recovery_unlock` proof resolves against;
    /// required when `allowed_proof_kinds` contains `recovery_unlock`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_keys: Option<Vec<RecoveryKeyEntry>>,
    /// Dedicated backup-only HPKE recipients referenced by
    /// `recovery_keys[].key_agreement_ref` and key-backup envelopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key_agreements: Option<Vec<RecoveryKeyAgreementEntry>>,
    /// Two-person-rule / cooldown enforcement layered on the proofs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_requirement: Option<RecoveryApprovalRequirement>,
    /// Where the recovery strand MUST emit auditable records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<RecoveryAuditConfig>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub not_before: Option<DateTime<Utc>>,
    /// `null` permitted; an empty `allowed_proof_kinds` revocation policy
    /// MUST set this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    pub auth_data: RecoveryPolicyAuthData,
    /// `x_*` extension fields (`patternProperties`).
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

impl RecoveryPolicy {
    pub const SCHEMA: &'static str = SchemaId::RECOVERY_POLICY_V1;
    pub const SIGNATURE_TYPE: &'static str = RECOVERY_POLICY_SIGNATURE_TYPE;

    /// Canonical detached-signature transcript shared by policy producers and
    /// verifiers. Every present top-level policy member except `auth_data` is
    /// authenticated under the fixed policy domain.
    pub fn signature_transcript_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let policy = serde_json::to_value(self).map_err(|error| {
            WireError::Protocol(format!("failed to serialize recovery policy: {error}"))
        })?;
        recovery_policy_signature_transcript_bytes(&policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::RECOVERY_POLICY_V1 {
            return Err(WireError::Protocol(
                "recovery policy schema must be ak.schema.recovery_policy.v1".to_owned(),
            ));
        }
        if !matches!(
            self.auth_data.signature_algorithm.as_str(),
            "Ed25519" | "ML-DSA-65"
        ) || Base64UrlString::new(self.auth_data.signature.clone()).is_err()
        {
            return Err(WireError::Protocol(
                "recovery policy auth_data must carry an Ed25519 or ML-DSA-65 base64url signature"
                    .to_owned(),
            ));
        }
        if self.version < 1
            || (self.version == 1) != self.supersedes.is_none()
            || (self.version >= 2 && self.supersedes.is_none())
        {
            return Err(WireError::Protocol(
                "recovery policy version and supersedes do not form a valid chain".to_owned(),
            ));
        }
        let unique_proof_kinds = self
            .allowed_proof_kinds
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if unique_proof_kinds.len() != self.allowed_proof_kinds.len() {
            return Err(WireError::Protocol(
                "recovery policy allowed_proof_kinds must be unique".to_owned(),
            ));
        }
        if self.allowed_proof_kinds.is_empty() && self.expires_at.is_none() {
            return Err(WireError::Protocol(
                "revoked recovery policy requires expires_at".to_owned(),
            ));
        }
        self.validate_publication_authorization_rules(&unique_proof_kinds)?;
        self.require_proof_configuration(
            RecoveryProofKind::ThresholdRecovery,
            self.threshold.is_some(),
            "threshold",
        )?;
        self.require_proof_configuration(
            RecoveryProofKind::DeviceQuorum,
            self.device_quorum.is_some(),
            "device_quorum",
        )?;
        self.require_proof_configuration(
            RecoveryProofKind::TrustedRecoveryService,
            self.trusted_recovery_services
                .as_ref()
                .is_some_and(|items| !items.is_empty()),
            "trusted_recovery_services",
        )?;

        let recovery_signing_key_enabled = unique_proof_kinds.iter().any(|kind| {
            matches!(
                kind,
                RecoveryProofKind::RecoveryUnlock | RecoveryProofKind::ThresholdRecovery
            )
        });
        let recovery_keys = self.recovery_keys.as_deref().unwrap_or_default();
        let agreements = self.recovery_key_agreements.as_deref().unwrap_or_default();
        if recovery_signing_key_enabled && (recovery_keys.is_empty() || agreements.is_empty()) {
            return Err(WireError::Protocol(
                "recovery_unlock and threshold_recovery require recovery_keys and recovery_key_agreements".to_owned(),
            ));
        }
        if !recovery_keys.is_empty() && agreements.is_empty() {
            return Err(WireError::Protocol(
                "recovery_keys require recovery_key_agreements".to_owned(),
            ));
        }

        let agreement_refs = agreements
            .iter()
            .map(|entry| entry.key_agreement_ref.as_str())
            .collect::<BTreeSet<_>>();
        if agreement_refs.len() != agreements.len() {
            return Err(WireError::Protocol(
                "recovery_key_agreements key_agreement_ref values must be unique".to_owned(),
            ));
        }
        for entry in agreements {
            entry.validate()?;
        }

        let verification_methods = recovery_keys
            .iter()
            .map(|entry| entry.verification_method.as_str())
            .collect::<BTreeSet<_>>();
        if verification_methods.len() != recovery_keys.len() {
            return Err(WireError::Protocol(
                "recovery_keys verification_method values must be unique".to_owned(),
            ));
        }
        for entry in recovery_keys {
            entry.validate()?;
            if !agreement_refs.contains(entry.key_agreement_ref.as_str()) {
                return Err(WireError::Protocol(format!(
                    "recovery key {} references an unknown key agreement",
                    entry.verification_method
                )));
            }
        }

        Ok(())
    }

    fn validate_publication_authorization_rules(
        &self,
        allowed_proof_kinds: &BTreeSet<RecoveryProofKind>,
    ) -> Result<()> {
        if self.publication_authorization_rules.len() != allowed_proof_kinds.len() {
            return Err(WireError::Protocol(
                "recovery policy requires exactly one publication authorization rule per proof kind"
                    .to_owned(),
            ));
        }

        let active_recovery_methods = self
            .recovery_keys
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|entry| {
                entry.not_before <= self.issued_at
                    && self.issued_at <= entry.expires_at
                    && entry
                        .revoked_at
                        .is_none_or(|revoked_at| self.issued_at < revoked_at)
            })
            .map(|entry| entry.verification_method.as_str())
            .collect::<BTreeSet<_>>();
        let trusted_service_methods = self
            .trusted_recovery_services
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|service| service.authorization_verification_method.as_str())
            .collect::<BTreeSet<_>>();

        let mut previous_rule_id: Option<&str> = None;
        let mut seen_proof_kinds = BTreeSet::new();
        for rule in &self.publication_authorization_rules {
            if previous_rule_id.is_some_and(|previous| previous >= rule.rule_id.as_str()) {
                return Err(WireError::Protocol(
                    "recovery publication authorization rules must be ordered by rule_id"
                        .to_owned(),
                ));
            }
            previous_rule_id = Some(&rule.rule_id);
            if rule.rule_id != rule.proof_kind.as_wire_str()
                || !allowed_proof_kinds.contains(&rule.proof_kind)
                || !seen_proof_kinds.insert(rule.proof_kind)
                || rule.issuer_role != AuthoritySetIssuerRole::IdentityRecovery
                || rule.allowed_actions.as_slice() != [arkret_wire::event_kind_str::DEVICE_REANCHOR]
                || rule.issuers.is_empty()
                || rule.issuers.len() > 32
                || rule.threshold == 0
                || usize::try_from(rule.threshold).unwrap_or(usize::MAX) > rule.issuers.len()
                || rule.issuers.windows(2).any(|pair| {
                    pair[0].verification_method.as_str() >= pair[1].verification_method.as_str()
                })
            {
                return Err(WireError::Protocol(
                    "recovery publication authorization rule is not canonical".to_owned(),
                ));
            }

            let issuer_methods = rule
                .issuers
                .iter()
                .map(|issuer| issuer.verification_method.as_str())
                .collect::<BTreeSet<_>>();
            match rule.proof_kind {
                RecoveryProofKind::DidRoot => {
                    if rule.threshold != 1
                        || issuer_methods.len() != 1
                        || !issuer_methods.contains(self.auth_data.verification_method.as_str())
                    {
                        return Err(WireError::Protocol(
                            "did_root publication rule must use the policy authority method at threshold 1"
                                .to_owned(),
                        ));
                    }
                }
                RecoveryProofKind::RecoveryUnlock | RecoveryProofKind::ThresholdRecovery => {
                    if rule.threshold != 1 || issuer_methods != active_recovery_methods {
                        return Err(WireError::Protocol(
                            "recovery signing publication rule must use the active recovery key set at threshold 1"
                                .to_owned(),
                        ));
                    }
                }
                RecoveryProofKind::DeviceQuorum => {
                    let quorum = self.device_quorum.as_ref().ok_or_else(|| {
                        WireError::Protocol(
                            "device_quorum publication rule requires device_quorum".to_owned(),
                        )
                    })?;
                    let distinct_members = quorum.members.iter().collect::<BTreeSet<_>>();
                    if quorum.k < 2
                        || usize::try_from(quorum.k).unwrap_or(usize::MAX) > quorum.members.len()
                        || distinct_members.len() != quorum.members.len()
                        || rule.threshold != quorum.k
                        || rule.issuers.len() != quorum.members.len()
                    {
                        return Err(WireError::Protocol(
                            "device_quorum publication rule does not match the device quorum"
                                .to_owned(),
                        ));
                    }
                }
                RecoveryProofKind::TrustedRecoveryService => {
                    let services = self
                        .trusted_recovery_services
                        .as_deref()
                        .unwrap_or_default();
                    if services.iter().any(|service| {
                        service
                            .authorization_verification_method
                            .as_str()
                            .split_once('#')
                            .is_none_or(|(controller, _)| controller != service.service_id.as_str())
                    }) || rule.threshold != 1
                        || issuer_methods != trusted_service_methods
                    {
                        return Err(WireError::Protocol(
                            "trusted recovery service publication rule does not match the declared service methods"
                                .to_owned(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn require_proof_configuration(
        &self,
        proof_kind: RecoveryProofKind,
        present: bool,
        field: &str,
    ) -> Result<()> {
        if self.allowed_proof_kinds.contains(&proof_kind) && !present {
            return Err(WireError::Protocol(format!(
                "recovery policy proof kind {proof_kind:?} requires {field}"
            )));
        }
        Ok(())
    }
}

/// Strongly typed recovery-policy members before signature metadata exists.
/// This is an authoring input, not a serializable wire object.
#[derive(Clone, Debug)]
pub struct UnsignedRecoveryPolicyBody {
    pub policy_id: PolicyId,
    pub principal_id: DidCoreId,
    pub version: u64,
    pub supersedes: Option<PolicyId>,
    pub trust_domain: TrustDomainId,
    pub allowed_proof_kinds: Vec<RecoveryProofKind>,
    pub publication_authorization_rules: Vec<RecoveryPublicationAuthorizationRule>,
    pub threshold: Option<RecoveryThresholdConfig>,
    pub device_quorum: Option<RecoveryDeviceQuorumConfig>,
    pub trusted_recovery_services: Option<Vec<RecoveryTrustedService>>,
    pub recovery_keys: Option<Vec<RecoveryKeyEntry>>,
    pub recovery_key_agreements: Option<Vec<RecoveryKeyAgreementEntry>>,
    pub approval_requirement: Option<RecoveryApprovalRequirement>,
    pub audit: Option<RecoveryAuditConfig>,
    pub issued_at: DateTime<Utc>,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub extra: XExtensionMap,
}

/// Recovery policy authoring state before its detached signature exists.
#[derive(Clone, Debug)]
pub struct UnsignedRecoveryPolicy {
    body: UnsignedRecoveryPolicyBody,
    verification_method: DidUrl,
    signature_algorithm: KeyBackupSignatureAlgorithm,
}

impl UnsignedRecoveryPolicy {
    pub fn new(
        body: UnsignedRecoveryPolicyBody,
        verification_method: DidUrl,
        signature_algorithm: KeyBackupSignatureAlgorithm,
    ) -> Result<Self> {
        validate_key_backup_signature_algorithm(signature_algorithm)?;
        Ok(Self {
            body,
            verification_method,
            signature_algorithm,
        })
    }

    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        let policy = recovery_policy_unsigned_value(&self.body)?;
        recovery_policy_signature_transcript_bytes(&policy)
    }

    pub fn attach_signature(self, signature: Base64UrlString) -> Result<RecoveryPolicy> {
        let body = self.body;
        let policy = RecoveryPolicy {
            schema: RecoveryPolicy::SCHEMA.to_owned(),
            policy_id: body.policy_id,
            principal_id: body.principal_id,
            version: body.version,
            supersedes: body.supersedes,
            trust_domain: body.trust_domain,
            allowed_proof_kinds: body.allowed_proof_kinds,
            publication_authorization_rules: body.publication_authorization_rules,
            threshold: body.threshold,
            device_quorum: body.device_quorum,
            trusted_recovery_services: body.trusted_recovery_services,
            recovery_keys: body.recovery_keys,
            recovery_key_agreements: body.recovery_key_agreements,
            approval_requirement: body.approval_requirement,
            audit: body.audit,
            issued_at: body.issued_at,
            not_before: body.not_before,
            expires_at: body.expires_at,
            auth_data: RecoveryPolicyAuthData {
                verification_method: self.verification_method,
                signature_algorithm: self.signature_algorithm.as_str().to_owned(),
                signature: signature.into_string(),
            },
            extra: body.extra,
        };
        policy.validate()?;
        Ok(policy)
    }
}

fn recovery_policy_signature_transcript_bytes(policy: &Value) -> Result<Vec<u8>> {
    domain_separated_unsigned_object_bytes(RecoveryPolicy::SIGNATURE_TYPE, policy)
}

fn recovery_policy_unsigned_value(body: &UnsignedRecoveryPolicyBody) -> Result<Value> {
    let mut value = json!({
        "schema": RecoveryPolicy::SCHEMA,
        "policy_id": &body.policy_id,
        "principal_id": &body.principal_id,
        "version": body.version,
        "supersedes": &body.supersedes,
        "trust_domain": &body.trust_domain,
        "allowed_proof_kinds": &body.allowed_proof_kinds,
        "publication_authorization_rules": &body.publication_authorization_rules,
        "threshold": &body.threshold,
        "device_quorum": &body.device_quorum,
        "trusted_recovery_services": &body.trusted_recovery_services,
        "recovery_keys": &body.recovery_keys,
        "recovery_key_agreements": &body.recovery_key_agreements,
        "approval_requirement": &body.approval_requirement,
        "audit": &body.audit,
        "issued_at": arkret_canonical::canonical::format_timestamp_canonical(body.issued_at),
        "not_before": body.not_before.map(arkret_canonical::canonical::format_timestamp_canonical),
        "expires_at": body.expires_at.map(arkret_canonical::canonical::format_timestamp_canonical),
    });
    let object = value.as_object_mut().expect("policy literal is an object");
    for (present, field) in [
        (body.threshold.is_some(), "threshold"),
        (body.device_quorum.is_some(), "device_quorum"),
        (
            body.trusted_recovery_services.is_some(),
            "trusted_recovery_services",
        ),
        (body.recovery_keys.is_some(), "recovery_keys"),
        (
            body.recovery_key_agreements.is_some(),
            "recovery_key_agreements",
        ),
        (body.approval_requirement.is_some(), "approval_requirement"),
        (body.audit.is_some(), "audit"),
        (body.not_before.is_some(), "not_before"),
        (body.expires_at.is_some(), "expires_at"),
    ] {
        if !present {
            object.remove(field);
        }
    }
    for (key, extension) in body.extra.iter() {
        object.insert(key.clone(), extension.clone());
    }
    Ok(value)
}

fn domain_separated_unsigned_object_bytes(domain: &str, value: &Value) -> Result<Vec<u8>> {
    let mut unsigned = value.clone();
    let object = unsigned.as_object_mut().ok_or_else(|| {
        WireError::Protocol("signature subject must serialize as an object".to_owned())
    })?;
    object.remove("auth_data");
    let mut transcript = format!("{domain}\n").into_bytes();
    transcript.extend(arkret_canonical::canonical_json_bytes(&unsigned)?);
    Ok(transcript)
}

/// Read-model summary for the currently accepted recovery policy.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicySummary {
    pub policy_id: PolicyId,
    pub principal_id: DidCoreId,
    pub version: u64,
    pub acceptance_basis: LeaseBasisRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_policy_ref: Option<RecoveryPolicyRef>,
    pub trust_domain: TrustDomainId,
    pub allowed_proof_kinds: Vec<RecoveryProofKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<RecoveryPolicy>,
}

/// Principal control-stream frontier used by recovery policy read models.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryControlFrontier {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub observed_at: Option<DateTime<Utc>>,
}

/// Response for `ak.root.identity.recovery_policy.resource.get`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyActiveOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<DidCoreId>,
    pub active_policy: Option<RecoveryPolicySummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy_ref: Option<RecoveryPolicyRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub as_of: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_frontier: Option<RecoveryControlFrontier>,
}

/// Canonical `ak.policy.set` payload used by recovery-policy publication.
///
/// The generic policy reducer also supports state-only updates, but recovery
/// policy publication deliberately exposes only a complete policy value. This
/// keeps the signed Event as the sole publication fact without admitting an
/// alternate raw-policy HTTP shape.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicySetPayload {
    pub policy_id: PolicyId,
    pub value: RecoveryPolicy,
}

impl RecoveryPolicySetPayload {
    pub fn validate(&self) -> Result<()> {
        if self.policy_id != self.value.policy_id {
            return Err(WireError::Protocol(
                "recovery policy payload policy_id must equal value.policy_id".to_owned(),
            ));
        }
        self.value.validate()
    }
}

/// Request for `ak.root.identity.recovery_policy.command.publish`.
///
/// This has the same transport members as [`EventInitialSubmission`], while
/// its validation narrows the Event kind and payload to the recovery-policy
/// contract.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyPublishRequest {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub event: Event,
    pub authorization_lease: AuthorizationLease,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cba_proof_bundles: Vec<CbaProofBundle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_proposal_ack: Option<ControlProposalAck>,
}

impl RecoveryPolicyPublishRequest {
    pub fn policy_payload(&self) -> Result<RecoveryPolicySetPayload> {
        if self.event.kind != EventKind::PolicySet {
            return Err(WireError::Protocol(
                "recovery policy publication Event kind must be ak.policy.set".to_owned(),
            ));
        }
        let payload = serde_json::from_value(
            serde_json::to_value(&self.event.payload)
                .map_err(|error| WireError::Protocol(error.to_string()))?,
        )
        .map_err(|error| {
            WireError::Protocol(format!("invalid recovery policy payload: {error}"))
        })?;
        RecoveryPolicySetPayload::validate(&payload)?;
        Ok(payload)
    }

    pub fn validate_structural(&self, digest_suite: arkret_canonical::DigestSuite) -> Result<()> {
        EventInitialSubmission::from(self.clone()).validate_structural(digest_suite)?;
        self.policy_payload().map(|_| ())
    }
}

impl From<RecoveryPolicyPublishRequest> for EventInitialSubmission {
    fn from(value: RecoveryPolicyPublishRequest) -> Self {
        Self {
            event: value.event,
            authorization_lease: Some(value.authorization_lease),
            cba_proof_bundles: value.cba_proof_bundles,
            control_proposal_ack: value.control_proposal_ack,
            membership_compensation_evidence: None,
        }
    }
}

/// Response for `ak.root.identity.recovery_policy.command.publish`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyPublishOutcome {
    pub ok: bool,
    pub policy_id: PolicyId,
    pub principal_id: DidCoreId,
    pub version: u64,
    pub acceptance_basis: LeaseBasisRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

/// `recovery-policy.schema.json#/properties/threshold` — Shamir-style
/// threshold recovery configuration.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryThresholdConfig {
    /// Minimum shares to reconstruct (MUST be >= 2).
    pub k: u32,
    /// Total shares issued (MUST equal `shares.len()` and be >= `k`).
    pub n: u32,
    pub shares: Vec<RecoveryShare>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vss_root_commitment: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reshare_policy: Option<RecoveryResharePolicy>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReshareScheme {
    None,
    ProactiveVss,
    ProactiveFeldman,
    ServiceDefined,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryResharePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_share_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<RecoveryReshareScheme>,
}

/// `recovery-policy.schema.json#/$defs/share` — single recovery share.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryShare {
    pub share_id: String,
    pub holder: DidCoreId,
    pub transport: String,
    pub share_commitment: ShareShareCommitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason_code: Option<String>,
}

/// `recovery-policy.schema.json#/properties/device_quorum`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryDeviceQuorumConfig {
    pub k: u32,
    pub members: Vec<DeviceId>,
}

/// Signed deterministic publication-rule projection carried by a recovery
/// policy. `proof_kind` selects the recovery factor; the remaining fields
/// project directly into an authority-set authorization rule after the
/// acceptance basis rederives every verification method.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPublicationAuthorizationRule {
    pub rule_id: String,
    pub proof_kind: RecoveryProofKind,
    pub issuer_role: AuthoritySetIssuerRole,
    pub allowed_actions: Vec<String>,
    pub issuers: Vec<AuthoritySetIssuer>,
    pub threshold: u32,
}

/// `recovery-policy.schema.json#/properties/trusted_recovery_services[]`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryTrustedService {
    pub service_id: DidCoreId,
    pub audience: NonEmptyString,
    pub authorization_verification_method: DidUrl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_action_scope: Option<Vec<String>>,
}

/// `recovery-policy.schema.json#/$defs/recovery_key_entry` — a recovery
/// signing key the principal authorizes for `recovery_unlock` proofs. The
/// `verification_method` is the stable `recovery_secret_ref` a recovery_unlock
/// proof references; the proof signature is verified under this entry's public
/// key resolved via `verification_method`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryKeyEntry {
    /// DID URL identifying this recovery signing key
    /// (e.g. `did:webvh:...#recovery-1`). Unique within `recovery_keys[]`.
    pub verification_method: DidUrl,
    /// Signing public multikey. This is never the paired HPKE public key.
    pub public_key_multibase: NonEmptyString,
    /// Dedicated backup recipient entry paired with this signing key.
    pub key_agreement_ref: DidUrl,
    /// Signature algorithm; v1 fixes this to `Ed25519`.
    pub signature_algorithm: RecoveryKeySignatureAlgorithm,
    /// Earliest instant this key may authorize a `recovery_unlock` proof.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    /// Instant after which this key MUST NOT authorize a proof.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    /// When set, the entry is revoked from this instant onward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl RecoveryKeyEntry {
    pub fn validate(&self) -> Result<()> {
        validate_canonical_multibase(self.public_key_multibase.as_str())?;
        if self.not_before >= self.expires_at {
            return Err(WireError::Protocol(
                "recovery key expires_at must be after not_before".to_owned(),
            ));
        }
        if self
            .revoked_at
            .is_some_and(|revoked_at| revoked_at < self.not_before)
        {
            return Err(WireError::Protocol(
                "recovery key revoked_at must not precede not_before".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryKeySignatureAlgorithm {
    Ed25519,
    ES256,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryKeyAgreementAlgorithm {
    X25519,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryKeyAgreementUse {
    BackupHpke,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RecoveryHpkeSuite {
    #[serde(rename = "ak.hpke_x25519_aead_chacha20poly1305.v1")]
    X25519ChaCha20Poly1305,
    #[serde(rename = "ak.hpke_x25519_aead_aes256gcm.v1")]
    X25519Aes256Gcm,
}

/// `recovery-policy.schema.json#/$defs/recovery_key_agreement_entry`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyAgreementEntry {
    pub key_agreement_ref: DidUrl,
    pub key_agreement_algorithm: RecoveryKeyAgreementAlgorithm,
    pub public_key_multibase: NonEmptyString,
    pub hpke_suites: Vec<RecoveryHpkeSuite>,
    #[serde(rename = "use")]
    pub usage: RecoveryKeyAgreementUse,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl RecoveryKeyAgreementEntry {
    pub fn validate(&self) -> Result<()> {
        let decoded = validate_canonical_multibase(self.public_key_multibase.as_str())?;
        let (codec, header_len) = decode_multicodec_varint(&decoded).ok_or_else(|| {
            WireError::Protocol("recovery key agreement has an invalid multicodec".to_owned())
        })?;
        if codec != 0xec || decoded.len().saturating_sub(header_len) != 32 {
            return Err(WireError::Protocol(
                "recovery key agreement must carry a 32-byte x25519-pub multikey".to_owned(),
            ));
        }
        let suites = self.hpke_suites.iter().copied().collect::<BTreeSet<_>>();
        if suites.is_empty() || suites.len() != self.hpke_suites.len() {
            return Err(WireError::Protocol(
                "recovery key agreement hpke_suites must be non-empty and unique".to_owned(),
            ));
        }
        if self.not_before >= self.expires_at {
            return Err(WireError::Protocol(
                "recovery key agreement expires_at must be after not_before".to_owned(),
            ));
        }
        if self
            .revoked_at
            .is_some_and(|revoked_at| revoked_at < self.not_before)
        {
            return Err(WireError::Protocol(
                "recovery key agreement revoked_at must not precede not_before".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_canonical_multibase(value: &str) -> Result<Vec<u8>> {
    let decoded = decode_multibase_base58btc(value)?;
    if decoded.is_empty() || encode_multibase_base58btc(&decoded) != value {
        return Err(WireError::Protocol(
            "public_key_multibase must use canonical non-empty base58btc".to_owned(),
        ));
    }
    Ok(decoded)
}

/// `recovery-policy.schema.json#/properties/approval_requirement`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryApprovalRequirement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_approvals: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announcement_required: Option<bool>,
}

/// `recovery-policy.schema.json#/properties/audit`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryAuditConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_required: Option<bool>,
}

/// `recovery-policy.schema.json#/properties/auth_data`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryPolicyAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub signature: String,
}

/// AKP recovery proof-family enum, aligned to `recovery-policy.schema.json`
/// `allowed_proof_kinds[]` and `recovery-receipt.schema.json`
/// `proof_summary.kind`. Cryptographic proof validation is specified by
/// device-lifecycle verifier rules and handled outside this discriminator.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryProofKind {
    /// Current DID-root signature, only when the frozen PCR policy opts in.
    DidRoot,
    /// Recovery passphrase / hardware-wrapped unlock evidence.
    RecoveryUnlock,
    /// Device-quorum signed reset (threshold of trusted devices).
    DeviceQuorum,
    /// External trusted recovery service (e.g. OIDC, custodian).
    TrustedRecoveryService,
    /// Shamir threshold-share reconstruction.
    ThresholdRecovery,
}

impl RecoveryProofKind {
    /// All variants in `recovery-policy.schema.json` enum order.
    pub const ALL: &'static [Self] = &[
        Self::DidRoot,
        Self::RecoveryUnlock,
        Self::DeviceQuorum,
        Self::TrustedRecoveryService,
        Self::ThresholdRecovery,
    ];

    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::DidRoot => "did_root",
            Self::RecoveryUnlock => "recovery_unlock",
            Self::DeviceQuorum => "device_quorum",
            Self::TrustedRecoveryService => "trusted_recovery_service",
            Self::ThresholdRecovery => "threshold_recovery",
        }
    }
}

/// REC-1 (spec head, `recovery-receipt.schema.json`) — Rust shape for
/// `ak.schema.recovery_receipt.v1`. Signed completion receipt for a principal
/// recovery strand, bound to the `recovery_session_id` used by every proof,
/// backup unlock, and MLS Welcome replay action.
///
/// Required surface: `schema`, `receipt_id`, `transaction_id`,
/// `transaction_request_digest`, `principal_id`,
/// `recovery_session_id`, `policy_id`, `policy_version`, `trust_domain`,
/// `new_device_id`, `proof_summary`, `backup_classes_unlocked`,
/// `welcome_count`, `outcome`, `started_at`, `completed_at`, `auth_data`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryReceipt {
    /// Schema id (`ak.schema.recovery_receipt.v1`).
    pub schema: String,
    pub receipt_id: ReceiptId,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub principal_id: DidCoreId,
    pub recovery_session_id: RecoverySessionId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub trust_domain: TrustDomainId,
    pub new_device_id: DeviceId,
    pub identity_model: RecoveryIdentityModel,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub previous_model_generation_ref: u64,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub result_model_generation_ref: u64,
    pub authorization_event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_list_update_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reanchor_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reanchor_batch_receipt_id: Option<ReceiptId>,
    pub proof_summary: RecoveryProofSummary,
    pub backup_classes_unlocked: Vec<RecoveryBackupClassUnlocked>,
    /// MLS Welcomes successfully replayed for the recovering device.
    pub welcome_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_realm_summary: Option<Vec<RecoveryWelcomeRealmSummary>>,
    pub outcome: RecoveryReceiptOutcome,
    /// MUST be present when `outcome != completed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_reason_code: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub started_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub completed_at: DateTime<Utc>,
    pub auth_data: RecoveryReceiptAuthData,
    /// `x_*` extension fields (`patternProperties`).
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

impl RecoveryReceipt {
    pub const SCHEMA: &'static str = SchemaId::RECOVERY_RECEIPT_V1;
    pub const SIGNATURE_TYPE: &'static str =
        arkret_wire::DomainSeparationId::IDENTITY_RECOVERY_RECEIPT_SIGNATURE_V1;

    /// Canonical signature input shared by clients and verifiers. Every
    /// present top-level receipt member except `auth_data` is authenticated.
    pub fn signature_transcript_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let payload = serde_json::to_value(self).map_err(|error| {
            WireError::Protocol(format!("failed to serialize recovery receipt: {error}"))
        })?;
        recovery_receipt_signature_transcript_bytes(&payload)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::RECOVERY_RECEIPT_V1 {
            return Err(WireError::Protocol(
                "recovery receipt schema must be ak.schema.recovery_receipt.v1".to_owned(),
            ));
        }
        validate_recovery_receipt_body(
            self.policy_version,
            self.identity_model,
            &self.previous_model_generation_ref,
            &self.result_model_generation_ref,
            self.device_list_update_event_id.is_some(),
            self.reanchor_event_id.is_some(),
            self.reanchor_batch_receipt_id.is_some(),
            self.outcome,
            self.outcome_reason_code.as_deref(),
            self.started_at,
            self.completed_at,
        )?;
        if self.auth_data.signature_algorithm != "Ed25519" {
            return Err(WireError::Protocol(
                "recovery receipt signature_algorithm must be Ed25519".to_owned(),
            ));
        }
        if Base64UrlString::new(self.auth_data.signature.clone()).is_err() {
            return Err(WireError::Protocol(
                "recovery receipt signature must be non-empty base64url".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Strongly typed recovery-receipt members before signature metadata exists.
#[derive(Clone, Debug)]
pub struct UnsignedRecoveryReceiptBody {
    pub receipt_id: ReceiptId,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub principal_id: DidCoreId,
    pub recovery_session_id: RecoverySessionId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub trust_domain: TrustDomainId,
    pub new_device_id: DeviceId,
    pub identity_model: RecoveryIdentityModel,
    pub previous_model_generation_ref: u64,
    pub result_model_generation_ref: u64,
    pub authorization_event_id: EventId,
    pub device_list_update_event_id: Option<EventId>,
    pub reanchor_event_id: Option<EventId>,
    pub reanchor_batch_receipt_id: Option<ReceiptId>,
    pub proof_summary: RecoveryProofSummary,
    pub backup_classes_unlocked: Vec<RecoveryBackupClassUnlocked>,
    pub welcome_count: u64,
    pub welcome_realm_summary: Option<Vec<RecoveryWelcomeRealmSummary>>,
    pub outcome: RecoveryReceiptOutcome,
    pub outcome_reason_code: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub extra: XExtensionMap,
}

/// Recovery receipt authoring state before the replacement-device signature.
#[derive(Clone, Debug)]
pub struct UnsignedRecoveryReceipt {
    body: UnsignedRecoveryReceiptBody,
    verification_method: DidUrl,
}

impl UnsignedRecoveryReceipt {
    pub fn new(body: UnsignedRecoveryReceiptBody, verification_method: DidUrl) -> Result<Self> {
        validate_recovery_receipt_body(
            body.policy_version,
            body.identity_model,
            &body.previous_model_generation_ref,
            &body.result_model_generation_ref,
            body.device_list_update_event_id.is_some(),
            body.reanchor_event_id.is_some(),
            body.reanchor_batch_receipt_id.is_some(),
            body.outcome,
            body.outcome_reason_code.as_deref(),
            body.started_at,
            body.completed_at,
        )?;
        Ok(Self {
            body,
            verification_method,
        })
    }

    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        let receipt = recovery_receipt_unsigned_value(&self.body);
        recovery_receipt_signature_transcript_bytes(&receipt)
    }

    pub fn attach_signature(self, signature: Base64UrlString) -> Result<RecoveryReceipt> {
        let body = self.body;
        let receipt = RecoveryReceipt {
            schema: RecoveryReceipt::SCHEMA.to_owned(),
            receipt_id: body.receipt_id,
            transaction_id: body.transaction_id,
            transaction_request_digest: body.transaction_request_digest,
            prepared_plan_digest: body.prepared_plan_digest,
            principal_id: body.principal_id,
            recovery_session_id: body.recovery_session_id,
            policy_id: body.policy_id,
            policy_version: body.policy_version,
            trust_domain: body.trust_domain,
            new_device_id: body.new_device_id,
            identity_model: body.identity_model,
            previous_model_generation_ref: body.previous_model_generation_ref,
            result_model_generation_ref: body.result_model_generation_ref,
            authorization_event_id: body.authorization_event_id,
            device_list_update_event_id: body.device_list_update_event_id,
            reanchor_event_id: body.reanchor_event_id,
            reanchor_batch_receipt_id: body.reanchor_batch_receipt_id,
            proof_summary: body.proof_summary,
            backup_classes_unlocked: body.backup_classes_unlocked,
            welcome_count: body.welcome_count,
            welcome_realm_summary: body.welcome_realm_summary,
            outcome: body.outcome,
            outcome_reason_code: body.outcome_reason_code,
            started_at: body.started_at,
            completed_at: body.completed_at,
            auth_data: RecoveryReceiptAuthData {
                verification_method: self.verification_method,
                signature_algorithm: "Ed25519".to_owned(),
                signature: signature.into_string(),
            },
            extra: body.extra,
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_recovery_receipt_body(
    policy_version: u64,
    identity_model: RecoveryIdentityModel,
    previous_model_generation_ref: &u64,
    result_model_generation_ref: &u64,
    device_list_update_present: bool,
    reanchor_event_present: bool,
    reanchor_batch_receipt_present: bool,
    outcome: RecoveryReceiptOutcome,
    outcome_reason_code: Option<&str>,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
) -> Result<()> {
    if policy_version == 0 {
        return Err(WireError::Protocol(
            "recovery receipt policy_version must be positive".to_owned(),
        ));
    }
    if identity_model != RecoveryIdentityModel::PcrPolicy
        || *previous_model_generation_ref == 0
        || *result_model_generation_ref <= *previous_model_generation_ref
        || device_list_update_present
        || !reanchor_event_present
        || !reanchor_batch_receipt_present
    {
        return Err(WireError::Protocol(
            "PCR-policy recovery receipt requires an advancing re-anchor artifact pair".to_owned(),
        ));
    }
    if completed_at < started_at {
        return Err(WireError::Protocol(
            "recovery receipt completed_at precedes started_at".to_owned(),
        ));
    }
    if outcome == RecoveryReceiptOutcome::Completed && outcome_reason_code.is_some() {
        return Err(WireError::Protocol(
            "completed recovery receipt must omit outcome_reason_code".to_owned(),
        ));
    }
    if outcome != RecoveryReceiptOutcome::Completed && outcome_reason_code.is_none_or(str::is_empty)
    {
        return Err(WireError::Protocol(
            "non-completed recovery receipt requires outcome_reason_code".to_owned(),
        ));
    }
    Ok(())
}

fn recovery_receipt_signature_transcript_bytes(receipt: &Value) -> Result<Vec<u8>> {
    domain_separated_unsigned_object_bytes(RecoveryReceipt::SIGNATURE_TYPE, receipt)
}

fn recovery_receipt_unsigned_value(body: &UnsignedRecoveryReceiptBody) -> Value {
    let mut value = json!({
        "schema": RecoveryReceipt::SCHEMA,
        "receipt_id": &body.receipt_id,
        "transaction_id": &body.transaction_id,
        "transaction_request_digest": &body.transaction_request_digest,
        "prepared_plan_digest": &body.prepared_plan_digest,
        "principal_id": &body.principal_id,
        "recovery_session_id": &body.recovery_session_id,
        "policy_id": &body.policy_id,
        "policy_version": body.policy_version,
        "trust_domain": &body.trust_domain,
        "new_device_id": &body.new_device_id,
        "identity_model": body.identity_model,
        "previous_model_generation_ref": &body.previous_model_generation_ref,
        "result_model_generation_ref": &body.result_model_generation_ref,
        "authorization_event_id": &body.authorization_event_id,
        "device_list_update_event_id": &body.device_list_update_event_id,
        "reanchor_event_id": &body.reanchor_event_id,
        "reanchor_batch_receipt_id": &body.reanchor_batch_receipt_id,
        "proof_summary": &body.proof_summary,
        "backup_classes_unlocked": &body.backup_classes_unlocked,
        "welcome_count": body.welcome_count,
        "welcome_realm_summary": &body.welcome_realm_summary,
        "outcome": body.outcome,
        "outcome_reason_code": &body.outcome_reason_code,
        "started_at": arkret_canonical::canonical::format_timestamp_canonical(body.started_at),
        "completed_at": arkret_canonical::canonical::format_timestamp_canonical(body.completed_at),
    });
    let object = value.as_object_mut().expect("receipt literal is an object");
    for (present, field) in [
        (
            body.device_list_update_event_id.is_some(),
            "device_list_update_event_id",
        ),
        (body.reanchor_event_id.is_some(), "reanchor_event_id"),
        (
            body.reanchor_batch_receipt_id.is_some(),
            "reanchor_batch_receipt_id",
        ),
        (
            body.welcome_realm_summary.is_some(),
            "welcome_realm_summary",
        ),
        (body.outcome_reason_code.is_some(), "outcome_reason_code"),
    ] {
        if !present {
            object.remove(field);
        }
    }
    for (key, extension) in body.extra.iter() {
        object.insert(key.clone(), extension.clone());
    }
    value
}

/// `recovery-receipt.schema.json#/properties/proof_summary`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryProofSummary {
    pub kind: RecoveryProofKind,
    pub proof_digest: Hash,
    /// Required for `device_quorum` and `threshold_recovery`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum_participant_count: Option<u32>,
    /// Participating share ids when `kind = threshold_recovery`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_ids: Option<Vec<String>>,
}

/// `recovery-receipt.schema.json#/properties/backup_classes_unlocked[]`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryBackupClassUnlocked {
    /// `recovery-receipt.schema.json` backup-class discriminator; reuses the
    /// canonical §7.1 controlled vocabulary rather than a duplicate enum.
    pub backup_kind: BackupKind,
    pub backup_id: BackupId,
    pub series_id: BackupSeriesId,
    pub ciphertext_digest: Hash,
}

/// `recovery-receipt.schema.json#/properties/welcome_realm_summary[]`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryWelcomeRealmSummary {
    pub realm_id: RealmId,
    pub mls_group_id: String,
    pub epoch: u64,
}

/// `recovery-receipt.schema.json#/properties/outcome` enum.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReceiptOutcome {
    Completed,
    Partial,
    AbortedByUser,
    PolicyDenied,
    EvidenceInsufficient,
    ServiceDefined,
}

/// `recovery-receipt.schema.json#/properties/auth_data`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryReceiptAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub signature: String,
}

// ─── DID-proof session grant strand ──────────────────────────────────────────
//
// The wire shapes for `POST /_arkret/gate/account/session-grants`
// (`ak.gate.account.command.issue_session_grant`) live in `crate::http` as
// `SessionGrantRequestBody` / `SessionGrantOutcome`, mirroring
// `service-operation-dtos.schema.json#/$defs/SessionGrantRequestBody`.
// The spec HTTP binding registers exactly one operation (proof in body,
// `x-arkret-auth.proof_in_body: true`); challenge acquisition is a
// deployment-local concern per `identity-did.md` §5.1 and has no
// dedicated `/_arkret/` sub-path.
