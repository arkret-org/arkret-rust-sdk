//! Key backup envelope, recovery policy, and recovery receipt wire models.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::{
    decode_multibase_base58btc, decode_multicodec_varint, encode_multibase_base58btc,
};
use arkret_wire::{
    AccountId, ActorId, AuditReasonText, AuthoritySetIssuer, AuthoritySetIssuerRole,
    AuthorizationLease, BackupId, BackupObjectRef, BackupRotationBinding, BackupRotationKind,
    BackupSeriesId, Base64UrlString, CbsProofBundle, ControlProposalAck, Cursor, DeviceId,
    DidCoreId, DidUrl, EpochRange, Event, EventId, EventInitialSubmission, EventKind,
    HPKE_SUITE_X25519_CHACHA20POLY1305_V1, HPKE_SUITES, Hash, HistoryEffectiveScope, LeaseBasisRef,
    NonEmptyString, PayloadProof, PolicyId, ProofContextId, RECOVERY_POLICY_SIGNATURE_TYPE,
    RealmId, ReasonCode, ReceiptId, RecoverySessionId, Result, SchemaId, SealId,
    ServiceOperationId, TransactionId, TrustDomainId, WireError, XExtensionMap,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::artifacts_keys::{KeyBackupUnlockProof, RecoveryIdentityModel, RecoveryPolicyRef};

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

/// One backup class evaluated at the Account Station's accepted PCR basis.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupActiveSeriesPointer {
    Absent {},
    Active {
        active_series_id: BackupSeriesId,
        series_pointer_version: u64,
    },
}

impl BackupActiveSeriesPointer {
    pub fn series_id(&self) -> Option<&BackupSeriesId> {
        match self {
            Self::Absent {} => None,
            Self::Active {
                active_series_id, ..
            } => Some(active_series_id),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupActiveSeriesState {
    pub account_id: AccountId,
    pub control_realm_id: RealmId,
    pub seal_basis: arkret_wire::SealBasis,
    pub secret_storage: BackupActiveSeriesPointer,
    pub mls_history: BackupActiveSeriesPointer,
}

impl BackupActiveSeriesState {
    pub fn pointer(&self, kind: BackupKind) -> &BackupActiveSeriesPointer {
        match kind {
            BackupKind::SecretStorage => &self.secret_storage,
            BackupKind::MlsHistory => &self.mls_history,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.seal_basis.validate_protocol_bounds()?;
        for pointer in [&self.secret_storage, &self.mls_history] {
            if matches!(
                pointer,
                BackupActiveSeriesPointer::Active {
                    series_pointer_version: 0,
                    ..
                }
            ) {
                return Err(WireError::Protocol(
                    "active backup pointer version must be positive".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsList {
    pub backups: Vec<KeyBackupSummary>,
    pub active_series: BackupActiveSeriesState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
}

impl KeysBackupsList {
    pub fn validate_for_query(&self, query: &KeyBackupsListQuery) -> Result<()> {
        self.active_series.validate()?;
        let limit = query.limit.unwrap_or(50);
        if !(1..=200).contains(&limit)
            || self.backups.len() > limit as usize
            || self.has_more != self.next_cursor.is_some()
            || (self.has_more && self.backups.is_empty())
        {
            return Err(WireError::Protocol(
                "backup metadata page exceeds its bounds or has inconsistent continuation"
                    .to_owned(),
            ));
        }
        let actor = ActorId::account(self.active_series.account_id.clone());
        for row in &self.backups {
            if row.actor_id != actor
                || query
                    .series_id
                    .as_ref()
                    .is_some_and(|series| series != &row.series_id)
                || query
                    .backup_kind
                    .is_some_and(|kind| kind != row.backup_kind)
            {
                return Err(WireError::Protocol(
                    "backup metadata page crosses its account or filter".to_owned(),
                ));
            }
        }
        let key = |row: &KeyBackupSummary| {
            (
                row.backup_kind.as_str().to_owned(),
                row.series_id.to_string(),
                row.series_seq,
                row.backup_id.to_string(),
            )
        };
        if self
            .backups
            .windows(2)
            .any(|pair| key(&pair[0]) >= key(&pair[1]))
            || arkret_canonical::canonical_json_bytes(self)?.len() > 1024 * 1024
        {
            return Err(WireError::Protocol(
                "backup metadata page is unordered or exceeds 1 MiB".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Conformance-vector id of the key-backup unlock-proof KAT
/// (`zh/conformance/conformance-vectors.md`).
pub const VECTOR_ID_KEY_BACKUP_UNLOCK_PROOF: &str = "ak.vector.key_backup.unlock_proof.v1";

/// Signing context of the canonical delete-intent transcript
/// (`key-management.md` §7.8.1). `high-risk-authority-proof.schema.json` is one
/// wire leaf shared by several consumers, so the leaf itself owns no context:
/// this row is registered with
/// `consumer_operation = ak.self.keys.backups.resource.delete.v1`, and reusing
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
    /// Recovery-unlock proof. The session MUST be verified and unexpired for
    /// the exact account, and its accepted proof summary MUST bind this proof's
    /// verification method to a recovery key in the frozen policy.
    RecoveryUnlock {
        recovery_session_id: RecoverySessionId,
        proof: PayloadProof,
    },
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
    /// and established by recovery unlock or device quorum. v1 carries no
    /// attestation reference here: the recovery policy has no attestation
    /// switch, so the field would be an unverified configuration surface.
    TrustedRecoveryService {
        service_id: DidCoreId,
        recovery_session_id: RecoverySessionId,
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

/// Request body of `ak.self.keys.backups.command.issue_delete_challenge.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsIssueDeleteChallengeRequestBody {
    /// While a challenge for the same `(account_id, backup_id, request_id)` is
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
    pub account_id: AccountId,
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
            "operation": ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_DELETE_V1,
            "request_id": self.request_id.as_str(),
            "account_id": &self.account_id,
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
    pub reason: Option<AuditReasonText>,
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
pub enum BackupSeriesEraseRowStatus {
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
    pub cbs_proof_bundles: Vec<CbsProofBundle>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSeriesEraseRow {
    pub backup_kind: BackupRotationKind,
    pub previous_series_id: BackupSeriesId,
    pub new_series_id: BackupSeriesId,
    pub status: BackupSeriesEraseRowStatus,
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
    pub series_results: Vec<BackupSeriesEraseRow>,
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
            != arkret_wire::CapabilityActionId::SELF_KEYS_BACKUP_SERIES_COMMAND_ERASE_V1
        {
            return Err(WireError::Protocol(
                "backup-series erase requires the exact erase authorization action".to_owned(),
            ));
        }
        if self.cbs_proof_bundles.len() > 64 {
            return Err(WireError::Protocol(
                "backup-series erase exceeds 64 CBS proof bundles".to_owned(),
            ));
        }
        for bundle in &self.cbs_proof_bundles {
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
                BackupSeriesEraseRowStatus::Erased if !result.remaining_backups.is_empty() => {
                    return Err(WireError::Protocol(
                        "erased backup series cannot retain remaining backups".to_owned(),
                    ));
                }
                BackupSeriesEraseRowStatus::Erased if result.reason_code.is_some() => {
                    return Err(WireError::Protocol(
                        "erased backup series cannot carry a reason code".to_owned(),
                    ));
                }
                BackupSeriesEraseRowStatus::Pending if result.reason_code.is_some() => {
                    return Err(WireError::Protocol(
                        "pending backup series cannot carry a reason code".to_owned(),
                    ));
                }
                BackupSeriesEraseRowStatus::FailedRetryable if result.reason_code.is_none() => {
                    return Err(WireError::Protocol(
                        "failed-retryable backup series requires a reason code".to_owned(),
                    ));
                }
                BackupSeriesEraseRowStatus::Pending
                | BackupSeriesEraseRowStatus::FailedRetryable => {
                    has_incomplete = true;
                }
                BackupSeriesEraseRowStatus::Erased => {}
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
#[serde(deny_unknown_fields)]
pub struct KeysBackupsReplaceOutcome {
    pub status: KeyBackupPutStatus,
    pub backup_id: BackupId,
    pub ciphertext_digest: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupSummary {
    pub backup_id: BackupId,
    pub actor_id: ActorId,
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
    pub contents: Vec<KeyBackupContentIndex>,
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
    pub actor_id: ActorId,
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
    pub contents: Vec<KeyBackupContentIndex>,
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
    /// `supersedes_id` + `supersedes_digest` REQUIRED).
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
    pub supersedes_id: Option<BackupId>,
    /// Key-backup hardening — canonical SHA-256 of the predecessor envelope,
    /// excluding `auth_data.signature`, mixed into the signing transcript on
    /// successor envelopes. REQUIRED whenever `supersedes_id` is set.
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
                let [KeyBackupContentIndex::HistorySecretRanges(index)] = self.contents.as_slice()
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
            0 if self.supersedes_id.is_some() || self.supersedes_digest.is_some() => {
                return Err(WireError::Protocol(
                    "key backup genesis forbids supersedes_id and supersedes_digest".to_owned(),
                ));
            }
            0 => {}
            _ if self.supersedes_id.is_none() || self.supersedes_digest.is_none() => {
                return Err(WireError::Protocol(
                    "key backup successor requires supersedes_id and supersedes_digest".to_owned(),
                ));
            }
            _ => {
                if self.supersedes_id.as_ref() == Some(&self.backup_id) {
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
        if domain.subdomain.trim().is_empty() {
            return Err(WireError::Protocol(
                "key backup domain-separation subdomain must not be empty".to_owned(),
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
        // key-management.md 7.9: an unknown, reserved or name-contradicting
        // `aead.aead_profile` fails closed for every recipient method, before
        // any per-method field-set rule runs.
        if let Err(reason) = self.aead.validate_aead_profile() {
            return Err(WireError::Protocol(format!(
                "key backup encryption: {reason} `{}`",
                self.aead.aead_profile.as_deref().unwrap_or_default()
            )));
        }
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
#[serde(deny_unknown_fields)]
pub struct KeyBackupDomainSeparation {
    pub subdomain: String,
    #[serde(default, skip_serializing_if = "XExtensionMap::is_empty")]
    pub aead_aad_extensions: XExtensionMap,
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

/// Reserved-but-unpublished AEAD profile namespace. `ak.aead.*` describes only
/// the AEAD construction; KEM agility belongs to `encryption.hpke_suite`, so an
/// envelope that encodes KEM semantics here fails closed even once a hybrid KEM
/// row goes active (key-management.md 7.9).
const RESERVED_HYBRID_KEM_AEAD_PROFILE_PREFIX: &str = "ak.aead.hybrid_kem.";

impl KeyBackupAead {
    /// Registry check for `aead_profile` (key-management.md 7.9, normative).
    ///
    /// An absent profile is allowed; a present one MUST name an active
    /// `aead-profile-registry.json` row and MUST agree with `aead.name`.
    /// Unknown, reserved-but-unpublished (`ak.aead.hybrid_kem.*`) or
    /// name-contradicting profiles fail closed: a receiver MUST NOT infer AEAD
    /// parameters from `aead.name` alone. The `Err` payload is the registered
    /// reason code so callers can attach it verbatim.
    pub fn validate_aead_profile(&self) -> std::result::Result<(), &'static str> {
        let Some(profile) = self.aead_profile.as_deref() else {
            return Ok(());
        };
        if profile.starts_with(RESERVED_HYBRID_KEM_AEAD_PROFILE_PREFIX) {
            return Err(ReasonCode::UNSUPPORTED_AEAD_PROFILE);
        }
        let registered = arkret_wire::AeadProfileId::from_wire(profile)
            .ok_or(ReasonCode::UNSUPPORTED_AEAD_PROFILE)?;
        let pinned = match registered {
            arkret_wire::AeadProfileId::Chacha20Poly1305V1 => KeyBackupAeadName::Chacha20Poly1305,
            arkret_wire::AeadProfileId::Xchacha20Poly1305V1 => KeyBackupAeadName::Xchacha20Poly1305,
        };
        if pinned != self.name {
            return Err(ReasonCode::UNSUPPORTED_AEAD_PROFILE);
        }
        Ok(())
    }
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
pub enum KeyBackupContentIndex {
    SecretStorage(SecretStorageContentIndex),
    HistorySecretRanges(HistorySecretRangeIndex),
}

impl KeyBackupContentIndex {
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
/// A closed methods union is the only signed recovery configuration source.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryPolicy {
    /// Schema id (`ak.schema.recovery_policy.v1`).
    pub schema: String,
    pub policy_id: PolicyId,
    pub account_id: AccountId,
    /// Monotonically increasing counter scoped by exact `account_id`.
    pub version: u64,
    /// Predecessor `policy_id`; `None` only for the genesis policy.
    pub supersedes_id: Option<PolicyId>,
    pub trust_domain: TrustDomainId,
    pub methods: Vec<RecoveryMethod>,
    /// Minimum wall-clock delay between recovery session creation and proof
    /// acceptance. Absence means no delay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_seconds: Option<u64>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub not_before: Option<DateTime<Utc>>,
    /// Natural expiry; explicit revoke is methods = [].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    pub auth_data: RecoveryPolicyAuthData,
    /// `x_*` extension fields (`patternProperties`).
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

impl RecoveryPolicy {
    /// Recheck a frozen session against accepted policy history without replacing
    /// its authority with a later policy. A revocation remains effective after
    /// a subsequent policy re-enables recovery.
    pub fn validate_inflight_authority(
        &self,
        updates: &[RecoveryPolicy],
        proof: Option<&crate::RecoverySessionProof>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.validate()?;
        let denied =
            || WireError::Protocol("recovery policy authority expired or revoked".to_owned());
        if self.methods.is_empty()
            || self.not_before.is_some_and(|at| now < at)
            || self.expires_at.is_some_and(|at| now >= at)
        {
            return Err(denied());
        }
        for update in updates {
            if update.account_id != self.account_id {
                return Err(denied());
            }
            if update.version > self.version && update.methods.is_empty() {
                return Err(denied());
            }
        }
        let mut used_keys = BTreeSet::new();
        if let Some(crate::RecoverySessionProof::RecoveryUnlock(proof)) = proof {
            used_keys.insert(proof.verification_method.as_str());
        }
        for method in &self.methods {
            for key in method.signing_keys() {
                if used_keys.contains(key.verification_method.as_str()) && !key.active_at(now) {
                    return Err(denied());
                }
            }
        }
        for update in updates
            .iter()
            .filter(|update| update.version > self.version)
        {
            for method in &update.methods {
                for key in method.signing_keys() {
                    if used_keys.contains(key.verification_method.as_str())
                        && key.revoked_at.is_some_and(|at| now >= at)
                    {
                        return Err(denied());
                    }
                }
            }
        }
        Ok(())
    }

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
            || (self.version == 1) != self.supersedes_id.is_none()
            || (self.version >= 2 && self.supersedes_id.is_none())
        {
            return Err(WireError::Protocol(
                "recovery policy version and supersedes_id do not form a valid chain".to_owned(),
            ));
        }
        if self
            .not_before
            .zip(self.expires_at)
            .is_some_and(|(start, end)| start >= end)
            || self.expires_at.is_some_and(|end| end <= self.issued_at)
        {
            return Err(WireError::Protocol(
                "recovery policy validity interval is empty".to_owned(),
            ));
        }
        let mut kinds = BTreeSet::new();
        let mut signing_refs = BTreeSet::new();
        let mut recipient_refs = BTreeSet::new();
        if self.methods.len() > 4 {
            return Err(WireError::Protocol("too many recovery methods".to_owned()));
        }
        for method in &self.methods {
            if !kinds.insert(method.kind()) {
                return Err(WireError::Protocol(
                    "recovery method tags must be unique".to_owned(),
                ));
            }
            method.validate()?;
            for key in method.signing_keys() {
                key.validate()?;
                if !signing_refs.insert(key.verification_method.as_str())
                    || !recipient_refs.insert(key.backup_hpke.key_agreement_ref.as_str())
                {
                    return Err(WireError::Protocol(
                        "recovery signing and recipient refs must each be unique".to_owned(),
                    ));
                }
            }
        }
        if !signing_refs.is_disjoint(&recipient_refs) {
            return Err(WireError::Protocol(
                "signing and backup HPKE method references must be disjoint".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn method(&self, kind: RecoveryProofKind) -> Option<&RecoveryMethod> {
        self.methods.iter().find(|method| method.kind() == kind)
    }

    pub fn signing_keys(&self) -> Vec<&RecoveryKeyEntry> {
        self.methods
            .iter()
            .flat_map(RecoveryMethod::signing_keys)
            .collect()
    }

    pub fn active_hpke_recipients(&self, at: DateTime<Utc>) -> Vec<&RecoveryKeyAgreementEntry> {
        if self.not_before.is_some_and(|start| at < start)
            || self.expires_at.is_some_and(|end| at >= end)
        {
            return Vec::new();
        }
        self.signing_keys()
            .into_iter()
            .filter(|key| key.active_at(at))
            .map(|key| &key.backup_hpke)
            .filter(|key| {
                key.not_before <= at
                    && at < key.expires_at
                    && key.revoked_at.is_none_or(|revoked| at < revoked)
            })
            .collect()
    }

    /// The authority methods that require external accepted evidence are supplied
    /// by the verifier. In particular, no DID root or device method is guessed
    /// from a policy signature or a core identifier.
    pub fn publication_authorization_rules(
        &self,
        evaluated_at: DateTime<Utc>,
        root_methods: &[DidUrl],
        device_methods: &BTreeMap<DeviceId, DidUrl>,
    ) -> Result<Vec<RecoveryPublicationAuthorizationRule>> {
        let mut rules = Vec::new();
        for method in &self.methods {
            let (mut methods, threshold) = match method {
                RecoveryMethod::DidRoot {} => {
                    if root_methods.is_empty() {
                        return Err(WireError::Protocol(
                            "accepted DID-root authority is missing".to_owned(),
                        ));
                    }
                    (root_methods.to_vec(), 1)
                }
                RecoveryMethod::RecoveryUnlock { keys } => (
                    keys.iter()
                        .filter(|key| key.active_at(evaluated_at))
                        .map(|k| k.verification_method.clone())
                        .collect(),
                    1,
                ),
                RecoveryMethod::DeviceQuorum { k, member_ids } => {
                    let methods = member_ids
                        .iter()
                        .map(|id| {
                            device_methods.get(id).cloned().ok_or_else(|| {
                                WireError::Protocol(
                                    "accepted quorum device method is missing".to_owned(),
                                )
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    (methods, *k)
                }
                RecoveryMethod::TrustedRecoveryService { services } => (
                    services
                        .iter()
                        .map(|s| s.authorization_verification_method.clone())
                        .collect(),
                    1,
                ),
            };
            methods.sort();
            methods.dedup();
            if methods.is_empty() || threshold as usize > methods.len() {
                return Err(WireError::Protocol(
                    "recovery authority threshold is unsatisfied".to_owned(),
                ));
            }
            rules.push(RecoveryPublicationAuthorizationRule {
                rule_id: method.kind().as_wire_str().to_owned(),
                proof_kind: method.kind(),
                issuer_role: AuthoritySetIssuerRole::IdentityRecovery,
                allowed_actions: vec![arkret_wire::event_kind_str::DEVICE_REANCHOR.to_owned()],
                issuers: methods
                    .into_iter()
                    .map(|verification_method| AuthoritySetIssuer {
                        verification_method,
                    })
                    .collect(),
                threshold,
            });
        }
        rules.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
        Ok(rules)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryMethod {
    DidRoot {},
    RecoveryUnlock {
        keys: Vec<RecoveryKeyEntry>,
    },
    DeviceQuorum {
        k: u32,
        member_ids: Vec<DeviceId>,
    },
    TrustedRecoveryService {
        services: Vec<RecoveryTrustedService>,
    },
}

impl RecoveryMethod {
    pub fn kind(&self) -> RecoveryProofKind {
        match self {
            Self::DidRoot {} => RecoveryProofKind::DidRoot,
            Self::RecoveryUnlock { .. } => RecoveryProofKind::RecoveryUnlock,
            Self::DeviceQuorum { .. } => RecoveryProofKind::DeviceQuorum,
            Self::TrustedRecoveryService { .. } => RecoveryProofKind::TrustedRecoveryService,
        }
    }
    pub fn signing_keys(&self) -> Vec<&RecoveryKeyEntry> {
        match self {
            Self::RecoveryUnlock { keys } => keys.iter().collect(),
            _ => Vec::new(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::DidRoot {} => true,
            Self::RecoveryUnlock { keys } => !keys.is_empty() && keys.len() <= 32,
            Self::DeviceQuorum { k, member_ids } => {
                *k >= 2
                    && *k as usize <= member_ids.len()
                    && member_ids.iter().collect::<BTreeSet<_>>().len() == member_ids.len()
            }
            Self::TrustedRecoveryService { services } => {
                !services.is_empty()
                    && services.len() <= 32
                    && services
                        .iter()
                        .map(|s| &s.service_id)
                        .collect::<BTreeSet<_>>()
                        .len()
                        == services.len()
            }
        };
        if !valid {
            return Err(WireError::Protocol(
                "recovery method has invalid threshold, empty members or duplicate entries"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Strongly typed recovery-policy members before signature metadata exists.
/// This is an authoring input, not a serializable wire object.
#[derive(Clone, Debug)]
pub struct UnsignedRecoveryPolicyBody {
    pub policy_id: PolicyId,
    pub account_id: AccountId,
    pub version: u64,
    pub supersedes_id: Option<PolicyId>,
    pub trust_domain: TrustDomainId,
    pub methods: Vec<RecoveryMethod>,
    pub cooldown_seconds: Option<u64>,
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
            account_id: body.account_id,
            version: body.version,
            supersedes_id: body.supersedes_id,
            trust_domain: body.trust_domain,
            methods: body.methods,
            cooldown_seconds: body.cooldown_seconds,
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
        "account_id": &body.account_id,
        "version": body.version,
        "supersedes_id": &body.supersedes_id,
        "trust_domain": &body.trust_domain,
        "methods": &body.methods,
        "cooldown_seconds": &body.cooldown_seconds,
        "issued_at": arkret_canonical::canonical::format_timestamp_canonical(body.issued_at),
        "not_before": body.not_before.map(arkret_canonical::canonical::format_timestamp_canonical),
        "expires_at": body.expires_at.map(arkret_canonical::canonical::format_timestamp_canonical),
    });
    let object = value.as_object_mut().expect("policy literal is an object");
    for (present, field) in [
        (body.cooldown_seconds.is_some(), "cooldown_seconds"),
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
    pub account_id: AccountId,
    pub version: u64,
    pub acceptance_basis_ref: LeaseBasisRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_policy_ref: Option<RecoveryPolicyRef>,
    pub trust_domain: TrustDomainId,
    pub methods: Vec<RecoveryMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_id: Option<PolicyId>,
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

/// Response for `ak.root.identity.recovery_policy.resource.get.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyActiveOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<AccountId>,
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

/// Request for `ak.root.identity.recovery_policy.command.publish.v1`.
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
    pub cbs_proof_bundles: Vec<CbsProofBundle>,
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
            publication_event: None,
            mls_frontier_leaves: None,
            authorization_lease: Some(value.authorization_lease),
            cbs_proof_bundles: value.cbs_proof_bundles,
            control_proposal_ack: value.control_proposal_ack,
            membership_compensation_evidence: None,
        }
    }
}

/// Response for `ak.root.identity.recovery_policy.command.publish.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyPublishOutcome {
    pub policy_id: PolicyId,
    pub account_id: AccountId,
    pub version: u64,
    pub acceptance_basis_ref: LeaseBasisRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

/// Deterministic projection of a signed methods entry and accepted authority
/// evidence. This derived view is never a second signed policy configuration.
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

/// `recovery-policy.schema.json#/$defs/recovery_method`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTrustedService {
    pub service_id: DidCoreId,
    pub audience: NonEmptyString,
    pub authorization_verification_method: DidUrl,
}

/// `recovery-policy.schema.json#/$defs/recovery_key_entry` — a recovery
/// signing key the principal authorizes for `recovery_unlock` proofs. The
/// `verification_method` is the stable `recovery_secret_ref` a recovery_unlock
/// proof references; the proof signature is verified under this entry's public
/// key resolved via `verification_method`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyEntry {
    /// DID URL identifying this recovery signing key
    /// (e.g. `did:webvh:...#recovery-1`). Unique within method signing entries.
    pub verification_method: DidUrl,
    /// Signing public multikey. This is never the paired HPKE public key.
    pub public_key_multibase: NonEmptyString,
    /// Dedicated backup recipient entry paired with this signing key.
    pub backup_hpke: RecoveryKeyAgreementEntry,
    /// Registered signature algorithm (PQ use requires the matching profile).
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
    pub fn active_at(&self, at: DateTime<Utc>) -> bool {
        self.not_before <= at
            && at < self.expires_at
            && self.revoked_at.is_none_or(|revoked| at < revoked)
    }

    pub fn validate(&self) -> Result<()> {
        self.backup_hpke.validate()?;
        if self.public_key_multibase == self.backup_hpke.public_key_multibase {
            return Err(WireError::Protocol(
                "recovery signing key has invalid algorithm or reuses backup material".to_owned(),
            ));
        }
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

/// `recovery-policy.schema.json#/properties/auth_data`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryPolicyAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub signature: String,
}

/// AKP recovery proof-family enum, aligned to `recovery-policy.schema.json`
/// `methods[].kind` and `recovery-receipt.schema.json`
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
}

impl RecoveryProofKind {
    /// All variants in `recovery-policy.schema.json` enum order.
    pub const ALL: &'static [Self] = &[
        Self::DidRoot,
        Self::RecoveryUnlock,
        Self::DeviceQuorum,
        Self::TrustedRecoveryService,
    ];

    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::DidRoot => "did_root",
            Self::RecoveryUnlock => "recovery_unlock",
            Self::DeviceQuorum => "device_quorum",
            Self::TrustedRecoveryService => "trusted_recovery_service",
        }
    }
}

/// REC-1 (spec head, `recovery-receipt.schema.json`) — Rust shape for
/// `ak.schema.recovery_receipt.v1`. Signed completion receipt for a principal
/// recovery strand, bound to the `recovery_session_id` used by every proof,
/// backup unlock, and MLS Welcome replay action.
///
/// Required surface: `schema`, `receipt_id`, `transaction_id`,
/// `transaction_request_digest`, `account_id`,
/// `recovery_session_id`, `policy_id`, `policy_version`, `trust_domain`,
/// `new_device_id`, `reanchor_batch_receipt_id`, `first_generation_seal_id`,
/// `proof_summary`, `unlocked_backups`, `welcome_count`, `outcome`,
/// `started_at`, `completed_at`, `auth_data`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryReceipt {
    /// Schema id (`ak.schema.recovery_receipt.v1`).
    pub schema: String,
    pub receipt_id: ReceiptId,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub account_id: AccountId,
    pub recovery_session_id: RecoverySessionId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub trust_domain: TrustDomainId,
    pub new_device_id: DeviceId,
    pub identity_model: RecoveryIdentityModel,
    pub recovery_authority_kind: RecoveryAuthorityKind,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub previous_model_generation_ref: u64,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub result_model_generation_ref: u64,
    pub authorization_event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reanchor_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reanchor_batch_receipt_id: Option<ReceiptId>,
    /// Identity of the first new-generation Seal committed by this recovery.
    /// It equals `prepared_plan.binding.first_generation_seal_id` and the id of
    /// the Seal carried beside this receipt in the same `RecoveryTerminalCommit`.
    pub first_generation_seal_id: SealId,
    pub proof_summary: RecoveryProofSummary,
    pub unlocked_backups: Vec<RecoveryBackupClassUnlocked>,
    /// MLS Welcomes successfully replayed for the recovering device.
    pub welcome_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_realm_summaries: Option<Vec<RecoveryWelcomeRealmSummary>>,
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

/// Recovery authority selected by the accepted PCR recovery policy for the
/// signed terminal receipt.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAuthorityKind {
    PcrPolicy,
    DidRoot,
}

/// Strongly typed recovery-receipt members before signature metadata exists.
#[derive(Clone, Debug)]
pub struct UnsignedRecoveryReceiptBody {
    pub receipt_id: ReceiptId,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub account_id: AccountId,
    pub recovery_session_id: RecoverySessionId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub trust_domain: TrustDomainId,
    pub new_device_id: DeviceId,
    pub identity_model: RecoveryIdentityModel,
    pub recovery_authority_kind: RecoveryAuthorityKind,
    pub previous_model_generation_ref: u64,
    pub result_model_generation_ref: u64,
    pub authorization_event_id: EventId,
    pub reanchor_event_id: Option<EventId>,
    pub reanchor_batch_receipt_id: Option<ReceiptId>,
    pub first_generation_seal_id: SealId,
    pub proof_summary: RecoveryProofSummary,
    pub unlocked_backups: Vec<RecoveryBackupClassUnlocked>,
    pub welcome_count: u64,
    pub welcome_realm_summaries: Option<Vec<RecoveryWelcomeRealmSummary>>,
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
            account_id: body.account_id,
            recovery_session_id: body.recovery_session_id,
            policy_id: body.policy_id,
            policy_version: body.policy_version,
            trust_domain: body.trust_domain,
            new_device_id: body.new_device_id,
            identity_model: body.identity_model,
            recovery_authority_kind: body.recovery_authority_kind,
            previous_model_generation_ref: body.previous_model_generation_ref,
            result_model_generation_ref: body.result_model_generation_ref,
            authorization_event_id: body.authorization_event_id,
            reanchor_event_id: body.reanchor_event_id,
            reanchor_batch_receipt_id: body.reanchor_batch_receipt_id,
            first_generation_seal_id: body.first_generation_seal_id,
            proof_summary: body.proof_summary,
            unlocked_backups: body.unlocked_backups,
            welcome_count: body.welcome_count,
            welcome_realm_summaries: body.welcome_realm_summaries,
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
        "account_id": &body.account_id,
        "recovery_session_id": &body.recovery_session_id,
        "policy_id": &body.policy_id,
        "policy_version": body.policy_version,
        "trust_domain": &body.trust_domain,
        "new_device_id": &body.new_device_id,
        "identity_model": body.identity_model,
        "recovery_authority_kind": body.recovery_authority_kind,
        "previous_model_generation_ref": &body.previous_model_generation_ref,
        "result_model_generation_ref": &body.result_model_generation_ref,
        "authorization_event_id": &body.authorization_event_id,
        "reanchor_event_id": &body.reanchor_event_id,
        "reanchor_batch_receipt_id": &body.reanchor_batch_receipt_id,
        "first_generation_seal_id": &body.first_generation_seal_id,
        "proof_summary": &body.proof_summary,
        "unlocked_backups": &body.unlocked_backups,
        "welcome_count": body.welcome_count,
        "welcome_realm_summaries": &body.welcome_realm_summaries,
        "outcome": body.outcome,
        "outcome_reason_code": &body.outcome_reason_code,
        "started_at": arkret_canonical::canonical::format_timestamp_canonical(body.started_at),
        "completed_at": arkret_canonical::canonical::format_timestamp_canonical(body.completed_at),
    });
    let object = value.as_object_mut().expect("receipt literal is an object");
    for (present, field) in [
        (body.reanchor_event_id.is_some(), "reanchor_event_id"),
        (
            body.reanchor_batch_receipt_id.is_some(),
            "reanchor_batch_receipt_id",
        ),
        (
            body.welcome_realm_summaries.is_some(),
            "welcome_realm_summaries",
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
    /// Required for `device_quorum`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum_participant_count: Option<u32>,
}

/// `recovery-receipt.schema.json#/properties/unlocked_backups[]`.
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

/// `recovery-receipt.schema.json#/properties/welcome_realm_summaries[]`.
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

#[cfg(test)]
mod closed_outcome_tests {
    use super::*;

    #[test]
    fn key_backup_outcomes_reject_unknown_fields() {
        let list = json!({
            "backups": [],
            "has_more": false,
            "unexpected": 42
        });
        let list_error = serde_json::from_value::<KeysBackupsList>(list).unwrap_err();
        assert!(list_error.to_string().contains("unknown field"));

        let replace = json!({
            "status": "accepted",
            "backup_id": "ak:backup:01964137-0000-7000-8000-000000000000",
            "ciphertext_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "unexpected": 42
        });
        let replace_error =
            serde_json::from_value::<KeysBackupsReplaceOutcome>(replace).unwrap_err();
        assert!(replace_error.to_string().contains("unknown field"));
    }
}

#[cfg(test)]
mod aead_profile_tests {
    use super::*;

    fn aead(name: KeyBackupAeadName, profile: Option<&str>) -> KeyBackupAead {
        KeyBackupAead {
            name,
            aead_profile: profile.map(str::to_owned),
            nonce_salt: None,
            nonce: None,
            enc: None,
            extra: XExtensionMap::default(),
        }
    }

    #[test]
    fn absent_profile_is_allowed() {
        assert!(
            aead(KeyBackupAeadName::Xchacha20Poly1305, None)
                .validate_aead_profile()
                .is_ok()
        );
    }

    #[test]
    fn active_registry_profile_matching_its_name_is_allowed() {
        assert!(
            aead(
                KeyBackupAeadName::Xchacha20Poly1305,
                Some("ak.aead.xchacha20_poly1305.v1"),
            )
            .validate_aead_profile()
            .is_ok()
        );
        assert!(
            aead(
                KeyBackupAeadName::Chacha20Poly1305,
                Some("ak.aead.chacha20_poly1305.v1"),
            )
            .validate_aead_profile()
            .is_ok()
        );
    }

    #[test]
    fn unknown_reserved_and_contradicting_profiles_fail_closed() {
        for (name, profile) in [
            // Unregistered profile id.
            (
                KeyBackupAeadName::Xchacha20Poly1305,
                "ak.aead.unpublished_future.v1",
            ),
            // Reserved-but-unpublished hybrid KEM namespace.
            (
                KeyBackupAeadName::Xchacha20Poly1305,
                "ak.aead.hybrid_kem.x25519_mlkem768.v1",
            ),
            // Registered profile that contradicts `aead.name`; the profile
            // pins the algorithm, so the name may not be trusted instead.
            (
                KeyBackupAeadName::Aes256Gcm,
                "ak.aead.xchacha20_poly1305.v1",
            ),
        ] {
            assert_eq!(
                aead(name, Some(profile)).validate_aead_profile(),
                Err(ReasonCode::UNSUPPORTED_AEAD_PROFILE),
                "{profile} under {name:?} must fail closed",
            );
        }
    }

    #[test]
    fn encryption_validate_rejects_an_unsupported_profile() {
        let encryption = KeyBackupEncryption {
            recipient_method: KeyBackupRecipientMethod::SecretStorageKey,
            recipient_key_ref: Some("ak.secret_storage.default".to_owned()),
            aead: aead(
                KeyBackupAeadName::Xchacha20Poly1305,
                Some("ak.aead.hybrid_kem.x25519_mlkem768.v1"),
            ),
            kdf: None,
            key_commitment: None,
            hpke_suite: None,
            extra: XExtensionMap::default(),
        };
        let error = encryption.validate().expect_err("reserved profile");
        assert!(
            error
                .to_string()
                .contains(ReasonCode::UNSUPPORTED_AEAD_PROFILE),
            "{error}",
        );
    }
}

// ─── DID-proof session grant strand ──────────────────────────────────────────
//
// The wire shapes for `POST /_arkret/gate/account/session-grants`
// (`ak.gate.account.command.issue_session_grant.v1`) live in `crate::http` as
// `SessionGrantRequestBody` / `SessionGrantOutcome`, mirroring
// `service-operation-dtos.schema.json#/$defs/SessionGrantRequestBody`.
// The spec HTTP binding registers exactly one operation (proof in body,
// `x-arkret-auth.proof_in_body: true`); challenge acquisition is a
// deployment-local concern per `identity-did.md` §5.1 and has no
// dedicated `/_arkret/` sub-path.

#[cfg(test)]
mod current_backup_page_tests {
    use serde_json::json;

    use super::*;

    fn page() -> Value {
        json!({"backups": [], "has_more": false, "active_series": {
            "account_id": {"principal_id":"ak:did_core:web:alice.example", "station_id":"ak:did_core:web:station.example"},
            "control_realm_id":"ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
            "seal_basis":{"leaves":[format!("ak:seal:sha256:{}", "b".repeat(64))]},
            "secret_storage":{"state":"absent"}, "mls_history":{"state":"absent"}
        }})
    }
    fn query() -> KeyBackupsListQuery {
        KeyBackupsListQuery {
            series_id: None,
            backup_kind: None,
            cursor: None,
            limit: None,
        }
    }
    #[test]
    fn current_backup_page_requires_both_explicit_pointer_states() {
        let good: KeysBackupsList = serde_json::from_value(page()).unwrap();
        good.validate_for_query(&query()).unwrap();
        for pointer in ["secret_storage", "mls_history"] {
            let mut wire = page();
            wire["active_series"]
                .as_object_mut()
                .unwrap()
                .remove(pointer);
            assert!(serde_json::from_value::<KeysBackupsList>(wire).is_err());
        }
        for field in ["active_series", "backups"] {
            let mut wire = page();
            wire.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<KeysBackupsList>(wire).is_err());
        }
        let mut wire = page();
        wire["next_cursor"] = Value::Null;
        assert!(serde_json::from_value::<KeysBackupsList>(wire).is_err());
        let mut wire = page();
        wire["active_series"]["secret_storage"] = json!({"state":"absent", "active_series_id":"ak:backup_series:01964137-1000-7000-8000-000000000001"});
        assert!(serde_json::from_value::<KeysBackupsList>(wire).is_err());
    }
    #[test]
    fn current_backup_page_rejects_zero_version_and_false_completion() {
        let mut wire = page();
        wire["active_series"]["secret_storage"] = json!({"state":"active", "active_series_id":"ak:backup_series:01964137-1000-7000-8000-000000000001", "series_pointer_version":0});
        let invalid: KeysBackupsList = serde_json::from_value(wire).unwrap();
        assert!(invalid.validate_for_query(&query()).is_err());
        let mut wire = page();
        wire["has_more"] = true.into();
        let invalid: KeysBackupsList = serde_json::from_value(wire).unwrap();
        assert!(invalid.validate_for_query(&query()).is_err());
    }
    #[test]
    fn current_backup_page_checks_actor_filter_order_and_bounds() {
        let mut wire = page();
        let row = json!({"backup_id":"ak:backup:01964137-1000-7000-8000-000000000001", "actor_id":{"kind":"account", "account_id":wire["active_series"]["account_id"]},
            "backup_kind":"secret_storage", "backup_version":"kb_1", "created_at":"2026-09-09T00:00:00.000Z", "ciphertext_digest":format!("sha256:{}", "a".repeat(64)),
            "encryption":{"recipient_method":"secret_storage_key"}, "series_id":"ak:backup_series:01964137-1000-7000-8000-000000000001", "series_seq":0});
        wire["backups"] = json!([row]);
        let good: KeysBackupsList = serde_json::from_value(wire).unwrap();
        good.validate_for_query(&query()).unwrap();
        let mut invalid = good.clone();
        invalid.backups.push(invalid.backups[0].clone());
        assert!(invalid.validate_for_query(&query()).is_err());
        let mut invalid = good.clone();
        invalid.active_series.account_id.station_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(invalid.validate_for_query(&query()).is_err());
        let mut filter = query();
        filter.backup_kind = Some(BackupKind::MlsHistory);
        assert!(good.validate_for_query(&filter).is_err());
        filter = query();
        filter.limit = Some(201);
        assert!(good.validate_for_query(&filter).is_err());
    }
}

#[cfg(test)]
mod recovery_method_tests {
    use super::*;

    #[test]
    fn recovery_methods_are_closed_and_duplicate_holders_cannot_lower_the_threshold() {
        let root: RecoveryMethod = serde_json::from_value(json!({"kind":"did_root"})).unwrap();
        root.validate().unwrap();
        assert!(
            serde_json::from_value::<RecoveryMethod>(
                json!({"kind":"did_root", "verification_method":"did:key:z6MkPinned#root"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<RecoveryMethod>(
                json!({"kind":"device_quorum", "k":2, "member_ids":[], "threshold":1})
            )
            .is_err()
        );
        let member = "ak:device:01904100-0000-7000-8000-000000000001";
        let quorum: RecoveryMethod = serde_json::from_value(
            json!({"kind":"device_quorum","k":2,"member_ids":[member,member]}),
        )
        .unwrap();
        assert!(quorum.validate().is_err());
        let unlock: RecoveryMethod =
            serde_json::from_value(json!({"kind":"recovery_unlock","keys":[]})).unwrap();
        assert!(unlock.validate().is_err());
    }

    #[test]
    fn frozen_sessions_survive_rotation_but_not_expiry_or_explicit_revocation() {
        let fixture =
            arkret_schema_conformance::spec_json_artifact("fixtures/recovery-policy-fixture.json")
                .unwrap();
        let mut value =
            fixture["schema_validation_cases"][0]["instance"]["event"]["payload"]["value"].clone();
        value["methods"] = json!([{"kind":"did_root"}]);
        let mut frozen: RecoveryPolicy = serde_json::from_value(value).unwrap();
        let now = frozen.issued_at + chrono::Duration::seconds(10);
        frozen.expires_at = Some(now + chrono::Duration::seconds(60));
        let mut rotation = frozen.clone();
        rotation.version += 1;
        frozen
            .validate_inflight_authority(&[rotation.clone()], None, now)
            .unwrap();
        assert!(
            frozen
                .validate_inflight_authority(&[], None, frozen.expires_at.unwrap())
                .is_err()
        );
        let mut revoke = rotation.clone();
        revoke.methods.clear();
        let mut reenabled = rotation.clone();
        reenabled.version += 1;
        assert!(
            frozen
                .validate_inflight_authority(&[revoke, reenabled], None, now)
                .is_err()
        );

        let key: RecoveryKeyEntry = serde_json::from_value(
            arkret_schema_conformance::spec_json_artifact("fixtures/key-backup-fixture.json")
                .unwrap()
                .pointer("/schema_validation_cases/3/instance/methods/0/keys/0")
                .unwrap()
                .clone(),
        )
        .unwrap();
        frozen.methods = vec![
            RecoveryMethod::RecoveryUnlock {
                keys: vec![key.clone()],
            },
            RecoveryMethod::DidRoot {},
        ];
        let proof:crate::RecoverySessionProof=serde_json::from_value(json!({
            "kind":"recovery_unlock","challenge":"A".repeat(43),
            "recovery_secret_ref":key.verification_method,"verification_method":key.verification_method,
            "signature_algorithm":"Ed25519","unlock_commitment":format!("sha256:{}","a".repeat(64)),"signature":arkret_canonical::base64url_encode([0u8; 64])
        })).unwrap();
        rotation = frozen.clone();
        rotation.version += 1;
        let RecoveryMethod::RecoveryUnlock { keys } = &mut rotation.methods[0] else {
            unreachable!()
        };
        keys[0].revoked_at = Some(now);
        assert!(
            frozen
                .validate_inflight_authority(&[rotation.clone()], Some(&proof), now)
                .is_err()
        );
        // Revoking one factor cannot silently turn independent OR methods into AND.
        let root_proof: crate::RecoverySessionProof = serde_json::from_value(json!({
            "kind":"did_root","challenge":"A".repeat(43),
            "verification_method":"did:web:alice.example#root",
            "signature_algorithm":"Ed25519","signature":arkret_canonical::base64url_encode([0u8; 64])
        }))
        .unwrap();
        frozen
            .validate_inflight_authority(&[rotation], Some(&root_proof), now)
            .unwrap();
    }

    #[test]
    fn signed_policy_has_one_source_and_requires_external_root_evidence() {
        let value = json!({
            "schema":"ak.schema.recovery_policy.v1",
            "policy_id":"ak:policy:01904100-0000-7000-8000-000000000001",
            "account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:station.example"},
            "version":1,"supersedes_id":null,"trust_domain":"ak:trust_domain:station.example",
            "methods":[{"kind":"did_root"}],"issued_at":"2026-09-10T00:00:00.000Z",
            "auth_data":{"verification_method":"did:web:alice.example#device","signature_algorithm":"Ed25519","signature":"c2ln"}
        });
        let mut policy: RecoveryPolicy = serde_json::from_value(value.clone()).unwrap();
        policy.validate().unwrap();
        assert!(
            policy
                .publication_authorization_rules(policy.issued_at, &[], &BTreeMap::new())
                .is_err()
        );
        let root = DidUrl::new("did:web:alice.example#root").unwrap();
        let rules = policy
            .publication_authorization_rules(policy.issued_at, &[root.clone()], &BTreeMap::new())
            .unwrap();
        assert_eq!(rules[0].issuers[0].verification_method, root);
        policy.methods.push(RecoveryMethod::DidRoot {});
        assert!(policy.validate().is_err());
        let mut old = value;
        old["allowed_proof_kinds"] = json!(["did_root"]);
        assert!(serde_json::from_value::<RecoveryPolicy>(old).is_err());
    }

    #[test]
    fn trusted_service_entries_are_or_alternatives_with_exact_authority_members() {
        let service = json!({
            "service_id":"ak:did_core:web:recovery.example",
            "audience":"https://station.example/recovery",
            "authorization_verification_method":"did:web:recovery.example#recovery"
        });
        let method: RecoveryMethod = serde_json::from_value(
            json!({"kind":"trusted_recovery_service","services":[service.clone()]}),
        )
        .unwrap();
        method.validate().unwrap();
        let duplicate: RecoveryMethod = serde_json::from_value(
            json!({"kind":"trusted_recovery_service","services":[service.clone(),service.clone()]}),
        )
        .unwrap();
        assert!(duplicate.validate().is_err());
        assert!(
            serde_json::from_value::<RecoveryMethod>(
                json!({"kind":"trusted_recovery_service","k":1,"services":[service]})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<RecoveryMethod>(
                json!({"kind":"trusted_recovery_service","services":[{
                    "service_id":"ak:did_core:web:recovery.example",
                    "audience":"https://station.example/recovery",
                    "authorization_verification_method":"did:web:recovery.example#recovery",
                    "recovery_action_scope":["everything"]
                }]})
            )
            .is_err()
        );
    }
}
