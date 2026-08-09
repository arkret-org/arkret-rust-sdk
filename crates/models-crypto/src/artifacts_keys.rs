//! Key management and recovery schema artifact counterparts.

use std::collections::BTreeMap;

use arkret_wire::{
    AuthoritySetPolicy, AuthoritySetRef, BackupId, BackupSeriesId, Base64UrlString, DeviceId,
    DeviceReanchorPreFenceBasis, Did, DidUrl, Error, EventId, Hash, LeaseBasisRef, NonEmptyString,
    PolicyId, RECOVERY_IDENTITY_REANCHOR_AUTHORITY_SET_ID, RealmId, ReasonCode, RecoverySessionId,
    Result, SchemaId, ScopeRef, TransactionId, TypedTrustDomainId, XExtensionMap,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::key_backup::{
    BackupKind, BackupSeriesEraseOutcome, BackupSeriesEraseRequestBody, KeyBackup,
    KeyBackupSignatureAlgorithm, KeysBackupsDeleteChallenge, KeysBackupsDeleteOutcome,
    KeysBackupsDeleteRequestBody, KeysBackupsIssueDeleteChallengeRequestBody, KeysBackupsList,
    KeysBackupsReplaceOutcome, ManagedPrincipalBinding, RecoveryProofKind,
};
use crate::keys::{
    DeviceGenerationStatus, KeysClaimOutcome, KeysClaimRequestBody, KeysQueryOutcome,
    KeysQueryRequestBody, KeysUploadOutcome, KeysUploadRequestBody,
};

/// Counterpart for `spec/v1/artifacts/schemas/key-backup-plaintext.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupPlaintext {
    pub schema: String,
    pub backup_id: BackupId,
    pub backup_kind: BackupKind,
    pub series_id: BackupSeriesId,
    pub series_seq: u64,
    pub items: Vec<PlaintextItem>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

impl KeyBackupPlaintext {
    pub const SCHEMA: &'static str = SchemaId::KEY_BACKUP_PLAINTEXT_V1;

    /// Validate the decrypted keybag and its byte-for-byte binding to the
    /// authenticated public envelope. A receiver MUST run this before importing
    /// any secret material.
    pub fn validate_for_envelope(&self, envelope: &KeyBackup) -> Result<()> {
        envelope.validate_envelope_fields()?;
        if self.schema != Self::SCHEMA {
            return Err(Error::Protocol(format!(
                "key backup plaintext schema must be {}",
                Self::SCHEMA
            )));
        }
        if self.backup_id != envelope.backup_id
            || self.backup_kind != envelope.backup_kind
            || self.series_id != envelope.series_id
            || self.series_seq != envelope.series_seq
        {
            return Err(Error::Protocol(
                "key backup plaintext envelope identity mismatch".to_owned(),
            ));
        }
        if self.items.is_empty() || self.items.len() != envelope.contents.len() {
            return Err(Error::Protocol(
                "key backup public/plaintext item counts differ or are empty".to_owned(),
            ));
        }
        for (public, secret) in envelope.contents.iter().zip(&self.items) {
            secret.validate()?;
            if public.item_kind != secret.item_kind
                || public.secret_id.as_deref() != Some(secret.secret_id.as_str())
                || public.realm_id != secret.realm_id
                || public.managed_principal_binding != secret.managed_principal_binding
                || public.mls_group_id != secret.mls_group_id
                || public.epoch != secret.epoch
                || public.first_event_id != secret.first_event_id
                || public.last_event_id != secret.last_event_id
                || public.secret_version != secret.secret_version()?
            {
                return Err(Error::Protocol(
                    "key backup public/plaintext item metadata mismatch".to_owned(),
                ));
            }
        }

        let canonical_set = |bindings: Vec<ManagedPrincipalBinding>| {
            bindings
                .into_iter()
                .map(|binding| {
                    arkret_canonical::canonical_json_bytes(&binding)
                        .map(|bytes| (bytes, binding))
                        .map_err(Error::from)
                })
                .collect::<Result<BTreeMap<_, _>>>()
                .map(|bindings| bindings.into_values().collect::<Vec<_>>())
        };
        let public_bindings = canonical_set(
            envelope
                .contents
                .iter()
                .filter_map(|item| item.managed_principal_binding.clone())
                .collect(),
        )?;
        let plaintext_bindings = canonical_set(
            self.items
                .iter()
                .filter_map(|item| item.managed_principal_binding.clone())
                .collect(),
        )?;
        let aad_bindings = canonical_set(
            envelope
                .domain_separation
                .aead_aad
                .managed_principal_bindings
                .clone(),
        )?;
        if public_bindings != plaintext_bindings || public_bindings != aad_bindings {
            return Err(Error::Protocol(
                "key backup public/plaintext/AAD managed binding sets differ".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Counterpart for `spec/v1/artifacts/schemas/key-backup-plaintext.schema.json#/$defs/item_kind`.
pub type ItemKind = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/key-backup-plaintext.schema.json#/$defs/plaintext_item`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlaintextItem {
    pub item_kind: ItemKind,
    pub secret_id: String,
    pub secret_b64u: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_principal_binding: Option<ManagedPrincipalBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<EventId>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

impl PlaintextItem {
    pub fn validate(&self) -> Result<()> {
        if self.secret_id.is_empty()
            || !self
                .secret_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        {
            return Err(Error::Protocol(
                "key backup plaintext secret_id must match ^[A-Za-z0-9_.-]+$".to_owned(),
            ));
        }
        let secret =
            arkret_canonical::base64url::base64url_decode(&self.secret_b64u).map_err(|error| {
                Error::Protocol(format!(
                    "key backup plaintext secret_b64u must be unpadded base64url: {error}"
                ))
            })?;
        if secret.is_empty() || self.secret_b64u.contains('=') {
            return Err(Error::Protocol(
                "key backup plaintext secret_b64u must encode non-empty bytes without padding"
                    .to_owned(),
            ));
        }
        if self.managed_principal_binding.is_some()
            && (self.realm_id.is_none()
                || !matches!(
                    self.item_kind.as_str(),
                    "mls_group_state" | "mls_epoch_secret" | "pending_welcome"
                ))
        {
            return Err(Error::Protocol(
                "managed key backup plaintext requires realm_id and an MLS item_kind".to_owned(),
            ));
        }
        Ok(())
    }

    /// Project the plaintext generation into the public envelope's bounded
    /// `secret_version` index without truncation.
    pub fn secret_version(&self) -> Result<Option<u32>> {
        self.secret_generation
            .map(|generation| {
                u32::try_from(generation).map_err(|_| {
                    Error::Protocol(
                        "key backup plaintext secret_generation exceeds public secret_version"
                            .to_owned(),
                    )
                })
            })
            .transpose()
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/key-backup-unlock-proof.schema.json#/properties/auth_data`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupUnlockProofAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: Base64UrlString,
    pub signed_fields: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupUnlockProof {
    pub schema: String,
    pub recovery_session_id: RecoverySessionId,
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub backup_id: BackupId,
    pub backup_kind: BackupKind,
    pub series_id: BackupSeriesId,
    pub ciphertext_digest: Hash,
    pub proof_kind: ProofKind,
    pub proof_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    pub auth_data: KeyBackupUnlockProofAuthData,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

impl KeyBackupUnlockProof {
    pub const SCHEMA: &'static str = SchemaId::KEY_BACKUP_UNLOCK_PROOF_V1;

    /// Validate the signed wire shape and the SDK-owned signature coverage.
    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(Error::Protocol(format!(
                "key backup unlock proof schema must be {}",
                Self::SCHEMA
            )));
        }
        validate_unlock_proof_signature_algorithm(self.auth_data.signature_algorithm)?;
        if self.challenge.as_deref().is_some_and(|challenge| {
            challenge.len() != 43
                || !challenge.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
                })
        }) {
            return Err(Error::Protocol(
                "key backup unlock proof challenge must be 43 base64url characters".to_owned(),
            ));
        }
        let actual = self
            .auth_data
            .signed_fields
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        if actual.len() != self.auth_data.signed_fields.len()
            || KEY_BACKUP_UNLOCK_PROOF_SIGNED_FIELDS
                .iter()
                .any(|field| !actual.contains(field))
        {
            return Err(Error::Protocol(
                "key backup unlock proof signed_fields must be unique and cover the canonical field set"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical signature transcript for a fully formed receiver-side proof.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut unsigned = serde_json::to_value(self)?;
        unsigned
            .get_mut("auth_data")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                Error::Protocol("key backup unlock proof auth_data must be an object".to_owned())
            })?
            .remove("signature");
        key_backup_unlock_proof_signing_payload_bytes(&unsigned)
    }
}

const KEY_BACKUP_UNLOCK_PROOF_SIGNED_FIELDS: [&str; 11] = [
    "schema",
    "recovery_session_id",
    "principal_id",
    "requesting_device_id",
    "backup_id",
    "backup_kind",
    "series_id",
    "ciphertext_digest",
    "proof_kind",
    "proof_digest",
    "issued_at",
];

/// Signature metadata for an unlock proof before a signature exists.
#[derive(Clone, Debug)]
pub struct UnsignedKeyBackupUnlockProofAuthData {
    verification_method: DidUrl,
    signature_algorithm: KeyBackupSignatureAlgorithm,
}

impl UnsignedKeyBackupUnlockProofAuthData {
    pub fn new(
        verification_method: DidUrl,
        signature_algorithm: KeyBackupSignatureAlgorithm,
    ) -> Result<Self> {
        validate_unlock_proof_signature_algorithm(signature_algorithm)?;
        Ok(Self {
            verification_method,
            signature_algorithm,
        })
    }
}

/// Strongly typed unlock-proof authoring state. It is intentionally not
/// serializable, so only [`Self::attach_signature`] can produce the outbound
/// wire model.
#[derive(Clone, Debug)]
pub struct UnsignedKeyBackupUnlockProof {
    recovery_session_id: RecoverySessionId,
    principal_id: Did,
    requesting_device_id: DeviceId,
    backup_id: BackupId,
    backup_kind: BackupKind,
    series_id: BackupSeriesId,
    ciphertext_digest: Hash,
    proof_kind: ProofKind,
    proof_digest: Hash,
    challenge: Option<Base64UrlString>,
    issued_at: DateTime<Utc>,
    auth_data: UnsignedKeyBackupUnlockProofAuthData,
    extra: XExtensionMap,
}

impl UnsignedKeyBackupUnlockProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        recovery_session_id: RecoverySessionId,
        principal_id: Did,
        requesting_device_id: DeviceId,
        backup_id: BackupId,
        backup_kind: BackupKind,
        series_id: BackupSeriesId,
        ciphertext_digest: Hash,
        proof_kind: ProofKind,
        proof_digest: Hash,
        challenge: Option<Base64UrlString>,
        issued_at: DateTime<Utc>,
        auth_data: UnsignedKeyBackupUnlockProofAuthData,
    ) -> Result<Self> {
        if challenge
            .as_ref()
            .is_some_and(|challenge| challenge.as_str().len() != 43)
        {
            return Err(Error::Protocol(
                "key backup unlock proof challenge must be 43 base64url characters".to_owned(),
            ));
        }
        validate_unlock_proof_signature_algorithm(auth_data.signature_algorithm)?;
        Ok(Self {
            recovery_session_id,
            principal_id,
            requesting_device_id,
            backup_id,
            backup_kind,
            series_id,
            ciphertext_digest,
            proof_kind,
            proof_digest,
            challenge,
            issued_at,
            auth_data,
            extra: XExtensionMap::default(),
        })
    }

    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        key_backup_unlock_proof_signing_payload_bytes(&self.unsigned_wire_value()?)
    }

    pub fn attach_signature(self, signature: Base64UrlString) -> Result<KeyBackupUnlockProof> {
        let proof = KeyBackupUnlockProof {
            schema: KeyBackupUnlockProof::SCHEMA.to_owned(),
            recovery_session_id: self.recovery_session_id,
            principal_id: self.principal_id,
            requesting_device_id: self.requesting_device_id,
            backup_id: self.backup_id,
            backup_kind: self.backup_kind,
            series_id: self.series_id,
            ciphertext_digest: self.ciphertext_digest,
            proof_kind: self.proof_kind,
            proof_digest: self.proof_digest,
            challenge: self.challenge.map(Base64UrlString::into_string),
            issued_at: self.issued_at,
            auth_data: KeyBackupUnlockProofAuthData {
                verification_method: self.auth_data.verification_method,
                signature_algorithm: self.auth_data.signature_algorithm,
                signature,
                signed_fields: KEY_BACKUP_UNLOCK_PROOF_SIGNED_FIELDS
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            },
            extra: self.extra,
        };
        proof.validate()?;
        Ok(proof)
    }

    fn unsigned_wire_value(&self) -> Result<Value> {
        #[derive(Serialize)]
        struct UnsignedAuthData<'a> {
            verification_method: &'a DidUrl,
            signature_algorithm: KeyBackupSignatureAlgorithm,
            signed_fields: [&'static str; 11],
        }

        #[derive(Serialize)]
        struct UnsignedProof<'a> {
            schema: &'static str,
            recovery_session_id: &'a RecoverySessionId,
            principal_id: &'a Did,
            requesting_device_id: &'a DeviceId,
            backup_id: &'a BackupId,
            backup_kind: BackupKind,
            series_id: &'a BackupSeriesId,
            ciphertext_digest: &'a Hash,
            proof_kind: ProofKind,
            proof_digest: &'a Hash,
            #[serde(skip_serializing_if = "Option::is_none")]
            challenge: Option<&'a Base64UrlString>,
            #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
            issued_at: DateTime<Utc>,
            auth_data: UnsignedAuthData<'a>,
            #[serde(flatten)]
            extra: &'a XExtensionMap,
        }

        serde_json::to_value(UnsignedProof {
            schema: KeyBackupUnlockProof::SCHEMA,
            recovery_session_id: &self.recovery_session_id,
            principal_id: &self.principal_id,
            requesting_device_id: &self.requesting_device_id,
            backup_id: &self.backup_id,
            backup_kind: self.backup_kind,
            series_id: &self.series_id,
            ciphertext_digest: &self.ciphertext_digest,
            proof_kind: self.proof_kind,
            proof_digest: &self.proof_digest,
            challenge: self.challenge.as_ref(),
            issued_at: self.issued_at,
            auth_data: UnsignedAuthData {
                verification_method: &self.auth_data.verification_method,
                signature_algorithm: self.auth_data.signature_algorithm,
                signed_fields: KEY_BACKUP_UNLOCK_PROOF_SIGNED_FIELDS,
            },
            extra: &self.extra,
        })
        .map_err(Error::from)
    }
}

fn validate_unlock_proof_signature_algorithm(algorithm: KeyBackupSignatureAlgorithm) -> Result<()> {
    if algorithm == KeyBackupSignatureAlgorithm::Es256 {
        return Err(Error::Protocol(
            "key backup unlock proof signature_algorithm must be Ed25519 or ML-DSA-65".to_owned(),
        ));
    }
    Ok(())
}

fn key_backup_unlock_proof_signing_payload_bytes(unsigned: &Value) -> Result<Vec<u8>> {
    Ok(arkret_canonical::canonical_json_bytes(unsigned)?)
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/key-backup-unlock-proof.schema.json#/$defs/proof_kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    PrincipalSigning,
    RecoveryUnlock,
    DeviceQuorum,
    TrustedRecoveryService,
    ThresholdRecovery,
}

/// Counterpart for the shared signature object used by key operations:
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/signature` and
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/signature`
/// (identical shape: `{kid, signature_algorithm?, sig}`).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyOperationSignature {
    pub kid: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<NonEmptyString>,
    pub sig: Base64UrlString,
}

/// Counterpart for `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/failure`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keypackage_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub reason_code: ReasonCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_claim_record`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageClaimRecord {
    pub claim_id: String,
    pub keypackage_ref: String,
    pub keypackage_digest: Hash,
    pub principal_id: Did,
    pub device_id: String,
    pub key_package: String,
    pub capabilities: Vec<String>,
    pub capabilities_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key_authorize_event_id: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub device_signature: KeyOperationSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resort: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_ref_array`.
pub type KeyPackageRefArray = Vec<String>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_upload_entry`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageUploadEntry {
    pub keypackage_id: String,
    pub keypackage_ref: String,
    pub keypackage_digest: Hash,
    pub key_package: Base64UrlString,
    pub cipher_suites: Vec<String>,
    pub capabilities: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<KeyOperationSignature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resort: Option<bool>,
}

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
// Untagged wire union; boxing a variant changes the public constructor shape
// without changing the JSON.
#[allow(clippy::large_enum_variant)]
pub enum KeysOperations {
    KeysUploadRequestBody(KeysUploadRequestBody),
    KeysUploadOutcome(KeysUploadOutcome),
    KeysQueryRequestBody(KeysQueryRequestBody),
    KeysQueryOutcome(KeysQueryOutcome),
    KeysClaimRequestBody(KeysClaimRequestBody),
    KeysClaimOutcome(KeysClaimOutcome),
    KeysBackupsReplaceOutcome(KeysBackupsReplaceOutcome),
    KeysBackupsList(KeysBackupsList),
    KeysBackupsIssueDeleteChallengeRequestBody(KeysBackupsIssueDeleteChallengeRequestBody),
    KeysBackupsDeleteChallenge(KeysBackupsDeleteChallenge),
    KeysBackupsDeleteRequestBody(KeysBackupsDeleteRequestBody),
    KeysBackupsDeleteOutcome(KeysBackupsDeleteOutcome),
    BackupSeriesEraseRequestBody(BackupSeriesEraseRequestBody),
    BackupSeriesEraseOutcome(BackupSeriesEraseOutcome),
}

impl KeysOperations {
    pub const SCHEMA: &'static str = SchemaId::KEYS_OPERATIONS_V1;
}

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/algorithm_counts`.
pub type AlgorithmCounts = BTreeMap<NonEmptyString, u64>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/algorithm_key_records`.
pub type AlgorithmKeyRecords = BTreeMap<NonEmptyString, KeyRecord>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/backup_metadata`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupMetadata {
    pub backup_id: BackupId,
    pub actor_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub backup_kind: BackupKind,
    pub backup_version: String,
    pub series_id: BackupSeriesId,
    pub series_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<BackupId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier_ref: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy_ref: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
    pub ciphertext_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<BTreeMap<String, Value>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/device_algorithm_map`.
pub type DeviceAlgorithmMap = BTreeMap<DeviceId, NonEmptyString>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/device_key_records`.
pub type DeviceKeyRecords = BTreeMap<DeviceId, AlgorithmKeyRecords>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/key_record`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRecord {
    pub key: Base64UrlString,
    pub algorithm: NonEmptyString,
    pub signature: KeyOperationSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub created_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/principal_device_algorithm_map`.
pub type PrincipalDeviceAlgorithmMap = BTreeMap<Did, DeviceAlgorithmMap>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/principal_device_key_records`.
pub type PrincipalDeviceKeyRecords = BTreeMap<Did, DeviceKeyRecords>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/query_device_map`.
pub type QueryDeviceMap = BTreeMap<Did, Vec<DeviceId>>;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-policy.schema.json#/$defs/share`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareShareCommitment {
    pub algorithm: RecoveryShareCommitmentAlgorithm,
    pub commitment_b64u: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryShareCommitmentAlgorithm {
    FeldmanVssSha256,
    PedersenVssSha256,
    ShareHashSha256,
    ShareHashBlake3,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    pub share_id: String,
    pub holder: Did,
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

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/challenge`.
pub type Challenge = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/generic_recovery_transcript`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecoveryModelGenerationRef(NonEmptyString);

impl RecoveryModelGenerationRef {
    pub fn new(value: NonEmptyString) -> Result<Self> {
        if !valid_did_version_id(value.as_str()) {
            return Err(Error::Protocol(
                "recovery model_generation_ref must be a did:webvh version id".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn validate_for(&self, identity_model: RecoveryIdentityModel) -> Result<()> {
        if identity_model != RecoveryIdentityModel::RootAnchored
            || !valid_did_version_id(self.as_str())
        {
            return Err(Error::Protocol(
                "recovery transcript generation is not root-anchored".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "GenericRecoveryTranscriptWire")]
pub struct GenericRecoveryTranscript {
    pub kind: RecoveryProofKind,
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TypedTrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub identity_model: RecoveryIdentityModel,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub model_generation_ref: RecoveryModelGenerationRef,
    pub publication_authority_context_digest: Hash,
    pub challenge: Challenge,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub proof_body: BTreeMap<String, Value>,
    pub schema: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenericRecoveryTranscriptWire {
    kind: RecoveryProofKind,
    principal_id: Did,
    requesting_device_id: DeviceId,
    trust_domain: TypedTrustDomainId,
    policy_id: PolicyId,
    policy_version: u64,
    recovery_session_id: RecoverySessionId,
    identity_model: RecoveryIdentityModel,
    model_generation_ref: RecoveryModelGenerationRef,
    publication_authority_context_digest: Hash,
    challenge: Challenge,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    proof_body: BTreeMap<String, Value>,
    schema: String,
}

impl TryFrom<GenericRecoveryTranscriptWire> for GenericRecoveryTranscript {
    type Error = String;

    fn try_from(wire: GenericRecoveryTranscriptWire) -> std::result::Result<Self, Self::Error> {
        let transcript = Self {
            schema: wire.schema,
            kind: wire.kind,
            principal_id: wire.principal_id,
            requesting_device_id: wire.requesting_device_id,
            trust_domain: wire.trust_domain,
            policy_id: wire.policy_id,
            policy_version: wire.policy_version,
            recovery_session_id: wire.recovery_session_id,
            identity_model: wire.identity_model,
            model_generation_ref: wire.model_generation_ref,
            publication_authority_context_digest: wire.publication_authority_context_digest,
            challenge: wire.challenge,
            expires_at: wire.expires_at,
            created_at: wire.created_at,
            proof_body: wire.proof_body,
        };
        transcript.validate().map_err(|error| error.to_string())?;
        Ok(transcript)
    }
}

impl GenericRecoveryTranscript {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "ak.identity.recovery_proof.v1" || self.policy_version < 1 {
            return Err(Error::Protocol(
                "generic recovery transcript has an invalid schema or policy_version".to_owned(),
            ));
        }
        self.model_generation_ref.validate_for(self.identity_model)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/principal_signing_transcript`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "PrincipalSigningTranscriptWire")]
pub struct PrincipalSigningTranscript {
    pub kind: RecoveryProofKind,
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TypedTrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub identity_model: RecoveryIdentityModel,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub model_generation_ref: RecoveryModelGenerationRef,
    pub publication_authority_context_digest: Hash,
    pub challenge: Challenge,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub schema: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalSigningTranscriptWire {
    kind: RecoveryProofKind,
    principal_id: Did,
    requesting_device_id: DeviceId,
    trust_domain: TypedTrustDomainId,
    policy_id: PolicyId,
    policy_version: u64,
    recovery_session_id: RecoverySessionId,
    identity_model: RecoveryIdentityModel,
    model_generation_ref: RecoveryModelGenerationRef,
    publication_authority_context_digest: Hash,
    challenge: Challenge,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    schema: String,
}

impl TryFrom<PrincipalSigningTranscriptWire> for PrincipalSigningTranscript {
    type Error = String;

    fn try_from(wire: PrincipalSigningTranscriptWire) -> std::result::Result<Self, Self::Error> {
        let transcript = Self {
            schema: wire.schema,
            kind: wire.kind,
            principal_id: wire.principal_id,
            requesting_device_id: wire.requesting_device_id,
            trust_domain: wire.trust_domain,
            policy_id: wire.policy_id,
            policy_version: wire.policy_version,
            recovery_session_id: wire.recovery_session_id,
            identity_model: wire.identity_model,
            model_generation_ref: wire.model_generation_ref,
            publication_authority_context_digest: wire.publication_authority_context_digest,
            challenge: wire.challenge,
            expires_at: wire.expires_at,
            created_at: wire.created_at,
        };
        transcript.validate().map_err(|error| error.to_string())?;
        Ok(transcript)
    }
}

impl PrincipalSigningTranscript {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "ak.identity.recovery_proof.v1"
            || self.kind != RecoveryProofKind::PrincipalSigning
            || self.policy_version < 1
        {
            return Err(Error::Protocol(
                "principal signing transcript has an invalid fixed field".to_owned(),
            ));
        }
        self.model_generation_ref.validate_for(self.identity_model)
    }
}

fn valid_did_version_id(value: &str) -> bool {
    let Some((sequence, suffix)) = value.split_once('-') else {
        return false;
    };
    !sequence.is_empty()
        && !sequence.starts_with('0')
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
        && !suffix.is_empty()
        && !suffix.chars().any(char::is_whitespace)
}

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/proof_summary`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofSummary {
    pub kind: RecoveryProofKind,
    pub proof_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<DidUrl>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/recovery_policy_ref`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyRef {
    pub policy_id: PolicyId,
    pub policy_version: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryIdentityModel {
    RootAnchored,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryPublicationAction {
    #[serde(rename = "ak.device.reanchor")]
    DeviceReanchor,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPublicationAuthorityContext {
    pub identity_model: RecoveryIdentityModel,
    pub basis_ref: LeaseBasisRef,
    pub scope_ref: ScopeRef,
    pub authority_set_ref: AuthoritySetRef,
    pub authority_set_policy: AuthoritySetPolicy,
    pub allowed_actions: Vec<RecoveryPublicationAction>,
}

impl RecoveryPublicationAuthorityContext {
    pub fn validate_for(&self, identity_model: RecoveryIdentityModel) -> Result<()> {
        let valid = identity_model == RecoveryIdentityModel::RootAnchored
            && self.identity_model == identity_model
            && self.authority_set_ref.authority_set_id
                == RECOVERY_IDENTITY_REANCHOR_AUTHORITY_SET_ID
            && self.allowed_actions == [RecoveryPublicationAction::DeviceReanchor];
        if !valid {
            return Err(Error::Protocol(
                "recovery publication authority context does not match the closed identity-model authority"
                    .to_owned(),
            ));
        }
        let allowed_action_names = self
            .allowed_actions
            .iter()
            .map(|action| match action {
                RecoveryPublicationAction::DeviceReanchor => "ak.device.reanchor",
            })
            .collect::<std::collections::BTreeSet<_>>();
        if self
            .authority_set_policy
            .authorization_rules
            .iter()
            .flat_map(|rule| rule.allowed_actions.iter())
            .any(|action| !allowed_action_names.contains(action.as_str()))
        {
            return Err(Error::Protocol(
                "recovery publication authority context policy exceeds its allowed actions"
                    .to_owned(),
            ));
        }
        for action in &self.allowed_actions {
            let action = match action {
                RecoveryPublicationAction::DeviceReanchor => "ak.device.reanchor",
            };
            let matching_rules = self
                .authority_set_policy
                .authorization_rules
                .iter()
                .filter(|rule| {
                    rule.allowed_actions
                        .iter()
                        .any(|candidate| candidate == action)
                })
                .collect::<Vec<_>>();
            if matching_rules.is_empty() {
                return Err(Error::Protocol(
                    "recovery publication authority context does not cover an allowed action"
                        .to_owned(),
                ));
            }
            for rule in matching_rules {
                self.authority_set_policy.validate_reference_and_action(
                    &self.authority_set_ref,
                    &self.scope_ref,
                    &rule.rule_id,
                    action,
                )?;
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Hash> {
        Ok(Hash::new(arkret_canonical::canonical_sha256(self)?)?)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/
/// recovery_session_create_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionCreateRequestBody {
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TypedTrustDomainId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_recovery_policy_ref: Option<RecoveryPolicyRef>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/
/// recovery_session_proof_submit_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionProofSubmitOutcome {
    pub recovery_session_id: RecoverySessionId,
    pub state: SessionState,
    pub verification: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_summary: Option<ProofSummary>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/
/// recovery_session_proof_submit_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionProofSubmitRequestBody {
    pub proof: RecoverySessionProof,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryPrincipalSigningProofKind {
    #[serde(rename = "principal_signing")]
    PrincipalSigning,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPrincipalSigningProof {
    pub kind: RecoveryPrincipalSigningProofKind,
    pub challenge: Challenge,
    pub verification_method: DidUrl,
    pub signature_algorithm: NonEmptyString,
    pub signature: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoverySessionUnlockProofKind {
    #[serde(rename = "recovery_unlock")]
    RecoveryUnlock,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionUnlockProof {
    pub kind: RecoverySessionUnlockProofKind,
    pub challenge: Challenge,
    pub recovery_secret_ref: NonEmptyString,
    pub verification_method: DidUrl,
    pub signature_algorithm: NonEmptyString,
    pub unlock_commitment: Hash,
    pub signature: Base64UrlString,
}

impl RecoverySessionUnlockProof {
    /// Exact `proof_body` embedded in the generic recovery transcript. Both
    /// the detached signature and `unlock_commitment` cover this body, so the
    /// two derived fields are omitted in one SDK-owned place.
    pub fn signature_independent_proof_body(&self) -> Result<BTreeMap<String, Value>> {
        let Value::Object(mut proof_body) = serde_json::to_value(self)? else {
            return Err(Error::Protocol(
                "recovery unlock proof must serialize as an object".to_owned(),
            ));
        };
        proof_body.remove("signature");
        proof_body.remove("unlock_commitment");
        Ok(proof_body.into_iter().collect())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDeviceQuorumSignature {
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub signature_algorithm: NonEmptyString,
    pub signature: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryDeviceQuorumProofKind {
    #[serde(rename = "device_quorum")]
    DeviceQuorum,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDeviceQuorumProof {
    pub kind: RecoveryDeviceQuorumProofKind,
    pub challenge: Challenge,
    #[serde(deserialize_with = "deserialize_minimum_two")]
    pub threshold: u64,
    pub signatures: Vec<RecoveryDeviceQuorumSignature>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustedRecoveryServiceSessionProofKind {
    #[serde(rename = "trusted_recovery_service")]
    TrustedRecoveryService,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRecoveryServiceSessionProof {
    pub kind: TrustedRecoveryServiceSessionProofKind,
    pub challenge: Challenge,
    pub service_id: Did,
    pub audience: NonEmptyString,
    pub verification_method: DidUrl,
    pub signature_algorithm: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<NonEmptyString>,
    pub signature: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecoverySessionProof {
    PrincipalSigning(RecoveryPrincipalSigningProof),
    RecoveryUnlock(RecoverySessionUnlockProof),
    DeviceQuorum(RecoveryDeviceQuorumProof),
    TrustedRecoveryService(TrustedRecoveryServiceSessionProof),
    ThresholdRecovery(ThresholdRecoveryProof),
}

fn deserialize_minimum_two<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u64::deserialize(deserializer)?;
    if value < 2 {
        return Err(serde::de::Error::custom("value must be at least two"));
    }
    Ok(value)
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/recovery_session_state`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoverySessionState {
    pub schema: String,
    pub recovery_session_id: RecoverySessionId,
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TypedTrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub identity_model: RecoveryIdentityModel,
    pub current_device_generation_ref: NonEmptyString,
    pub device_generation_status: DeviceGenerationStatus,
    pub registry_head: Hash,
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<serde_json::Value>))
    )]
    pub accepted_seal_frontier: Option<DeviceReanchorPreFenceBasis>,
    pub publication_authority_context: RecoveryPublicationAuthorityContext,
    pub publication_authority_context_digest: Hash,
    pub challenge: Challenge,
    pub state: SessionState,
    pub proof_summary: Option<ProofSummary>,
    pub transaction_id: Option<TransactionId>,
    pub rejection_reason_code: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Serialize for RecoverySessionState {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        self.validate().map_err(serde::ser::Error::custom)?;
        let expires_at = arkret_canonical::canonical::format_timestamp_canonical(self.expires_at);
        let created_at = arkret_canonical::canonical::format_timestamp_canonical(self.created_at);
        let updated_at = arkret_canonical::canonical::format_timestamp_canonical(self.updated_at);
        let mut map = serializer.serialize_map(Some(
            19 + usize::from(self.proof_summary.is_some())
                + usize::from(self.transaction_id.is_some())
                + usize::from(self.rejection_reason_code.is_some()),
        ))?;
        map.serialize_entry("schema", &self.schema)?;
        map.serialize_entry("recovery_session_id", &self.recovery_session_id)?;
        map.serialize_entry("principal_id", &self.principal_id)?;
        map.serialize_entry("requesting_device_id", &self.requesting_device_id)?;
        map.serialize_entry("trust_domain", &self.trust_domain)?;
        map.serialize_entry("policy_id", &self.policy_id)?;
        map.serialize_entry("policy_version", &self.policy_version)?;
        map.serialize_entry("identity_model", &self.identity_model)?;
        map.serialize_entry(
            "current_device_generation_ref",
            &self.current_device_generation_ref,
        )?;
        map.serialize_entry("device_generation_status", &self.device_generation_status)?;
        map.serialize_entry("registry_head", &self.registry_head)?;
        map.serialize_entry("accepted_seal_frontier", &self.accepted_seal_frontier)?;
        map.serialize_entry(
            "publication_authority_context",
            &self.publication_authority_context,
        )?;
        map.serialize_entry(
            "publication_authority_context_digest",
            &self.publication_authority_context_digest,
        )?;
        map.serialize_entry("challenge", &self.challenge)?;
        map.serialize_entry("state", &self.state)?;
        if let Some(proof_summary) = &self.proof_summary {
            map.serialize_entry("proof_summary", proof_summary)?;
        }
        if let Some(transaction_id) = &self.transaction_id {
            map.serialize_entry("transaction_id", transaction_id)?;
        }
        if let Some(reason) = &self.rejection_reason_code {
            map.serialize_entry("rejection_reason_code", reason)?;
        }
        map.serialize_entry("expires_at", &expires_at)?;
        map.serialize_entry("created_at", &created_at)?;
        map.serialize_entry("updated_at", &updated_at)?;
        map.end()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverySessionStateWire {
    schema: String,
    recovery_session_id: RecoverySessionId,
    principal_id: Did,
    requesting_device_id: DeviceId,
    trust_domain: TypedTrustDomainId,
    policy_id: PolicyId,
    policy_version: u64,
    identity_model: RecoveryIdentityModel,
    current_device_generation_ref: NonEmptyString,
    device_generation_status: DeviceGenerationStatus,
    registry_head: Hash,
    accepted_seal_frontier: Option<DeviceReanchorPreFenceBasis>,
    publication_authority_context: RecoveryPublicationAuthorityContext,
    publication_authority_context_digest: Hash,
    challenge: Challenge,
    state: SessionState,
    proof_summary: Option<ProofSummary>,
    transaction_id: Option<TransactionId>,
    rejection_reason_code: Option<String>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    updated_at: DateTime<Utc>,
}

fn validate_recovery_session_state_shape(
    identity_model: RecoveryIdentityModel,
    accepted_seal_frontier_present: bool,
) -> std::result::Result<(), &'static str> {
    let valid =
        identity_model == RecoveryIdentityModel::RootAnchored && accepted_seal_frontier_present;
    valid
        .then_some(())
        .ok_or("recovery session identity_model does not match its authoritative snapshot")
}

impl<'de> Deserialize<'de> for RecoverySessionState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let accepted_seal_frontier_present = value
            .as_object()
            .is_some_and(|object| object.contains_key("accepted_seal_frontier"));
        let wire: RecoverySessionStateWire =
            serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        validate_recovery_session_state_shape(wire.identity_model, accepted_seal_frontier_present)
            .map_err(serde::de::Error::custom)?;
        if matches!(wire.state, SessionState::Verified | SessionState::Completed)
            && wire.proof_summary.is_none()
        {
            return Err(serde::de::Error::custom(
                "verified or completed recovery session requires proof_summary",
            ));
        }
        if wire.state == SessionState::Rejected && wire.rejection_reason_code.is_none() {
            return Err(serde::de::Error::custom(
                "rejected recovery session requires rejection_reason_code",
            ));
        }
        let state = Self {
            schema: wire.schema,
            recovery_session_id: wire.recovery_session_id,
            principal_id: wire.principal_id,
            requesting_device_id: wire.requesting_device_id,
            trust_domain: wire.trust_domain,
            policy_id: wire.policy_id,
            policy_version: wire.policy_version,
            identity_model: wire.identity_model,
            current_device_generation_ref: wire.current_device_generation_ref,
            device_generation_status: wire.device_generation_status,
            registry_head: wire.registry_head,
            accepted_seal_frontier: wire.accepted_seal_frontier,
            publication_authority_context: wire.publication_authority_context,
            publication_authority_context_digest: wire.publication_authority_context_digest,
            challenge: wire.challenge,
            state: wire.state,
            proof_summary: wire.proof_summary,
            transaction_id: wire.transaction_id,
            rejection_reason_code: wire.rejection_reason_code,
            expires_at: wire.expires_at,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
        };
        state.validate().map_err(serde::de::Error::custom)?;
        Ok(state)
    }
}

impl RecoverySessionState {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "ak.schema.recovery_session.v1" {
            return Err(Error::Protocol(
                "recovery session schema must be ak.schema.recovery_session.v1".to_owned(),
            ));
        }
        if self.policy_version < 1 {
            return Err(Error::Protocol(
                "recovery session policy_version must be at least one".to_owned(),
            ));
        }
        validate_recovery_session_state_shape(self.identity_model, true)
            .map_err(|reason| Error::Protocol(reason.to_owned()))?;
        self.publication_authority_context
            .validate_for(self.identity_model)?;
        if self.publication_authority_context.digest()? != self.publication_authority_context_digest
        {
            return Err(Error::Protocol(
                "recovery publication authority context digest is invalid".to_owned(),
            ));
        }
        if matches!(self.state, SessionState::Verified | SessionState::Completed)
            && self.proof_summary.is_none()
        {
            return Err(Error::Protocol(
                "verified or completed recovery session requires proof_summary".to_owned(),
            ));
        }
        if self.state == SessionState::Rejected && self.rejection_reason_code.is_none() {
            return Err(Error::Protocol(
                "rejected recovery session requires rejection_reason_code".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/session_state`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Pending,
    Verified,
    Completed,
    Rejected,
    Expired,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/threshold_recovery_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRecoveryProofShareReleasesItem {
    pub share_id: NonEmptyString,
    pub holder: Did,
    pub transcript_digest: Hash,
    pub verification_method: DidUrl,
    pub signature_algorithm: NonEmptyString,
    pub signature: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdRecoveryProofKind {
    #[serde(rename = "threshold_recovery")]
    ThresholdRecovery,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRecoveryProof {
    pub kind: ThresholdRecoveryProofKind,
    pub challenge: Challenge,
    #[serde(deserialize_with = "deserialize_minimum_two")]
    pub threshold: u64,
    pub share_releases: Vec<ThresholdRecoveryProofShareReleasesItem>,
}

// ── Keypackage operations aggregate ──────────────────────────────────────
// The `arkret` umbrella re-exports this owner-defined enum at its root.

/// Counterpart for `spec/v1/artifacts/schemas/keypackage-operations.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum KeyPackageOperations {
    KeyPackagesUploadRequestBody(crate::http_bodies::KeyPackagesUploadRequestBody),
    KeyPackagesUploadOutcome(crate::http_bodies::KeyPackagesUploadOutcome),
    KeyPackagesClaimRequestBody(crate::http_bodies::KeyPackagesClaimRequestBody),
    KeyPackagesClaimOutcome(crate::http_bodies::KeyPackagesClaimOutcome),
    PeerKeyPackagesClaimRequestBody(crate::http_bodies::PeerKeyPackagesClaimRequestBody),
    PeerKeyPackagesClaimOutcome(crate::http_bodies::PeerKeyPackagesClaimOutcome),
    PeerKeyPackagesClaimQueryRequestBody(crate::http_bodies::PeerKeyPackagesClaimQueryRequestBody),
    PeerKeyPackagesClaimQueryOutcome(crate::http_bodies::PeerKeyPackagesClaimQueryOutcome),
    KeyPackagesConsumeRequestBody(crate::http_bodies::KeyPackagesConsumeRequestBody),
    KeyPackagesConsumeOutcome(crate::http_bodies::KeyPackagesConsumeOutcome),
    KeyPackagesRevokeRequestBody(crate::http_bodies::KeyPackagesRevokeRequestBody),
    KeyPackagesRevokeOutcome(crate::http_bodies::KeyPackagesRevokeOutcome),
}
