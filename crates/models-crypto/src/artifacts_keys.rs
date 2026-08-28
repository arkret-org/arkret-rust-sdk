//! Key management and recovery schema artifact counterparts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Deref;

use arkret_wire::{
    AuthoritySetPolicy, AuthoritySetRef, BackupId, BackupSeriesId, Base64UrlString, DeviceId,
    DeviceReanchorPreFenceSealFrontier, DidCoreId, DidUrl, DomainSeparationId, EventId, Hash,
    HistoryEffectiveScope, HistorySecretRange, LeaseBasisRef, NonEmptyString, PolicyId,
    PrincipalAuthorityKey, RECOVERY_IDENTITY_REANCHOR_AUTHORITY_SET_ID, ReasonCode,
    RecoverySessionId, RequestId, Result, SchemaId, ScopeRef, SessionGrantId, TransactionId,
    TrustDomainId, WireError, XExtensionMap,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::key_backup::{
    BackupKind, KeyBackup, KeyBackupContentItem, KeyBackupSignatureAlgorithm, RecoveryProofKind,
    SecretStorageContentIndex, SecretStorageItemKind,
};
use crate::keys::DeviceGenerationStatus;

/// The `backup_kind`-discriminated keybag body of
/// `spec/v1/artifacts/schemas/key-backup-plaintext.schema.json` (`oneOf`).
///
/// `effective_scope` exists only on the `mls_history` branch, and only that
/// branch packs [`HistorySecretRange`] items. key-management.md §7.1 forbids
/// active MLS state, group-state refs, policy/membership digests, secret ids
/// and versions in a history keybag; the closed union makes those shapes
/// unrepresentable rather than merely rejected.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "backup_kind", rename_all = "snake_case")]
pub enum KeyBackupKeybag {
    SecretStorage {
        items: Vec<SecretStorageItem>,
    },
    MlsHistory {
        effective_scope: HistoryEffectiveScope,
        items: Vec<HistorySecretRange>,
    },
}

impl KeyBackupKeybag {
    pub const fn backup_kind(&self) -> BackupKind {
        match self {
            Self::SecretStorage { .. } => BackupKind::SecretStorage,
            Self::MlsHistory { .. } => BackupKind::MlsHistory,
        }
    }

    pub fn item_count(&self) -> usize {
        match self {
            Self::SecretStorage { items } => items.len(),
            Self::MlsHistory { items, .. } => items.len(),
        }
    }
}

/// Counterpart for `spec/v1/artifacts/schemas/key-backup-plaintext.schema.json`.
///
/// `Deserialize` is written by hand rather than derived: the schema puts the
/// branch discriminator (`backup_kind`), the branch-only `effective_scope` and
/// the `x_` extension namespace on the same object, and two `#[serde(flatten)]`
/// targets cannot share one map without the extension map seeing the keybag's
/// own members.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize)]
pub struct KeyBackupPlaintext {
    pub schema: String,
    pub backup_id: BackupId,
    pub series_id: BackupSeriesId,
    pub series_seq: u64,
    #[serde(flatten)]
    pub keybag: KeyBackupKeybag,
    #[serde(default, flatten, skip_serializing_if = "XExtensionMap::is_empty")]
    pub extra: XExtensionMap,
}

#[derive(Deserialize)]
struct KeyBackupPlaintextWire {
    schema: String,
    backup_id: BackupId,
    backup_kind: BackupKind,
    series_id: BackupSeriesId,
    series_seq: u64,
    #[serde(default)]
    effective_scope: Option<HistoryEffectiveScope>,
    items: Vec<Value>,
    #[serde(default, flatten)]
    extra: XExtensionMap,
}

impl<'de> Deserialize<'de> for KeyBackupPlaintext {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let wire = KeyBackupPlaintextWire::deserialize(deserializer)?;
        let keybag = match (wire.backup_kind, wire.effective_scope) {
            (BackupKind::SecretStorage, None) => KeyBackupKeybag::SecretStorage {
                items: decode_keybag_items(wire.items).map_err(D::Error::custom)?,
            },
            (BackupKind::SecretStorage, Some(_)) => {
                return Err(D::Error::custom(
                    "secret_storage key backup plaintext must not carry effective_scope",
                ));
            }
            (BackupKind::MlsHistory, Some(effective_scope)) => KeyBackupKeybag::MlsHistory {
                effective_scope,
                items: decode_keybag_items(wire.items).map_err(D::Error::custom)?,
            },
            (BackupKind::MlsHistory, None) => {
                return Err(D::Error::custom(
                    "mls_history key backup plaintext requires effective_scope",
                ));
            }
        };
        Ok(Self {
            schema: wire.schema,
            backup_id: wire.backup_id,
            series_id: wire.series_id,
            series_seq: wire.series_seq,
            keybag,
            extra: wire.extra,
        })
    }
}

fn decode_keybag_items<T: serde::de::DeserializeOwned>(
    items: Vec<Value>,
) -> std::result::Result<Vec<T>, serde_json::Error> {
    items.into_iter().map(serde_json::from_value).collect()
}

impl KeyBackupPlaintext {
    pub const SCHEMA: &'static str = SchemaId::KEY_BACKUP_PLAINTEXT_V1;

    /// Validate the decrypted keybag and its byte-for-byte binding to the
    /// authenticated public envelope. A receiver MUST run this before importing
    /// any secret material.
    pub fn validate_for_envelope(&self, envelope: &KeyBackup) -> Result<()> {
        envelope.validate_envelope_fields()?;
        if self.schema != Self::SCHEMA {
            return Err(WireError::Protocol(format!(
                "key backup plaintext schema must be {}",
                Self::SCHEMA
            )));
        }
        if self.backup_id != envelope.backup_id
            || self.keybag.backup_kind() != envelope.backup_kind
            || self.series_id != envelope.series_id
            || self.series_seq != envelope.series_seq
        {
            return Err(WireError::Protocol(
                "key backup plaintext envelope identity mismatch".to_owned(),
            ));
        }
        if self.keybag.item_count() == 0 {
            return Err(WireError::Protocol(
                "key backup plaintext items must not be empty".to_owned(),
            ));
        }
        match &self.keybag {
            KeyBackupKeybag::SecretStorage { items } => Self::bind_secret_storage(items, envelope),
            KeyBackupKeybag::MlsHistory {
                effective_scope,
                items,
            } => Self::bind_mls_history(effective_scope, items, envelope),
        }
    }

    fn bind_secret_storage(items: &[SecretStorageItem], envelope: &KeyBackup) -> Result<()> {
        if items.len() != envelope.contents.len() {
            return Err(WireError::Protocol(
                "key backup public/plaintext item counts differ".to_owned(),
            ));
        }
        for secret in items {
            secret.validate()?;
            let _ = secret.secret_version()?;
        }
        let mut matched_plaintext = vec![false; items.len()];
        for public in &envelope.contents {
            let Some(public) = public.secret_storage() else {
                return Err(WireError::Protocol(
                    "secret_storage key backup must not index history secret ranges".to_owned(),
                ));
            };
            let matches = items
                .iter()
                .enumerate()
                .filter(|(index, secret)| {
                    !matched_plaintext[*index]
                        && secret_storage_metadata_matches(public, secret).unwrap_or(false)
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(WireError::Protocol(
                    "key backup public/plaintext items do not have a unique metadata match"
                        .to_owned(),
                ));
            }
            matched_plaintext[matches[0]] = true;
        }
        Ok(())
    }

    fn bind_mls_history(
        effective_scope: &HistoryEffectiveScope,
        items: &[HistorySecretRange],
        envelope: &KeyBackup,
    ) -> Result<()> {
        let [KeyBackupContentItem::HistorySecretRanges(index)] = envelope.contents.as_slice()
        else {
            return Err(WireError::Protocol(
                "mls_history key backup contents must be exactly one history_secret_ranges index"
                    .to_owned(),
            ));
        };
        if index.effective_scope != *effective_scope {
            return Err(WireError::Protocol(
                "key backup public/plaintext effective_scope differ".to_owned(),
            ));
        }
        for item in items {
            item.validate()?;
        }
        let packed = items
            .iter()
            .map(HistorySecretRange::epoch_range)
            .collect::<Vec<_>>();
        if packed != index.ranges {
            return Err(WireError::Protocol(
                "key backup packed history ranges do not equal the public range index".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/key-backup-plaintext.schema.json#/$defs/secret_storage_item`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretStorageItem {
    pub item_kind: SecretStorageItemKind,
    pub secret_id: String,
    pub secret_b64u: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_generation: Option<u64>,
    #[serde(default, flatten, skip_serializing_if = "XExtensionMap::is_empty")]
    pub extra: XExtensionMap,
}

impl SecretStorageItem {
    pub fn validate(&self) -> Result<()> {
        if self.secret_id.is_empty()
            || !self
                .secret_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        {
            return Err(WireError::Protocol(
                "key backup plaintext secret_id must match ^[A-Za-z0-9_.-]+$".to_owned(),
            ));
        }
        let secret =
            arkret_canonical::base64url::base64url_decode(&self.secret_b64u).map_err(|error| {
                WireError::Protocol(format!(
                    "key backup plaintext secret_b64u must be unpadded base64url: {error}"
                ))
            })?;
        if secret.is_empty() || self.secret_b64u.contains('=') {
            return Err(WireError::Protocol(
                "key backup plaintext secret_b64u must encode non-empty bytes without padding"
                    .to_owned(),
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
                    WireError::Protocol(
                        "key backup plaintext secret_generation exceeds public secret_version"
                            .to_owned(),
                    )
                })
            })
            .transpose()
    }
}

fn secret_storage_metadata_matches(
    public: &SecretStorageContentIndex,
    secret: &SecretStorageItem,
) -> Result<bool> {
    Ok(public.item_kind == secret.item_kind
        && public.secret_id.as_deref() == Some(secret.secret_id.as_str())
        && public.secret_version == secret.secret_version()?)
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
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupUnlockProof {
    pub schema: String,
    pub recovery_session_id: RecoverySessionId,
    pub principal_id: DidCoreId,
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

    /// Validate the signed wire shape.
    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(WireError::Protocol(format!(
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
            return Err(WireError::Protocol(
                "key backup unlock proof challenge must be 43 base64url characters".to_owned(),
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
                WireError::Protocol(
                    "key backup unlock proof auth_data must be an object".to_owned(),
                )
            })?
            .remove("signature");
        key_backup_unlock_proof_signing_payload_bytes(&unsigned)
    }
}

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
    principal_id: DidCoreId,
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
        principal_id: DidCoreId,
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
            return Err(WireError::Protocol(
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
        }

        #[derive(Serialize)]
        struct UnsignedProof<'a> {
            schema: &'static str,
            recovery_session_id: &'a RecoverySessionId,
            principal_id: &'a DidCoreId,
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
            },
            extra: &self.extra,
        })
        .map_err(WireError::from)
    }
}

fn validate_unlock_proof_signature_algorithm(algorithm: KeyBackupSignatureAlgorithm) -> Result<()> {
    if algorithm == KeyBackupSignatureAlgorithm::Es256 {
        return Err(WireError::Protocol(
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
#[derive(Clone, Debug, Serialize)]
pub struct KeyPackageClaimRecord {
    pub claim_id: String,
    pub keypackage_ref: String,
    pub principal_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairwise_verification_method: Option<DidUrl>,
    pub keypackage: String,
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key_authorize_event_id: Option<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resort: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPackageClaimRecordWire {
    claim_id: String,
    keypackage_ref: String,
    principal_id: DidCoreId,
    #[serde(default)]
    device_id: Option<DeviceId>,
    #[serde(default)]
    agent_id: Option<DidCoreId>,
    #[serde(default)]
    agent_verification_method: Option<DidUrl>,
    #[serde(default)]
    pairwise_verification_method: Option<DidUrl>,
    keypackage: String,
    capabilities: Vec<String>,
    #[serde(default)]
    device_authorize_event_id: Option<EventId>,
    #[serde(default)]
    agent_key_authorize_event_id: Option<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: DateTime<Utc>,
    #[serde(default)]
    revocation_status: Option<String>,
    #[serde(default)]
    last_resort: Option<bool>,
}

impl<'de> Deserialize<'de> for KeyPackageClaimRecord {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = KeyPackageClaimRecordWire::deserialize(deserializer)?;
        let record = Self {
            claim_id: wire.claim_id,
            keypackage_ref: wire.keypackage_ref,
            principal_id: wire.principal_id,
            device_id: wire.device_id,
            agent_id: wire.agent_id,
            agent_verification_method: wire.agent_verification_method,
            pairwise_verification_method: wire.pairwise_verification_method,
            keypackage: wire.keypackage,
            capabilities: wire.capabilities,
            device_authorize_event_id: wire.device_authorize_event_id,
            agent_key_authorize_event_id: wire.agent_key_authorize_event_id,
            expires_at: wire.expires_at,
            revocation_status: wire.revocation_status,
            last_resort: wire.last_resort,
        };
        record.validate_shape().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

impl KeyPackageClaimRecord {
    /// Enforce the closed claim-record union and scalar profiles at the wire
    /// boundary. Callers must never be able to deserialize a record that the
    /// authoritative schema would reject and then forget a separate validator.
    pub fn validate_shape(&self) -> std::result::Result<(), &'static str> {
        NonEmptyString::new(self.claim_id.clone())?;
        if self.claim_id.starts_with("ak:") {
            return Err("KeyPackage claim_id must not use the ak: namespace");
        }
        NonEmptyString::new(self.keypackage_ref.clone())?;
        Base64UrlString::new(self.keypackage.clone())?;

        let capabilities = self
            .capabilities
            .iter()
            .map(|value| NonEmptyString::new(value.clone()).map(|_| value.as_str()))
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        if capabilities.is_empty() || capabilities.len() != self.capabilities.len() {
            return Err("KeyPackage claim capabilities must be non-empty and unique");
        }
        if self.revocation_status.as_deref().is_some_and(|status| {
            !matches!(
                status,
                "active" | "expired" | "revoked" | "principal_deactivated" | "device_revoked"
            )
        }) {
            return Err("KeyPackage claim revocation_status is not registered");
        }

        match (
            &self.device_id,
            &self.device_authorize_event_id,
            &self.agent_id,
            &self.agent_verification_method,
            &self.agent_key_authorize_event_id,
            &self.pairwise_verification_method,
        ) {
            (Some(_), Some(_), None, None, None, None) => Ok(()),
            (None, None, Some(agent_id), Some(_), Some(_), None)
                if agent_id.as_core_id() == self.principal_id.as_core_id() =>
            {
                Ok(())
            }
            (None, None, None, None, None, Some(method)) => {
                crate::MlsEndpointIdentity::minimal_metadata_pairwise(
                    self.principal_id.clone(),
                    method.clone(),
                )
                .map(|_| ())
                .map_err(|_| "KeyPackage claim pairwise endpoint binding is invalid")
            }
            _ => Err(
                "KeyPackage claim must select exactly one device, Native Agent, or minimal-metadata pairwise branch",
            ),
        }
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_upload_entry`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageUploadEntry {
    pub keypackage_id: String,
    pub keypackage_ref: String,
    pub keypackage: Base64UrlString,
    pub cipher_suites: Vec<String>,
    pub capabilities: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resort: Option<bool>,
}

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/algorithm_counts`.
pub type AlgorithmCounts = BTreeMap<NonEmptyString, u64>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/algorithm_key_records`.
pub type AlgorithmKeyRecords = BTreeMap<NonEmptyString, KeyRecord>;

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
pub type PrincipalDeviceAlgorithmMap = BTreeMap<DidCoreId, DeviceAlgorithmMap>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/principal_device_key_records`.
pub type PrincipalDeviceKeyRecords = BTreeMap<DidCoreId, DeviceKeyRecords>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/query_device_map`.
pub type QueryDeviceMap = BTreeMap<DidCoreId, Vec<DeviceId>>;

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

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/challenge`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Challenge(Base64UrlString);

impl Challenge {
    /// Create a recovery challenge from the canonical 256-bit base64url form.
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, &'static str> {
        let value = Base64UrlString::new(value)?;
        if value.as_str().len() != 43 {
            return Err("recovery challenge must be exactly 43 base64url characters");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0.into_string()
    }
}

impl AsRef<str> for Challenge {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for Challenge {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for Challenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for Challenge {
    type Error = &'static str;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Challenge> for String {
    fn from(value: Challenge) -> Self {
        value.into_string()
    }
}

impl<'de> Deserialize<'de> for Challenge {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "GenericRecoveryTranscriptWire")]
pub struct GenericRecoveryTranscript {
    pub kind: RecoveryProofKind,
    pub request_id: RequestId,
    pub session_grant_id: SessionGrantId,
    pub session_grant_cnf_jkt: String,
    pub principal_authority: PrincipalAuthorityKey,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub identity_model: RecoveryIdentityModel,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub model_generation_ref: u64,
    pub publication_authority_context_digest: Hash,
    pub challenge: Challenge,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub proof_body: GenericRecoveryProofBody,
    pub schema: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenericRecoveryTranscriptWire {
    kind: RecoveryProofKind,
    request_id: RequestId,
    session_grant_id: SessionGrantId,
    session_grant_cnf_jkt: String,
    principal_authority: PrincipalAuthorityKey,
    requesting_device_id: DeviceId,
    trust_domain: TrustDomainId,
    policy_id: PolicyId,
    policy_version: u64,
    recovery_session_id: RecoverySessionId,
    identity_model: RecoveryIdentityModel,
    model_generation_ref: u64,
    publication_authority_context_digest: Hash,
    challenge: Challenge,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    proof_body: GenericRecoveryProofBody,
    schema: String,
}

impl TryFrom<GenericRecoveryTranscriptWire> for GenericRecoveryTranscript {
    type Error = String;

    fn try_from(wire: GenericRecoveryTranscriptWire) -> std::result::Result<Self, Self::Error> {
        let transcript = Self {
            schema: wire.schema,
            kind: wire.kind,
            request_id: wire.request_id,
            session_grant_id: wire.session_grant_id,
            session_grant_cnf_jkt: wire.session_grant_cnf_jkt,
            principal_authority: wire.principal_authority,
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
        if self.schema != DomainSeparationId::IDENTITY_RECOVERY_PROOF_V1 || self.policy_version < 1
        {
            return Err(WireError::Protocol(
                "generic recovery transcript has an invalid schema or policy_version".to_owned(),
            ));
        }
        if self.identity_model != RecoveryIdentityModel::PcrPolicy || self.model_generation_ref == 0
        {
            return Err(WireError::Protocol(
                "recovery transcript generation must be a positive PCR generation".to_owned(),
            ));
        }
        validate_recovery_grant_jkt(&self.session_grant_cnf_jkt)?;
        if self.kind == RecoveryProofKind::DidRoot
            || self.kind != self.proof_body.kind()
            || &self.challenge != self.proof_body.challenge()
        {
            return Err(WireError::Protocol(
                "generic recovery transcript kind/challenge must match one closed non-did_root proof body"
                    .to_owned(),
            ));
        }
        self.proof_body.validate()?;
        Ok(())
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/did_root_transcript`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "DidRootTranscriptWire")]
pub struct DidRootTranscript {
    pub kind: RecoveryProofKind,
    pub request_id: RequestId,
    pub session_grant_id: SessionGrantId,
    pub session_grant_cnf_jkt: String,
    pub principal_authority: PrincipalAuthorityKey,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub identity_model: RecoveryIdentityModel,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub model_generation_ref: u64,
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
struct DidRootTranscriptWire {
    kind: RecoveryProofKind,
    request_id: RequestId,
    session_grant_id: SessionGrantId,
    session_grant_cnf_jkt: String,
    principal_authority: PrincipalAuthorityKey,
    requesting_device_id: DeviceId,
    trust_domain: TrustDomainId,
    policy_id: PolicyId,
    policy_version: u64,
    recovery_session_id: RecoverySessionId,
    identity_model: RecoveryIdentityModel,
    model_generation_ref: u64,
    publication_authority_context_digest: Hash,
    challenge: Challenge,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    schema: String,
}

impl TryFrom<DidRootTranscriptWire> for DidRootTranscript {
    type Error = String;

    fn try_from(wire: DidRootTranscriptWire) -> std::result::Result<Self, Self::Error> {
        let transcript = Self {
            schema: wire.schema,
            kind: wire.kind,
            request_id: wire.request_id,
            session_grant_id: wire.session_grant_id,
            session_grant_cnf_jkt: wire.session_grant_cnf_jkt,
            principal_authority: wire.principal_authority,
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

impl DidRootTranscript {
    pub fn validate(&self) -> Result<()> {
        if self.schema != DomainSeparationId::IDENTITY_RECOVERY_PROOF_V1
            || self.kind != RecoveryProofKind::DidRoot
            || self.policy_version < 1
        {
            return Err(WireError::Protocol(
                "did_root transcript has an invalid fixed field".to_owned(),
            ));
        }
        if self.identity_model != RecoveryIdentityModel::PcrPolicy || self.model_generation_ref == 0
        {
            return Err(WireError::Protocol(
                "did_root generation must be a positive PCR generation".to_owned(),
            ));
        }
        validate_recovery_grant_jkt(&self.session_grant_cnf_jkt)?;
        Ok(())
    }
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
    PcrPolicy,
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
        let valid = identity_model == RecoveryIdentityModel::PcrPolicy
            && self.identity_model == identity_model
            && self.authority_set_ref.authority_set_id
                == RECOVERY_IDENTITY_REANCHOR_AUTHORITY_SET_ID
            && self.allowed_actions == [RecoveryPublicationAction::DeviceReanchor];
        if !valid {
            return Err(WireError::Protocol(
                "recovery publication authority context does not match the closed identity-model authority"
                    .to_owned(),
            ));
        }
        let allowed_action_names = self
            .allowed_actions
            .iter()
            .map(|action| match action {
                RecoveryPublicationAction::DeviceReanchor => {
                    arkret_wire::event_kind_str::DEVICE_REANCHOR
                }
            })
            .collect::<BTreeSet<_>>();
        if self
            .authority_set_policy
            .authorization_rules
            .iter()
            .flat_map(|rule| rule.allowed_actions.iter())
            .any(|action| !allowed_action_names.contains(action.as_str()))
        {
            return Err(WireError::Protocol(
                "recovery publication authority context policy exceeds its allowed actions"
                    .to_owned(),
            ));
        }
        for action in &self.allowed_actions {
            let action = match action {
                RecoveryPublicationAction::DeviceReanchor => {
                    arkret_wire::event_kind_str::DEVICE_REANCHOR
                }
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
                return Err(WireError::Protocol(
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
    pub request_id: RequestId,
    pub principal_authority: PrincipalAuthorityKey,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TrustDomainId,
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
pub enum RecoveryDidRootProofKind {
    #[serde(rename = "did_root")]
    DidRoot,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDidRootProof {
    pub kind: RecoveryDidRootProofKind,
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryFactorSignatureAlgorithm {
    Ed25519,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

impl TryFrom<&NonEmptyString> for RecoveryFactorSignatureAlgorithm {
    type Error = WireError;

    fn try_from(value: &NonEmptyString) -> Result<Self> {
        match value.as_str() {
            "Ed25519" => Ok(Self::Ed25519),
            "ML-DSA-65" => Ok(Self::MlDsa65),
            _ => Err(WireError::Protocol(
                "recovery factor signature_algorithm must be Ed25519 or ML-DSA-65".to_owned(),
            )),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryUnlockProofBody {
    pub kind: RecoverySessionUnlockProofKind,
    pub challenge: Challenge,
    pub recovery_secret_ref: NonEmptyString,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoveryFactorSignatureAlgorithm,
}

impl RecoverySessionUnlockProof {
    /// Exact `proof_body` embedded in the generic recovery transcript. Both
    /// the detached signature and `unlock_commitment` cover this body, so the
    /// two derived fields are omitted in one SDK-owned place.
    pub fn signature_independent_proof_body(&self) -> Result<RecoveryUnlockProofBody> {
        Ok(RecoveryUnlockProofBody {
            kind: self.kind,
            challenge: self.challenge.clone(),
            recovery_secret_ref: self.recovery_secret_ref.clone(),
            verification_method: self.verification_method.clone(),
            signature_algorithm: RecoveryFactorSignatureAlgorithm::try_from(
                &self.signature_algorithm,
            )?,
        })
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDeviceQuorumSignatureBody {
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoveryFactorSignatureAlgorithm,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDeviceQuorumProofBody {
    pub kind: RecoveryDeviceQuorumProofKind,
    pub challenge: Challenge,
    #[serde(deserialize_with = "deserialize_minimum_two")]
    pub threshold: u64,
    pub signatures: Vec<RecoveryDeviceQuorumSignatureBody>,
}

impl RecoveryDeviceQuorumProof {
    pub fn signature_independent_proof_body(&self) -> Result<RecoveryDeviceQuorumProofBody> {
        Ok(RecoveryDeviceQuorumProofBody {
            kind: self.kind,
            challenge: self.challenge.clone(),
            threshold: self.threshold,
            signatures: self
                .signatures
                .iter()
                .map(|signature| {
                    Ok(RecoveryDeviceQuorumSignatureBody {
                        device_id: signature.device_id.clone(),
                        verification_method: signature.verification_method.clone(),
                        signature_algorithm: RecoveryFactorSignatureAlgorithm::try_from(
                            &signature.signature_algorithm,
                        )?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }
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
    pub service_id: DidCoreId,
    pub audience: NonEmptyString,
    pub verification_method: DidUrl,
    pub signature_algorithm: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<NonEmptyString>,
    pub signature: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRecoveryServiceProofBody {
    pub kind: TrustedRecoveryServiceSessionProofKind,
    pub challenge: Challenge,
    pub service_id: DidCoreId,
    pub audience: NonEmptyString,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoveryFactorSignatureAlgorithm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<NonEmptyString>,
}

impl TrustedRecoveryServiceSessionProof {
    pub fn signature_independent_proof_body(&self) -> Result<TrustedRecoveryServiceProofBody> {
        Ok(TrustedRecoveryServiceProofBody {
            kind: self.kind,
            challenge: self.challenge.clone(),
            service_id: self.service_id.clone(),
            audience: self.audience.clone(),
            verification_method: self.verification_method.clone(),
            signature_algorithm: RecoveryFactorSignatureAlgorithm::try_from(
                &self.signature_algorithm,
            )?,
            attestation_ref: self.attestation_ref.clone(),
        })
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RecoverySessionProof {
    DidRoot(RecoveryDidRootProof),
    RecoveryUnlock(RecoverySessionUnlockProof),
    DeviceQuorum(RecoveryDeviceQuorumProof),
    TrustedRecoveryService(TrustedRecoveryServiceSessionProof),
    ThresholdRecovery(ThresholdRecoveryProof),
}

impl<'de> Deserialize<'de> for RecoverySessionProof {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value.get("kind").and_then(Value::as_str) {
            Some("did_root") => serde_json::from_value(value)
                .map(Self::DidRoot)
                .map_err(serde::de::Error::custom),
            Some("recovery_unlock") => serde_json::from_value(value)
                .map(Self::RecoveryUnlock)
                .map_err(serde::de::Error::custom),
            Some("device_quorum") => serde_json::from_value(value)
                .map(Self::DeviceQuorum)
                .map_err(serde::de::Error::custom),
            Some("trusted_recovery_service") => serde_json::from_value(value)
                .map(Self::TrustedRecoveryService)
                .map_err(serde::de::Error::custom),
            Some("threshold_recovery") => serde_json::from_value(value)
                .map(Self::ThresholdRecovery)
                .map_err(serde::de::Error::custom),
            Some(kind) => Err(serde::de::Error::custom(format!(
                "unsupported recovery session proof kind '{kind}'"
            ))),
            None => Err(serde::de::Error::custom(
                "recovery session proof is missing kind discriminator",
            )),
        }
    }
}

impl RecoverySessionProof {
    /// Reconstruct the schema-closed transcript projection. `did_root` is the
    /// only factor without a proof_body; every signature carrier is deleted.
    pub fn signature_independent_proof_body(&self) -> Result<Option<GenericRecoveryProofBody>> {
        match self {
            Self::DidRoot(_) => Ok(None),
            Self::RecoveryUnlock(proof) => proof
                .signature_independent_proof_body()
                .map(GenericRecoveryProofBody::RecoveryUnlock)
                .map(Some),
            Self::DeviceQuorum(proof) => proof
                .signature_independent_proof_body()
                .map(GenericRecoveryProofBody::DeviceQuorum)
                .map(Some),
            Self::TrustedRecoveryService(proof) => proof
                .signature_independent_proof_body()
                .map(GenericRecoveryProofBody::TrustedRecoveryService)
                .map(Some),
            Self::ThresholdRecovery(proof) => proof
                .signature_independent_proof_body()
                .map(GenericRecoveryProofBody::ThresholdRecovery)
                .map(Some),
        }
    }
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
    pub request_id: RequestId,
    pub recovery_session_id: RecoverySessionId,
    pub session_grant_id: SessionGrantId,
    pub session_grant_cnf_jkt: String,
    pub principal_authority: PrincipalAuthorityKey,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub identity_model: RecoveryIdentityModel,
    pub current_device_generation_ref: u64,
    pub device_generation_status: DeviceGenerationStatus,
    pub registry_head: Hash,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub accepted_seal_frontier: DeviceReanchorPreFenceSealFrontier,
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
            22 + usize::from(self.proof_summary.is_some())
                + usize::from(self.transaction_id.is_some())
                + usize::from(self.rejection_reason_code.is_some()),
        ))?;
        map.serialize_entry("schema", &self.schema)?;
        map.serialize_entry("request_id", &self.request_id)?;
        map.serialize_entry("recovery_session_id", &self.recovery_session_id)?;
        map.serialize_entry("session_grant_id", &self.session_grant_id)?;
        map.serialize_entry("session_grant_cnf_jkt", &self.session_grant_cnf_jkt)?;
        map.serialize_entry("principal_authority", &self.principal_authority)?;
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
    request_id: RequestId,
    recovery_session_id: RecoverySessionId,
    session_grant_id: SessionGrantId,
    session_grant_cnf_jkt: String,
    principal_authority: PrincipalAuthorityKey,
    requesting_device_id: DeviceId,
    trust_domain: TrustDomainId,
    policy_id: PolicyId,
    policy_version: u64,
    identity_model: RecoveryIdentityModel,
    current_device_generation_ref: u64,
    device_generation_status: DeviceGenerationStatus,
    registry_head: Hash,
    accepted_seal_frontier: DeviceReanchorPreFenceSealFrontier,
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
) -> std::result::Result<(), &'static str> {
    (identity_model == RecoveryIdentityModel::PcrPolicy)
        .then_some(())
        .ok_or("recovery session identity_model does not match its authoritative snapshot")
}

impl<'de> Deserialize<'de> for RecoverySessionState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RecoverySessionStateWire::deserialize(deserializer)?;
        validate_recovery_session_state_shape(wire.identity_model)
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
            request_id: wire.request_id,
            recovery_session_id: wire.recovery_session_id,
            session_grant_id: wire.session_grant_id,
            session_grant_cnf_jkt: wire.session_grant_cnf_jkt,
            principal_authority: wire.principal_authority,
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
        if self.schema != SchemaId::RECOVERY_SESSION_V1 {
            return Err(WireError::Protocol(
                "recovery session schema must be ak.schema.recovery_session.v1".to_owned(),
            ));
        }
        if self.policy_version < 1 {
            return Err(WireError::Protocol(
                "recovery session policy_version must be at least one".to_owned(),
            ));
        }
        if self.current_device_generation_ref == 0 {
            return Err(WireError::Protocol(
                "current_device_generation_ref must be positive".to_owned(),
            ));
        }
        validate_recovery_grant_jkt(&self.session_grant_cnf_jkt)?;
        validate_recovery_session_state_shape(self.identity_model)
            .map_err(|reason| WireError::Protocol(reason.to_owned()))?;
        self.publication_authority_context
            .validate_for(self.identity_model)?;
        if self.publication_authority_context.digest()? != self.publication_authority_context_digest
        {
            return Err(WireError::Protocol(
                "recovery publication authority context digest is invalid".to_owned(),
            ));
        }
        if matches!(self.state, SessionState::Verified | SessionState::Completed)
            && self.proof_summary.is_none()
        {
            return Err(WireError::Protocol(
                "verified or completed recovery session requires proof_summary".to_owned(),
            ));
        }
        if self.state == SessionState::Rejected && self.rejection_reason_code.is_none() {
            return Err(WireError::Protocol(
                "rejected recovery session requires rejection_reason_code".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_recovery_grant_jkt(value: &str) -> Result<()> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(WireError::Protocol(
            "recovery session grant cnf.jkt must be an unpadded SHA-256 JWK thumbprint".to_owned(),
        ));
    }
    Ok(())
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
    pub holder: DidCoreId,
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRecoveryProofShareReleaseBody {
    pub share_id: NonEmptyString,
    pub holder: DidCoreId,
    pub transcript_digest: Hash,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoveryFactorSignatureAlgorithm,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRecoveryProofBody {
    pub kind: ThresholdRecoveryProofKind,
    pub challenge: Challenge,
    #[serde(deserialize_with = "deserialize_minimum_two")]
    pub threshold: u64,
    pub share_releases: Vec<ThresholdRecoveryProofShareReleaseBody>,
}

impl ThresholdRecoveryProof {
    pub fn signature_independent_proof_body(&self) -> Result<ThresholdRecoveryProofBody> {
        Ok(ThresholdRecoveryProofBody {
            kind: self.kind,
            challenge: self.challenge.clone(),
            threshold: self.threshold,
            share_releases: self
                .share_releases
                .iter()
                .map(|release| {
                    Ok(ThresholdRecoveryProofShareReleaseBody {
                        share_id: release.share_id.clone(),
                        holder: release.holder.clone(),
                        transcript_digest: release.transcript_digest.clone(),
                        verification_method: release.verification_method.clone(),
                        signature_algorithm: RecoveryFactorSignatureAlgorithm::try_from(
                            &release.signature_algorithm,
                        )?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

/// Closed signature-independent body of a non-`did_root` recovery transcript.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GenericRecoveryProofBody {
    RecoveryUnlock(RecoveryUnlockProofBody),
    DeviceQuorum(RecoveryDeviceQuorumProofBody),
    TrustedRecoveryService(TrustedRecoveryServiceProofBody),
    ThresholdRecovery(ThresholdRecoveryProofBody),
}

impl GenericRecoveryProofBody {
    pub const fn kind(&self) -> RecoveryProofKind {
        match self {
            Self::RecoveryUnlock(_) => RecoveryProofKind::RecoveryUnlock,
            Self::DeviceQuorum(_) => RecoveryProofKind::DeviceQuorum,
            Self::TrustedRecoveryService(_) => RecoveryProofKind::TrustedRecoveryService,
            Self::ThresholdRecovery(_) => RecoveryProofKind::ThresholdRecovery,
        }
    }

    pub fn challenge(&self) -> &Challenge {
        match self {
            Self::RecoveryUnlock(body) => &body.challenge,
            Self::DeviceQuorum(body) => &body.challenge,
            Self::TrustedRecoveryService(body) => &body.challenge,
            Self::ThresholdRecovery(body) => &body.challenge,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::RecoveryUnlock(_) | Self::TrustedRecoveryService(_) => Ok(()),
            Self::DeviceQuorum(body) if body.signatures.len() >= 2 => Ok(()),
            Self::ThresholdRecovery(body) if body.share_releases.len() >= 2 => Ok(()),
            Self::DeviceQuorum(_) => Err(WireError::Protocol(
                "device_quorum transcript proof_body requires at least two signatures".to_owned(),
            )),
            Self::ThresholdRecovery(_) => Err(WireError::Protocol(
                "threshold_recovery transcript proof_body requires at least two share releases"
                    .to_owned(),
            )),
        }
    }
}

#[cfg(test)]
mod untagged_contract_tests {
    use super::*;

    #[test]
    fn embedded_recovery_transcript_kat_closes_all_five_factors() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/recovery-transcript-fixture.json")
                .unwrap();
        let public_key = arkret_canonical::base64url_decode(
            fixture
                .pointer("/test_key/public_key")
                .unwrap()
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let verifying_key =
            VerifyingKey::from_bytes(public_key.as_slice().try_into().unwrap()).unwrap();
        let cases = fixture.get("cases").unwrap().as_array().unwrap();
        assert_eq!(cases.len(), RecoveryProofKind::ALL.len());

        for (case, expected_kind) in cases.iter().zip(RecoveryProofKind::ALL) {
            assert_eq!(
                case.get("kind").unwrap().as_str().unwrap(),
                expected_kind.as_wire_str()
            );
            let transcript = case.get("transcript").unwrap();
            let canonical = arkret_canonical::canonical_json_bytes(transcript).unwrap();
            assert_eq!(
                std::str::from_utf8(&canonical).unwrap(),
                case.get("transcript_jcs").unwrap().as_str().unwrap()
            );
            let signature = Signature::from_slice(
                &arkret_canonical::base64url_decode(
                    case.get("signature_b64u").unwrap().as_str().unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            verifying_key.verify(&canonical, &signature).unwrap();

            if *expected_kind == RecoveryProofKind::DidRoot {
                serde_json::from_value::<DidRootTranscript>(transcript.clone()).unwrap();
            } else {
                serde_json::from_value::<GenericRecoveryTranscript>(transcript.clone()).unwrap();
            }

            let proof: RecoverySessionProof =
                serde_json::from_value(case.get("source_proof").unwrap().clone()).unwrap();
            let projected = proof.signature_independent_proof_body().unwrap();
            assert_eq!(
                projected
                    .as_ref()
                    .map(|value| serde_json::to_value(value).unwrap()),
                transcript.get("proof_body").cloned()
            );

            let replay = case.pointer("/cross_factor_replay/transcript").unwrap();
            let replay_bytes = arkret_canonical::canonical_json_bytes(replay).unwrap();
            assert!(verifying_key.verify(&replay_bytes, &signature).is_err());
        }

        let mut did_root_with_body = cases[0].get("transcript").unwrap().clone();
        did_root_with_body["proof_body"] = serde_json::json!({});
        assert!(serde_json::from_value::<DidRootTranscript>(did_root_with_body).is_err());

        let recovery_unlock = cases[1].get("transcript").unwrap();
        let mut wrong_kind = recovery_unlock.clone();
        wrong_kind["kind"] = Value::String("device_quorum".to_owned());
        assert!(serde_json::from_value::<GenericRecoveryTranscript>(wrong_kind).is_err());

        let mut wrong_body_challenge = recovery_unlock.clone();
        wrong_body_challenge["proof_body"]["challenge"] = Value::String("B".repeat(43));
        assert!(serde_json::from_value::<GenericRecoveryTranscript>(wrong_body_challenge).is_err());

        let mut unknown_algorithm = recovery_unlock.clone();
        unknown_algorithm["proof_body"]["signature_algorithm"] = Value::String("ES256".to_owned());
        assert!(serde_json::from_value::<GenericRecoveryTranscript>(unknown_algorithm).is_err());
    }

    #[test]
    fn recovery_challenge_enforces_the_exact_schema_shape() {
        let valid = "A".repeat(43);
        let challenge = Challenge::new(valid.clone()).unwrap();
        assert_eq!(challenge.as_str(), valid);
        assert_eq!(serde_json::to_value(&challenge).unwrap(), valid);

        for invalid in [
            "A".repeat(42),
            "A".repeat(44),
            format!("{}=", "A".repeat(42)),
        ] {
            assert!(Challenge::new(invalid.clone()).is_err());
            assert!(serde_json::from_value::<Challenge>(Value::String(invalid)).is_err());
        }
    }

    #[test]
    fn recovery_session_proof_requires_a_registered_kind() {
        for value in [
            serde_json::json!({}),
            serde_json::json!({"kind": "future_recovery_proof"}),
        ] {
            assert!(serde_json::from_value::<RecoverySessionProof>(value).is_err());
        }
    }

    #[test]
    fn portable_history_keybag_rejects_a_sidecar_effective_scope() {
        let keybag = serde_json::json!({
            "schema": KeyBackupPlaintext::SCHEMA,
            "backup_id": "ak:backup:01964137-0000-7000-8000-000000000000",
            "backup_kind": "mls_history",
            "series_id": "ak:backup_series:01964137-0000-7000-8000-000000000001",
            "series_seq": 0,
            "effective_scope": {
                "kind": "sidecar",
                "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
                "sidecar_id": "ak:sidecar:Ae0kN-KHls3vjqQ9FHo4P_2uAhcMVu8dI8qHcFsqGn5d",
            },
            "items": [{"from_epoch": 1, "to_epoch": 1, "secrets_b64u": "AA"}],
        });
        assert!(serde_json::from_value::<KeyBackupPlaintext>(keybag).is_err());
    }

    #[test]
    fn portable_history_keybag_rejects_active_mls_state_items() {
        let keybag = serde_json::json!({
            "schema": KeyBackupPlaintext::SCHEMA,
            "backup_id": "ak:backup:01964137-0000-7000-8000-000000000000",
            "backup_kind": "mls_history",
            "series_id": "ak:backup_series:01964137-0000-7000-8000-000000000001",
            "series_seq": 0,
            "effective_scope": {
                "kind": "realm",
                "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
            },
            "items": [{
                "item_kind": "mls_group_state",
                "secret_id": "group-state",
                "secret_b64u": "AA",
            }],
        });
        assert!(serde_json::from_value::<KeyBackupPlaintext>(keybag).is_err());
    }

    #[test]
    fn secret_storage_keybag_rejects_an_effective_scope() {
        let keybag = serde_json::json!({
            "schema": KeyBackupPlaintext::SCHEMA,
            "backup_id": "ak:backup:01964137-0000-7000-8000-000000000000",
            "backup_kind": "secret_storage",
            "series_id": "ak:backup_series:01964137-0000-7000-8000-000000000001",
            "series_seq": 0,
            "effective_scope": {
                "kind": "realm",
                "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
            },
            "items": [{
                "item_kind": "private_account_state",
                "secret_id": "account-state",
                "secret_b64u": "AA",
            }],
        });
        assert!(serde_json::from_value::<KeyBackupPlaintext>(keybag).is_err());
    }

    #[test]
    fn a_history_range_index_rejects_secret_storage_only_fields() {
        let index = serde_json::json!({
            "item_kind": "history_secret_ranges",
            "effective_scope": {
                "kind": "realm",
                "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
            },
            "ranges": [{"from_epoch": 0, "to_epoch": 3}],
            "secret_id": "segment",
        });
        assert!(serde_json::from_value::<KeyBackupContentItem>(index).is_err());
    }
}
