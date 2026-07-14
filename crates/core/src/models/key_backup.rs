use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupPath {
    pub backup_id: BackupId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupsListQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub series_id: Option<BackupSeriesId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_class: Option<BackupClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysBackupsList {
    #[serde(default)]
    pub backups: Vec<KeyBackupSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum KeyBackupDeleteProof {
    DetachedJws(KeyBackupDeleteDetachedJwsProof),
    Development(KeyBackupDeleteDevelopmentProof),
}

pub const KEY_BACKUP_DELETE_DEVELOPMENT_PROOF_KIND: &str = "ak.key_backup.delete.development.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyBackupDeleteDevelopmentProof {
    pub kind: String,
    pub value: String,
}

impl KeyBackupDeleteDevelopmentProof {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            kind: KEY_BACKUP_DELETE_DEVELOPMENT_PROOF_KIND.to_owned(),
            value: value.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyBackupDeleteDetachedJwsProof {
    pub kind: String,
    pub issuer: Did,
    pub verification_method: String,
    pub jws: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsDeleteRequestBody {
    pub proof: KeyBackupDeleteProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysBackupsDeleteOutcome {
    pub deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<BackupId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysBackupsUnlockRequestBody {
    pub proof: KeyBackupUnlockProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupPutStatus {
    Accepted,
    Duplicate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysBackupsPutOutcome {
    pub status: KeyBackupPutStatus,
    pub backup_id: BackupId,
    pub ciphertext_digest: String,
}

pub type KeysBackupsReplaceOutcome = KeysBackupsPutOutcome;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupSummary {
    pub backup_id: BackupId,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub backup_class: BackupClass,
    pub backup_version: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupSummaryEncryption {
    pub recipient_method: KeyBackupRecipientMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_key_ref: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackup {
    pub backup_id: BackupId,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub backup_class: BackupClass,
    #[serde(default, skip_serializing_if = "is_false")]
    pub mixed_secret_storage: bool,
    pub backup_version: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    pub frontier_ref: Option<KeyBackupFrontierRef>,
    /// Recovery policy tuple under which this envelope was produced. Required
    /// for `backup_class=did_recovery`; optional signed hint for other classes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_policy_ref: Option<RecoveryPolicyRef>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl KeyBackup {
    pub fn is_first_did_recovery_backup(&self) -> bool {
        self.backup_class == BackupClass::DidRecovery && self.series_seq == 0
    }

    pub fn satisfies_first_did_recovery_backup_gate(&self) -> bool {
        self.is_first_did_recovery_backup()
            && self.recovery_policy_ref.is_some()
            && self.auth_data.as_ref().is_some_and(|auth| {
                !auth.device_id.as_str().is_empty()
                    && !auth.verification_method.is_empty()
                    && !auth.signature.is_empty()
                    && auth
                        .signed_fields
                        .iter()
                        .any(|field| field == "recovery_policy_ref")
            })
            && !self.contents.is_empty()
            && !self.ciphertext_digest.is_empty()
    }

    pub fn summary(&self) -> KeyBackupSummary {
        KeyBackupSummary {
            backup_id: self.backup_id.clone(),
            actor_id: self.actor_id.clone(),
            device_id: self.device_id.clone(),
            backup_class: self.backup_class,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyBackupFrontierRef {
    pub frontier_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssk_generation: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupRecipientMethod {
    PassphraseKdf,
    RecoveryPublicKey,
    SecretStorageKey,
}

/// Default-MUST application-layer HPKE suite selector. An absent
/// `encryption.hpke_suite` on a `recovery_public_key` envelope denotes this row
/// (key-backup.schema.json `encryption.hpke_suite`; hpke-suite-registry.json
/// `role=v1_default_must`).
pub const DEFAULT_HPKE_SUITE: &str = "ak.hpke_x25519_aead_chacha20poly1305.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct KeyBackupEncryptionWire {
    recipient_method: KeyBackupRecipientMethod,
    recipient_key_ref: Option<String>,
    kdf: Option<KeyBackupKdf>,
    aead: KeyBackupAead,
    key_commitment: Option<String>,
    hpke_suite: Option<String>,
    #[serde(default, flatten)]
    extra: BTreeMap<String, Value>,
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
                if self.kdf.is_none() {
                    return Err(Error::Protocol(
                        "key backup encryption: passphrase_kdf requires `kdf`".to_owned(),
                    ));
                }
                if self.aead.nonce.is_none() {
                    return Err(Error::Protocol(
                        "key backup encryption: passphrase_kdf requires `aead.nonce`".to_owned(),
                    ));
                }
                if self.aead.nonce_salt.is_none() {
                    return Err(Error::Protocol(
                        "key backup encryption: passphrase_kdf requires `aead.nonce_salt`"
                            .to_owned(),
                    ));
                }
                // hpke_suite applies only to recovery_public_key.
                if self.hpke_suite.is_some() {
                    return Err(Error::Protocol(
                        "key backup encryption: hpke_suite applies only to recovery_public_key"
                            .to_owned(),
                    ));
                }
            }
            KeyBackupRecipientMethod::SecretStorageKey => {
                // `then not kdf; required recipient_key_ref; aead requires nonce`.
                if self.kdf.is_some() {
                    return Err(Error::Protocol(
                        "key backup encryption: secret_storage_key forbids `kdf`".to_owned(),
                    ));
                }
                if self.recipient_key_ref.is_none() {
                    return Err(Error::Protocol(
                        "key backup encryption: secret_storage_key requires `recipient_key_ref`"
                            .to_owned(),
                    ));
                }
                if self.aead.nonce.is_none() {
                    return Err(Error::Protocol(
                        "key backup encryption: secret_storage_key requires `aead.nonce`"
                            .to_owned(),
                    ));
                }
                if self.hpke_suite.is_some() {
                    return Err(Error::Protocol(
                        "key backup encryption: hpke_suite applies only to recovery_public_key"
                            .to_owned(),
                    ));
                }
            }
            KeyBackupRecipientMethod::RecoveryPublicKey => {
                // `then not kdf; required recipient_key_ref; aead requires enc`.
                if self.kdf.is_some() {
                    return Err(Error::Protocol(
                        "key backup encryption: recovery_public_key forbids `kdf`".to_owned(),
                    ));
                }
                if self.recipient_key_ref.is_none() {
                    return Err(Error::Protocol(
                        "key backup encryption: recovery_public_key requires `recipient_key_ref`"
                            .to_owned(),
                    ));
                }
                if self.aead.enc.is_none() {
                    return Err(Error::Protocol(
                        "key backup encryption: recovery_public_key requires `aead.enc`".to_owned(),
                    ));
                }
                // An explicit hpke_suite (when present) MUST be an active
                // registry row, and the AEAD MUST equal the selected suite's
                // aead. Absent selector denotes DEFAULT_HPKE_SUITE.
                let suite_id = self.hpke_suite.as_deref().unwrap_or(DEFAULT_HPKE_SUITE);
                let suite_aead = active_hpke_suite_aead(suite_id)?.ok_or_else(|| {
                    Error::Protocol(format!(
                        "key backup encryption: hpke_suite `{suite_id}` is not an active \
                         hpke-suite-registry row (unsupported_hpke_suite)"
                    ))
                })?;
                if self.aead.name != suite_aead {
                    return Err(Error::Protocol(format!(
                        "key backup encryption: aead.name `{}` does not equal hpke_suite \
                         `{suite_id}` aead `{suite_aead}` (schema_violation)",
                        self.aead.name
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Return the AEAD name of an `active` `hpke-suite-registry.json` row, or
/// `Ok(None)` when the suite id is absent / `status != "active"`. Reads the
/// embedded registry snapshot so callers fail closed without a filesystem
/// dependency.
fn active_hpke_suite_aead(suite_id: &str) -> Result<Option<String>> {
    static ACTIVE_HPKE_SUITES: std::sync::OnceLock<
        std::result::Result<BTreeMap<String, String>, String>,
    > = std::sync::OnceLock::new();
    match ACTIVE_HPKE_SUITES.get_or_init(|| {
        let registry = crate::schema::embedded_json_artifact("registry/hpke-suite-registry.json")
            .map_err(|error| error.to_string())?;
        let suites = registry
            .get("suites")
            .and_then(Value::as_array)
            .ok_or_else(|| "hpke-suite-registry.json missing `suites` array".to_owned())?;
        let mut active = BTreeMap::new();
        for suite in suites {
            if suite.get("status").and_then(Value::as_str) != Some("active") {
                continue;
            }
            let Some(canonical_id) = suite.get("canonical_id").and_then(Value::as_str) else {
                continue;
            };
            let aead = suite
                .get("aead")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("hpke suite `{canonical_id}` missing `aead`"))?;
            active.insert(canonical_id.to_owned(), aead.to_owned());
        }
        Ok(active)
    }) {
        Ok(active) => Ok(active.get(suite_id).cloned()),
        Err(error) => Err(Error::Protocol(error.clone())),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupDomainSeparation {
    pub hkdf_info: String,
    pub subdomain: String,
    pub aead_aad: KeyBackupDomainSeparationAad,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupDomainSeparationAad {
    pub schema: String,
    pub actor_id: Did,
    pub device_id: String,
    pub backup_class: BackupClass,
    pub backup_version: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub item_types: Vec<String>,
    /// Canonical sorted set of every managed Agent PCR binding represented by
    /// the public content metadata and the encrypted plaintext keybag.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managed_principal_bindings: Vec<ManagedPrincipalBinding>,
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
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ManagedFrontierRef {
    pub frontier_digest: Hash,
    pub seal_ref: String,
    pub mls_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ManagedPrincipalBinding {
    pub managed_principal_id: Did,
    pub controller_id: Did,
    pub principal_control_realm_id: RealmId,
    pub authorization_ref: String,
    pub managed_frontier_ref: ManagedFrontierRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(try_from = "KeyBackupKdfWire")]
pub struct KeyBackupKdf {
    pub name: String,
    pub salt: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded_profile_reason: Option<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct KeyBackupKdfWire {
    name: String,
    salt: String,
    #[serde(default)]
    params: Value,
    degraded_profile_reason: Option<String>,
    #[serde(default, flatten)]
    extra: BTreeMap<String, Value>,
}

impl TryFrom<KeyBackupKdfWire> for KeyBackupKdf {
    type Error = String;

    fn try_from(wire: KeyBackupKdfWire) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            name: wire.name,
            salt: wire.salt,
            params: wire.params,
            degraded_profile_reason: wire.degraded_profile_reason,
            extra: wire.extra,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupAead {
    pub name: String,
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
    pub nonce_salt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// HPKE KEM encapsulated key for `recipient_method=recovery_public_key`
    /// (key-backup.schema.json `encryption.aead.enc`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc: Option<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupContentItem {
    pub item_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_principal_binding: Option<ManagedPrincipalBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    /// Monotonic version of the backed-up secret (e.g. `mls_account_secret`),
    /// used for deterministic preferred-backup selection and anti-rollback
    /// ordering (key-management.md §9.1). Present on versioned secret items;
    /// absent on share-style items (e.g. `recovery_key_share`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_version: Option<u32>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupAuthData {
    pub device_id: DeviceId,
    pub verification_method: String,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssk_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<EventId>,
    pub signed_fields: Vec<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupRetention {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_after: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<bool>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryPolicy {
    /// Schema id (`ak.schema.recovery_policy.v1`).
    pub schema: String,
    pub policy_id: PolicyId,
    pub principal_id: Did,
    /// Monotonically increasing counter scoped by `principal_id`.
    pub version: u64,
    /// Predecessor `policy_id`; `None` only for the genesis policy.
    pub supersedes: Option<PolicyId>,
    pub trust_domain: TypedTrustDomainId,
    pub allowed_proof_kinds: Vec<RecoveryProofKind>,
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
    /// Two-person-rule / cooldown enforcement layered on the proofs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_requirement: Option<RecoveryApprovalRequirement>,
    /// Where the recovery strand MUST emit auditable records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<RecoveryAuditConfig>,
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    /// `null` permitted; an empty `allowed_proof_kinds` revocation policy
    /// MUST set this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub auth_data: RecoveryPolicyAuthData,
    /// `x_*` extension fields (`patternProperties`).
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

/// Read-model summary for the currently accepted recovery policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicySummary {
    pub policy_id: PolicyId,
    pub principal_id: Did,
    pub version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_policy_ref: Option<RecoveryPolicyRef>,
    pub trust_domain: TypedTrustDomainId,
    pub allowed_proof_kinds: Vec<RecoveryProofKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub issued_at: DateTime<Utc>,
    pub accepted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<RecoveryPolicy>,
}

/// Principal control-stream frontier used by recovery policy read models.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoveryControlFrontier {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<DateTime<Utc>>,
}

/// Response for `ak.root.identity.recovery_policy.resource.get`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyActiveOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<Did>,
    pub active_policy: Option<RecoveryPolicySummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy_ref: Option<RecoveryPolicyRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_of: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_frontier: Option<RecoveryControlFrontier>,
}

/// Response for `ak.root.identity.recovery_policy.command.publish`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyPublishOutcome {
    pub ok: bool,
    pub policy_id: PolicyId,
    pub principal_id: Did,
    pub version: u64,
    pub accepted_at: DateTime<Utc>,
}

/// `recovery-policy.schema.json#/properties/threshold` — Shamir-style
/// threshold recovery configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReshareScheme {
    None,
    ProactiveVss,
    ProactiveFeldman,
    ServiceDefined,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoveryResharePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_share_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<RecoveryReshareScheme>,
}

/// `recovery-policy.schema.json#/$defs/share` — single recovery share.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryShare {
    pub share_id: String,
    pub holder: Did,
    pub transport: String,
    pub share_commitment: ShareShareCommitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason_code: Option<String>,
}

/// `recovery-policy.schema.json#/properties/device_quorum`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryDeviceQuorumConfig {
    pub k: u32,
    pub members: Vec<DeviceId>,
}

/// `recovery-policy.schema.json#/properties/trusted_recovery_services[]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryTrustedService {
    pub service_id: Did,
    pub audience: String,
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryKeyEntry {
    /// DID URL identifying this recovery signing key
    /// (e.g. `did:webvh:...#recovery-1`). Unique within `recovery_keys[]`.
    pub verification_method: String,
    /// Signature algorithm; v1 fixes this to `Ed25519`.
    pub alg: String,
    /// Earliest instant this key may authorize a `recovery_unlock` proof.
    pub not_before: DateTime<Utc>,
    /// Instant after which this key MUST NOT authorize a proof.
    pub expires_at: DateTime<Utc>,
    /// When set, the entry is revoked from this instant onward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// `recovery-policy.schema.json#/properties/approval_requirement`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryApprovalRequirement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_approvals: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announcement_required: Option<bool>,
}

/// `recovery-policy.schema.json#/properties/audit`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryAuditConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_required: Option<bool>,
}

/// `recovery-policy.schema.json#/properties/auth_data` — detached signature
/// over the declared `signed_fields`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryPolicyAuthData {
    pub verification_method: String,
    pub signature_algorithm: String,
    pub signature: String,
    pub signed_fields: Vec<String>,
}

/// AKP recovery proof-family enum, aligned to `recovery-policy.schema.json`
/// `allowed_proof_kinds[]` and `recovery-receipt.schema.json`
/// `proof_summary.kind`. Cryptographic proof validation is specified by
/// device-lifecycle verifier rules and handled outside this discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RecoveryProofKind {
    /// Principal-key direct signature (sovereign deployments).
    PrincipalSigning,
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
        Self::PrincipalSigning,
        Self::RecoveryUnlock,
        Self::DeviceQuorum,
        Self::TrustedRecoveryService,
        Self::ThresholdRecovery,
    ];

    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::PrincipalSigning => "principal_signing",
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
/// Required surface: `schema`, `receipt_id`, `principal_id`,
/// `recovery_session_id`, `policy_id`, `policy_version`, `trust_domain`,
/// `new_device_id`, `proof_summary`, `backup_classes_unlocked`,
/// `welcome_count`, `outcome`, `started_at`, `completed_at`, `auth_data`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryReceipt {
    /// Schema id (`ak.schema.recovery_receipt.v1`).
    pub schema: String,
    pub receipt_id: ReceiptId,
    pub principal_id: Did,
    pub recovery_session_id: RecoverySessionId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub trust_domain: TypedTrustDomainId,
    pub new_device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_ssk_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_ssk_generation: Option<u64>,
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
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub auth_data: RecoveryReceiptAuthData,
    /// `x_*` extension fields (`patternProperties`).
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

/// `recovery-receipt.schema.json#/properties/proof_summary`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryProofSummary {
    pub kind: RecoveryProofKind,
    pub proof_digest: Hash,
    /// Required for `device_quorum` and `threshold_recovery`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum_size: Option<u32>,
    /// Participating share ids when `kind = threshold_recovery`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_ids: Option<Vec<String>>,
}

/// `recovery-receipt.schema.json#/properties/backup_classes_unlocked[]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryBackupClassUnlocked {
    pub backup_class: RecoveryBackupClass,
    pub backup_id: BackupId,
    pub series_id: BackupSeriesId,
    pub ciphertext_digest: Hash,
}

/// `recovery-receipt.schema.json` backup-class discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RecoveryBackupClass {
    DidRecovery,
    SecretStorage,
    MlsHistory,
}

/// `recovery-receipt.schema.json#/properties/welcome_realm_summary[]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryWelcomeRealmSummary {
    pub realm_id: RealmId,
    pub mls_group_id: String,
    pub epoch: u64,
}

/// `recovery-receipt.schema.json#/properties/outcome` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RecoveryReceiptAuthData {
    pub verification_method: String,
    pub signature_algorithm: String,
    pub signature: String,
    pub signed_fields: Vec<String>,
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

#[cfg(test)]
mod encryption_validate_tests {
    use super::*;

    fn aead(name: &str) -> KeyBackupAead {
        KeyBackupAead {
            name: name.to_owned(),
            aead_profile: None,
            nonce_salt: None,
            nonce: None,
            enc: None,
            extra: BTreeMap::new(),
        }
    }

    fn passphrase() -> KeyBackupEncryption {
        let mut aead = aead("xchacha20_poly1305");
        aead.nonce = Some("AAAA".to_owned());
        aead.nonce_salt = Some("AAAAAAAAAAAAAAAA".to_owned());
        KeyBackupEncryption {
            recipient_method: KeyBackupRecipientMethod::PassphraseKdf,
            recipient_key_ref: None,
            kdf: Some(KeyBackupKdf {
                name: "argon2id".to_owned(),
                salt: "AAAA".to_owned(),
                params: Value::Null,
                degraded_profile_reason: None,
                extra: BTreeMap::new(),
            }),
            aead,
            key_commitment: None,
            hpke_suite: None,
            extra: BTreeMap::new(),
        }
    }

    fn recovery_public_key(suite: Option<&str>, aead_name: &str) -> KeyBackupEncryption {
        let mut aead = aead(aead_name);
        aead.enc = Some("AAAA".to_owned());
        KeyBackupEncryption {
            recipient_method: KeyBackupRecipientMethod::RecoveryPublicKey,
            recipient_key_ref: Some("did:webvh:example#recovery".to_owned()),
            kdf: None,
            aead,
            key_commitment: None,
            hpke_suite: suite.map(str::to_owned),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn passphrase_kdf_requires_kdf_and_nonce_fields() {
        passphrase().validate().expect("valid passphrase envelope");

        let mut missing_kdf = passphrase();
        missing_kdf.kdf = None;
        assert!(missing_kdf.validate().is_err());

        let mut missing_salt = passphrase();
        missing_salt.aead.nonce_salt = None;
        assert!(missing_salt.validate().is_err());

        let mut stray_suite = passphrase();
        stray_suite.hpke_suite = Some(DEFAULT_HPKE_SUITE.to_owned());
        assert!(stray_suite.validate().is_err());
    }

    #[test]
    fn recovery_public_key_default_suite_passes() {
        // Absent selector denotes the default-MUST RFC 9180 ChaCha20-Poly1305
        // suite; aead.name MUST match that suite's AEAD.
        recovery_public_key(None, "chacha20_poly1305")
            .validate()
            .expect("default suite envelope is valid");
    }

    #[test]
    fn recovery_public_key_rejects_inactive_suite() {
        // Reserved (not active) PQ hybrid row MUST fail closed.
        let envelope = recovery_public_key(
            Some("ak.hpke_xwing_aead_chacha20poly1305.v1"),
            "xchacha20_poly1305",
        );
        assert!(envelope.validate().is_err());
        // Wholly unregistered id MUST fail closed.
        let bogus = recovery_public_key(Some("ak.hpke_bogus.v1"), "xchacha20_poly1305");
        assert!(bogus.validate().is_err());
    }

    #[test]
    fn recovery_public_key_rejects_aead_suite_mismatch() {
        // active aes256gcm suite but aead.name is xchacha → mismatch.
        let envelope = recovery_public_key(
            Some("ak.hpke_x25519_aead_aes256gcm.v1"),
            "xchacha20_poly1305",
        );
        assert!(envelope.validate().is_err());
        // Matching aead passes.
        recovery_public_key(Some("ak.hpke_x25519_aead_aes256gcm.v1"), "aes_256_gcm")
            .validate()
            .expect("matching aead is valid");
    }

    #[test]
    fn recovery_public_key_requires_enc_and_key_ref() {
        let mut missing_enc = recovery_public_key(None, "xchacha20_poly1305");
        missing_enc.aead.enc = None;
        assert!(missing_enc.validate().is_err());

        let mut missing_ref = recovery_public_key(None, "xchacha20_poly1305");
        missing_ref.recipient_key_ref = None;
        assert!(missing_ref.validate().is_err());

        let mut stray_kdf = recovery_public_key(None, "xchacha20_poly1305");
        stray_kdf.kdf = Some(KeyBackupKdf {
            name: "argon2id".to_owned(),
            salt: "AAAA".to_owned(),
            params: Value::Null,
            degraded_profile_reason: None,
            extra: BTreeMap::new(),
        });
        assert!(stray_kdf.validate().is_err());
    }

    #[test]
    fn deserialization_runs_validation() {
        // An invalid wire envelope (recovery_public_key without enc) is rejected
        // by serde via the `try_from` shim, not silently accepted.
        let json = serde_json::json!({
            "recipient_method": "recovery_public_key",
            "recipient_key_ref": "did:webvh:example#recovery",
            "aead": { "name": "xchacha20_poly1305" }
        });
        let parsed: std::result::Result<KeyBackupEncryption, _> = serde_json::from_value(json);
        assert!(
            parsed.is_err(),
            "missing aead.enc must fail deserialization"
        );
    }
}
