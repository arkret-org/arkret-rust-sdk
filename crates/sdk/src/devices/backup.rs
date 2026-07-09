use super::*;

fn is_false(value: &bool) -> bool {
    !*value
}

/// Schema-aligned encrypted key backup class
/// (`key-management.md` §7.1–§7.2).
///
/// Each variant maps to its own HKDF subdomain and AEAD AAD binding.
/// `External` is reserved for hardware-attested or third-party
/// backup providers that don't fit the on-device passphrase model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupClass {
    DidRecovery,
    SecretStorage,
    MlsHistory,
    External,
}

impl KeyBackupClass {
    /// Canonical wire string, mirroring the `serde(rename_all = "snake_case")`
    /// representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DidRecovery => "did_recovery",
            Self::SecretStorage => "secret_storage",
            Self::MlsHistory => "mls_history",
            Self::External => "external",
        }
    }

    /// HKDF `info` string for deriving an in-domain subkey from the
    /// passphrase-derived root unlock key, per `key-management.md`
    /// §7.2: `cokret-key-backup/<class>/<sub>/v1`.
    pub fn hkdf_info(&self, subdomain: &str) -> String {
        format!("cokret-key-backup/{}/{}/v1", self.as_str(), subdomain)
    }
}

/// HMAC-SHA256 helper (RFC 2104) used to bootstrap HKDF without a
/// dedicated dependency.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut k_prime = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let h = Sha256::digest(key);
        k_prime[..32].copy_from_slice(&h);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k_prime[i] ^ 0x36;
        opad[i] = k_prime[i] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let out = outer.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

/// HKDF-Expand (RFC 5869) restricted to 32-byte output (one round).
fn hkdf_expand_32(prk: &[u8], info: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(info.len() + 1);
    buf.extend_from_slice(info);
    buf.push(0x01);
    hmac_sha256(prk, &buf)
}

/// Recommended `key_commitment` construction
/// (`key-management.md` §7.2):
///
/// ```text
/// commitment_key = HKDF(derived_key, info="cokret-key-backup-commitment-v1")
/// key_commitment = SHA256(commitment_key)
/// ```
///
/// Used by callers to fail-fast when the user types a wrong passphrase.
/// The server MUST NOT use this field for authentication.
pub fn key_backup_commitment(derived_key: &[u8]) -> String {
    // HKDF-Extract with empty salt: PRK = HMAC-SHA256(zeros, IKM).
    let prk = hmac_sha256(&[0u8; 32], derived_key);
    let commitment_key = hkdf_expand_32(&prk, b"cokret-key-backup-commitment-v1");
    canonical::sha256_digest(commitment_key)
}

/// HKDF subdomain key derivation per `key-management.md` §7.2.
///
/// Returns 32 bytes of a domain-isolated subkey suitable for AEAD or
/// further key wrapping. Derives via HKDF-SHA256 over `derived_key`
/// using `info = backup_class.hkdf_info(subdomain)`.
pub fn key_backup_subdomain_key(
    derived_key: &[u8],
    backup_class: &KeyBackupClass,
    subdomain: &str,
) -> [u8; 32] {
    let info = backup_class.hkdf_info(subdomain);
    let prk = hmac_sha256(&[0u8; 32], derived_key);
    hkdf_expand_32(&prk, info.as_bytes())
}

/// Build the AEAD associated-data (AAD) blob that MUST bind a key-backup
/// envelope to its origin per `key-management.md` §7.1.
///
/// Returns canonical-JSON bytes covering:
/// `actor_id`, `device_id`, `backup_class`, `backup_version`,
/// `item_type`, `schema_id`, and `created_at`.
pub fn key_backup_aad(
    actor_id: &Did,
    device_id: Option<&DeviceId>,
    backup_class: &KeyBackupClass,
    backup_version: &str,
    item_type: &str,
    schema_id: &str,
    created_at: DateTime<Utc>,
) -> Result<Vec<u8>> {
    let aad = serde_json::json!({
        "actor_id": actor_id.as_str(),
        "device_id": device_id.map(|d| d.as_str()),
        "backup_class": backup_class.as_str(),
        "backup_version": backup_version,
        "item_type": item_type,
        "schema_id": schema_id,
        "created_at": created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    canonical::canonical_json_bytes(&aad)
}

// The backup encryption descriptor is owned by `cokret-core`
// (`models/key_backup.rs`, aligned with `key-backup.schema.json` including
// `hpke_suite` and open extension fields); the SDK reuses it directly.
use cokret_core::KeyBackupEncryption;

/// Schema-aligned backup content item.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyBackupContentItem {
    pub item_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub extra: Value,
}

/// Schema-aligned encrypted key backup facade from `ck.schema.key_backup.v1`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolKeyBackup {
    pub backup_id: String,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub backup_class: KeyBackupClass,
    #[serde(default, skip_serializing_if = "is_false")]
    pub mixed_secret_storage: bool,
    pub backup_version: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub encryption: KeyBackupEncryption,
    pub contents: Vec<KeyBackupContentItem>,
    pub ciphertext: String,
    pub ciphertext_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention: Option<Value>,
}
