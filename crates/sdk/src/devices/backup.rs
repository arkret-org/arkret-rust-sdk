use arkret_core::BackupClass;
use hkdf::Hkdf;

use super::*;

fn hkdf_sha256_32(input_key_material: &[u8], info: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    Hkdf::<Sha256>::new(None, input_key_material)
        .expand(info, &mut output)
        .expect("32-byte HKDF-SHA256 output is always valid");
    output
}

/// Recommended `key_commitment` construction
/// (`key-management.md` §7.2):
///
/// ```text
/// commitment_key = HKDF(derived_key, info="arkret-key-backup-commitment-v1")
/// key_commitment = SHA256(commitment_key)
/// ```
///
/// Used by callers to fail-fast when the user types a wrong passphrase.
/// The server MUST NOT use this field for authentication.
pub fn key_backup_commitment(derived_key: &[u8]) -> String {
    let commitment_key = hkdf_sha256_32(derived_key, b"arkret-key-backup-commitment-v1");
    canonical::sha256_digest(commitment_key)
}

/// HKDF subdomain key derivation per `key-management.md` §7.2.
///
/// Returns 32 bytes of a domain-isolated subkey suitable for AEAD or
/// further key wrapping. Derives via HKDF-SHA256 over `derived_key`
/// using `info = backup_class.hkdf_info(subdomain)`.
pub fn key_backup_subdomain_key(
    derived_key: &[u8],
    backup_class: BackupClass,
    subdomain: &str,
) -> [u8; 32] {
    let info = backup_class.hkdf_info(subdomain);
    hkdf_sha256_32(derived_key, info.as_bytes())
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
    backup_class: BackupClass,
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
    Ok(canonical::canonical_json_bytes(&aad)?)
}
