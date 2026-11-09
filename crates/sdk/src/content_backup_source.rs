//! Historical Service signature only; native custody and original binding are independent.

use arkret_models_collaboration::content_history::ContentBackupSource;
use arkret_wire::WireError;

/// Verify the owning Station's Service signature at its original observation.
/// This does not grant producer authority, disclose history or prove storage.
/// First admission also requires the exact original/endpoint/slot binding and
/// observation window, plus the native issuer and governor acceptance checks.
pub fn verify_content_backup_source_signature(
    source: &ContentBackupSource,
) -> Result<(), WireError> {
    let attestation = &source.attestation;
    attestation.validate()?;
    let account = attestation
        .producer
        .actor_id
        .as_account_id()
        .ok_or_else(|| WireError::Protocol("backup source has no Account producer".into()))?;
    crate::mls_roster_authority::verify_station_signature(
        &account.station_id,
        attestation.attested_at,
        &attestation.signature,
        &attestation.signing_payload_bytes()?,
        &source.origin_resolution,
    )
}
