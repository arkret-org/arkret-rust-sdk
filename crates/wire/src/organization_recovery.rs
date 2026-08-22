//! Realm-authority organization recovery key (RRK) wire objects.
//!
//! The archive is referenced from two independent contracts and therefore
//! lives on the shared wire boundary rather than inside either consumer: the
//! exporter MLS transition Events
//! (`event-payload.schema.json#/$defs/mls_genesis_payload` and
//! `#/$defs/mls_commit_payload`) embed exactly one archive per transition, and
//! the private history-key surface lists and replicates the same object.

use serde::{Deserialize, Serialize};

use crate::cba::SealBasis;
use crate::error::{Error, Result};
use crate::event_envelope::HistoryEffectiveScope;
use crate::{DidCoreId, DidUrl, EventId, Hash};

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/organization_recovery_archive`
/// `hpke_suite`. v1 fixes the single X25519 / ChaCha20-Poly1305 profile.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrganizationRecoveryHpkeSuite {
    #[serde(rename = "ak.hpke_x25519_aead_chacha20poly1305.v1")]
    Value,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/organization_recovery_archive`.
///
/// `transition_digest` is the `mls_transition_digest`: `commit_digest` for a
/// Commit and the closed Genesis core digest that excludes this archive, the
/// outer `event_id` and every proof.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRecoveryArchive {
    pub effective_scope: HistoryEffectiveScope,
    pub mls_group_id: String,
    pub epoch: u64,
    pub transition_digest: Hash,
    pub recovery_key_id: String,
    pub holder_principal_id: DidCoreId,
    pub holder_service_id: DidCoreId,
    pub key_agreement_ref: DidUrl,
    pub holder_signing_ref: DidUrl,
    pub hpke_suite: OrganizationRecoveryHpkeSuite,
    pub frozen_public_key_b64u: String,
    pub accepted_key_evidence_ref: EventId,
    pub holder_trusted_basis: SealBasis,
    pub enc: String,
    pub ciphertext: String,
}

impl OrganizationRecoveryArchive {
    pub const DOMAIN: &'static str = "ak.organization-recovery-archive-v1";

    pub fn validate(&self) -> Result<()> {
        validate_canonical_mls_group_id(&self.effective_scope, &self.mls_group_id)?;
        validate_recovery_key_id(&self.recovery_key_id)?;
        if self.frozen_public_key_b64u.len() != 43
            || !is_base64url(&self.frozen_public_key_b64u)
            || !matches!(
                crate::base64url::base64url_decode(&self.frozen_public_key_b64u),
                Ok(ref bytes) if bytes.len() == 32
            )
        {
            return Err(Error::Protocol(
                "archive frozen public key is invalid".to_owned(),
            ));
        }
        validate_base64url_bounded(&self.enc, 1, 2_048, "enc")?;
        validate_base64url_bounded(&self.ciphertext, 1, 16_384, "ciphertext")?;
        self.holder_trusted_basis.validate_protocol_bounds()
    }

    pub fn archive_digest(&self) -> Result<Hash> {
        self.validate()?;
        let mut preimage = Self::DOMAIN.as_bytes().to_vec();
        preimage.push(0);
        preimage.extend(crate::canonical::canonical_json_bytes(self)?);
        Ok(Hash::new(crate::canonical::sha256_digest(preimage))?)
    }
}

/// `common-ids.schema.json#/$defs/recovery_key_id`: `ak:recovery_key:<uuid-v7>`.
pub fn validate_recovery_key_id(value: &str) -> Result<()> {
    const PREFIX: &str = "ak:recovery_key:";
    let Some(uuid) = value.strip_prefix(PREFIX) else {
        return Err(Error::Protocol(
            "recovery_key_id must start with ak:recovery_key:".to_owned(),
        ));
    };
    let bytes = uuid.as_bytes();
    let shaped = bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|index| bytes[*index] == b'-')
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(byte)
        });
    if !shaped {
        return Err(Error::Protocol(
            "recovery_key_id must carry a canonical lowercase UUIDv7".to_owned(),
        ));
    }
    Ok(())
}

/// `mls_group_id` MUST equal the canonical derivation from the effective scope.
pub fn validate_canonical_mls_group_id(
    scope: &HistoryEffectiveScope,
    mls_group_id: &str,
) -> Result<()> {
    if mls_group_id.is_empty() || !is_base64url(mls_group_id) {
        return Err(Error::Protocol(
            "mls_group_id is not canonical base64url".to_owned(),
        ));
    }
    if scope.canonical_mls_group_id()? != mls_group_id {
        return Err(Error::Protocol(
            "mls_group_id does not match effective_scope".to_owned(),
        ));
    }
    Ok(())
}

pub fn is_base64url(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub fn validate_base64url_bounded(value: &str, min: usize, max: usize, field: &str) -> Result<()> {
    if !(min..=max).contains(&value.len()) || !is_base64url(value) {
        return Err(Error::Protocol(format!(
            "{field} is not canonical base64url"
        )));
    }
    Ok(())
}
