//! Exporter history-secret range wire objects.
//!
//! `history-key.schema.json#/$defs/epoch_range` and
//! `#/$defs/history_secret_range` are referenced from two independent
//! contracts and therefore live on the shared wire boundary rather than
//! inside either consumer: the private history-key surface indexes and
//! packs them, and the portable key backup
//! (`key-backup.schema.json#/properties/contents` plus
//! `key-backup-plaintext.schema.json`) carries the same two shapes.

use serde::{Deserialize, Serialize};

use crate::error::{Result, WireError};

/// Counterpart for
/// `spec/v1/artifacts/schemas/history-key.schema.json#/$defs/epoch_range`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochRange {
    pub from_epoch: u64,
    pub to_epoch: u64,
}

impl EpochRange {
    pub fn validate(&self) -> Result<()> {
        if self.from_epoch > self.to_epoch {
            return Err(WireError::Protocol(
                "history epoch range is empty".to_owned(),
            ));
        }
        Ok(())
    }

    /// Number of inclusive epochs the range covers.
    pub fn epoch_count(&self) -> Result<usize> {
        self.to_epoch
            .checked_sub(self.from_epoch)
            .and_then(|distance| distance.checked_add(1))
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| {
                WireError::Protocol("history epoch range count overflows usize".to_owned())
            })
    }
}

/// Sorted, disjoint, non-adjacent canonical range list shared by the history
/// request/receipt surface and the portable backup range index.
pub fn validate_canonical_ranges(ranges: &[EpochRange], maximum: usize) -> Result<()> {
    if ranges.is_empty() || ranges.len() > maximum {
        return Err(WireError::Protocol(format!(
            "history ranges must contain 1..={maximum} entries"
        )));
    }
    for range in ranges {
        range.validate()?;
    }
    for pair in ranges.windows(2) {
        if pair[0].to_epoch == u64::MAX || pair[0].to_epoch + 1 >= pair[1].from_epoch {
            return Err(WireError::Protocol(
                "history ranges must be sorted, disjoint, and non-adjacent".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/history-key.schema.json#/$defs/history_secret_range`.
///
/// `secrets_b64u` is the packed `history_secret[from] || ... || history_secret[to]`
/// concatenation. The decoded length is only checkable once `KDF.Nh` has been
/// resolved from the exact winning transition, so the length rule lives in
/// [`HistorySecretRange::validate_packed_length`] rather than in
/// [`HistorySecretRange::validate`].
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySecretRange {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub secrets_b64u: String,
}

impl HistorySecretRange {
    /// The public range index projection of this packed secret range.
    pub fn epoch_range(&self) -> EpochRange {
        EpochRange {
            from_epoch: self.from_epoch,
            to_epoch: self.to_epoch,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.epoch_range().validate()?;
        validate_unpadded_base64url(&self.secrets_b64u, "secrets_b64u")?;
        Ok(())
    }

    /// Enforce the fixed-width packing rule once the MLS ciphersuite `KDF.Nh`
    /// has been resolved from the exact winning transition.
    pub fn validate_packed_length(&self, kdf_nh: usize) -> Result<()> {
        self.validate()?;
        if kdf_nh == 0 {
            return Err(WireError::Protocol(
                "MLS ciphersuite KDF.Nh must be positive".to_owned(),
            ));
        }
        let expected = self
            .epoch_range()
            .epoch_count()?
            .checked_mul(kdf_nh)
            .ok_or_else(|| {
                WireError::Protocol("history secret range byte length overflows usize".to_owned())
            })?;
        let actual = crate::base64url::base64url_decode(&self.secrets_b64u)
            .map_err(|error| WireError::Protocol(format!("invalid history secret bytes: {error}")))?
            .len();
        if actual != expected {
            return Err(WireError::Protocol(format!(
                "history secret range contains {actual} bytes; expected {expected}"
            )));
        }
        Ok(())
    }
}

pub(crate) fn validate_unpadded_base64url(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(WireError::Protocol(format!(
            "{field} is not canonical unpadded base64url"
        )));
    }
    Ok(())
}
