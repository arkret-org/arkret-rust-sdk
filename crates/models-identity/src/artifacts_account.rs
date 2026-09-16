//! Account-operations schema artifact counterparts (identity face).
//!
//! The account-subscribe sync frame containers stay in the `arkret` umbrella
//! (`models/artifacts/account_sync.rs`).

use arkret_wire::{CommittedEventRef, DeviceId, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DeviceSummaryStatus {
    Active,
    Revoked,
    Expired,
    GenerationFenced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DeviceSummaryVerificationState {
    Verified,
    Unresolved,
    Stale,
}

/// Closed provenance of the verification checkpoint behind
/// [`DeviceSummaryVerificationState`], per `crypto-media/device-lifecycle.md`
/// §10.1. Login factors, SSO sessions, ordinary session grants and bare server
/// projections never mint a checkpoint, so they have no spelling here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DeviceSummaryVerificationSource {
    /// PCR genesis first device.
    Genesis,
    /// Accepted-device pairing or re-verification ceremony.
    PairingCode,
    /// Replacement device of an accepted recovery unit.
    Recovery,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/device_summary`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSummary {
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub status: DeviceSummaryStatus,
    pub verification_state: DeviceSummaryVerificationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_source: Option<DeviceSummaryVerificationSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<CommittedEventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub authorized_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub last_seen_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl DeviceSummary {
    pub fn validate(&self) -> Result<()> {
        validate_device_summary_evidence(
            self.verification_state,
            self.verification_source,
            self.authorization_ref.as_ref(),
        )
    }
}

pub fn validate_device_summary_evidence(
    verification_state: DeviceSummaryVerificationState,
    verification_source: Option<DeviceSummaryVerificationSource>,
    authorization_ref: Option<&CommittedEventRef>,
) -> Result<()> {
    // `device-lifecycle.md` §10.1: the provenance is present exactly when a
    // checkpoint exists. `stale` keeps the source of the checkpoint it used to
    // hold, `unresolved` never had one.
    match verification_state {
        DeviceSummaryVerificationState::Verified if verification_source.is_none() => {
            return Err(WireError::Protocol(
                "verified device summary requires a verification_source".to_owned(),
            ));
        }
        DeviceSummaryVerificationState::Unresolved if verification_source.is_some() => {
            return Err(WireError::Protocol(
                "unresolved device summary must not carry a verification_source".to_owned(),
            ));
        }
        _ => {}
    }
    if matches!(
        verification_state,
        DeviceSummaryVerificationState::Verified | DeviceSummaryVerificationState::Stale
    ) {
        if authorization_ref.is_none() {
            return Err(WireError::Protocol(
                "verified or stale device summary requires its exact committed authorization Event"
                    .to_owned(),
            ));
        }
    } else if authorization_ref.is_some() {
        return Err(WireError::Protocol(
            "an unresolved device summary must not expose an authorization reference".to_owned(),
        ));
    }
    Ok(())
}
