//! Account-operations schema artifact counterparts (identity face).
//!
//! The account-subscribe sync frame containers stay in the `arkret` umbrella
//! (`models/artifacts/account_sync.rs`).

use arkret_wire::{DeviceId, DeviceRevocationGateRecord, EventId, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DeviceSummaryStatus {
    Active,
    RevocationPending,
    Revoked,
    Expired,
    GenerationFenced,
    Conflicted,
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
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub authorized_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub last_seen_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_states: Option<Vec<DeviceRevocationGateRecord>>,
}

impl DeviceSummary {
    pub fn validate(&self) -> Result<()> {
        validate_device_summary_evidence(
            self.status,
            self.verification_state,
            self.verification_source,
            self.authorized_event_ref.as_ref(),
            self.revocation_states.as_deref(),
        )
    }
}

pub fn validate_device_summary_evidence(
    status: DeviceSummaryStatus,
    verification_state: DeviceSummaryVerificationState,
    verification_source: Option<DeviceSummaryVerificationSource>,
    authorized_event_ref: Option<&EventId>,
    revocation_states: Option<&[DeviceRevocationGateRecord]>,
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
        if authorized_event_ref.is_none() {
            return Err(WireError::Protocol(
                "verified or stale device summary requires its exact committed authorization Event"
                    .to_owned(),
            ));
        }
    } else if authorized_event_ref.is_some() {
        return Err(WireError::Protocol(
            "an unresolved device summary must not expose an authorization reference".to_owned(),
        ));
    }
    match status {
        DeviceSummaryStatus::RevocationPending | DeviceSummaryStatus::Revoked => {
            let states = revocation_states.ok_or_else(|| {
                WireError::Protocol("revocation status requires revocation_states".to_owned())
            })?;
            if states.is_empty() || states.len() > 128 {
                return Err(WireError::Protocol(
                    "revocation_states must contain 1..=128 records".to_owned(),
                ));
            }
            if status == DeviceSummaryStatus::RevocationPending
                && states.iter().any(|state| !state.is_pending())
            {
                return Err(WireError::Protocol(
                    "revocation_pending requires only pending records".to_owned(),
                ));
            }
            if status == DeviceSummaryStatus::Revoked
                && !states.iter().any(|state| state.is_revoked())
            {
                return Err(WireError::Protocol(
                    "revoked requires a committed revocation record".to_owned(),
                ));
            }
            let mut previous = None;
            for state in states {
                state.validate()?;
                let key = (state.acceptance_seq(), state.proposal_event_id().as_str());
                if previous.is_some_and(|previous| previous >= key) {
                    return Err(WireError::Protocol(
                        "revocation_states must be unique and strictly sorted".to_owned(),
                    ));
                }
                previous = Some(key);
            }
        }
        _ if revocation_states.is_some() => {
            return Err(WireError::Protocol(
                "this device status must not carry revocation_states".to_owned(),
            ));
        }
        _ => {}
    }
    Ok(())
}
