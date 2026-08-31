//! Account-operations schema artifact counterparts (identity face).
//!
//! The account-subscribe sync frame containers stay in the `arkret` umbrella
//! (`models/artifacts/account_sync.rs`).

use arkret_wire::{
    DeviceId, DeviceRevocationGateRecord, EventId, MAX_DEVICE_REVOCATION_GATE_RECORDS, Result,
    WireError,
};
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
        validate_device_summary_state(self.status, self.revocation_states.as_deref())
    }
}

pub fn validate_device_summary_state(
    status: DeviceSummaryStatus,
    revocation_states: Option<&[DeviceRevocationGateRecord]>,
) -> Result<()> {
    let states = revocation_states.unwrap_or_default();
    if states.len() > MAX_DEVICE_REVOCATION_GATE_RECORDS {
        return Err(WireError::Protocol(
            "device summary exceeds the 128 revocation-state bound".to_owned(),
        ));
    }
    for state in states {
        state.validate()?;
    }
    if states.windows(2).any(|pair| {
        (
            pair[0].acceptance_seq(),
            pair[0].proposal_event_id().as_str(),
        ) >= (
            pair[1].acceptance_seq(),
            pair[1].proposal_event_id().as_str(),
        )
    }) {
        return Err(WireError::Protocol(
            "device summary revocation_states must be sorted and duplicate-free".to_owned(),
        ));
    }
    match status {
        DeviceSummaryStatus::RevocationPending
            if !states.is_empty() && states.iter().all(DeviceRevocationGateRecord::is_pending) => {}
        DeviceSummaryStatus::Revoked
            if !states.is_empty() && states.iter().any(DeviceRevocationGateRecord::is_revoked) => {}
        DeviceSummaryStatus::Active
        | DeviceSummaryStatus::Expired
        | DeviceSummaryStatus::GenerationFenced
        | DeviceSummaryStatus::Conflicted
            if revocation_states.is_none() => {}
        _ => {
            return Err(WireError::Protocol(
                "device summary status is inconsistent with revocation_states".to_owned(),
            ));
        }
    }
    Ok(())
}
