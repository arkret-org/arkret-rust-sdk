//! Bounded account-summary and baseline carriers for client-sync section 2.3.

use std::collections::BTreeSet;

use arkret_wire::{Cursor, RealmId, Result, StrandId, WireError};
use serde::{Deserialize, Serialize};

pub const ACCOUNT_SYNC_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const ACCOUNT_SYNC_MAX_WIRE_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const ACCOUNT_SYNC_MAX_ROUND_BYTES: usize = 16 * 1024 * 1024;
pub const ACCOUNT_SYNC_MAX_ROUND_FRAMES: usize = 16;
pub const ACCOUNT_SYNC_MAX_COLLECTION_ITEMS: usize = 100;
pub const ACCOUNT_SYNC_MAX_REALMS: usize = 16;
pub const ACCOUNT_SYNC_MAX_STRANDS: usize = 32;
pub const ACCOUNT_SYNC_MAX_KIND_FILTERS: usize = 64;
pub const ACCOUNT_SYNC_MAX_LIST_BYTES: usize = 1024 * 1024;
pub const ACCOUNT_SYNC_DEFAULT_LIST_LIMIT: u32 = 20;
pub const ACCOUNT_SYNC_DEFAULT_TIMELINE_LIMIT: u32 = 20;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub(crate) fn demand_error(message: impl Into<String>) -> WireError {
    WireError::Protocol(message.into())
}

pub(crate) fn bounded_unique<T: Ord>(items: &[T], maximum: usize, field: &str) -> Result<()> {
    if items.len() > maximum || items.iter().collect::<BTreeSet<_>>().len() != items.len() {
        return Err(demand_error(format!(
            "{field} exceeds its bound or contains duplicates"
        )));
    }
    Ok(())
}

pub(crate) fn validate_demand_cursor(value: &str) -> Result<()> {
    let tail = value
        .strip_prefix("ak:cursor:")
        .ok_or_else(|| demand_error("Invalid cursor prefix"))?;
    if tail.is_empty()
        || value.len() > 2048
        || !tail
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(demand_error(
            "Cursor must be an opaque bounded base64url token",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmListRequest {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub after: Option<Cursor>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub limit: Option<u32>,
}

impl RealmListRequest {
    pub fn validate(&self) -> Result<()> {
        if let Some(after) = &self.after {
            validate_demand_cursor(after.as_str())?;
        }
        if self.limit.is_some_and(|limit| !(1..=100).contains(&limit)) {
            return Err(demand_error("Realm list limit must be between 1 and 100"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmListMembership {
    Join,
    Knock,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmRow {
    pub realm_id: RealmId,
    pub revision: u64,
    pub activity_position: u64,
    pub membership: RealmListMembership,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub title: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub default_strand_id: Option<StrandId>,
}

impl RealmRow {
    pub fn validate(&self) -> Result<()> {
        if self.revision > MAX_SAFE_INTEGER
            || self.activity_position > MAX_SAFE_INTEGER
            || self
                .title
                .as_ref()
                .is_some_and(|title| title.chars().count() > 4096)
        {
            return Err(demand_error(
                "Realm summary exceeds its integer or title bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmListPage {
    pub snapshot_cursor: Cursor,
    pub snapshot_revision: u64,
    pub items: Vec<RealmRow>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub next_cursor: Option<Cursor>,
    pub complete: bool,
}

impl RealmListPage {
    pub fn validate(&self) -> Result<()> {
        validate_demand_cursor(self.snapshot_cursor.as_str())?;
        if let Some(next) = &self.next_cursor {
            validate_demand_cursor(next.as_str())?;
        }
        if self.snapshot_revision > MAX_SAFE_INTEGER
            || self.complete == self.next_cursor.is_some()
            || self.items.len() > ACCOUNT_SYNC_MAX_COLLECTION_ITEMS
            || arkret_canonical::canonical_json_bytes(self)?.len() > ACCOUNT_SYNC_MAX_LIST_BYTES
        {
            return Err(demand_error(
                "Realm list page has an invalid bound or continuation",
            ));
        }
        let mut seen = BTreeSet::new();
        for item in &self.items {
            item.validate()?;
            if item.revision > self.snapshot_revision || !seen.insert(&item.realm_id) {
                return Err(demand_error(
                    "Realm list page has a repeated or post-snapshot row",
                ));
            }
        }
        for pair in self.items.windows(2) {
            if pair[0].activity_position < pair[1].activity_position
                || (pair[0].activity_position == pair[1].activity_position
                    && pair[0].realm_id >= pair[1].realm_id)
            {
                return Err(demand_error(
                    "Realm list page is not in stable activity order",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmListRemoval {
    pub realm_id: RealmId,
    pub revision: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmListChanges {
    pub upserts: Vec<RealmRow>,
    pub removals: Vec<RealmListRemoval>,
}

impl RealmListChanges {
    pub fn validate(&self) -> Result<()> {
        if self.upserts.len() + self.removals.len() > ACCOUNT_SYNC_MAX_COLLECTION_ITEMS {
            return Err(demand_error("Realm summary changes exceed 100 items"));
        }
        let mut seen = BTreeSet::new();
        for item in &self.upserts {
            item.validate()?;
            if !seen.insert(&item.realm_id) {
                return Err(demand_error("Realm summary changes repeat a Realm"));
            }
        }
        for item in &self.removals {
            if item.revision > MAX_SAFE_INTEGER || !seen.insert(&item.realm_id) {
                return Err(demand_error(
                    "Realm summary changes contain an invalid removal",
                ));
            }
        }
        if self.upserts.windows(2).any(|pair| {
            (pair[0].revision, &pair[0].realm_id) >= (pair[1].revision, &pair[1].realm_id)
        }) || self.removals.windows(2).any(|pair| {
            (pair[0].revision, &pair[0].realm_id) >= (pair[1].revision, &pair[1].realm_id)
        }) {
            return Err(demand_error(
                "Realm summary changes are not in revision order",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountBaselineChannel {
    AccountDataEvents,
    StationCas,
    DeviceLists,
    Notifications,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBaselineSegment {
    pub snapshot_cursor: Cursor,
    pub channels: Vec<AccountBaselineChannel>,
    pub completed_channels: Vec<AccountBaselineChannel>,
}

impl AccountBaselineSegment {
    pub fn validate(&self) -> Result<()> {
        validate_demand_cursor(self.snapshot_cursor.as_str())?;
        bounded_unique(&self.channels, 4, "baseline.channels")?;
        bounded_unique(&self.completed_channels, 4, "baseline.completed_channels")?;
        if self.channels.is_empty()
            || self
                .completed_channels
                .iter()
                .any(|channel| !self.channels.contains(channel))
        {
            return Err(demand_error(
                "Baseline completion must be a subset of its nonempty channel set",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDetailBaseline {
    pub snapshot_cursor: Cursor,
    pub cut_revision: u64,
    pub coverage: super::current_results::CurrentCoverage,
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInvalidation {
    pub realm_id: RealmId,
    pub revision: u64,
}

impl RealmInvalidation {
    pub fn validate(&self) -> Result<()> {
        if self.revision > MAX_SAFE_INTEGER {
            return Err(demand_error(
                "Realm invalidation revision exceeds the safe integer bound",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmDetailErrorCode {
    FrontierUnavailable,
    LimitExceeded,
    TemporarilyUnavailable,
    NotFound,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDetailUnavailable {
    pub error_code: RealmDetailErrorCode,
}
/// Counts all data and control frames in one bounded HTTP round.
#[derive(Clone, Debug, Default)]
pub struct AccountSyncRoundBudget {
    frame_count: usize,
    canonical_bytes: usize,
}

impl AccountSyncRoundBudget {
    pub fn observe(&mut self, canonical_bytes: usize) -> Result<()> {
        let bytes = self
            .canonical_bytes
            .checked_add(canonical_bytes)
            .ok_or_else(|| demand_error("Account round size overflow"))?;
        if self.frame_count >= ACCOUNT_SYNC_MAX_ROUND_FRAMES
            || canonical_bytes > ACCOUNT_SYNC_MAX_FRAME_BYTES
            || bytes > ACCOUNT_SYNC_MAX_ROUND_BYTES
        {
            return Err(demand_error(
                "Account sync round exceeds its frame or byte budget",
            ));
        }
        self.frame_count += 1;
        self.canonical_bytes = bytes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn list_request_rejects_null_unknown_and_excessive_limit() {
        for value in [
            serde_json::json!({"after":null}),
            serde_json::json!({"offset":1}),
        ] {
            assert!(serde_json::from_value::<RealmListRequest>(value).is_err());
        }
        assert!(
            RealmListRequest {
                after: None,
                limit: Some(101)
            }
            .validate()
            .is_err()
        );
        assert!(
            RealmListRequest {
                after: None,
                limit: Some(1)
            }
            .validate()
            .is_ok()
        );
    }
    #[test]
    fn round_budget_is_cumulative() {
        let mut budget = AccountSyncRoundBudget::default();
        budget.observe(ACCOUNT_SYNC_MAX_FRAME_BYTES).unwrap();
        budget.observe(ACCOUNT_SYNC_MAX_FRAME_BYTES).unwrap();
        assert!(budget.observe(1).is_err());
        let mut budget = AccountSyncRoundBudget::default();
        for _ in 0..ACCOUNT_SYNC_MAX_ROUND_FRAMES {
            budget.observe(1).unwrap();
        }
        assert!(budget.observe(1).is_err());
    }
}
