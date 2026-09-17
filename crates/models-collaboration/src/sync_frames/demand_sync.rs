//! Demand-driven account-subscribe payloads: the Realm list, the frozen
//! baseline windows, and per-Realm unavailability.
//!
//! These are the members an account `delta` frame carries when the client asked
//! for a Realm list page or a baseline cut. Every cursor here is a *frozen
//! generation handle*, never an ordered position: `snapshot_cursor` identifies
//! which cut a segment belongs to and is repeated identically across that cut's
//! segments. It is never passed back as the account `after` parameter and never
//! compared for order.
//!
//! Nothing in this module names a Realm-global position. Where a Realm's
//! durable coordinate is needed at all it is a `revision` of one typed current
//! result, and stream continuity is expressed per stream by
//! [`arkret_wire::CommitStreamHead`].

use std::collections::BTreeSet;

use arkret_wire::{RealmId, Result, StrandId, WireError};
use serde::{Deserialize, Serialize};

/// Canonical byte ceiling for one account-subscribe frame's payload.
pub const ACCOUNT_SYNC_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// Ceiling on one NDJSON line before it is even parsed.
pub const ACCOUNT_SYNC_MAX_WIRE_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Ceiling on the canonical bytes of one subscribe round.
pub const ACCOUNT_SYNC_MAX_ROUND_BYTES: usize = 16 * 1024 * 1024;
/// Ceiling on the frame count of one subscribe round.
pub const ACCOUNT_SYNC_MAX_ROUND_FRAMES: usize = 16;
/// Ceiling on any bounded collection carried by one frame.
pub const ACCOUNT_SYNC_MAX_COLLECTION_ITEMS: usize = 100;
/// Ceiling on `realms` detail entries in one frame.
pub const ACCOUNT_SYNC_MAX_REALMS: usize = 16;
/// Ceiling on `filter.strand_ids`.
pub const ACCOUNT_SYNC_MAX_STRANDS: usize = 32;
/// Ceiling on either Event-kind filter list.
pub const ACCOUNT_SYNC_MAX_KIND_FILTERS: usize = 64;
/// Default Realm-list page size when the request does not name one.
pub const ACCOUNT_SYNC_DEFAULT_LIST_LIMIT: u32 = 20;
/// Default per-Realm timeline ceiling when the filter does not name one.
pub const ACCOUNT_SYNC_DEFAULT_TIMELINE_LIMIT: u32 = 20;
/// Protocol ceiling on `filter.timeline_limit`.
pub const ACCOUNT_SYNC_MAX_TIMELINE_LIMIT: u32 = 100;

pub(crate) fn protocol_error(message: impl Into<String>) -> WireError {
    WireError::Protocol(message.into())
}

pub(crate) fn validate_snapshot_cursor(value: &str) -> Result<()> {
    let tail = value
        .strip_prefix("ak:cursor:")
        .ok_or_else(|| protocol_error("invalid account stream cursor prefix"))?;
    if tail.is_empty()
        || value.len() > 2048
        || !tail
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(protocol_error("invalid bounded account stream cursor"));
    }
    Ok(())
}

/// Membership states a Realm list row may report.
///
/// Invite lifecycle records are not membership and never appear here, so the
/// enum is deliberately only these two.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmListMembership {
    Join,
    Knock,
}

/// One row of the account's Realm list.
///
/// `activity_position` orders the list for display only. It is a list-local
/// ranking key issued by the account's own Station — not a commit coordinate,
/// not comparable across accounts, and never a substitute for a
/// [`arkret_wire::CommitStreamHead`].
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/realm_list_row`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmListRow {
    pub realm_id: RealmId,
    pub revision: u64,
    pub activity_position: u64,
    pub membership: RealmListMembership,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_strand_id: Option<StrandId>,
}

impl RealmListRow {
    pub fn validate(&self) -> Result<()> {
        if self
            .title
            .as_ref()
            .is_some_and(|title| title.chars().count() > 4096)
        {
            return Err(protocol_error(
                "Realm list item title exceeds 4096 code points",
            ));
        }
        Ok(())
    }
}

/// One page of the frozen Realm list cut identified by `snapshot_cursor`.
///
/// `next_cursor` presence is the *only* terminal signal; there is no separate
/// `has_more` flag, because two sources for one fact can disagree. A page that
/// carries `next_cursor` must carry at least one item, or the caller could not
/// make progress.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/realm_list_page`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmListPage {
    pub snapshot_cursor: String,
    pub snapshot_revision: u64,
    pub items: Vec<RealmListRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl RealmListPage {
    pub fn validate(&self) -> Result<()> {
        validate_snapshot_cursor(&self.snapshot_cursor)?;
        if self.items.len() > ACCOUNT_SYNC_MAX_COLLECTION_ITEMS {
            return Err(protocol_error("Realm list page exceeds 100 items"));
        }
        if unique_realm_ids(self.items.iter().map(|item| &item.realm_id)) != self.items.len() {
            return Err(protocol_error("Realm list page repeats a Realm"));
        }
        for item in &self.items {
            item.validate()?;
        }
        if let Some(next_cursor) = &self.next_cursor {
            validate_snapshot_cursor(next_cursor)?;
            if self.items.is_empty() {
                return Err(protocol_error(
                    "a nonterminal Realm list page must carry at least one item",
                ));
            }
        }
        Ok(())
    }

    /// True when this page is the last of its cut.
    pub const fn is_terminal(&self) -> bool {
        self.next_cursor.is_none()
    }
}

fn unique_realm_ids<'a>(values: impl Iterator<Item = &'a RealmId>) -> usize {
    values.map(RealmId::as_str).collect::<BTreeSet<_>>().len()
}

/// One Realm leaving the account's Realm list at a stated revision.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/realm_list_removal`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmListRemoval {
    pub realm_id: RealmId,
    pub revision: u64,
}

/// Live Realm-list deltas applied on top of a delivered cut.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/realm_list_changes`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmListChanges {
    pub upserts: Vec<RealmListRow>,
    pub removals: Vec<RealmListRemoval>,
}

impl RealmListChanges {
    pub fn validate(&self) -> Result<()> {
        if self.upserts.len() > ACCOUNT_SYNC_MAX_COLLECTION_ITEMS
            || self.removals.len() > ACCOUNT_SYNC_MAX_COLLECTION_ITEMS
        {
            return Err(protocol_error("Realm list changes exceed 100 items"));
        }
        if unique_realm_ids(self.upserts.iter().map(|item| &item.realm_id)) != self.upserts.len()
            || unique_realm_ids(self.removals.iter().map(|item| &item.realm_id))
                != self.removals.len()
        {
            return Err(protocol_error("Realm list changes repeat a Realm"));
        }
        for item in &self.upserts {
            item.validate()?;
        }
        Ok(())
    }
}

/// The four independent account-level baseline channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountBaselineChannel {
    AccountDataEvents,
    StationCas,
    DeviceLists,
    Notifications,
}

/// One segment of the account-level baseline cut.
///
/// `channels` names the channels this segment carries; `completed_channels`
/// names the channels whose delivery is now finished. Completion is per
/// channel and says only that delivery finished — it is not authentication,
/// not decryption, and not a read permission.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/account_baseline_segment`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBaselineSegment {
    pub snapshot_cursor: String,
    pub channels: Vec<AccountBaselineChannel>,
    pub completed_channels: Vec<AccountBaselineChannel>,
}

impl AccountBaselineSegment {
    pub fn validate(&self) -> Result<()> {
        validate_snapshot_cursor(&self.snapshot_cursor)?;
        if self.channels.is_empty() {
            return Err(protocol_error(
                "account baseline segment must name at least one channel",
            ));
        }
        for (field, values) in [
            ("channels", &self.channels),
            ("completed_channels", &self.completed_channels),
        ] {
            if values.len() > 4 || values.iter().collect::<BTreeSet<_>>().len() != values.len() {
                return Err(protocol_error(format!(
                    "account baseline {field} exceeds its bound or repeats a channel"
                )));
            }
        }
        Ok(())
    }

    /// True once every channel this cut covers has been delivered.
    pub fn completes(&self, channel: AccountBaselineChannel) -> bool {
        self.completed_channels.contains(&channel)
    }
}

/// The frozen timeline window generation for one Realm.
///
/// `window_limit` is the *cumulative* ceiling of the whole frozen window after
/// the request targets are merged, not the count emitted in this frame. Byte
/// budgets decide only how the window is segmented; they never lower it, or a
/// client could not tell a short window from a truncated one.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/realm_timeline_baseline`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmTimelineBaseline {
    pub snapshot_cursor: String,
    pub window_limit: u32,
    pub complete: bool,
}

impl RealmTimelineBaseline {
    pub fn validate(&self) -> Result<()> {
        validate_snapshot_cursor(&self.snapshot_cursor)?;
        if self.window_limit > ACCOUNT_SYNC_MAX_TIMELINE_LIMIT {
            return Err(protocol_error(
                "Realm timeline baseline window_limit must be <= 100",
            ));
        }
        Ok(())
    }
}

/// Why one requested Realm detail could not be answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmDetailErrorCode {
    RevisionUnavailable,
    LimitExceeded,
    TemporarilyUnavailable,
    NotFound,
}

/// A Realm detail entry replaced by an explicit failure.
///
/// This is the only way a frame may say "no data for this Realm": silence
/// would be indistinguishable from an empty Realm.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/realm_sync_entry/properties/unavailable`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDetailUnavailable {
    pub error_code: RealmDetailErrorCode,
}

/// One Realm whose cached projection the client must re-read at `revision`.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/realm_invalidation`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInvalidation {
    pub realm_id: RealmId,
    pub revision: u64,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn item(seed: &str) -> serde_json::Value {
        json!({
            "realm_id": seed,
            "revision": 7,
            "activity_position": 3,
            "membership": "join",
        })
    }

    fn realm_a() -> &'static str {
        "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs"
    }

    fn realm_b() -> &'static str {
        "ak:realm:BVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs"
    }

    #[test]
    fn realm_list_item_rejects_unknown_members_and_retired_memberships() {
        let mut value = item(realm_a());
        value["leave"] = json!(true);
        assert!(serde_json::from_value::<RealmListRow>(value).is_err());

        let mut retired = item(realm_a());
        retired["membership"] = json!("invite");
        assert!(serde_json::from_value::<RealmListRow>(retired).is_err());
    }

    #[test]
    fn realm_list_page_round_trips_in_schema_field_order() {
        let value = json!({
            "snapshot_cursor": "ak:cursor:aaa",
            "snapshot_revision": 11,
            "items": [item(realm_a())],
            "next_cursor": "ak:cursor:bbb",
        });
        let page: RealmListPage = serde_json::from_value(value.clone()).unwrap();
        page.validate().unwrap();
        assert!(!page.is_terminal());
        assert_eq!(serde_json::to_value(&page).unwrap(), value);
    }

    #[test]
    fn nonterminal_page_without_items_is_refused() {
        let page: RealmListPage = serde_json::from_value(json!({
            "snapshot_cursor": "ak:cursor:aaa",
            "snapshot_revision": 11,
            "items": [],
            "next_cursor": "ak:cursor:bbb",
        }))
        .unwrap();
        assert!(
            page.validate()
                .unwrap_err()
                .to_string()
                .contains("at least one item")
        );
    }

    #[test]
    fn realm_list_page_refuses_a_repeated_realm() {
        let page: RealmListPage = serde_json::from_value(json!({
            "snapshot_cursor": "ak:cursor:aaa",
            "snapshot_revision": 11,
            "items": [item(realm_a()), item(realm_a())],
        }))
        .unwrap();
        assert!(page.validate().unwrap_err().to_string().contains("repeats"));
    }

    #[test]
    fn realm_list_changes_validate_both_sides() {
        let changes: RealmListChanges = serde_json::from_value(json!({
            "upserts": [item(realm_a())],
            "removals": [{"realm_id": realm_b(), "revision": 4}],
        }))
        .unwrap();
        changes.validate().unwrap();
    }

    #[test]
    fn baseline_segment_requires_a_channel_and_refuses_duplicates() {
        let empty: AccountBaselineSegment = serde_json::from_value(json!({
            "snapshot_cursor": "ak:cursor:aaa",
            "channels": [],
            "completed_channels": [],
        }))
        .unwrap();
        assert!(empty.validate().is_err());

        let duplicated: AccountBaselineSegment = serde_json::from_value(json!({
            "snapshot_cursor": "ak:cursor:aaa",
            "channels": ["station_cas", "station_cas"],
            "completed_channels": [],
        }))
        .unwrap();
        assert!(duplicated.validate().is_err());

        let good: AccountBaselineSegment = serde_json::from_value(json!({
            "snapshot_cursor": "ak:cursor:aaa",
            "channels": ["station_cas", "notifications"],
            "completed_channels": ["station_cas"],
        }))
        .unwrap();
        good.validate().unwrap();
        assert!(good.completes(AccountBaselineChannel::StationCas));
        assert!(!good.completes(AccountBaselineChannel::Notifications));
    }

    #[test]
    fn timeline_baseline_window_limit_is_bounded_and_cursor_checked() {
        let over: RealmTimelineBaseline = serde_json::from_value(json!({
            "snapshot_cursor": "ak:cursor:aaa",
            "window_limit": 101,
            "complete": false,
        }))
        .unwrap();
        assert!(over.validate().is_err());

        let bad_cursor: RealmTimelineBaseline = serde_json::from_value(json!({
            "snapshot_cursor": "cursor:aaa",
            "window_limit": 20,
            "complete": true,
        }))
        .unwrap();
        assert!(bad_cursor.validate().is_err());
    }

    #[test]
    fn realm_detail_unavailable_is_a_closed_enum() {
        let value = json!({"error_code": "revision_unavailable"});
        let unavailable: RealmDetailUnavailable = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            unavailable.error_code,
            RealmDetailErrorCode::RevisionUnavailable
        );
        assert_eq!(serde_json::to_value(unavailable).unwrap(), value);
        assert!(
            serde_json::from_value::<RealmDetailUnavailable>(json!({"error_code": "frontier_gap"}))
                .is_err()
        );
    }
}
