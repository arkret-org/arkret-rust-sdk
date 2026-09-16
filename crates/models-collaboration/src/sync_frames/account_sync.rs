//! Per-Realm projection members of one account `delta` frame.
//!
//! Window-start state, the Realm summary and the unread counts are *derived
//! projections*. They are not part of any state hash, they are not commit
//! coordinates, and they are never reducer input: a client may show them and
//! must not treat them as authority. Authority for a Realm is the typed current
//! result set plus each stream's [`arkret_wire::CommitStreamHead`].

use std::collections::BTreeSet;

use arkret_wire::{ActorId, BlobRef, RealmId, Result, WireError, string_profiles};
use serde::{Deserialize, Serialize};

use crate::sync_frames::demand_sync::ACCOUNT_SYNC_MAX_COLLECTION_ITEMS;

/// Protocol ceiling on `summary.hero_ids`.
pub const ACCOUNT_SYNC_MAX_HERO_IDS: usize = 20;
/// Code-point ceiling of the `display_text_256` profile.
pub const DISPLAY_TEXT_256_MAX_CODE_POINTS: usize = 256;
/// Code-point ceiling the Realm metadata summary applies to `short_text`.
pub const REALM_METADATA_SUMMARY_MAX_CODE_POINTS: usize = 4096;

fn protocol_error(message: impl Into<String>) -> WireError {
    WireError::Protocol(message.into())
}

/// One actor's display projection as it stood at the timeline window start.
///
/// The key is the complete [`ActorId`], never a bare principal DID: two
/// accounts of the same principal on different Stations are distinct rows with
/// their own display projections, and collapsing them would merge two
/// identities.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/state_at_window_start/properties/actor_profiles/
// items`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowStartActorProfile {
    pub actor_id: ActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
}

impl WindowStartActorProfile {
    pub fn validate(&self) -> Result<()> {
        if let Some(display_name) = &self.display_name {
            string_profiles::validate_single_line_display_text(
                display_name,
                DISPLAY_TEXT_256_MAX_CODE_POINTS,
            )?;
        }
        Ok(())
    }
}

/// Projection-only strong Realm role, emitted only after the server validated
/// the registered Realm profile and its discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStartCollaborationRole {
    DirectConversation,
}

/// Realm metadata as it stood at the window start.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/state_at_window_start/properties/realm_metadata`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowStartRealmMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collaboration_role: Option<WindowStartCollaborationRole>,
}

impl WindowStartRealmMetadata {
    pub fn validate(&self) -> Result<()> {
        if let Some(title) = &self.title {
            string_profiles::validate_single_line_display_text(
                title,
                DISPLAY_TEXT_256_MAX_CODE_POINTS,
            )?;
        }
        if let Some(summary) = &self.summary {
            string_profiles::validate_short_text(summary, REALM_METADATA_SUMMARY_MAX_CODE_POINTS)?;
        }
        if self
            .join_rule
            .as_ref()
            .is_some_and(|rule| rule.is_empty() || rule.chars().count() > 128)
        {
            return Err(protocol_error(
                "window-start join_rule must be 1..=128 code points",
            ));
        }
        Ok(())
    }
}

/// The E2EE epoch in force at the window start.
///
/// `None` is a real answer, not missing data: a Realm may have no executable
/// MLS epoch at that point, and the schema models that as an explicit `null`
/// rather than an absent member.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/state_at_window_start/properties/e2ee_epoch`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowStartE2eeEpoch {
    pub epoch: u64,
    pub key_ref: String,
}

impl WindowStartE2eeEpoch {
    pub fn validate(&self) -> Result<()> {
        if self.key_ref.is_empty() || self.key_ref.len() > 2048 {
            return Err(protocol_error(
                "window-start e2ee_epoch key_ref must be 1..=2048 bytes",
            ));
        }
        Ok(())
    }
}

/// Derived projection state at the start of a Realm's timeline window.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/state_at_window_start`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateAtWindowStart {
    pub actor_profiles: Vec<WindowStartActorProfile>,
    pub realm_metadata: WindowStartRealmMetadata,
    pub e2ee_epoch: Option<WindowStartE2eeEpoch>,
}

impl StateAtWindowStart {
    /// Enforce the schema's ordering and uniqueness rules for the profile
    /// rows: entries are sorted by the unsigned UTF-8 bytes of the canonical
    /// JSON of `actor_id`, and a repeated ActorId is rejected even when its
    /// display fields differ.
    pub fn validate(&self) -> Result<()> {
        if self.actor_profiles.len() > ACCOUNT_SYNC_MAX_COLLECTION_ITEMS {
            return Err(protocol_error(
                "window-start actor_profiles exceed 100 entries",
            ));
        }
        let mut previous: Option<Vec<u8>> = None;
        let mut seen = BTreeSet::new();
        for profile in &self.actor_profiles {
            profile.validate()?;
            let key = arkret_canonical::canonical_json_bytes(&profile.actor_id)?;
            if !seen.insert(key.clone()) {
                return Err(protocol_error(
                    "window-start actor_profiles repeat an ActorId",
                ));
            }
            if previous.as_ref().is_some_and(|earlier| *earlier >= key) {
                return Err(protocol_error(
                    "window-start actor_profiles are not sorted by canonical ActorId bytes",
                ));
            }
            previous = Some(key);
        }
        self.realm_metadata.validate()?;
        if let Some(epoch) = &self.e2ee_epoch {
            epoch.validate()?;
        }
        Ok(())
    }
}

/// Lightweight display counts for one Realm.
///
/// `invited_member_count` counts caller-private pending Invite inbox entries.
/// It is not derived from `ak.member.state`, implies no membership, and must
/// never create a roster row.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/realm_summary`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSubscribeRealmSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_member_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invited_member_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hero_ids: Option<Vec<ActorId>>,
}

impl AccountSubscribeRealmSummary {
    pub fn validate(&self) -> Result<()> {
        let Some(hero_ids) = &self.hero_ids else {
            return Ok(());
        };
        if hero_ids.len() > ACCOUNT_SYNC_MAX_HERO_IDS {
            return Err(protocol_error("Realm summary hero_ids exceed 20 entries"));
        }
        let mut seen = BTreeSet::new();
        for actor_id in hero_ids {
            if !seen.insert(arkret_canonical::canonical_json_bytes(actor_id)?) {
                return Err(protocol_error("Realm summary hero_ids repeat an ActorId"));
            }
        }
        Ok(())
    }
}

/// Holder-private unread counters for one Realm.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/unread_notification_counts`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSubscribeUnreadCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highlight_count: Option<u64>,
}

/// Identity of the Realm a per-Realm projection belongs to.
///
/// Kept separate from the projection payloads so a caller can carry the
/// `realms` map key alongside a typed entry without re-parsing the string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmProjectionKey(pub RealmId);

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn actor(seed: &str) -> serde_json::Value {
        json!({"principal_id": seed, "station_id": "ak:did_core:web:alice.example"})
    }

    fn window_start(profiles: serde_json::Value) -> serde_json::Value {
        json!({
            "actor_profiles": profiles,
            "realm_metadata": {},
            "e2ee_epoch": null,
        })
    }

    fn parse(value: serde_json::Value) -> StateAtWindowStart {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn null_e2ee_epoch_is_an_answer_and_round_trips() {
        let value = window_start(json!([]));
        let state = parse(value.clone());
        state.validate().unwrap();
        assert!(state.e2ee_epoch.is_none());
        assert_eq!(serde_json::to_value(&state).unwrap(), value);
    }

    #[test]
    fn duplicate_actor_rows_are_rejected_even_with_different_display_fields() {
        let state = parse(window_start(json!([
            {"actor_id": actor("ak:did_core:web:a.example"), "display_name": "A"},
            {"actor_id": actor("ak:did_core:web:a.example"), "display_name": "B"},
        ])));
        let error = state.validate().unwrap_err().to_string();
        assert!(error.contains("repeat an ActorId") || error.contains("not sorted"));
    }

    #[test]
    fn unsorted_actor_rows_are_rejected() {
        let state = parse(window_start(json!([
            {"actor_id": actor("ak:did_core:web:b.example")},
            {"actor_id": actor("ak:did_core:web:a.example")},
        ])));
        assert!(
            state
                .validate()
                .unwrap_err()
                .to_string()
                .contains("not sorted")
        );
    }

    #[test]
    fn sorted_distinct_actor_rows_pass() {
        let state = parse(window_start(json!([
            {"actor_id": actor("ak:did_core:web:a.example")},
            {"actor_id": actor("ak:did_core:web:b.example")},
        ])));
        state.validate().unwrap();
    }

    #[test]
    fn realm_metadata_rejects_a_retired_collaboration_role() {
        assert!(
            serde_json::from_value::<WindowStartRealmMetadata>(
                json!({"collaboration_role": "broadcast"})
            )
            .is_err()
        );
        let metadata: WindowStartRealmMetadata =
            serde_json::from_value(json!({"collaboration_role": "direct_conversation"})).unwrap();
        metadata.validate().unwrap();
    }

    #[test]
    fn summary_hero_ids_are_bounded_and_unique() {
        let repeated: AccountSubscribeRealmSummary = serde_json::from_value(json!({
            "hero_ids": [actor("ak:did_core:web:a.example"), actor("ak:did_core:web:a.example")],
        }))
        .unwrap();
        assert!(
            repeated
                .validate()
                .unwrap_err()
                .to_string()
                .contains("repeat")
        );
    }

    #[test]
    fn unread_counts_reject_unknown_members() {
        let value = json!({"notification_count": 3, "highlight_count": 1});
        let counts: AccountSubscribeUnreadCounts = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(counts).unwrap(), value);
        assert!(
            serde_json::from_value::<AccountSubscribeUnreadCounts>(json!({"unread_count": 3}))
                .is_err()
        );
    }
}
