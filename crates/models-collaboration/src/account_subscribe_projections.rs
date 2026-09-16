//! Account-subscribe projection rows that are carried by, but not owned by,
//! the subscribe frame envelope.
//!
//! `account-subscribe-frame.schema.json` puts two closed projections inside
//! otherwise generic containers: the member roster carried by one
//! `realm_sync_entry`, and the Agent runtime approval branch of one
//! `notification_delta`. Both are product surfaces with their own closed field
//! sets and their own fail-closed disclosure rules, so they live here as typed
//! counterparts rather than inside the frame module.

use arkret_models_identity::handle_claim::HandleClaim;
use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{AccountId, ActorId, Cursor, DidCoreId, Event, EventId, Hash, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Effective membership rows a roster may disclose.
///
/// Invite lifecycle records are not membership and never appear here, which is
/// why the enum is closed at the two effective `ak.member.state` values.
/// `account-subscribe-frame.schema.json#/$defs/member_roster_entry.membership`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MemberRosterMembership {
    Join,
    Knock,
}

/// Counterpart for
/// `account-subscribe-frame.schema.json#/$defs/member_roster_entry`.
///
/// The schema's `dependentRequired` block is the entry's whole privacy rule:
/// inline identity Events, handle-claim digests, inline handle claims and the
/// truncation flag are all linkable to one member, so each one may appear only
/// when `subject_account_id` is already disclosed. [`Self::validate`] enforces
/// that, so an entry that reaches a caller has never leaked a subject through
/// a side channel the projection itself declined to disclose.
// Field declaration order is byte-for-byte the properties order of
// account-subscribe-frame.schema.json#/$defs/member_roster_entry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberRosterEntry {
    pub actor_id: ActorId,
    pub membership: MemberRosterMembership,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_account_id: Option<AccountId>,
    /// Effective `ak.member.identity.update` Event ids for this actor after
    /// replacement refs are applied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_display_state_digest: Option<Hash>,
    /// Inline effective `ak.member.identity.update` envelopes. These are the
    /// original Events, never a query-time re-encryption or projection
    /// rewrite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_events: Option<Vec<Event>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_claim_digests: Option<Vec<Hash>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_claims: Option<Vec<HandleClaim>>,
    /// True when `handle_claims` is truncated or replaced by digest-only
    /// hints. Absence of a claim is never proof that the member has no handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_claims_limited: Option<bool>,
}

impl MemberRosterEntry {
    pub fn validate(&self) -> Result<()> {
        if self.subject_account_id.is_none() {
            for (member, present) in [
                ("identity_events", self.identity_events.is_some()),
                ("handle_claim_digests", self.handle_claim_digests.is_some()),
                ("handle_claims", self.handle_claims.is_some()),
                (
                    "handle_claims_limited",
                    self.handle_claims_limited.is_some(),
                ),
            ] {
                if present {
                    return Err(WireError::Protocol(format!(
                        "member roster entry {member} requires a disclosed subject_account_id"
                    )));
                }
            }
        }
        require_unique(
            "identity_event_ids",
            self.identity_event_ids.iter().map(EventId::as_str),
        )?;
        if let Some(digests) = &self.handle_claim_digests {
            require_unique("handle_claim_digests", digests.iter().map(Hash::as_str))?;
        }
        if let Some(claims) = &self.handle_claims
            && let Some(subject) = &self.subject_account_id
        {
            for claim in claims {
                if claim.claim.subject_account_id != *subject {
                    return Err(WireError::Protocol(
                        "member roster handle claim subject_account_id must equal the entry subject"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn require_unique<'a>(member: &str, values: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut seen: Vec<&str> = Vec::new();
    for value in values {
        if seen.contains(&value) {
            return Err(WireError::Protocol(format!(
                "member roster entry {member} must not repeat a value"
            )));
        }
        seen.push(value);
    }
    Ok(())
}

/// Counterpart for
/// `account-subscribe-frame.schema.json#/$defs/member_roster`.
// Field declaration order is byte-for-byte the properties order of
// account-subscribe-frame.schema.json#/$defs/member_roster.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberRoster {
    pub entries: Vec<MemberRosterEntry>,
    /// True when `entries` is truncated. A truncated page is never the
    /// complete Realm roster, whatever its length.
    pub limited: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
}

impl MemberRoster {
    pub const MAX_ENTRIES: usize = 100;

    pub fn validate(&self) -> Result<()> {
        if self.entries.len() > Self::MAX_ENTRIES {
            return Err(WireError::Protocol(
                "member roster page carries at most 100 entries".to_owned(),
            ));
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        Ok(())
    }
}

/// Correlation id of one Agent runtime approval request.
///
/// The schema forbids the `ak:` prefix so this id can never be confused with a
/// typed protocol identifier; the newtype keeps that check on the
/// deserialization path.
/// `account-subscribe-frame.schema.json#/$defs/agent_runtime_approval_notification_data.
/// approval_request_id`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct AgentRuntimeApprovalRequestId(String);

impl AgentRuntimeApprovalRequestId {
    pub const MAX_BYTES: usize = 128;

    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > Self::MAX_BYTES {
            return Err(WireError::Protocol(
                "agent runtime approval request id must be 1..128 characters".to_owned(),
            ));
        }
        if value.starts_with("ak:") {
            return Err(WireError::Protocol(
                "agent runtime approval request id must not use the ak: identifier namespace"
                    .to_owned(),
            ));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        {
            return Err(WireError::Protocol(
                "agent runtime approval request id must match ^(?!ak:)[A-Za-z0-9._:-]{1,128}$"
                    .to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AgentRuntimeApprovalRequestId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AgentRuntimeApprovalRequestId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Counterpart for
/// `account-subscribe-frame.schema.json#/$defs/agent_runtime_approval_notification_data`.
///
/// This is the `upsert` payload of the Agent runtime approval branch of one
/// `notification_delta`, selected by an `ak:notification:<uuidv7>` delta id.
// Field declaration order is byte-for-byte the properties order of
// account-subscribe-frame.schema.json#/$defs/agent_runtime_approval_notification_data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalNotificationData {
    pub approval_request_id: AgentRuntimeApprovalRequestId,
    pub agent_id: DidCoreId,
    #[serde(with = "canonical_timestamp")]
    pub requested_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl AgentRuntimeApprovalNotificationData {
    /// An approval window that has already closed at the instant it is
    /// announced is never actionable, so the two timestamps are ordered.
    pub fn validate(&self) -> Result<()> {
        if self.expires_at <= self.requested_at {
            return Err(WireError::Protocol(
                "agent runtime approval expires_at must be after requested_at".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const EVENT: &str = "ak:event:Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_EVENT: &str = "ak:event:Abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER_DIGEST: &str =
        "blake3:2222222222222222222222222222222222222222222222222222222222222222";

    fn subject() -> Value {
        json!({
            "principal_id": "ak:did_core:webvh:z6mkmemberprincipal",
            "station_id": "ak:did_core:webvh:z6mkmemberstation"
        })
    }

    fn entry_value() -> Value {
        json!({
            "actor_id": { "kind": "account", "account_id": subject() },
            "membership": "join",
            "subject_account_id": subject(),
            "identity_event_ids": [EVENT, OTHER_EVENT],
            "member_display_state_digest": DIGEST,
            "handle_claim_digests": [DIGEST, OTHER_DIGEST],
            "handle_claims_limited": true
        })
    }

    fn undisclosed_entry_value() -> Value {
        json!({
            "actor_id": { "kind": "account", "account_id": subject() },
            "membership": "knock"
        })
    }

    #[test]
    fn entry_round_trips_in_schema_property_order() {
        let entry: MemberRosterEntry = serde_json::from_value(entry_value()).unwrap();
        assert_eq!(entry.membership, MemberRosterMembership::Join);
        assert_eq!(entry.identity_event_ids.len(), 2);
        assert_eq!(entry.handle_claims_limited, Some(true));
        assert!(entry.handle_claims.is_none());
        entry.validate().unwrap();
        assert_eq!(serde_json::to_value(&entry).unwrap(), entry_value());
    }

    #[test]
    fn only_actor_id_and_membership_are_required() {
        let entry: MemberRosterEntry = serde_json::from_value(undisclosed_entry_value()).unwrap();
        entry.validate().unwrap();
        assert!(entry.subject_account_id.is_none());
        assert!(entry.identity_event_ids.is_empty());
        assert_eq!(
            serde_json::to_value(&entry).unwrap(),
            undisclosed_entry_value()
        );

        for member in ["actor_id", "membership"] {
            let mut missing = entry_value();
            missing.as_object_mut().unwrap().remove(member);
            assert!(serde_json::from_value::<MemberRosterEntry>(missing).is_err());
        }
    }

    #[test]
    fn linkable_members_require_a_disclosed_subject() {
        for (member, value) in [
            ("identity_events", json!([])),
            ("handle_claim_digests", json!([DIGEST])),
            ("handle_claims", json!([])),
            ("handle_claims_limited", json!(false)),
        ] {
            let mut undisclosed = undisclosed_entry_value();
            undisclosed
                .as_object_mut()
                .unwrap()
                .insert(member.to_owned(), value);
            let entry: MemberRosterEntry = serde_json::from_value(undisclosed).unwrap();
            assert!(
                entry.validate().is_err(),
                "{member} must require subject_account_id"
            );
        }
    }

    #[test]
    fn membership_never_carries_an_invite_lifecycle_value() {
        for (wire, expected) in [
            ("join", MemberRosterMembership::Join),
            ("knock", MemberRosterMembership::Knock),
        ] {
            let decoded: MemberRosterMembership = serde_json::from_value(json!(wire)).unwrap();
            assert_eq!(decoded, expected);
        }
        for refused in ["invite", "leave", "ban"] {
            assert!(serde_json::from_value::<MemberRosterMembership>(json!(refused)).is_err());
        }
    }

    #[test]
    fn repeated_digests_and_event_ids_are_refused() {
        let mut repeated = entry_value();
        repeated
            .as_object_mut()
            .unwrap()
            .insert("identity_event_ids".to_owned(), json!([EVENT, EVENT]));
        let entry: MemberRosterEntry = serde_json::from_value(repeated).unwrap();
        assert!(entry.validate().is_err());

        let mut repeated = entry_value();
        repeated
            .as_object_mut()
            .unwrap()
            .insert("handle_claim_digests".to_owned(), json!([DIGEST, DIGEST]));
        let entry: MemberRosterEntry = serde_json::from_value(repeated).unwrap();
        assert!(entry.validate().is_err());
    }

    #[test]
    fn entries_reject_unknown_members() {
        let mut extended = entry_value();
        extended
            .as_object_mut()
            .unwrap()
            .insert("display_name".to_owned(), json!("Ada"));
        assert!(serde_json::from_value::<MemberRosterEntry>(extended).is_err());

        let mut roster = json!({ "entries": [], "limited": false });
        roster
            .as_object_mut()
            .unwrap()
            .insert("total".to_owned(), json!(0));
        assert!(serde_json::from_value::<MemberRoster>(roster).is_err());
    }

    #[test]
    fn roster_page_is_capped_and_validates_each_entry() {
        let roster: MemberRoster = serde_json::from_value(json!({
            "entries": [entry_value()],
            "limited": true,
            "next_cursor": "ak:cursor:Zm9ydGhlbmV4dHBhZ2U"
        }))
        .unwrap();
        roster.validate().unwrap();
        assert!(roster.limited);
        assert!(roster.next_cursor.is_some());

        let oversized = MemberRoster {
            entries: vec![
                serde_json::from_value::<MemberRosterEntry>(entry_value()).unwrap();
                MemberRoster::MAX_ENTRIES + 1
            ],
            limited: true,
            next_cursor: None,
        };
        assert!(oversized.validate().is_err());
    }

    fn approval_value() -> Value {
        json!({
            "approval_request_id": "approval.2026-09-16:0001",
            "agent_id": "ak:did_core:webvh:z6mkagent",
            "requested_at": "2026-09-16T00:00:00.000Z",
            "expires_at": "2026-09-16T00:05:00.000Z"
        })
    }

    #[test]
    fn approval_notification_round_trips_in_schema_property_order() {
        let data: AgentRuntimeApprovalNotificationData =
            serde_json::from_value(approval_value()).unwrap();
        assert_eq!(
            data.approval_request_id.as_str(),
            "approval.2026-09-16:0001"
        );
        data.validate().unwrap();
        assert_eq!(serde_json::to_value(&data).unwrap(), approval_value());
    }

    #[test]
    fn approval_notification_has_no_optional_member() {
        for member in [
            "approval_request_id",
            "agent_id",
            "requested_at",
            "expires_at",
        ] {
            let mut missing = approval_value();
            missing.as_object_mut().unwrap().remove(member);
            assert!(
                serde_json::from_value::<AgentRuntimeApprovalNotificationData>(missing).is_err(),
                "{member} must be required"
            );
        }
        let mut extended = approval_value();
        extended
            .as_object_mut()
            .unwrap()
            .insert("agent_slug".to_owned(), json!("scheduler"));
        assert!(serde_json::from_value::<AgentRuntimeApprovalNotificationData>(extended).is_err());
    }

    #[test]
    fn approval_request_id_never_enters_the_typed_identifier_namespace() {
        for accepted in ["a", "approval.1", "A_b-c:d", &"z".repeat(128)] {
            AgentRuntimeApprovalRequestId::new(accepted).unwrap();
        }
        for refused in [
            "",
            "ak:notification:1",
            "ak:",
            "approval/1",
            "approval 1",
            &"z".repeat(129),
        ] {
            assert!(
                AgentRuntimeApprovalRequestId::new(refused).is_err(),
                "{refused:?} must be refused"
            );
        }
        let mut typed = approval_value();
        typed.as_object_mut().unwrap().insert(
            "approval_request_id".to_owned(),
            json!("ak:notification:0198ff00-0000-7000-8000-000000000001"),
        );
        assert!(serde_json::from_value::<AgentRuntimeApprovalNotificationData>(typed).is_err());
    }

    #[test]
    fn an_already_closed_approval_window_is_refused() {
        let mut closed = approval_value();
        closed
            .as_object_mut()
            .unwrap()
            .insert("expires_at".to_owned(), json!("2026-09-16T00:00:00.000Z"));
        let data: AgentRuntimeApprovalNotificationData = serde_json::from_value(closed).unwrap();
        assert!(data.validate().is_err());
    }
}
