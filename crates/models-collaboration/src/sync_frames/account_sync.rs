//! Account-subscribe sync frame artifact counterparts.
//!
//! Frame containers for `ak.self.account.stream.subscribe` deltas:
//! notification projections, device-message envelopes, event and
//! ephemeral containers, timelines, and the per-Realm roster entry
//! carried by account-subscribe frames.

use crate::internal_prelude::*;

/// Closed action set for account notification projection deltas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationDeltaAction {
    Add,
    Update,
    Remove,
}

/// Closed notification data discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountNotificationDataKind {
    AgentRuntimeApproval,
}

/// Account-private Agent runtime approval projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalNotificationData {
    pub kind: AccountNotificationDataKind,
    pub approval_request_id: OpaqueLocalId,
    pub agent_id: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub requested_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

/// Closed terminal reasons for an Agent runtime approval notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRuntimeApprovalRemovalReason {
    Approved,
    Expired,
    Renewed,
    Deactivated,
    Superseded,
}

/// Optional data carried by a remove delta.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalNotificationRemovalData {
    pub kind: AccountNotificationDataKind,
    pub reason: AgentRuntimeApprovalRemovalReason,
}

/// Closed data branches for account notification deltas.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NotificationData {
    AgentRuntimeApproval(AgentRuntimeApprovalNotificationData),
    AgentRuntimeApprovalRemoval(AgentRuntimeApprovalNotificationRemovalData),
}

/// Strongly typed account notification projection delta.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotificationDelta {
    pub id: NotificationId,
    pub action: NotificationDeltaAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<NotificationData>,
    pub notification_kind: NotificationKind,
}

impl NotificationDelta {
    pub fn try_new(
        id: NotificationId,
        notification_kind: NotificationKind,
        action: NotificationDeltaAction,
        data: Option<NotificationData>,
    ) -> Result<Self> {
        let delta = Self {
            id,
            notification_kind,
            action,
            data,
        };
        delta.validate_shape()?;
        Ok(delta)
    }

    pub fn validate_shape(&self) -> Result<()> {
        if self.notification_kind != NotificationKind::Agent {
            return Err(Error::Protocol(
                "account notification delta notification_kind must be agent".to_owned(),
            ));
        }
        match (self.action, self.data.as_ref()) {
            (
                NotificationDeltaAction::Add | NotificationDeltaAction::Update,
                Some(NotificationData::AgentRuntimeApproval(_)),
            )
            | (
                NotificationDeltaAction::Remove,
                None | Some(NotificationData::AgentRuntimeApprovalRemoval(_)),
            ) => Ok(()),
            (NotificationDeltaAction::Add | NotificationDeltaAction::Update, _) => {
                Err(Error::Protocol(
                    "notification add/update requires agent_runtime_approval data".to_owned(),
                ))
            }
            (NotificationDeltaAction::Remove, _) => Err(Error::Protocol(
                "notification remove data must contain only a terminal reason".to_owned(),
            )),
        }
    }

    pub fn agent_runtime_approval(&self) -> Option<&AgentRuntimeApprovalNotificationData> {
        match self.data.as_ref() {
            Some(NotificationData::AgentRuntimeApproval(data)) => Some(data),
            None | Some(NotificationData::AgentRuntimeApprovalRemoval(_)) => None,
        }
    }

    pub fn agent_runtime_approval_removal(
        &self,
    ) -> Option<&AgentRuntimeApprovalNotificationRemovalData> {
        match self.data.as_ref() {
            Some(NotificationData::AgentRuntimeApprovalRemoval(data)) => Some(data),
            None | Some(NotificationData::AgentRuntimeApproval(_)) => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationDeltaWire {
    id: NotificationId,
    action: NotificationDeltaAction,
    #[serde(default)]
    data: Option<NotificationData>,
    notification_kind: NotificationKind,
}

impl<'de> Deserialize<'de> for NotificationDelta {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = NotificationDeltaWire::deserialize(deserializer)?;
        Self::try_new(wire.id, wire.notification_kind, wire.action, wire.data)
            .map_err(serde::de::Error::custom)
    }
}

/// Dedicated notification container for account subscribe.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationContainer {
    pub items: Vec<NotificationDelta>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/device-message.schema.json`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceMessageEnvelope {
    pub message_id: DeviceMessageId,
    pub kind: ProtocolKind,
    pub sender_principal_id: Did,
    pub sender_device_id: DeviceId,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub sent_at: DateTime<Utc>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub content: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_proof: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<BTreeMap<String, Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceMessageEnvelopeWire {
    message_id: DeviceMessageId,
    kind: ProtocolKind,
    sender_principal_id: Did,
    sender_device_id: DeviceId,
    recipient_principal_id: Did,
    recipient_device_id: DeviceId,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    sent_at: DateTime<Utc>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    content: BTreeMap<String, Value>,
    #[serde(default)]
    device_proof: Option<BTreeMap<String, Value>>,
    #[serde(default)]
    unsigned: Option<BTreeMap<String, Value>>,
}

impl<'de> Deserialize<'de> for DeviceMessageEnvelope {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeviceMessageEnvelopeWire::deserialize(deserializer)?;
        if wire.expires_at <= wire.sent_at {
            return Err(serde::de::Error::custom(
                "device message expires_at must be later than sent_at",
            ));
        }
        Ok(Self {
            message_id: wire.message_id,
            kind: wire.kind,
            sender_principal_id: wire.sender_principal_id,
            sender_device_id: wire.sender_device_id,
            recipient_principal_id: wire.recipient_principal_id,
            recipient_device_id: wire.recipient_device_id,
            sent_at: wire.sent_at,
            expires_at: wire.expires_at,
            content: wire.content,
            device_proof: wire.device_proof,
            unsigned: wire.unsigned,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceMessageContainer {
    pub messages: Vec<DeviceMessageEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl DeviceMessageContainer {
    pub fn validate(&self) -> Result<()> {
        if !self.messages.is_empty() && self.ack_token.is_none() {
            return Err(Error::Protocol(
                "non-empty to_device messages require ack_token".to_owned(),
            ));
        }
        if self
            .ack_token
            .as_ref()
            .is_some_and(|token| token.is_empty() || token.len() > 1024)
        {
            return Err(Error::Protocol(
                "to_device ack_token must contain 1..=1024 bytes".to_owned(),
            ));
        }
        if self.limited == Some(true) && self.next_cursor.is_none() {
            return Err(Error::Protocol(
                "limited to_device batches require next_cursor".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/event_container`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventContainer {
    pub events: Vec<Event>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSubscribeDeviceListChanges {
    pub changed: Vec<Did>,
    pub left: Vec<Did>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/timeline`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Timeline {
    pub events: Vec<Event>,
    pub limited: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ordered_log_conflicts: Vec<OrderedLogConflictDiagnostic>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderedLogConflictDiagnostic {
    pub cell: String,
    pub issuer: Did,
    pub issuer_seq: u64,
    pub reason: String,
    pub winner_event_id: EventId,
    pub winner_event_digest: String,
    pub loser_event_ids: Vec<EventId>,
    pub loser_event_digests: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowStartActorProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowStartRealmMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collaboration_role: Option<CollaborationRealmRole>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowStartE2eeEpoch {
    pub epoch: u64,
    pub key_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WindowStartNullableE2eeEpoch {
    Epoch(WindowStartE2eeEpoch),
    Null(()),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateAtWindowStart {
    pub actor_profiles: BTreeMap<Did, WindowStartActorProfile>,
    pub realm_metadata: WindowStartRealmMetadata,
    pub e2ee_epoch: WindowStartNullableE2eeEpoch,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSubscribeRealmSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_member_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invited_member_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heroes: Option<Vec<Did>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSubscribeUnreadCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highlight_count: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSyncEntryEventStatesItem {
    pub event_id: EventId,
    pub event_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_state_reason_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSyncEntryBottomsItem {
    pub cell: String,
    pub status: String,
    pub bottom: Bottom,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSyncEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline: Option<Timeline>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_at_window_start: Option<StateAtWindowStart>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<EventContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_after: Option<EventContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data: Option<EventContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<AccountSubscribeRealmSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<MemberRosterEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members_limited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members_next_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread_notifications: Option<AccountSubscribeUnreadCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_states: Option<Vec<RealmSyncEntryEventStatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bottoms: Option<Vec<RealmSyncEntryBottomsItem>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceMessagesSendRequestBody {
    pub messages: BTreeMap<Did, BTreeMap<DeviceId, DeviceMessageTarget>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceMessageTarget {
    pub message_id: DeviceMessageId,
    pub kind: ProtocolKind,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub content: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceMessagesSendOutcome {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub delivered: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown_devices: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceMessagesGetOutcome {
    pub messages: Vec<DeviceMessageEnvelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub limited: bool,
    #[serde(default)]
    pub lost: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceMessagesAckRequestBody {
    pub ack_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceMessagesAckOutcome {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pruned_count: Option<u64>,
}

#[cfg(test)]
mod device_message_dto_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn device_message_target_rejects_non_object_content_and_invalid_kind() {
        let valid = json!({
            "message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "ak.key.verification.request",
            "content": {"transaction_id": "txn"},
            "expires_at": "2026-07-15T01:00:00.000Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(valid).is_ok());

        let missing_message_id = json!({
            "kind": "ak.key.verification.request",
            "content": {"transaction_id": "txn"},
            "expires_at": "2026-07-15T01:00:00.000Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(missing_message_id).is_err());

        let invalid_kind = json!({
            "message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "key.verification.request",
            "content": {},
            "expires_at": "2026-07-15T01:00:00.000Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(invalid_kind).is_err());

        let scalar_content = json!({
            "message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "ak.key.verification.request",
            "content": "legacy payload",
            "expires_at": "2026-07-15T01:00:00.000Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(scalar_content).is_err());
    }
}

#[cfg(test)]
mod device_message_tests {
    use serde_json::json;

    use super::*;

    fn envelope_value() -> Value {
        json!({
            "message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "ak.key.verification.request",
            "sender_principal_id": "did:webvh:z6mkfixture:alice.example",
            "sender_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "recipient_principal_id": "did:webvh:z6mkfixture:alice.example",
            "recipient_device_id": "ak:device:01904100-0000-7000-8000-000000000002",
            "sent_at": "2026-07-15T00:00:00.000Z",
            "expires_at": "2026-07-15T00:10:00.000Z",
            "content": {"transaction_id": "txn"},
            "device_proof": {"vendor_proof": true},
            "unsigned": {"retry_after_ms": 1000}
        })
    }

    #[test]
    fn device_message_envelope_enforces_closed_object_shape_and_expiry_order() {
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(envelope_value()).is_ok());

        let mut expired = envelope_value();
        expired["expires_at"] = expired["sent_at"].clone();
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(expired).is_err());

        let mut scalar_content = envelope_value();
        scalar_content["content"] = json!("legacy payload");
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(scalar_content).is_err());

        let mut unknown_root_field = envelope_value();
        unknown_root_field["legacy"] = json!(true);
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(unknown_root_field).is_err());

        let mut missing_message_id = envelope_value();
        missing_message_id
            .as_object_mut()
            .unwrap()
            .remove("message_id");
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(missing_message_id).is_err());
    }
}

/// Membership state in [`MemberRosterEntry`]. Mirrors
/// `account-subscribe-frame.schema.json#/$defs/member_roster_entry.membership`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    Join,
    Invite,
    Knock,
}

/// R3.2 roster v2 — Lightweight per-actor entry on the Realm members
/// roster projection carried by `account.subscribe` frames.
///
/// Entries MUST NOT carry display name or naked handle strings directly;
/// handle strings may appear only inside signed `HandleClaim` objects in
/// [`Self::handle_claims`]. The disclosure-gated fields (`identity_events`,
/// `handle_claim_digests`, `handle_claims`, `handle_claims_limited`) MUST
/// be omitted unless [`Self::subject_id`] is disclosed — enforced by
/// [`Self::validate`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberRosterEntry {
    pub actor_id: Did,
    pub membership: MembershipState,
    /// Disclosed principal / holder DID for this member. Required whenever
    /// any handle-claim / identity-event evidence is included (see
    /// [`Self::validate`]). Omitted when subject disclosure is not
    /// authorized for the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<Did>,
    /// Effective `ak.member.identity.update` event ids for this actor
    /// after replacement edges are applied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_event_ids: Vec<EventId>,
    /// R3.2 rename of the prior `identity_state_digest` roster field.
    /// Digest over effective identity events + visible handle-claim
    /// digests; see `member_display_state_digest`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_display_state_digest: Option<Hash>,
    /// Optional inline effective `ak.member.identity.update` Event
    /// envelopes. When present these are the original events, NOT
    /// query-time re-encryption or projection rewrites. MUST be omitted
    /// unless `subject_id` is disclosed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_events: Vec<Event>,
    /// Digests of currently visible effective `ak.schema.handle_claim.v1`
    /// objects. MUST be omitted unless `subject_id` is disclosed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_claim_digests: Option<Vec<Hash>>,
    /// Optional inline signed handle-claim evidence. Every claim's
    /// `subject` MUST equal `subject_id`. MUST be omitted unless
    /// `subject_id` is disclosed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_claims: Option<Vec<HandleClaim>>,
    /// `true` when `handle_claims` is truncated or replaced by digest-only
    /// hints. Clients MUST NOT interpret missing claims as "no handle".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_claims_limited: Option<bool>,
}

impl MemberRosterEntry {
    /// R3.2 dependentRequired enforcement: the disclosure-gated fields MUST
    /// NOT appear unless `subject_id` is present, and every inline
    /// `handle_claims[].subject` MUST equal `subject_id`.
    pub fn validate(&self) -> Result<()> {
        let gated_present = !self.identity_events.is_empty()
            || self.handle_claim_digests.is_some()
            || self.handle_claims.is_some()
            || self.handle_claims_limited.is_some();
        if gated_present && self.subject_id.is_none() {
            return Err(Error::Protocol(
                "member_roster_entry: identity_events / handle_claim_digests / handle_claims / \
                 handle_claims_limited require subject_id disclosure"
                    .to_owned(),
            ));
        }
        if let (Some(subject), Some(claims)) = (&self.subject_id, &self.handle_claims) {
            for claim in claims {
                match &claim.subject {
                    Some(s) if s == subject => {}
                    _ => {
                        return Err(Error::Protocol(
                            "member_roster_entry: handle_claims[].subject must equal subject_id"
                                .to_owned(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_actor(label: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{label}.example")).unwrap()
    }

    fn fake_event_ref(suffix: &str) -> EventId {
        EventId::new(format!("ak:event:01904100-0000-8000-8000-{:0>12}", suffix)).unwrap()
    }

    #[test]
    fn member_roster_entry_round_trips_through_json() {
        let entry = MemberRosterEntry {
            actor_id: fake_actor("alice"),
            membership: MembershipState::Join,
            subject_id: None,
            identity_event_ids: vec![fake_event_ref("0030"), fake_event_ref("0031")],
            member_display_state_digest: Some(
                Hash::new(
                    "sha256:abababababababababababababababababababababababababababababababab",
                )
                .unwrap(),
            ),
            identity_events: vec![],
            handle_claim_digests: None,
            handle_claims: None,
            handle_claims_limited: None,
        };
        let json = serde_json::to_value(&entry).unwrap();
        // Confirm wire shape: actor_id + membership are always present;
        // empty `identity_events` is omitted by `skip_serializing_if`.
        assert!(json.get("actor_id").is_some());
        assert_eq!(json["membership"], serde_json::json!("join"));
        let decoded: MemberRosterEntry = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, entry);
        entry.validate().unwrap();
    }

    #[test]
    fn member_roster_entry_gated_fields_require_subject_id() {
        // handle_claims_limited present without subject_id MUST fail.
        let entry = MemberRosterEntry {
            actor_id: fake_actor("alice"),
            membership: MembershipState::Join,
            subject_id: None,
            identity_event_ids: vec![],
            member_display_state_digest: None,
            identity_events: vec![],
            handle_claim_digests: None,
            handle_claims: None,
            handle_claims_limited: Some(true),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn member_roster_entry_rejects_unknown_fields() {
        let raw = serde_json::json!({
            "actor_id": fake_actor("alice"),
            "membership": "join",
            "unexpected": 42
        });
        let parsed: std::result::Result<MemberRosterEntry, _> = serde_json::from_value(raw);
        assert!(parsed.is_err(), "unknown roster fields must be rejected");
    }
}
