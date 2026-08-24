//! Account-subscribe sync frame artifact counterparts.
//!
//! Frame containers for `ak.self.account.stream.subscribe` deltas:
//! notification projections, device-message envelopes, event and
//! ephemeral containers, timelines, and the per-Realm roster entry
//! carried by account-subscribe frames.

use arkret_wire::{ActorPrivateUpdateKind, DidCoreId};
use serde::Serializer;

use crate::internal_prelude::*;

/// Standard non-Event device-message kinds shared by wire validation and the
/// client drafting layer.
pub mod device_message_kind {
    pub const KEY_VERIFICATION_REQUEST: &str = "ak.key.verification.request";
    pub const KEY_VERIFICATION_READY: &str = "ak.key.verification.ready";
    pub const KEY_VERIFICATION_START: &str = "ak.key.verification.start";
    pub const KEY_VERIFICATION_ACCEPT: &str = "ak.key.verification.accept";
    pub const KEY_VERIFICATION_KEY: &str = "ak.key.verification.key";
    pub const KEY_VERIFICATION_MAC: &str = "ak.key.verification.mac";
    pub const KEY_VERIFICATION_DONE: &str = "ak.key.verification.done";
    pub const KEY_VERIFICATION_CANCEL: &str = "ak.key.verification.cancel";
    pub const MLS_WELCOME_V1: &str = arkret_wire::event_kind_str::MLS_WELCOME;
}

/// Closed action set for account notification projection deltas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationDeltaAction {
    Upsert,
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
    pub agent_id: DidCoreId,
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
            return Err(WireError::Protocol(
                "account notification delta notification_kind must be agent".to_owned(),
            ));
        }
        match (self.action, self.data.as_ref()) {
            (NotificationDeltaAction::Upsert, Some(NotificationData::AgentRuntimeApproval(_)))
            | (
                NotificationDeltaAction::Remove,
                None | Some(NotificationData::AgentRuntimeApprovalRemoval(_)),
            ) => Ok(()),
            (NotificationDeltaAction::Upsert, _) => Err(WireError::Protocol(
                "notification upsert requires agent_runtime_approval data".to_owned(),
            )),
            (NotificationDeltaAction::Remove, _) => Err(WireError::Protocol(
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

#[cfg(test)]
mod notification_delta_tests {
    use serde_json::json;

    use super::*;

    fn approval_delta(action: &str) -> serde_json::Value {
        json!({
            "id": "ak:notification:01964137-0000-7000-8000-000000000001",
            "action": action,
            "data": {
                "kind": "agent_runtime_approval",
                "approval_request_id": "agent_runtime_approval:01964137-0000-7000-8000-000000000000",
                "agent_id": "ak:did_core:webvh:z6mkfixtureagent",
                "requested_at": "2026-07-13T10:00:00.000Z",
                "expires_at": "2026-07-13T10:15:00.000Z"
            },
            "notification_kind": "agent"
        })
    }

    #[test]
    fn notification_delta_accepts_upsert_and_rejects_retired_actions() {
        let delta: NotificationDelta = serde_json::from_value(approval_delta("upsert")).unwrap();
        assert_eq!(delta.action, NotificationDeltaAction::Upsert);
        assert!(serde_json::from_value::<NotificationDelta>(approval_delta("add")).is_err());
        assert!(serde_json::from_value::<NotificationDelta>(approval_delta("update")).is_err());
    }

    #[test]
    fn notification_delta_rejects_unknown_members() {
        let mut value = approval_delta("upsert");
        value["legacy_action"] = json!("add");
        assert!(serde_json::from_value::<NotificationDelta>(value).is_err());
    }
}

/// Dedicated notification container for account subscribe.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationContainer {
    pub items: Vec<NotificationDelta>,
}

/// Closed sender endpoint of one to-device message.
///
/// A Native Agent runtime is not a human device:
/// It cannot be represented as an `ak:device`, so the endpoint is a closed XOR
/// rather than an `Option<DeviceId>` a producer could fill with a principal id.
///
/// The Agent branch carries the signer evidence the device branch gets from
/// the accepted device projection: without `sender_agent_verification_method`
/// and `sender_agent_key_authorize_event_id` a receiver would hold an Agent
/// principal id and no way to say which key currently speaks for it.
///
/// The Service branch is narrower: only the recipient Principal Server's
/// internal actor-private materializer may produce it. Envelope validation
/// additionally requires an actor-private update kind and equal sender /
/// recipient principal ids.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DeviceMessageSender {
    Device {
        sender_device_id: DeviceId,
    },
    NativeAgent {
        sender_agent_id: DidCoreId,
        sender_agent_verification_method: DidUrl,
        sender_agent_key_authorize_event_id: EventId,
    },
    Service {
        sender_service_id: DidCoreId,
    },
}

/// The five wire slots the endpoint XOR is spelled with.
///
/// Deliberately not `deny_unknown_fields`: this shape is flattened into the
/// envelope and into the queued body, so the surrounding fields reach it as
/// "unknown" ones. Strictness that matters here is the XOR itself.
#[derive(Deserialize)]
struct DeviceMessageSenderWire {
    #[serde(default)]
    sender_device_id: Option<DeviceId>,
    #[serde(default)]
    sender_agent_id: Option<DidCoreId>,
    #[serde(default)]
    sender_agent_verification_method: Option<DidUrl>,
    #[serde(default)]
    sender_agent_key_authorize_event_id: Option<EventId>,
    #[serde(default)]
    sender_service_id: Option<DidCoreId>,
}

impl<'de> Deserialize<'de> for DeviceMessageSender {
    /// A derived `untagged` deserializer would accept a device id sitting next
    /// to a complete Agent triple and silently keep only the device — the exact
    /// smuggling the closed XOR exists to stop. So the branch is selected from
    /// the full slot tuple instead of by first-variant-that-fits.
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeviceMessageSenderWire::deserialize(deserializer)?;
        Self::from_slots(
            wire.sender_device_id,
            wire.sender_agent_id,
            wire.sender_agent_verification_method,
            wire.sender_agent_key_authorize_event_id,
            wire.sender_service_id,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl DeviceMessageSender {
    /// Select the endpoint branch from the five wire slots, or reject.
    ///
    /// Exactly one complete branch is legal. A half-filled Agent branch, or a
    /// device id beside an Agent id, would let a producer carry a second
    /// unauthenticated sender identity past the rule that an Agent is never
    /// spelled as an `ak:device`.
    pub fn from_slots(
        sender_device_id: Option<DeviceId>,
        sender_agent_id: Option<DidCoreId>,
        sender_agent_verification_method: Option<DidUrl>,
        sender_agent_key_authorize_event_id: Option<EventId>,
        sender_service_id: Option<DidCoreId>,
    ) -> std::result::Result<Self, &'static str> {
        match (
            sender_device_id,
            sender_agent_id,
            sender_agent_verification_method,
            sender_agent_key_authorize_event_id,
            sender_service_id,
        ) {
            (Some(sender_device_id), None, None, None, None) => {
                Ok(Self::Device { sender_device_id })
            }
            (
                None,
                Some(sender_agent_id),
                Some(sender_agent_verification_method),
                Some(sender_agent_key_authorize_event_id),
                None,
            ) => Ok(Self::NativeAgent {
                sender_agent_id,
                sender_agent_verification_method,
                sender_agent_key_authorize_event_id,
            }),
            (None, None, None, None, Some(sender_service_id)) => {
                Ok(Self::Service { sender_service_id })
            }
            _ => Err(
                "device message sender must contain exactly one complete device, Native Agent, or Service branch",
            ),
        }
    }

    /// The endpoint half of the receiver dedupe key.
    ///
    /// `device-message.schema.json` keys deduplication on
    /// `(sender_principal_id, <endpoint>, device_message_id)`; the endpoint is the
    /// device for a human sender, the Agent principal for a Native Agent, and
    /// the Principal Server service id for a Service sender.
    pub fn endpoint_id(&self) -> &str {
        match self {
            Self::Device { sender_device_id } => sender_device_id.as_str(),
            Self::NativeAgent {
                sender_agent_id, ..
            } => sender_agent_id.as_str(),
            Self::Service { sender_service_id } => sender_service_id.as_str(),
        }
    }

    /// The authoring device, when the sender is one.
    pub fn device_id(&self) -> Option<&DeviceId> {
        match self {
            Self::Device { sender_device_id } => Some(sender_device_id),
            Self::NativeAgent { .. } | Self::Service { .. } => None,
        }
    }

    /// The Principal Server materializer, when this is the restricted service
    /// branch.
    pub fn service_id(&self) -> Option<&DidCoreId> {
        match self {
            Self::Service { sender_service_id } => Some(sender_service_id),
            Self::Device { .. } | Self::NativeAgent { .. } => None,
        }
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/device-message.schema.json`.
///
/// The schema root is `additionalProperties: false`, and that closure is
/// enforced by [`DeviceMessageEnvelopeWire`] — the only deserializer for this
/// type. This struct carries no `deny_unknown_fields` of its own: the attribute
/// is consumed solely by serde's `Deserialize` derive, which this type does not
/// use, and serde rejects it outright alongside `#[serde(flatten)]`, so
/// spelling it here would claim a guarantee this derive cannot make.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceMessageEnvelope {
    pub device_message_id: DeviceMessageId,
    pub kind: ProtocolKind,
    pub sender_principal_id: DidCoreId,
    #[serde(flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub sender: DeviceMessageSender,
    pub recipient_principal_id: DidCoreId,
    pub recipient_device_id: DeviceId,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub sent_at: DateTime<Utc>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub content: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_proof: Option<PayloadProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<BTreeMap<String, Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceMessageEnvelopeWire {
    device_message_id: DeviceMessageId,
    kind: ProtocolKind,
    sender_principal_id: DidCoreId,
    #[serde(default)]
    sender_device_id: Option<DeviceId>,
    #[serde(default)]
    sender_agent_id: Option<DidCoreId>,
    #[serde(default)]
    sender_agent_verification_method: Option<DidUrl>,
    #[serde(default)]
    sender_agent_key_authorize_event_id: Option<EventId>,
    #[serde(default)]
    sender_service_id: Option<DidCoreId>,
    recipient_principal_id: DidCoreId,
    recipient_device_id: DeviceId,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    sent_at: DateTime<Utc>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    content: BTreeMap<String, Value>,
    #[serde(default)]
    device_proof: Option<PayloadProof>,
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
        let sender = DeviceMessageSender::from_slots(
            wire.sender_device_id,
            wire.sender_agent_id,
            wire.sender_agent_verification_method,
            wire.sender_agent_key_authorize_event_id,
            wire.sender_service_id,
        )
        .map_err(serde::de::Error::custom)?;
        if matches!(&sender, DeviceMessageSender::Service { .. }) {
            if wire.sender_principal_id != wire.recipient_principal_id {
                return Err(serde::de::Error::custom(
                    "service device message sender_principal_id must equal recipient_principal_id",
                ));
            }
            if ActorPrivateUpdateKind::from_wire(wire.kind.as_str()).is_none() {
                return Err(serde::de::Error::custom(
                    "service device message sender is restricted to actor-private update kinds",
                ));
            }
        }
        Ok(Self {
            device_message_id: wire.device_message_id,
            kind: wire.kind,
            sender_principal_id: wire.sender_principal_id,
            sender,
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
            return Err(WireError::Protocol(
                "non-empty to_device messages require ack_token".to_owned(),
            ));
        }
        if self
            .ack_token
            .as_ref()
            .is_some_and(|token| token.is_empty() || token.len() > 1024)
        {
            return Err(WireError::Protocol(
                "to_device ack_token must contain 1..=1024 bytes".to_owned(),
            ));
        }
        if self.limited == Some(true) && self.next_cursor.is_none() {
            return Err(WireError::Protocol(
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
    pub changed: Vec<DidCoreId>,
    pub left: Vec<DidCoreId>,
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
    pub ordered_log_siblings: Vec<OrderedLogSiblingDiagnostic>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderedLogSiblingDiagnostic {
    pub cell: String,
    pub issuer: DidCoreId,
    pub issuer_seq: u64,
    pub reason: String,
    pub event_ids: Vec<EventId>,
    pub event_digests: Vec<String>,
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
    pub actor_profiles: BTreeMap<DidCoreId, WindowStartActorProfile>,
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
    pub heroes: Option<Vec<DidCoreId>>,
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
    pub messages: BTreeMap<DidCoreId, BTreeMap<DeviceId, DeviceMessageTarget>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceMessageTarget {
    pub device_message_id: DeviceMessageId,
    pub kind: ProtocolKind,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub content: BTreeMap<String, Value>,
}

/// Closed operation set carried by actor-private account-data update messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorPrivateAccountDataOperation {
    Put,
    Delete,
}

/// Account-data delta carried inside an actor-private device update.
///
/// `content` is intentionally open JSON because account-data values are an
/// application-owned extension boundary. The surrounding update variant and
/// revision contract remain strongly typed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorPrivateAccountDataUpdate {
    pub operation: ActorPrivateAccountDataOperation,
    pub account_data_key: String,
    pub revision: u64,
    pub content: Option<Value>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

/// Read-cursor delta carried inside an actor-private device update.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorPrivateReadCursorUpdate {
    pub schema: String,
    pub actor_id: DidCoreId,
    pub device_id: DeviceId,
    pub realm_id: RealmId,
    pub read_scope: ReadCursorScope,
    pub position: crate::objects::read_receipts::ReadCursorPosition,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

/// Self-describing actor-private update envelope. The wire `type` tag and its
/// content shape cannot be constructed independently. Its sender is the same
/// closed flattened XOR as [`DeviceMessageEnvelope`], because Principal Server
/// CAS materializers have no authoring device id.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "type")]
pub enum ActorPrivateDeviceUpdate {
    #[serde(rename = "ak.account_data.update")]
    AccountData {
        #[serde(flatten)]
        sender: DeviceMessageSender,
        content: ActorPrivateAccountDataUpdate,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        created_at: DateTime<Utc>,
    },
    #[serde(rename = "ak.account.blocklist.update")]
    Blocklist {
        #[serde(flatten)]
        sender: DeviceMessageSender,
        content: ActorPrivateAccountDataUpdate,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        created_at: DateTime<Utc>,
    },
    #[serde(rename = "ak.read_cursor.update")]
    ReadCursor {
        #[serde(flatten)]
        sender: DeviceMessageSender,
        content: ActorPrivateReadCursorUpdate,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        created_at: DateTime<Utc>,
    },
}

/// Closed deserialization shape for [`ActorPrivateDeviceUpdate`].
///
/// The public type flattens [`DeviceMessageSender`] when serializing. A derived
/// flattened deserializer cannot also use `deny_unknown_fields`, so it would
/// silently accept an extra sender slot or an unrelated root field. This wire
/// type instead names all five sender slots and closes every variant before
/// selecting the XOR through [`DeviceMessageSender::from_slots`].
#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum ActorPrivateDeviceUpdateWire {
    #[serde(rename = "ak.account_data.update")]
    AccountData {
        #[serde(default)]
        sender_device_id: Option<DeviceId>,
        #[serde(default)]
        sender_agent_id: Option<DidCoreId>,
        #[serde(default)]
        sender_agent_verification_method: Option<DidUrl>,
        #[serde(default)]
        sender_agent_key_authorize_event_id: Option<EventId>,
        #[serde(default)]
        sender_service_id: Option<DidCoreId>,
        content: ActorPrivateAccountDataUpdate,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        created_at: DateTime<Utc>,
    },
    #[serde(rename = "ak.account.blocklist.update")]
    Blocklist {
        #[serde(default)]
        sender_device_id: Option<DeviceId>,
        #[serde(default)]
        sender_agent_id: Option<DidCoreId>,
        #[serde(default)]
        sender_agent_verification_method: Option<DidUrl>,
        #[serde(default)]
        sender_agent_key_authorize_event_id: Option<EventId>,
        #[serde(default)]
        sender_service_id: Option<DidCoreId>,
        content: ActorPrivateAccountDataUpdate,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        created_at: DateTime<Utc>,
    },
    #[serde(rename = "ak.read_cursor.update")]
    ReadCursor {
        #[serde(default)]
        sender_device_id: Option<DeviceId>,
        #[serde(default)]
        sender_agent_id: Option<DidCoreId>,
        #[serde(default)]
        sender_agent_verification_method: Option<DidUrl>,
        #[serde(default)]
        sender_agent_key_authorize_event_id: Option<EventId>,
        #[serde(default)]
        sender_service_id: Option<DidCoreId>,
        content: ActorPrivateReadCursorUpdate,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        created_at: DateTime<Utc>,
    },
}

impl ActorPrivateDeviceUpdateWire {
    fn sender(
        sender_device_id: Option<DeviceId>,
        sender_agent_id: Option<DidCoreId>,
        sender_agent_verification_method: Option<DidUrl>,
        sender_agent_key_authorize_event_id: Option<EventId>,
        sender_service_id: Option<DidCoreId>,
    ) -> std::result::Result<DeviceMessageSender, &'static str> {
        DeviceMessageSender::from_slots(
            sender_device_id,
            sender_agent_id,
            sender_agent_verification_method,
            sender_agent_key_authorize_event_id,
            sender_service_id,
        )
    }
}

impl<'de> Deserialize<'de> for ActorPrivateDeviceUpdate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match ActorPrivateDeviceUpdateWire::deserialize(deserializer)? {
            ActorPrivateDeviceUpdateWire::AccountData {
                sender_device_id,
                sender_agent_id,
                sender_agent_verification_method,
                sender_agent_key_authorize_event_id,
                sender_service_id,
                content,
                created_at,
            } => Ok(Self::AccountData {
                sender: ActorPrivateDeviceUpdateWire::sender(
                    sender_device_id,
                    sender_agent_id,
                    sender_agent_verification_method,
                    sender_agent_key_authorize_event_id,
                    sender_service_id,
                )
                .map_err(serde::de::Error::custom)?,
                content,
                created_at,
            }),
            ActorPrivateDeviceUpdateWire::Blocklist {
                sender_device_id,
                sender_agent_id,
                sender_agent_verification_method,
                sender_agent_key_authorize_event_id,
                sender_service_id,
                content,
                created_at,
            } => Ok(Self::Blocklist {
                sender: ActorPrivateDeviceUpdateWire::sender(
                    sender_device_id,
                    sender_agent_id,
                    sender_agent_verification_method,
                    sender_agent_key_authorize_event_id,
                    sender_service_id,
                )
                .map_err(serde::de::Error::custom)?,
                content,
                created_at,
            }),
            ActorPrivateDeviceUpdateWire::ReadCursor {
                sender_device_id,
                sender_agent_id,
                sender_agent_verification_method,
                sender_agent_key_authorize_event_id,
                sender_service_id,
                content,
                created_at,
            } => Ok(Self::ReadCursor {
                sender: ActorPrivateDeviceUpdateWire::sender(
                    sender_device_id,
                    sender_agent_id,
                    sender_agent_verification_method,
                    sender_agent_key_authorize_event_id,
                    sender_service_id,
                )
                .map_err(serde::de::Error::custom)?,
                content,
                created_at,
            }),
        }
    }
}

impl ActorPrivateDeviceUpdate {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AccountData { .. } => ActorPrivateUpdateKind::ACCOUNT_DATA_UPDATE,
            Self::Blocklist { .. } => ActorPrivateUpdateKind::ACCOUNT_BLOCKLIST_UPDATE,
            Self::ReadCursor { .. } => ActorPrivateUpdateKind::READ_CURSOR_UPDATE,
        }
    }

    pub fn sender(&self) -> &DeviceMessageSender {
        match self {
            Self::AccountData { sender, .. }
            | Self::Blocklist { sender, .. }
            | Self::ReadCursor { sender, .. } => sender,
        }
    }

    /// Authoring device when this update came from a holder device. Service
    /// materializers intentionally return `None`.
    pub fn sender_device_id(&self) -> Option<&DeviceId> {
        self.sender().device_id()
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        match self {
            Self::AccountData { created_at, .. }
            | Self::Blocklist { created_at, .. }
            | Self::ReadCursor { created_at, .. } => created_at.to_owned(),
        }
    }
}

/// Projection metadata attached to an MLS Welcome to-device delivery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsWelcomeProjectionBinding {
    pub source_event_id: String,
    pub mls_welcome_id: String,
    pub key_package_id: String,
}

/// SDK-owned outbound MLS Welcome device-message envelope. The standard kind
/// is emitted by the serializer and cannot diverge from the typed payload.
#[derive(Clone, Debug)]
pub struct MlsWelcomeProjectedDeviceMessage {
    pub sender_device_id: String,
    pub expires_at: DateTime<Utc>,
    pub content: crate::events_payloads::MlsWelcomePayload,
    pub unsigned: MlsWelcomeProjectionBinding,
}

impl Serialize for MlsWelcomeProjectedDeviceMessage {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Wire<'a> {
            kind: EventKind,
            sender_device_id: &'a str,
            #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
            expires_at: DateTime<Utc>,
            content: &'a crate::events_payloads::MlsWelcomePayload,
            unsigned: &'a MlsWelcomeProjectionBinding,
        }
        Wire {
            kind: EventKind::MlsWelcome,
            sender_device_id: &self.sender_device_id,
            expires_at: self.expires_at.to_owned(),
            content: &self.content,
            unsigned: &self.unsigned,
        }
        .serialize(serializer)
    }
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
            "device_message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "ak.key.verification.request",
            "content": {"transaction_id": "txn"},
            "expires_at": "2026-07-15T01:00:00.000Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(valid).is_ok());

        let missing_device_message_id = json!({
            "kind": "ak.key.verification.request",
            "content": {"transaction_id": "txn"},
            "expires_at": "2026-07-15T01:00:00.000Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(missing_device_message_id).is_err());

        let invalid_kind = json!({
            "device_message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "key.verification.request",
            "content": {},
            "expires_at": "2026-07-15T01:00:00.000Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(invalid_kind).is_err());

        let scalar_content = json!({
            "device_message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "ak.key.verification.request",
            "content": "not an object",
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
            "device_message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "ak.key.verification.request",
            "sender_principal_id": "ak:did_core:webvh:z6mkfixture",
            "sender_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "recipient_principal_id": "ak:did_core:webvh:z6mkfixture",
            "recipient_device_id": "ak:device:01904100-0000-7000-8000-000000000002",
            "sent_at": "2026-07-15T00:00:00.000Z",
            "expires_at": "2026-07-15T00:10:00.000Z",
            "content": {"transaction_id": "txn"},
            "device_proof": {
                "kind": "detached_jws",
                "verification_method": "did:webvh:z6mkfixture:example.test#device-1",
                "payload_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "created_at": "2026-07-15T00:00:00.000Z",
                "jws": "e30..c2ln"
            },
            "unsigned": {"retry_after_ms": 1000}
        })
    }

    fn agent_sender_fields() -> Value {
        json!({
            "sender_agent_id": "ak:did_core:webvh:z6mkfixtureagent",
            "sender_agent_verification_method":
                "did:webvh:z6mkfixtureagent:agent.example#agent-key-1",
            "sender_agent_key_authorize_event_id":
                "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e"
        })
    }

    fn service_sender_fields() -> Value {
        json!({
            "sender_service_id": "ak:did_core:webvh:z6mkfixtureservice"
        })
    }

    /// The two sender endpoints are one closed XOR: a Native Agent has no
    /// device identity and MUST NOT be spelled as one, and its branch is only
    /// usable complete — an Agent principal id without the key that currently
    /// speaks for it is not an authenticatable sender.
    /// A derived `untagged` deserializer picks the first variant that fits, so
    /// a device id beside a complete Agent triple would parse as the device and
    /// silently drop the Agent identity. This pins that it does not.
    #[test]
    fn a_sender_carrying_both_branches_is_rejected_not_narrowed() {
        let both = json!({
            "sender_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "sender_agent_id": "ak:did_core:webvh:z6mkfixtureagent",
            "sender_agent_verification_method":
                "did:webvh:z6mkfixtureagent:agent.example#agent-key-1",
            "sender_agent_key_authorize_event_id":
                "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e"
        });
        assert!(serde_json::from_value::<DeviceMessageSender>(both).is_err());
        assert!(
            serde_json::from_value::<DeviceMessageSender>(json!({
                "sender_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "sender_service_id": "ak:did_core:webvh:z6mkfixtureservice"
            }))
            .is_err(),
            "a mixed device/service branch is not a sender"
        );
        assert!(
            serde_json::from_value::<DeviceMessageSender>(service_sender_fields()).is_ok(),
            "a lone service slot is the complete third branch"
        );
        assert!(
            serde_json::from_value::<DeviceMessageSender>(json!({
                "sender_agent_id": "ak:did_core:webvh:z6mkfixtureagent"
            }))
            .is_err(),
            "a half-filled Agent branch is not a sender"
        );
        // Surrounding envelope keys are not the sender's business: the shape is
        // flattened, so it must tolerate them while still enforcing the XOR.
        assert!(
            serde_json::from_value::<DeviceMessageSender>(json!({
                "device_message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
                "sender_device_id": "ak:device:01904100-0000-7000-8000-000000000001"
            }))
            .is_ok()
        );
    }

    #[test]
    fn device_message_sender_endpoint_is_a_closed_xor() {
        let mut agent = envelope_value();
        agent.as_object_mut().unwrap().remove("sender_device_id");
        for (key, value) in agent_sender_fields().as_object().unwrap() {
            agent
                .as_object_mut()
                .unwrap()
                .insert(key.clone(), value.clone());
        }
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(agent.clone()).is_ok());

        let mut both = agent.clone();
        both.as_object_mut().unwrap().insert(
            "sender_device_id".to_owned(),
            json!("ak:device:01904100-0000-7000-8000-000000000001"),
        );
        assert!(
            serde_json::from_value::<DeviceMessageEnvelope>(both).is_err(),
            "a Native Agent sender must not also carry a device id"
        );

        let mut half_agent = agent.clone();
        half_agent
            .as_object_mut()
            .unwrap()
            .remove("sender_agent_verification_method");
        assert!(
            serde_json::from_value::<DeviceMessageEnvelope>(half_agent).is_err(),
            "a half-filled Agent branch must not be accepted"
        );

        let mut no_endpoint = envelope_value();
        no_endpoint
            .as_object_mut()
            .unwrap()
            .remove("sender_device_id");
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(no_endpoint).is_err());

        let mut service = envelope_value();
        service.as_object_mut().unwrap().remove("sender_device_id");
        service["kind"] = json!(ActorPrivateUpdateKind::ACCOUNT_DATA_UPDATE);
        for (key, value) in service_sender_fields().as_object().unwrap() {
            service
                .as_object_mut()
                .unwrap()
                .insert(key.clone(), value.clone());
        }
        let parsed = serde_json::from_value::<DeviceMessageEnvelope>(service.clone()).unwrap();
        assert_eq!(
            parsed.sender.endpoint_id(),
            "ak:did_core:webvh:z6mkfixtureservice"
        );
        assert!(parsed.sender.device_id().is_none());

        let mut service_with_device = service.clone();
        service_with_device["sender_device_id"] =
            json!("ak:device:01904100-0000-7000-8000-000000000001");
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(service_with_device).is_err());

        let mut service_with_normal_kind = service.clone();
        service_with_normal_kind["kind"] = json!("ak.secret.request");
        assert!(
            serde_json::from_value::<DeviceMessageEnvelope>(service_with_normal_kind).is_err(),
            "service senders are restricted to actor-private update kinds"
        );

        let mut cross_principal_service = service;
        cross_principal_service["sender_principal_id"] =
            json!("ak:did_core:webvh:z6mkfixtureother");
        assert!(
            serde_json::from_value::<DeviceMessageEnvelope>(cross_principal_service).is_err(),
            "service senders cannot cross the recipient principal boundary"
        );
    }

    #[test]
    fn actor_private_service_update_round_trips_without_a_fake_device() {
        let value = json!({
            "type": ActorPrivateUpdateKind::ACCOUNT_DATA_UPDATE,
            "sender_service_id": "ak:did_core:webvh:z6mkfixtureservice",
            "content": {
                "operation": "put",
                "account_data_key": "ak.account.invite_delivery",
                "revision": 3,
                "content": {
                    "schema": "ak.schema.invite_delivery.v1",
                    "updated_at": "2026-07-15T00:00:00.000Z",
                    "entries": []
                },
                "updated_at": "2026-07-15T00:00:00.000Z"
            },
            "created_at": "2026-07-15T00:00:00.000Z"
        });
        let update: ActorPrivateDeviceUpdate = serde_json::from_value(value.clone()).unwrap();
        assert!(update.sender_device_id().is_none());
        assert_eq!(
            update.sender().endpoint_id(),
            "ak:did_core:webvh:z6mkfixtureservice"
        );
        assert_eq!(serde_json::to_value(update).unwrap(), value);

        let mut mixed = value.clone();
        mixed["sender_device_id"] = json!("ak:device:01904100-0000-7000-8000-000000000001");
        assert!(
            serde_json::from_value::<ActorPrivateDeviceUpdate>(mixed).is_err(),
            "actor-private update cannot mix service and device sender slots"
        );

        let mut half_agent = value;
        half_agent
            .as_object_mut()
            .unwrap()
            .remove("sender_service_id");
        half_agent["sender_agent_id"] = json!("ak:did_core:webvh:z6mkfixtureagent");
        assert!(
            serde_json::from_value::<ActorPrivateDeviceUpdate>(half_agent).is_err(),
            "actor-private update cannot carry a half-filled Agent sender"
        );
    }

    #[test]
    fn device_message_envelope_enforces_closed_object_shape_and_expiry_order() {
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(envelope_value()).is_ok());

        let mut expired = envelope_value();
        expired["expires_at"] = expired["sent_at"].clone();
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(expired).is_err());

        let mut scalar_content = envelope_value();
        scalar_content["content"] = json!("not an object");
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(scalar_content).is_err());

        let mut unknown_root_field = envelope_value();
        unknown_root_field["unexpected"] = json!(true);
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(unknown_root_field).is_err());

        let mut missing_device_message_id = envelope_value();
        missing_device_message_id
            .as_object_mut()
            .unwrap()
            .remove("device_message_id");
        assert!(
            serde_json::from_value::<DeviceMessageEnvelope>(missing_device_message_id).is_err()
        );
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
    pub actor_id: DidCoreId,
    pub membership: MembershipState,
    /// Disclosed principal / holder DID for this member. Required whenever
    /// any handle-claim / identity-event evidence is included (see
    /// [`Self::validate`]). Omitted when subject disclosure is not
    /// authorized for the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<DidCoreId>,
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
            return Err(WireError::Protocol(
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
                        return Err(WireError::Protocol(
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

    fn fake_actor(label: &str) -> DidCoreId {
        DidCoreId::new(format!("ak:did_core:webvh:z6mkfixture{label}")).unwrap()
    }

    fn fake_event_ref(suffix: &str) -> EventId {
        EventId::from_event_digest(
            &Hash::new(arkret_canonical::sha256_digest(suffix.as_bytes())).unwrap(),
        )
        .unwrap()
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
