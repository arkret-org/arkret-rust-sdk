//! Account-subscribe sync frame artifact counterparts.
//!
//! Frame containers for `ak.self.account.stream.subscribe.v1` deltas:
//! notification projections, device-message envelopes, event and
//! ephemeral containers, timelines, and the per-Realm roster entry
//! carried by account-subscribe frames.

use arkret_models_crypto::secret_share::{SecretShareRequestContent, SecretShareSendContent};
use arkret_models_identity::artifacts_device_identity::KeyVerificationContent;
use arkret_wire::{AccountId, ActorId, ActorPrivateUpdateKind, DidCoreId};
use serde::Serializer;

use crate::internal_prelude::*;
use crate::objects::read_receipts::{NotificationIdentity, OrdinaryProjectionContent};

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

/// Account-private Agent runtime approval projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalNotificationData {
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
    pub reason: AgentRuntimeApprovalRemovalReason,
}

/// Closed terminal reasons for an ordinary source-Event notification row.
///
/// Every value is server-observable. Inbox disposition (read / dismissed /
/// archived) is holder-private state and never removes a current row, so it has
/// no representation here — a Station that wanted to express "the user read it"
/// would have to invent a reason, and there is none to invent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrdinaryNotificationRemovalReason {
    SourceRemoved,
    AccessRevoked,
    Expired,
    Superseded,
}

/// Required data of an ordinary source-Event notification `remove` delta.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrdinaryNotificationRemovalData {
    pub reason: OrdinaryNotificationRemovalReason,
}

/// Closed data branches for account notification deltas.
///
/// Serialization is untagged because the wire carries no discriminator of its
/// own; deserialization is *not*, and must not be. `expired` and `superseded`
/// belong to both removal vocabularies, so an untagged decoder would accept an
/// ordinary removal reason on an Agent approval row (and the reverse) whenever
/// the two vocabularies overlap. [`NotificationDelta`] therefore selects the
/// branch from the `id` form first and only then parses `data` into that
/// branch's type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum NotificationData {
    AgentRuntimeApproval(AgentRuntimeApprovalNotificationData),
    AgentRuntimeApprovalRemoval(AgentRuntimeApprovalNotificationRemovalData),
    OrdinaryProjection(Box<OrdinaryProjectionContent>),
    OrdinaryRemoval(OrdinaryNotificationRemovalData),
}

/// Strongly typed account notification projection delta.
///
/// One channel carries both notification branches, and the `id` form is the
/// only discriminator: `ak:notification:<uuidv7>` is an Agent runtime approval,
/// `ak:notification_projection:<token>` is an ordinary source-Event current
/// row. Both share the projector, the channel position and the per-frame
/// budget; there is no second notification list operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotificationDelta {
    pub id: NotificationIdentity,
    pub action: NotificationDeltaAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<NotificationData>,
}

impl NotificationDelta {
    pub fn try_new(
        id: NotificationIdentity,
        action: NotificationDeltaAction,
        data: Option<NotificationData>,
    ) -> Result<Self> {
        let delta = Self { id, action, data };
        delta.validate_shape()?;
        Ok(delta)
    }

    pub fn validate_shape(&self) -> Result<()> {
        match (&self.id, self.action, self.data.as_ref()) {
            (
                NotificationIdentity::AgentApproval(_),
                NotificationDeltaAction::Upsert,
                Some(NotificationData::AgentRuntimeApproval(_)),
            )
            | (
                NotificationIdentity::AgentApproval(_),
                NotificationDeltaAction::Remove,
                None | Some(NotificationData::AgentRuntimeApprovalRemoval(_)),
            ) => Ok(()),
            (
                NotificationIdentity::Projection(_),
                NotificationDeltaAction::Upsert,
                Some(NotificationData::OrdinaryProjection(content)),
            ) => content.validate(),
            (
                NotificationIdentity::Projection(_),
                NotificationDeltaAction::Remove,
                Some(NotificationData::OrdinaryRemoval(_)),
            ) => Ok(()),
            (NotificationIdentity::AgentApproval(_), NotificationDeltaAction::Upsert, _) => {
                Err(WireError::Protocol(
                    "notification upsert requires agent_runtime_approval data".to_owned(),
                ))
            }
            (NotificationIdentity::AgentApproval(_), NotificationDeltaAction::Remove, _) => {
                Err(WireError::Protocol(
                    "notification remove data must contain only a terminal reason".to_owned(),
                ))
            }
            (NotificationIdentity::Projection(_), NotificationDeltaAction::Upsert, _) => {
                Err(WireError::Protocol(
                    "ordinary notification upsert requires ordinary projection content".to_owned(),
                ))
            }
            (NotificationIdentity::Projection(_), NotificationDeltaAction::Remove, _) => {
                Err(WireError::Protocol(
                    "ordinary notification remove requires a server-observable reason".to_owned(),
                ))
            }
        }
    }

    pub fn agent_runtime_approval(&self) -> Option<&AgentRuntimeApprovalNotificationData> {
        match self.data.as_ref() {
            Some(NotificationData::AgentRuntimeApproval(data)) => Some(data),
            _ => None,
        }
    }

    pub fn agent_runtime_approval_removal_reason(
        &self,
    ) -> Option<AgentRuntimeApprovalRemovalReason> {
        match self.data.as_ref() {
            Some(NotificationData::AgentRuntimeApprovalRemoval(data)) => Some(data.reason),
            _ => None,
        }
    }

    pub fn ordinary_projection(&self) -> Option<&OrdinaryProjectionContent> {
        match self.data.as_ref() {
            Some(NotificationData::OrdinaryProjection(content)) => Some(content),
            _ => None,
        }
    }

    pub fn ordinary_removal_reason(&self) -> Option<OrdinaryNotificationRemovalReason> {
        match self.data.as_ref() {
            Some(NotificationData::OrdinaryRemoval(data)) => Some(data.reason),
            _ => None,
        }
    }

    /// Recompute the ordinary projection identity from the authenticated
    /// recipient's own AccountId and compare it with the delivered row id.
    ///
    /// A recipient MUST run this before displaying an ordinary current row: the
    /// id is the only thing binding the row to *this* account, and the row
    /// itself does not carry a recipient field to compare against. Branches
    /// with no recomputable identity (Agent approvals, and ordinary removals,
    /// which carry only a reason) return `Ok` without asserting anything.
    pub fn verify_recipient_binding(&self, recipient_account_id: &AccountId) -> Result<()> {
        self.validate_shape()?;
        match (&self.id, self.data.as_ref()) {
            (
                NotificationIdentity::Projection(id),
                Some(NotificationData::OrdinaryProjection(content)),
            ) => content.verify_id(recipient_account_id, id),
            _ => Ok(()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationDeltaWire {
    id: NotificationIdentity,
    action: NotificationDeltaAction,
    #[serde(default)]
    data: Option<Value>,
}

impl<'de> Deserialize<'de> for NotificationDelta {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = NotificationDeltaWire::deserialize(deserializer)?;
        let data = match (&wire.id, wire.action, wire.data) {
            (_, _, None) => None,
            (
                NotificationIdentity::AgentApproval(_),
                NotificationDeltaAction::Upsert,
                Some(raw),
            ) => Some(NotificationData::AgentRuntimeApproval(
                serde_json::from_value(raw).map_err(serde::de::Error::custom)?,
            )),
            (
                NotificationIdentity::AgentApproval(_),
                NotificationDeltaAction::Remove,
                Some(raw),
            ) => Some(NotificationData::AgentRuntimeApprovalRemoval(
                serde_json::from_value(raw).map_err(serde::de::Error::custom)?,
            )),
            (NotificationIdentity::Projection(_), NotificationDeltaAction::Upsert, Some(raw)) => {
                Some(NotificationData::OrdinaryProjection(Box::new(
                    serde_json::from_value(raw).map_err(serde::de::Error::custom)?,
                )))
            }
            (NotificationIdentity::Projection(_), NotificationDeltaAction::Remove, Some(raw)) => {
                Some(NotificationData::OrdinaryRemoval(
                    serde_json::from_value(raw).map_err(serde::de::Error::custom)?,
                ))
            }
        };
        Self::try_new(wire.id, wire.action, data).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod notification_delta_tests {
    use serde_json::json;

    use super::*;

    /// Identity KAT from `id-kind-registry.json`: this recipient, Realm, source
    /// Event and `message` kind derive exactly the projection id below.
    const KAT_REALM: &str = "ak:realm:AdF_8ICakbYdEH0Cnl-w5o1WFlnh5rXGWqY_-_G6yM7N";
    const KAT_EVENT: &str = "ak:event:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq";
    const KAT_PROJECTION: &str =
        "ak:notification_projection:AdaNq4qN-xTAcv8kCT3P9mL5AsSzg0PFlSELggvhw2Pw";

    fn kat_recipient() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
        )
    }

    fn approval_delta(action: &str) -> Value {
        json!({
            "id": "ak:notification:01964137-0000-7000-8000-000000000001",
            "action": action,
            "data": {
                "approval_request_id": "agent_runtime_approval:01964137-0000-7000-8000-000000000000",
                "agent_id": "ak:did_core:webvh:z6mkfixtureagent",
                "requested_at": "2026-07-13T10:00:00.000Z",
                "expires_at": "2026-07-13T10:15:00.000Z"
            }
        })
    }

    fn ordinary_delta(action: &str, data: Value) -> Value {
        json!({"id": KAT_PROJECTION, "action": action, "data": data})
    }

    fn ordinary_content() -> Value {
        json!({
            "realm_id": KAT_REALM,
            "source_event_id": KAT_EVENT,
            "notification_kind": "message",
            "priority": "normal",
            "created_at": "2026-09-10T10:00:00.000Z"
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
        value["unknown_action"] = json!("add");
        assert!(serde_json::from_value::<NotificationDelta>(value).is_err());

        let mut retired_notification_kind = approval_delta("upsert");
        retired_notification_kind["notification_kind"] = json!("agent");
        assert!(serde_json::from_value::<NotificationDelta>(retired_notification_kind).is_err());

        let mut retired_data_kind = approval_delta("upsert");
        retired_data_kind["data"]["kind"] = json!("agent_runtime_approval");
        assert!(serde_json::from_value::<NotificationDelta>(retired_data_kind).is_err());
    }

    #[test]
    fn ordinary_current_row_round_trips_and_binds_its_recipient() {
        let delta: NotificationDelta =
            serde_json::from_value(ordinary_delta("upsert", ordinary_content())).unwrap();
        let content = delta.ordinary_projection().expect("ordinary branch");
        assert_eq!(content.notification_kind, OrdinaryNotificationKind::Message);
        assert!(delta.agent_runtime_approval().is_none());
        delta.verify_recipient_binding(&kat_recipient()).unwrap();

        let other_station = AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        );
        assert!(delta.verify_recipient_binding(&other_station).is_err());
        assert_eq!(
            serde_json::to_value(&delta).unwrap(),
            ordinary_delta("upsert", ordinary_content())
        );
    }

    #[test]
    fn ordinary_row_refuses_inbox_state_and_identity_members() {
        for forbidden in ["id", "schema", "actor_id", "state"] {
            let mut content = ordinary_content();
            content[forbidden] = json!("unread");
            assert!(
                serde_json::from_value::<NotificationDelta>(ordinary_delta("upsert", content))
                    .is_err(),
                "{forbidden}"
            );
        }
        let mut agent_kind = ordinary_content();
        agent_kind["notification_kind"] = json!("agent");
        assert!(
            serde_json::from_value::<NotificationDelta>(ordinary_delta("upsert", agent_kind))
                .is_err()
        );
        let mut invite_kind = ordinary_content();
        invite_kind["notification_kind"] = json!("invite");
        assert!(
            serde_json::from_value::<NotificationDelta>(ordinary_delta("upsert", invite_kind))
                .is_err()
        );
    }

    #[test]
    fn removal_vocabularies_do_not_cross_branches() {
        let delta: NotificationDelta =
            serde_json::from_value(ordinary_delta("remove", json!({"reason": "expired"}))).unwrap();
        assert_eq!(
            delta.ordinary_removal_reason(),
            Some(OrdinaryNotificationRemovalReason::Expired)
        );
        assert!(delta.agent_runtime_approval_removal_reason().is_none());

        // `approved` is an Agent-only reason and `access_revoked` an ordinary
        // one; the shared `expired` / `superseded` values are exactly why the
        // branch cannot be chosen by trying both data shapes.
        assert!(
            serde_json::from_value::<NotificationDelta>(ordinary_delta(
                "remove",
                json!({"reason": "approved"})
            ))
            .is_err()
        );
        let mut agent_remove = approval_delta("remove");
        agent_remove["data"] = json!({"reason": "access_revoked"});
        assert!(serde_json::from_value::<NotificationDelta>(agent_remove).is_err());

        // An ordinary remove carries no optional data: the reason is required.
        let mut bare = ordinary_delta("remove", json!({}));
        bare.as_object_mut().unwrap().remove("data");
        assert!(serde_json::from_value::<NotificationDelta>(bare).is_err());
    }

    #[test]
    fn branch_data_cannot_be_delivered_under_the_other_id_form() {
        let mut approval_under_projection = approval_delta("upsert");
        approval_under_projection["id"] = json!(KAT_PROJECTION);
        assert!(serde_json::from_value::<NotificationDelta>(approval_under_projection).is_err());

        let mut ordinary_under_approval = ordinary_delta("upsert", ordinary_content());
        ordinary_under_approval["id"] =
            json!("ak:notification:01964137-0000-7000-8000-000000000001");
        assert!(serde_json::from_value::<NotificationDelta>(ordinary_under_approval).is_err());
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
/// A Agent runtime is not a human device:
/// It cannot be represented as an `ak:device`, so the endpoint is a closed XOR
/// rather than an `Option<DeviceId>` a producer could fill with a principal id.
///
/// The Agent branch carries the signer evidence the device branch gets from
/// the accepted device projection: without `sender_agent_verification_method`
/// and `sender_agent_key_authorize_event_id` a receiver would hold an Agent
/// principal id and no way to say which key currently speaks for it.
///
/// The Service branch is narrower: only the recipient Station's
/// internal actor-private materializer may produce it. Envelope validation
/// additionally requires an actor-private update kind and equal sender /
/// recipient principal ids.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DeviceMessageSender {
    Device {
        sender_account_id: AccountId,
        sender_device_id: DeviceId,
    },
    Agent {
        sender_agent_id: DidCoreId,
        sender_agent_verification_method: DidUrl,
        sender_agent_key_authorize_event_id: EventId,
    },
    Service {
        sender_id: DidCoreId,
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
    sender_account_id: Option<AccountId>,
    #[serde(default)]
    sender_device_id: Option<DeviceId>,
    #[serde(default)]
    sender_agent_id: Option<DidCoreId>,
    #[serde(default)]
    sender_agent_verification_method: Option<DidUrl>,
    #[serde(default)]
    sender_agent_key_authorize_event_id: Option<EventId>,
    #[serde(default)]
    sender_id: Option<DidCoreId>,
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
            wire.sender_account_id,
            wire.sender_device_id,
            wire.sender_agent_id,
            wire.sender_agent_verification_method,
            wire.sender_agent_key_authorize_event_id,
            wire.sender_id,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl DeviceMessageSender {
    /// Select the endpoint branch from the six wire slots, or reject.
    ///
    /// Exactly one complete branch is legal. A half-filled Agent branch, or a
    /// device id beside an Agent id, would let a producer carry a second
    /// unauthenticated sender identity past the rule that an Agent is never
    /// spelled as an `ak:device`.
    pub fn from_slots(
        sender_account_id: Option<AccountId>,
        sender_device_id: Option<DeviceId>,
        sender_agent_id: Option<DidCoreId>,
        sender_agent_verification_method: Option<DidUrl>,
        sender_agent_key_authorize_event_id: Option<EventId>,
        sender_id: Option<DidCoreId>,
    ) -> std::result::Result<Self, &'static str> {
        match (
            sender_account_id,
            sender_device_id,
            sender_agent_id,
            sender_agent_verification_method,
            sender_agent_key_authorize_event_id,
            sender_id,
        ) {
            (Some(sender_account_id), Some(sender_device_id), None, None, None, None) => {
                Ok(Self::Device {
                    sender_account_id,
                    sender_device_id,
                })
            }
            (
                None,
                None,
                Some(sender_agent_id),
                Some(sender_agent_verification_method),
                Some(sender_agent_key_authorize_event_id),
                None,
            ) => Ok(Self::Agent {
                sender_agent_id,
                sender_agent_verification_method,
                sender_agent_key_authorize_event_id,
            }),
            (None, None, None, None, None, Some(sender_id)) => Ok(Self::Service { sender_id }),
            _ => Err(
                "device message sender must contain exactly one complete device, Agent, or Service branch",
            ),
        }
    }

    /// The endpoint half of the receiver dedupe key.
    ///
    /// `device-message.schema.json` keys deduplication on
    /// The device branch additionally binds the exact sender AccountId; Agent
    /// and Station branches use their branch-specific identity directly.
    pub fn endpoint_id(&self) -> &str {
        match self {
            Self::Device {
                sender_device_id, ..
            } => sender_device_id.as_str(),
            Self::Agent {
                sender_agent_id, ..
            } => sender_agent_id.as_str(),
            Self::Service { sender_id } => sender_id.as_str(),
        }
    }

    /// The authoring device, when the sender is one.
    pub fn device_id(&self) -> Option<&DeviceId> {
        match self {
            Self::Device {
                sender_device_id, ..
            } => Some(sender_device_id),
            Self::Agent { .. } | Self::Service { .. } => None,
        }
    }

    /// The Station materializer, when this is the restricted service
    /// branch.
    pub fn service_id(&self) -> Option<&DidCoreId> {
        match self {
            Self::Service { sender_id } => Some(sender_id),
            Self::Device { .. } | Self::Agent { .. } => None,
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
    #[serde(flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub sender: DeviceMessageSender,
    pub recipient_account_id: AccountId,
    pub recipient_device_id: DeviceId,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub sent_at: DateTime<Utc>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub content: DeviceMessageContent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<BTreeMap<String, Value>>,
}

/// Closed typed content for every registered device-message kind. Unregistered
/// `ak.*` extension kinds use the explicitly named extension branch.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum DeviceMessageContent {
    KeyVerification(Box<KeyVerificationContent>),
    SecretRequest(SecretShareRequestContent),
    SecretSend(SecretShareSendContent),
    AccountDataUpdate(ActorPrivateAccountDataUpdate),
    BlocklistUpdate(ActorPrivateAccountDataUpdate),
    ReadCursorUpdate(ActorPrivateReadCursorUpdate),
    Extension(BTreeMap<String, Value>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceMessageEnvelopeWire {
    device_message_id: DeviceMessageId,
    kind: ProtocolKind,
    #[serde(default)]
    sender_account_id: Option<AccountId>,
    #[serde(default)]
    sender_device_id: Option<DeviceId>,
    #[serde(default)]
    sender_agent_id: Option<DidCoreId>,
    #[serde(default)]
    sender_agent_verification_method: Option<DidUrl>,
    #[serde(default)]
    sender_agent_key_authorize_event_id: Option<EventId>,
    #[serde(default)]
    sender_id: Option<DidCoreId>,
    recipient_account_id: AccountId,
    recipient_device_id: DeviceId,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    sent_at: DateTime<Utc>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    content: Value,
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
            wire.sender_account_id,
            wire.sender_device_id,
            wire.sender_agent_id,
            wire.sender_agent_verification_method,
            wire.sender_agent_key_authorize_event_id,
            wire.sender_id,
        )
        .map_err(serde::de::Error::custom)?;
        if let DeviceMessageSender::Service { sender_id } = &sender {
            if sender_id != &wire.recipient_account_id.station_id {
                return Err(serde::de::Error::custom(
                    "service device message sender_id must equal recipient_account_id.station_id",
                ));
            }
            if ActorPrivateUpdateKind::from_wire(wire.kind.as_str()).is_none() {
                return Err(serde::de::Error::custom(
                    "service device message sender is restricted to actor-private update kinds",
                ));
            }
        }
        let content = decode_device_message_content(&wire.kind, wire.content)
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            device_message_id: wire.device_message_id,
            kind: wire.kind,
            sender,
            recipient_account_id: wire.recipient_account_id,
            recipient_device_id: wire.recipient_device_id,
            sent_at: wire.sent_at,
            expires_at: wire.expires_at,
            content,
            unsigned: wire.unsigned,
        })
    }
}

pub fn decode_device_message_content(
    kind: &ProtocolKind,
    content: Value,
) -> Result<DeviceMessageContent> {
    fn decode<T: serde::de::DeserializeOwned>(content: Value) -> Result<T> {
        serde_json::from_value(content).map_err(WireError::from)
    }
    let value = match kind.as_str() {
        "ak.secret.request" => {
            let value: SecretShareRequestContent = decode(content)?;
            value.validate()?;
            DeviceMessageContent::SecretRequest(value)
        }
        "ak.secret.send" => {
            let value: SecretShareSendContent = decode(content)?;
            value.validate()?;
            DeviceMessageContent::SecretSend(value)
        }
        "ak.account_data.update" => DeviceMessageContent::AccountDataUpdate(decode(content)?),
        "ak.account.blocklist.update" => DeviceMessageContent::BlocklistUpdate(decode(content)?),
        "ak.read_cursor.update" => DeviceMessageContent::ReadCursorUpdate(decode(content)?),
        kind if kind.starts_with("ak.key.verification.") => {
            let value: KeyVerificationContent = decode(content)?;
            validate_key_verification_content(kind, &value)?;
            DeviceMessageContent::KeyVerification(Box::new(value))
        }
        _ => DeviceMessageContent::Extension(decode(content)?),
    };
    Ok(value)
}

fn validate_key_verification_content(kind: &str, value: &KeyVerificationContent) -> Result<()> {
    let present = match kind {
        "ak.key.verification.request" => {
            value.methods.is_some() && value.timestamp.is_some() && value.expires_at.is_some()
        }
        "ak.key.verification.ready" => value.methods.is_some(),
        "ak.key.verification.start" => value.method.is_some(),
        "ak.key.verification.accept" => value.commitment.is_some(),
        "ak.key.verification.key" => value.key.is_some(),
        "ak.key.verification.mac" => value.mac.is_some() && value.keys.is_some(),
        "ak.key.verification.done" => true,
        "ak.key.verification.cancel" => value.code.is_some(),
        _ => false,
    };
    if present {
        Ok(())
    } else {
        Err(WireError::Protocol(format!(
            "{kind} content is missing required fields"
        )))
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
    pub changed_ids: Vec<ActorId>,
    pub left_ids: Vec<ActorId>,
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
    pub cell_id: String,
    pub issuer_id: DidCoreId,
    pub issuer_seq: u64,
    pub reason: String,
    pub event_ids: Vec<EventId>,
    pub event_digests: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowStartActorProfile {
    pub actor_id: ActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
}

impl CanonicalIdentityEntry for WindowStartActorProfile {
    type Identity = ActorId;
    fn identity(&self) -> &ActorId {
        &self.actor_id
    }
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
    #[serde(
        deserialize_with = "arkret_wire::deserialize_identity_entries",
        serialize_with = "arkret_wire::serialize_identity_entries"
    )]
    pub actor_profiles: Vec<WindowStartActorProfile>,
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
    pub hero_ids: Option<Vec<ActorId>>,
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
pub struct MemberRoster {
    pub entries: Vec<MemberRosterEntry>,
    pub limited: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSyncEventState {
    pub event_id: EventId,
    pub event_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_state_reason_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSyncBottom {
    pub cell_id: String,
    pub status: String,
    pub bottom: Bottom,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSyncEntry {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub timeline: Option<Timeline>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub timeline_baseline: Option<super::demand_sync::RealmTimelineBaseline>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub state_at_window_start: Option<StateAtWindowStart>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub current: Option<super::current_results::CurrentEntries>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub account_data: Option<EventContainer>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub summary: Option<AccountSubscribeRealmSummary>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub member_roster: Option<MemberRoster>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub unread_notifications: Option<AccountSubscribeUnreadCounts>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub event_states: Option<Vec<RealmSyncEventState>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub bottoms: Option<Vec<RealmSyncBottom>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub baseline: Option<super::demand_sync::RealmDetailBaseline>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub unavailable: Option<super::demand_sync::RealmDetailUnavailable>,
}

impl RealmSyncEntry {
    pub fn validate_demand(&self) -> Result<()> {
        use super::demand_sync::{demand_error, validate_demand_cursor};
        if let Some(baseline) = &self.baseline {
            validate_demand_cursor(baseline.snapshot_cursor.as_str())?;
            super::current_results::validate_current_revision(baseline.cut_revision)?;
            baseline.coverage.validate()?;
        }
        if let Some(current) = &self.current {
            current.validate()?;
            if let Some(baseline) = &self.baseline {
                for entry in &current.entries {
                    if entry.revision() > baseline.cut_revision
                        || !baseline.coverage.covers(entry.selector(), entry.target())
                    {
                        return Err(demand_error(
                            "Current baseline entry exceeds its cut or coverage",
                        ));
                    }
                }
            }
        }
        if let Some(timeline_baseline) = &self.timeline_baseline {
            timeline_baseline.validate()?;
            // A frozen window segment is only readable together with the
            // container it fragments: without `timeline` a client cannot tell a
            // zero-item window from an undelivered one, which is the gap this
            // carrier exists to close.
            if self.timeline.is_none() {
                return Err(demand_error(
                    "Timeline baseline requires its timeline container",
                ));
            }
        }
        if self.unavailable.is_some()
            && (self.timeline.is_some()
                || self.timeline_baseline.is_some()
                || self.state_at_window_start.is_some()
                || self.current.is_some()
                || self.account_data.is_some()
                || self.summary.is_some()
                || self.member_roster.is_some()
                || self.unread_notifications.is_some()
                || self.event_states.is_some()
                || self.bottoms.is_some()
                || self.baseline.is_some())
        {
            return Err(demand_error(
                "Unavailable Realm entries cannot carry detail data",
            ));
        }
        for container in [&self.account_data].into_iter().flatten() {
            if container.events.len() > 100 {
                return Err(demand_error("Realm state exceeds 100 Events"));
            }
        }
        if self
            .timeline
            .as_ref()
            .is_some_and(|timeline| timeline.events.len() > 100)
            || self
                .member_roster
                .as_ref()
                .is_some_and(|roster| roster.entries.len() > 100)
        {
            return Err(demand_error("Realm timeline or roster exceeds 100 items"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeviceMessagesSendRequestBody {
    /// Station-addressed device queue coordinates, as defined by
    /// device-lifecycle section 10.2; not an ActorId-keyed JSON object.
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

/// Read-cursor delta carried inside an actor-private device update
/// (`ak.read_cursor.update`, spec
/// `device-message.schema.json#/$defs/read_cursor_update_content`).
///
/// `schema` is `ak.schema.read_cursor_update.v1`
/// (`SchemaId::READ_CURSOR_UPDATE_V1`), NOT `ak.schema.read_cursor.v1`: this
/// is the Station's derived projection of the advance that currently wins the
/// causal-first merge for one `(actor_id, realm_id, read_scope)`, and its
/// `updated_at` is that winning advance's envelope `created_at`. The payload
/// object it derives from has neither an id nor an `updated_at`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorPrivateReadCursorUpdate {
    pub schema: String,
    pub actor_id: ActorId,
    pub device_id: DeviceId,
    pub realm_id: RealmId,
    pub read_scope: ReadCursorScope,
    pub position: crate::objects::read_receipts::ReadCursorPosition,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

/// Self-describing actor-private update envelope. The wire `type` tag and its
/// content shape cannot be constructed independently. Its sender is the same
/// closed flattened XOR as [`DeviceMessageEnvelope`], because Station
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
        sender_account_id: Option<AccountId>,
        #[serde(default)]
        sender_device_id: Option<DeviceId>,
        #[serde(default)]
        sender_agent_id: Option<DidCoreId>,
        #[serde(default)]
        sender_agent_verification_method: Option<DidUrl>,
        #[serde(default)]
        sender_agent_key_authorize_event_id: Option<EventId>,
        #[serde(default)]
        sender_id: Option<DidCoreId>,
        content: ActorPrivateAccountDataUpdate,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        created_at: DateTime<Utc>,
    },
    #[serde(rename = "ak.account.blocklist.update")]
    Blocklist {
        #[serde(default)]
        sender_account_id: Option<AccountId>,
        #[serde(default)]
        sender_device_id: Option<DeviceId>,
        #[serde(default)]
        sender_agent_id: Option<DidCoreId>,
        #[serde(default)]
        sender_agent_verification_method: Option<DidUrl>,
        #[serde(default)]
        sender_agent_key_authorize_event_id: Option<EventId>,
        #[serde(default)]
        sender_id: Option<DidCoreId>,
        content: ActorPrivateAccountDataUpdate,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        created_at: DateTime<Utc>,
    },
    #[serde(rename = "ak.read_cursor.update")]
    ReadCursor {
        #[serde(default)]
        sender_account_id: Option<AccountId>,
        #[serde(default)]
        sender_device_id: Option<DeviceId>,
        #[serde(default)]
        sender_agent_id: Option<DidCoreId>,
        #[serde(default)]
        sender_agent_verification_method: Option<DidUrl>,
        #[serde(default)]
        sender_agent_key_authorize_event_id: Option<EventId>,
        #[serde(default)]
        sender_id: Option<DidCoreId>,
        content: ActorPrivateReadCursorUpdate,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        created_at: DateTime<Utc>,
    },
}

impl ActorPrivateDeviceUpdateWire {
    fn sender(
        sender_account_id: Option<AccountId>,
        sender_device_id: Option<DeviceId>,
        sender_agent_id: Option<DidCoreId>,
        sender_agent_verification_method: Option<DidUrl>,
        sender_agent_key_authorize_event_id: Option<EventId>,
        sender_id: Option<DidCoreId>,
    ) -> std::result::Result<DeviceMessageSender, &'static str> {
        DeviceMessageSender::from_slots(
            sender_account_id,
            sender_device_id,
            sender_agent_id,
            sender_agent_verification_method,
            sender_agent_key_authorize_event_id,
            sender_id,
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
                sender_account_id,
                sender_device_id,
                sender_agent_id,
                sender_agent_verification_method,
                sender_agent_key_authorize_event_id,
                sender_id,
                content,
                created_at,
            } => Ok(Self::AccountData {
                sender: ActorPrivateDeviceUpdateWire::sender(
                    sender_account_id,
                    sender_device_id,
                    sender_agent_id,
                    sender_agent_verification_method,
                    sender_agent_key_authorize_event_id,
                    sender_id,
                )
                .map_err(serde::de::Error::custom)?,
                content,
                created_at,
            }),
            ActorPrivateDeviceUpdateWire::Blocklist {
                sender_account_id,
                sender_device_id,
                sender_agent_id,
                sender_agent_verification_method,
                sender_agent_key_authorize_event_id,
                sender_id,
                content,
                created_at,
            } => Ok(Self::Blocklist {
                sender: ActorPrivateDeviceUpdateWire::sender(
                    sender_account_id,
                    sender_device_id,
                    sender_agent_id,
                    sender_agent_verification_method,
                    sender_agent_key_authorize_event_id,
                    sender_id,
                )
                .map_err(serde::de::Error::custom)?,
                content,
                created_at,
            }),
            ActorPrivateDeviceUpdateWire::ReadCursor {
                sender_account_id,
                sender_device_id,
                sender_agent_id,
                sender_agent_verification_method,
                sender_agent_key_authorize_event_id,
                sender_id,
                content,
                created_at,
            } => Ok(Self::ReadCursor {
                sender: ActorPrivateDeviceUpdateWire::sender(
                    sender_account_id,
                    sender_device_id,
                    sender_agent_id,
                    sender_agent_verification_method,
                    sender_agent_key_authorize_event_id,
                    sender_id,
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
    pub sender_account_id: AccountId,
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
            sender_account_id: &'a AccountId,
            sender_device_id: &'a str,
            #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
            expires_at: DateTime<Utc>,
            content: &'a crate::events_payloads::MlsWelcomePayload,
            unsigned: &'a MlsWelcomeProjectionBinding,
        }
        Wire {
            kind: EventKind::MlsWelcome,
            sender_account_id: &self.sender_account_id,
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
#[serde(deny_unknown_fields)]
pub struct DeviceMessagesSendOutcome {
    pub delivered: BTreeMap<String, Value>,
    pub unknown_devices: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
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
    pub pruned_count: u64,
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
            "content": {
                "transaction_id": "txn",
                "from_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "methods": ["ak.key.verification.sas_v1"],
                "timestamp": "2026-07-15T00:00:00.000Z",
                "expires_at": "2026-07-15T00:10:00.000Z"
            },
            "expires_at": "2026-07-15T01:00:00.000Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(valid).is_ok());

        let missing_device_message_id = json!({
            "kind": "ak.key.verification.request",
            "content": {
                "transaction_id": "txn",
                "from_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "methods": ["ak.key.verification.sas_v1"],
                "timestamp": "2026-07-15T00:00:00.000Z",
                "expires_at": "2026-07-15T00:10:00.000Z"
            },
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
            "sender_account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:webvh:z6mkfixtureservice"
            },
            "sender_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "recipient_account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:webvh:z6mkfixtureservice"
            },
            "recipient_device_id": "ak:device:01904100-0000-7000-8000-000000000002",
            "sent_at": "2026-07-15T00:00:00.000Z",
            "expires_at": "2026-07-15T00:10:00.000Z",
            "content": {
                "transaction_id": "txn",
                "from_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "methods": ["ak.key.verification.sas_v1"],
                "timestamp": "2026-07-15T00:00:00.000Z",
                "expires_at": "2026-07-15T00:10:00.000Z"
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
            "sender_id": "ak:did_core:webvh:z6mkfixtureservice"
        })
    }

    /// The two sender endpoints are one closed XOR: an Agent has no
    /// device identity and MUST NOT be spelled as one, and its branch is only
    /// usable complete — an Agent principal id without the key that currently
    /// speaks for it is not an authenticatable sender.
    /// A derived `untagged` deserializer picks the first variant that fits, so
    /// a device id beside a complete Agent triple would parse as the device and
    /// silently drop the Agent identity. This pins that it does not.
    #[test]
    fn a_sender_carrying_both_branches_is_rejected_not_narrowed() {
        let both = json!({
            "sender_account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:webvh:z6mkfixtureservice"
            },
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
                "sender_account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixture",
                    "station_id": "ak:did_core:webvh:z6mkfixtureservice"
                },
                "sender_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "sender_id": "ak:did_core:webvh:z6mkfixtureservice"
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
                "sender_account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixture",
                    "station_id": "ak:did_core:webvh:z6mkfixtureservice"
                },
                "sender_device_id": "ak:device:01904100-0000-7000-8000-000000000001"
            }))
            .is_ok()
        );
    }

    #[test]
    fn device_message_sender_endpoint_is_a_closed_xor() {
        let mut agent = envelope_value();
        agent.as_object_mut().unwrap().remove("sender_account_id");
        agent.as_object_mut().unwrap().remove("sender_device_id");
        for (key, value) in agent_sender_fields().as_object().unwrap() {
            agent
                .as_object_mut()
                .unwrap()
                .insert(key.clone(), value.clone());
        }
        serde_json::from_value::<DeviceMessageEnvelope>(agent.clone()).expect("agent envelope");

        let mut both = agent.clone();
        both.as_object_mut().unwrap().insert(
            "sender_device_id".to_owned(),
            json!("ak:device:01904100-0000-7000-8000-000000000001"),
        );
        assert!(
            serde_json::from_value::<DeviceMessageEnvelope>(both).is_err(),
            "an Agent sender must not also carry a device id"
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
            .remove("sender_account_id");
        no_endpoint
            .as_object_mut()
            .unwrap()
            .remove("sender_device_id");
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(no_endpoint).is_err());

        let mut service = envelope_value();
        service.as_object_mut().unwrap().remove("sender_account_id");
        service.as_object_mut().unwrap().remove("sender_device_id");
        service["kind"] = json!(ActorPrivateUpdateKind::ACCOUNT_DATA_UPDATE);
        service["content"] = json!({
            "operation": "put",
            "account_data_key": "ak.account.invite_delivery",
            "revision": 1,
            "content": {},
            "updated_at": "2026-07-15T00:00:00.000Z"
        });
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
        cross_principal_service["recipient_account_id"]["station_id"] =
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
            "sender_id": "ak:did_core:webvh:z6mkfixtureservice",
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
        half_agent.as_object_mut().unwrap().remove("sender_id");
        half_agent["sender_agent_id"] = json!("ak:did_core:webvh:z6mkfixtureagent");
        assert!(
            serde_json::from_value::<ActorPrivateDeviceUpdate>(half_agent).is_err(),
            "actor-private update cannot carry a half-filled Agent sender"
        );
    }

    #[test]
    fn device_message_envelope_enforces_closed_object_shape_and_expiry_order() {
        serde_json::from_value::<DeviceMessageEnvelope>(envelope_value()).expect("device envelope");

        let mut expired = envelope_value();
        expired["expires_at"] = expired["sent_at"].clone();
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(expired).is_err());

        let mut scalar_content = envelope_value();
        scalar_content["content"] = json!("not an object");
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(scalar_content).is_err());

        let mut unknown_root_field = envelope_value();
        unknown_root_field["unexpected"] = json!(true);
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(unknown_root_field).is_err());

        let mut incomplete_known_content = envelope_value();
        incomplete_known_content["content"] = json!({
            "transaction_id": "txn",
            "from_device_id": "ak:device:01904100-0000-7000-8000-000000000001"
        });
        assert!(serde_json::from_value::<DeviceMessageEnvelope>(incomplete_known_content).is_err());

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
    Knock,
}

/// R3.2 roster v2 — Lightweight per-actor entry on the Realm members
/// roster projection carried by `account.subscribe` frames.
///
/// Entries MUST NOT carry display name or naked handle strings directly;
/// handle strings may appear only inside signed `HandleClaim` objects in
/// [`Self::handle_claims`]. The disclosure-gated fields (`identity_events`,
/// `handle_claim_digests`, `handle_claims`, `handle_claims_limited`) MUST
/// be omitted unless [`Self::subject_account_id`] is disclosed — enforced by
/// [`Self::validate`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberRosterEntry {
    pub actor_id: ActorId,
    pub membership: MembershipState,
    /// Disclosed exact account identity for this member. Required whenever
    /// any handle-claim / identity-event evidence is included (see
    /// [`Self::validate`]). Omitted when subject disclosure is not
    /// authorized for the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_account_id: Option<AccountId>,
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
        if gated_present && self.subject_account_id.is_none() {
            return Err(WireError::Protocol(
                "member_roster_entry: identity_events / handle_claim_digests / handle_claims / \
                 handle_claims_limited require subject_account_id disclosure"
                    .to_owned(),
            ));
        }
        if let (Some(subject), Some(claims)) = (&self.subject_account_id, &self.handle_claims) {
            for claim in claims {
                if &claim.claim.subject_account_id != subject {
                    return Err(WireError::Protocol(
                        "member_roster_entry: handle_claims[].subject_account_id must equal subject_account_id"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_actor(label: &str) -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(format!("ak:did_core:webvh:z6mkfixture{label}")).unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureserver").unwrap(),
        ))
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
            subject_account_id: None,
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
    fn member_roster_uses_nested_collection_boundary() {
        let raw = serde_json::json!({
            "entries": [],
            "limited": true,
            "next_cursor": "ak:cursor:roster-page-2"
        });
        let roster: MemberRoster = serde_json::from_value(raw.clone()).unwrap();
        assert!(roster.entries.is_empty());
        assert!(roster.limited);
        assert_eq!(
            roster.next_cursor.as_deref(),
            Some("ak:cursor:roster-page-2")
        );
        assert_eq!(serde_json::to_value(roster).unwrap(), raw);
    }

    #[test]
    fn member_roster_entry_gated_fields_require_subject_id() {
        // handle_claims_limited present without subject_id MUST fail.
        let entry = MemberRosterEntry {
            actor_id: fake_actor("alice"),
            membership: MembershipState::Join,
            subject_account_id: None,
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

    #[test]
    fn member_roster_entry_rejects_invite_lifecycle_as_membership() {
        let raw = serde_json::json!({
            "actor_id": fake_actor("alice"),
            "membership": "invite"
        });
        assert!(serde_json::from_value::<MemberRosterEntry>(raw).is_err());
    }

    #[test]
    fn device_message_outcomes_reject_unknown_fields() {
        let send = serde_json::json!({
            "ok": true,
            "unexpected": 42
        });
        let send_error = serde_json::from_value::<DeviceMessagesSendOutcome>(send).unwrap_err();
        assert!(send_error.to_string().contains("unknown field"));

        let get = serde_json::json!({
            "messages": [],
            "has_more": false,
            "unexpected": 42
        });
        let get_error = serde_json::from_value::<DeviceMessagesGetOutcome>(get).unwrap_err();
        assert!(get_error.to_string().contains("unknown field"));
    }

    #[test]
    fn window_profiles_are_sorted_by_full_actor_and_reject_duplicate_identity() {
        let actor = |station: &str| {
            serde_json::json!({
                "kind": "account", "account_id": {
                    "principal_id": "ak:did_core:web:alice.example", "station_id": station
                }
            })
        };
        let mut value = serde_json::json!({
            "actor_profiles": [
                {"actor_id": actor("ak:did_core:web:a.example"), "display_name": "Alice A"},
                {"actor_id": actor("ak:did_core:web:b.example"), "display_name": "Alice B"}
            ],
            "realm_metadata": {}, "e2ee_epoch": null
        });
        let state: StateAtWindowStart = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(state).unwrap(), value);
        value["actor_profiles"].as_array_mut().unwrap().reverse();
        assert!(serde_json::from_value::<StateAtWindowStart>(value.clone()).is_err());
        value["actor_profiles"][1]["actor_id"] = value["actor_profiles"][0]["actor_id"].clone();
        assert!(serde_json::from_value::<StateAtWindowStart>(value.clone()).is_err());
        value["actor_profiles"] = serde_json::json!({"ak:did_core:web:alice.example": {}});
        assert!(serde_json::from_value::<StateAtWindowStart>(value).is_err());
    }
}
