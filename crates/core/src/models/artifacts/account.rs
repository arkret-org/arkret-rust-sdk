//! Account and sync schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccountOperations {
    AccountView(AccountView),
    AccountRegisterRequestBody(AccountRegisterRequestBody),
    AccountRegisterOutcome(AccountRegisterOutcome),
    AccountUpdateProfileRequestBody(AccountUpdateProfileRequestBody),
    AccountUpdateProfileOutcome(AccountUpdateProfileOutcome),
    SessionRevokeRequestBody(SessionRevokeRequestBody),
    SessionRevokeOutcome(SessionRevokeOutcome),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/account_registration_audit`.
pub type AccountRegistrationAuditDto = AccountRegistrationAudit;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/
/// account_registration_audit_outcome`.
pub type AccountRegistrationAuditOutcomeDto = AccountRegistrationAuditOutcome;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/
/// account_registration_evidence_summary`.
pub type AccountRegistrationEvidenceSummaryDto = AccountRegistrationEvidenceSummary;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/
/// account_registration_invitation_policy`.
pub type AccountRegistrationInvitationPolicyDto = AccountRegistrationInvitationPolicy;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/account_registration_policy`.
pub type AccountRegistrationPolicyDto = AccountRegistrationPolicy;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/
/// account_registration_policy_evidence`.
pub type AccountRegistrationPolicyEvidenceDto = AccountRegistrationPolicyEvidence;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/
/// account_registration_rate_limit_policy`.
pub type AccountRegistrationRateLimitPolicyDto = AccountRegistrationRateLimitPolicy;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/
/// account_registration_verification_policy`.
pub type AccountRegistrationVerificationPolicyDto = AccountRegistrationVerificationPolicy;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/device_summaries`.
pub type DeviceSummaries = Vec<DeviceSummary>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/device_summary`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSummary {
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<DisplayName>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<Timestamp>,
}

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/display_name`.
pub type DisplayName = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/handle_claim_digests`.
pub type HandleClaimDigests = Vec<Hash>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/handle_claim_ref`.
pub type HandleClaimRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/profile_patch`.
pub type ProfilePatch = Patch;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/sha256_digest`.
pub type Sha256Digest = Hash;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/timestamp`.
pub type Timestamp = DateTime<Utc>;

/// Closed action set for account notification projection deltas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NotificationDeltaAction {
    Add,
    Update,
    Remove,
}

/// Closed notification data discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccountNotificationDataKind {
    AgentRuntimeApproval,
}

/// Account-private Agent runtime approval projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalNotificationData {
    pub kind: AccountNotificationDataKind,
    pub approval_request_id: String,
    pub agent_id: Did,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Closed terminal reasons for an Agent runtime approval notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalNotificationRemovalData {
    pub kind: AccountNotificationDataKind,
    pub reason: AgentRuntimeApprovalRemovalReason,
}

/// Closed data branches for account notification deltas.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum NotificationData {
    AgentRuntimeApproval(AgentRuntimeApprovalNotificationData),
    AgentRuntimeApprovalRemoval(AgentRuntimeApprovalNotificationRemovalData),
}

/// Strongly typed account notification projection delta.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct NotificationDelta {
    pub id: NotificationId,
    #[serde(rename = "type")]
    pub notification_type: NotificationType,
    pub action: NotificationDeltaAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<NotificationData>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationDeltaWire {
    id: NotificationId,
    #[serde(rename = "type")]
    notification_type: NotificationType,
    action: NotificationDeltaAction,
    #[serde(default)]
    data: Option<NotificationData>,
}

impl<'de> Deserialize<'de> for NotificationDelta {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = NotificationDeltaWire::deserialize(deserializer)?;
        if wire.notification_type != NotificationType::Agent {
            return Err(serde::de::Error::custom(
                "account notification delta type must be agent",
            ));
        }
        match (wire.action, wire.data.as_ref()) {
            (
                NotificationDeltaAction::Add | NotificationDeltaAction::Update,
                Some(NotificationData::AgentRuntimeApproval(_)),
            )
            | (
                NotificationDeltaAction::Remove,
                None | Some(NotificationData::AgentRuntimeApprovalRemoval(_)),
            ) => {}
            (NotificationDeltaAction::Add | NotificationDeltaAction::Update, _) => {
                return Err(serde::de::Error::custom(
                    "notification add/update requires agent_runtime_approval data",
                ));
            }
            (NotificationDeltaAction::Remove, _) => {
                return Err(serde::de::Error::custom(
                    "notification remove data must contain only a terminal reason",
                ));
            }
        }
        Ok(Self {
            id: wire.id,
            notification_type: wire.notification_type,
            action: wire.action,
            data: wire.data,
        })
    }
}

/// Dedicated notification container for account subscribe.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct NotificationContainer {
    pub items: Vec<NotificationDelta>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/device-message.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DeviceMessage {
    pub kind: NonEmptyString,
    pub sender_principal_id: Did,
    pub sender_device_id: DeviceId,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub sent_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub content: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_proof: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceMessageContainer {
    pub messages: Vec<DeviceMessage>,
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
    pub events: Vec<EventEnvelope>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountSubscribeDeviceListChanges {
    pub changed: Vec<Did>,
    pub left: Vec<Did>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/timeline`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Timeline {
    pub events: Vec<EventEnvelope>,
    pub limited: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_only: Option<bool>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSubscribeRealmSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_member_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invited_member_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heroes: Option<Vec<Did>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub bottom: crate::Bottom,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub ephemeral: Option<EventContainer>,
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
