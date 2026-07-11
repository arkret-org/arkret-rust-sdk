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

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/did_url`.
pub type DidUrl = String;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/display_name`.
pub type DisplayName = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/handle_claim_digests`.
pub type HandleClaimDigests = Vec<Hash>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/handle_claim_ref`.
pub type HandleClaimRef = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/non_empty_string`.
pub type NonEmptyString = String;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/profile_patch`.
pub type ProfilePatch = Patch;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/sha256_digest`.
pub type Sha256Digest = Hash;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/timestamp`.
pub type Timestamp = DateTime<Utc>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/
/// cursor_or_data_or_control_payload_present`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CursorOrDataOrControlPayloadPresentCursor {
    pub cursor: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CursorOrDataOrControlPayloadPresent {
    Cursor(CursorOrDataOrControlPayloadPresentCursor),
    DataOrControlPayloadPresent(DataOrControlPayloadPresent),
    ReconnectAfterPresent(ReconnectAfterPresent),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/
/// cursor_or_data_payload_present`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CursorOrDataPayloadPresentCursor {
    pub cursor: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CursorOrDataPayloadPresent {
    Cursor(CursorOrDataPayloadPresentCursor),
    DataOrControlPayloadPresent(DataOrControlPayloadPresent),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/cursor_value`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CursorValue {
    Variant0(crate::Cursor),
    Cursor(crate::Cursor),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/
/// data_or_control_payload_present`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataOrControlPayloadPresentRealms {
    pub realms: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataOrControlPayloadPresentToDevice {
    pub to_device: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataOrControlPayloadPresentDeviceLists {
    pub device_lists: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataOrControlPayloadPresentAccountData {
    pub account_data: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataOrControlPayloadPresentPresence {
    pub presence: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataOrControlPayloadPresentNotifications {
    pub notifications: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataOrControlPayloadPresentPartial {
    pub partial: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataOrControlPayloadPresentPriority {
    pub priority: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DataOrControlPayloadPresent {
    Realms(DataOrControlPayloadPresentRealms),
    ToDevice(DataOrControlPayloadPresentToDevice),
    DeviceLists(DataOrControlPayloadPresentDeviceLists),
    AccountData(DataOrControlPayloadPresentAccountData),
    Presence(DataOrControlPayloadPresentPresence),
    Notifications(DataOrControlPayloadPresentNotifications),
    Partial(DataOrControlPayloadPresentPartial),
    Priority(DataOrControlPayloadPresentPriority),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/device_message_container`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DeviceMessage {
    pub kind: String,
    pub sender_principal_id: Value,
    pub sender_device_id: String,
    pub recipient_principal_id: Value,
    pub recipient_device_id: String,
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
/// `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/realm_sync_entry`.
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

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/reconnect_after_present`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReconnectAfterPresent {
    pub reconnect_after_ms: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}
