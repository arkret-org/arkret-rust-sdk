use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone};
use chrono_tz::Tz;
use unicode_normalization::UnicodeNormalization;

use super::*;
use crate::base64url_encode;

pub const PROFILE_CALENDAR_EVENT: &str = "ck.profile.calendar_event.v1";
pub const PROFILE_PERSONAL_PRODUCTIVITY: &str = "ck.profile.personal_productivity.v1";
pub const PROFILE_DRAFT_SYNC: &str = "ck.profile.draft_sync.v1";
pub const PROFILE_FILE_TRANSFER: &str = "ck.profile.file_transfer.v1";
pub const PROFILE_PINNED_ITEMS: &str = "ck.profile.pinned_items.v1";
pub const PROFILE_DISAPPEARING_MESSAGES: &str = "ck.profile.disappearing_messages.v1";
pub const PROFILE_SEARCH_CLIENT_INDEX: &str = "ck.profile.search.client_index.v1";
pub const PROFILE_SEARCH_BLIND_INDEX: &str = "ck.profile.search.blind_index.v1";
pub const PROFILE_SEARCH_FORWARD_PRIVATE: &str = "ck.profile.search.forward_private.v1";
pub const FILE_TRANSFER_KEY_MESSAGE_KIND: &str = "ck.file_transfer.key.v1";
pub const FILE_TRANSFER_KEY_ENVELOPE_SCHEME: &str = "ck.hpke_x25519_aead_xchacha20poly1305.v1";

pub const MAX_CALENDAR_ATTENDEES: usize = 1_000;
pub const MAX_CALENDAR_RECURRENCE_COUNT: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PersonalProductivityValue {
    Reminder(ReminderValue),
    ScheduledSend(ScheduledSendValue),
    Snooze(SnoozeValue),
    SavedItem(SavedItemValue),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReminderValue {
    pub target_ref: String,
    pub due_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub updated_hlc: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledSendValue {
    pub planned_message_id: MessageId,
    pub send_at: String,
    pub message_payload: Value,
    pub message_payload_digest: String,
    pub updated_hlc: String,
}

impl ScheduledSendValue {
    pub fn validate_message_id_and_digest(&self) -> Result<()> {
        let payload_message_id = self
            .message_payload
            .get("message_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::Protocol("scheduled_send.message_payload.message_id required".to_owned())
            })?;
        if payload_message_id != self.planned_message_id.as_str() {
            return Err(Error::Protocol(
                "scheduled_send.message_payload.message_id must equal planned_message_id"
                    .to_owned(),
            ));
        }
        let digest = scheduled_send_message_payload_digest(&self.message_payload)?;
        if digest != self.message_payload_digest {
            return Err(Error::Protocol(
                "scheduled_send.message_payload_digest does not match message_payload".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnoozeValue {
    pub target_ref: String,
    pub snooze_expires_at: String,
    pub updated_hlc: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedItemValue {
    pub collection_title: String,
    pub target_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub updated_hlc: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftKind {
    Message,
    StrandField,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftSyncValue {
    pub target_ref: String,
    pub kind: DraftKind,
    pub draft_slot: String,
    pub content: Value,
    pub updated_hlc: String,
    pub origin_device_id: DeviceId,
    pub retention_expires_at: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecurrenceFrequency {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecurrenceWeekday {
    Mo,
    Tu,
    We,
    Th,
    Fr,
    Sa,
    Su,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarRecurrence {
    pub frequency: RecurrenceFrequency,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub by_day: Vec<RecurrenceWeekday>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarAttendeeRole {
    Required,
    Optional,
    Organizer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarAttendee {
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<CalendarAttendeeRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name_snapshot: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarEventFields {
    pub start: String,
    pub end: String,
    pub timezone: String,
    pub all_day: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recurrence: Option<CalendarRecurrence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attendees: Vec<CalendarAttendee>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RsvpStatus {
    Accepted,
    Declined,
    Tentative,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsvpSetPayload {
    pub event_ref: StrandId,
    pub status: RsvpStatus,
    pub occurrence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<Value>,
}

impl CalendarRecurrence {
    pub fn validate(&self) -> Result<()> {
        if self.count.is_some() && self.expires_at.is_some() {
            return Err(Error::Protocol(
                "calendar recurrence count and expires_at are mutually exclusive".to_owned(),
            ));
        }
        if self
            .count
            .is_some_and(|count| count > MAX_CALENDAR_RECURRENCE_COUNT)
        {
            return Err(Error::Protocol(
                "calendar recurrence count must be <= 10000".to_owned(),
            ));
        }
        if self.interval == Some(0) {
            return Err(Error::Protocol(
                "calendar recurrence interval must be positive".to_owned(),
            ));
        }
        if let Some(expires_at) = &self.expires_at {
            canonical::validate_timestamp_canonical(expires_at)?;
        }
        require_unique("calendar recurrence by_day", &self.by_day)?;
        Ok(())
    }
}

impl CalendarEventFields {
    pub fn validate(&self) -> Result<()> {
        let timezone = parse_calendar_timezone(&self.timezone)?;
        if self.all_day {
            let start = parse_calendar_date(&self.start, "calendar start")?;
            let end = parse_calendar_date(&self.end, "calendar end")?;
            if end < start {
                return Err(Error::Protocol(
                    "calendar all_day end must be on or after start".to_owned(),
                ));
            }
        } else {
            let start = parse_calendar_instant(&self.start, timezone, "calendar start")?;
            let end = parse_calendar_instant(&self.end, timezone, "calendar end")?;
            if end <= start {
                return Err(Error::Protocol(
                    "calendar end must be later than start".to_owned(),
                ));
            }
        }
        if let Some(recurrence) = &self.recurrence {
            recurrence.validate()?;
        }
        if self.attendees.len() > MAX_CALENDAR_ATTENDEES {
            return Err(Error::Protocol(
                "calendar attendees must contain <= 1000 entries".to_owned(),
            ));
        }
        let attendee_actor_ids = self
            .attendees
            .iter()
            .map(|attendee| attendee.actor_id.clone())
            .collect::<Vec<_>>();
        require_unique("calendar attendees actor_id", &attendee_actor_ids)?;
        Ok(())
    }

    pub fn canonical_occurrence_key(&self, occurrence: Option<&str>) -> Result<String> {
        let Some(occurrence) = occurrence.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok("series".to_owned());
        };
        let timezone = parse_calendar_timezone(&self.timezone)?;
        if self.all_day {
            let date = parse_calendar_occurrence_date(occurrence, timezone)?;
            return Ok(date.format("%Y-%m-%d").to_string());
        }
        let local = parse_calendar_occurrence_datetime(occurrence, timezone)?;
        Ok(format!(
            "{}[{}]",
            local.format("%Y-%m-%dT%H:%M:%S"),
            self.timezone
        ))
    }
}

pub fn calendar_event_fields_from_metadata_fields(
    fields: &BTreeMap<String, Value>,
) -> Result<Option<CalendarEventFields>> {
    const REQUIRED: &[&str] = &["start", "end", "timezone", "all_day"];
    const CORE: &[&str] = &[
        "start",
        "end",
        "timezone",
        "all_day",
        "recurrence",
        "call_id",
        "attendees",
    ];
    const EXTRACT: &[&str] = &[
        "start",
        "end",
        "timezone",
        "all_day",
        "recurrence",
        "location",
        "call_id",
        "attendees",
    ];
    if !CORE.iter().any(|key| fields.contains_key(*key)) {
        return Ok(None);
    }
    for key in REQUIRED {
        if !fields.contains_key(*key) {
            return Err(Error::Protocol(format!(
                "calendar event metadata.fields.{key} is required"
            )));
        }
    }
    let mut object = serde_json::Map::new();
    for key in EXTRACT {
        if let Some(value) = fields.get(*key) {
            object.insert((*key).to_owned(), value.clone());
        }
    }
    let fields = serde_json::from_value::<CalendarEventFields>(Value::Object(object))
        .map_err(|error| Error::Protocol(format!("calendar event fields invalid: {error}")))?;
    Ok(Some(fields))
}

pub fn validate_calendar_event_metadata_fields(fields: &BTreeMap<String, Value>) -> Result<()> {
    if let Some(calendar_fields) = calendar_event_fields_from_metadata_fields(fields)? {
        calendar_fields.validate()?;
    }
    Ok(())
}

pub fn canonical_calendar_rsvp_occurrence_key(
    fields: &BTreeMap<String, Value>,
    occurrence: Option<&str>,
) -> Result<String> {
    let Some(calendar_fields) = calendar_event_fields_from_metadata_fields(fields)? else {
        return Err(Error::Protocol(
            "rsvp event_ref must reference a calendar event".to_owned(),
        ));
    };
    calendar_fields.validate()?;
    calendar_fields.canonical_occurrence_key(occurrence)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryTrigger {
    OnSend,
    OnFirstRead,
    OnLastRead,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageExpiry {
    pub ttl_ms: u64,
    pub trigger: ExpiryTrigger,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisappearingPolicy {
    pub enabled: bool,
    pub max_ttl_ms: u64,
    pub allowed_triggers: Vec<ExpiryTrigger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_grace_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_plaintext_realms: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PinScope {
    Strand { id: StrandId },
    Realm { id: RealmId },
    Circle { id: CircleId },
    Space { id: SpaceId },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinAddPayload {
    pub pin_scope: PinScope,
    pub target_ref: String,
    pub rank: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinRemovePayload {
    pub pin_scope: PinScope,
    pub target_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_rank: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinReorderPayload {
    pub pin_scope: PinScope,
    pub target_ref: String,
    pub rank: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_rank: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SearchProfileRef {
    #[serde(rename = "ck.profile.search.client_index.v1")]
    ClientIndex,
    #[serde(rename = "ck.profile.search.blind_index.v1")]
    BlindIndex,
    #[serde(rename = "ck.profile.search.forward_private.v1")]
    ForwardPrivate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchDataClass {
    EncryptedIndex,
    BlindTokens,
    Plaintext,
    ReversibleSummary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchRevocationBehavior {
    FailClosed,
    DropStale,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchLeakageClass {
    DeterministicToken,
    ForwardPrivate,
    AccessHiding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchPolicy {
    pub enabled_profile_refs: Vec<SearchProfileRef>,
    pub allowed_service_dids: Vec<Did>,
    pub data_classes: Vec<SearchDataClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_retention_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_behavior: Option<SearchRevocationBehavior>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leakage_class: Option<SearchLeakageClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_rotation_cadence_ms: Option<u64>,
}

impl SearchPolicy {
    pub fn validate(&self) -> Result<()> {
        require_unique("enabled_profile_refs", &self.enabled_profile_refs)?;
        require_unique("allowed_service_dids", &self.allowed_service_dids)?;
        require_unique("data_classes", &self.data_classes)?;
        if self.data_classes.is_empty() {
            return Err(Error::Protocol(
                "search_policy.data_classes must not be empty".to_owned(),
            ));
        }
        let forward_private_enabled = self
            .enabled_profile_refs
            .contains(&SearchProfileRef::ForwardPrivate);
        if forward_private_enabled
            && !self
                .enabled_profile_refs
                .contains(&SearchProfileRef::BlindIndex)
        {
            return Err(Error::Protocol(
                "search_policy forward_private profile requires the blind_index profile".to_owned(),
            ));
        }
        let leakage_class = self
            .leakage_class
            .unwrap_or(SearchLeakageClass::DeterministicToken);
        if leakage_class == SearchLeakageClass::AccessHiding {
            return Err(Error::Protocol(
                "search_policy.leakage_class access_hiding requires an explicit access-hiding profile"
                    .to_owned(),
            ));
        }
        if forward_private_enabled && leakage_class != SearchLeakageClass::ForwardPrivate {
            return Err(Error::Protocol(
                "search_policy forward_private profile requires leakage_class forward_private"
                    .to_owned(),
            ));
        }
        if leakage_class == SearchLeakageClass::ForwardPrivate && !forward_private_enabled {
            return Err(Error::Protocol(
                "search_policy leakage_class forward_private requires the forward_private profile"
                    .to_owned(),
            ));
        }
        if forward_private_enabled && self.token_rotation_cadence_ms.is_none() {
            return Err(Error::Protocol(
                "search_policy forward_private profile requires token_rotation_cadence_ms"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedShardRef {
    pub shard_key: String,
    pub blob_ref: BlobId,
    pub ciphertext_digest: String,
}

impl EncryptedShardRef {
    pub fn validate(&self) -> Result<()> {
        if !looks_derived_key(&self.shard_key) {
            return Err(Error::Protocol(
                "encrypted shard shard_key must be an opaque derived key".to_owned(),
            ));
        }
        Hash::new(self.ciphertext_digest.clone())?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedIndexManifest {
    pub realm_id: RealmId,
    pub index_generation: u64,
    pub shards: Vec<EncryptedShardRef>,
    pub updated_hlc: String,
}

impl EncryptedIndexManifest {
    pub fn validate(&self) -> Result<()> {
        if self.shards.is_empty() {
            return Err(Error::Protocol(
                "encrypted index manifest requires at least one shard".to_owned(),
            ));
        }
        let mut shard_keys = BTreeSet::new();
        for shard in &self.shards {
            shard.validate()?;
            if !shard_keys.insert(&shard.shard_key) {
                return Err(Error::Protocol(
                    "encrypted index manifest shard_key values must be unique".to_owned(),
                ));
            }
        }
        if self.updated_hlc.trim().is_empty() {
            return Err(Error::Protocol(
                "encrypted index manifest updated_hlc must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTransferRecord {
    pub kind: String,
    pub transfer_id: String,
    pub blob_ref: String,
    pub content_digest: String,
    pub blob_size_bytes: u64,
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    pub plaintext_size_bytes: u64,
    pub access: FileTransferAccess,
    pub encryption: FileTransferEncryption,
    pub origin_device_id: String,
    pub created_at: String,
    pub updated_hlc: String,
    pub retention_expires_at: String,
    pub state: FileTransferState,
}

impl FileTransferRecord {
    pub fn validate(&self) -> Result<()> {
        if self.kind != "file_transfer" {
            return Err(Error::Protocol(
                "file-transfer record kind must be file_transfer".to_owned(),
            ));
        }
        validate_file_transfer_id(&self.transfer_id)?;
        validate_blob_ref(&self.blob_ref)?;
        Hash::new(self.content_digest.clone())?;
        validate_file_transfer_blob_digest_binding(&self.blob_ref, &self.content_digest)?;
        validate_media_type(&self.media_type)?;
        if let Some(filename) = &self.filename {
            let len = filename.chars().count();
            if filename.trim().is_empty() || len > 255 {
                return Err(Error::Protocol(
                    "file-transfer filename must be 1-255 non-blank chars".to_owned(),
                ));
            }
        }
        self.access.validate()?;
        self.encryption.validate()?;
        DeviceId::new(self.origin_device_id.clone()).map_err(|_| {
            Error::Protocol("file-transfer origin_device_id must be a ck:device id".to_owned())
        })?;
        canonical::validate_timestamp_canonical(&self.created_at)?;
        Hlc::new(self.updated_hlc.clone()).map_err(|_| {
            Error::Protocol("file-transfer updated_hlc must be a canonical HLC".to_owned())
        })?;
        canonical::validate_timestamp_canonical(&self.retention_expires_at)?;
        self.validate_aad_binding()?;
        self.validate_access_key_delivery_binding()
    }

    fn validate_aad_binding(&self) -> Result<()> {
        let aad = &self.encryption.aad;
        if aad.schema != FILE_TRANSFER_SCHEMA {
            return Err(Error::Protocol(
                "file-transfer AAD schema must be ck.schema.file_transfer.v1".to_owned(),
            ));
        }
        if aad.purpose != "file_transfer" {
            return Err(Error::Protocol(
                "file-transfer AAD purpose must be file_transfer".to_owned(),
            ));
        }
        if aad.transfer_id != self.transfer_id {
            return Err(Error::Protocol(
                "file-transfer AAD transfer_id must match record transfer_id".to_owned(),
            ));
        }
        if aad.origin_device_id != self.origin_device_id {
            return Err(Error::Protocol(
                "file-transfer AAD origin_device_id must match record origin_device_id".to_owned(),
            ));
        }
        if aad.created_at != self.created_at {
            return Err(Error::Protocol(
                "file-transfer AAD created_at must match record created_at".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_access_key_delivery_binding(&self) -> Result<()> {
        match self.access.visibility {
            FileTransferAccessVisibility::ActorPrivate => {
                if !self.access.recipient_device_ids.is_empty() {
                    return Err(Error::Protocol(
                        "actor_private file-transfer access must not list recipient devices"
                            .to_owned(),
                    ));
                }
                if !matches!(
                    &self.encryption.key_delivery,
                    FileTransferKeyDelivery::AccountDataWrappedKey { .. }
                ) {
                    return Err(Error::Protocol(
                        "actor_private file-transfer requires account_data_wrapped_key".to_owned(),
                    ));
                }
            }
            FileTransferAccessVisibility::DeviceBound => {
                if self.access.recipient_device_ids.is_empty() {
                    return Err(Error::Protocol(
                        "device_bound file-transfer access requires recipient_device_ids"
                            .to_owned(),
                    ));
                }
                if !matches!(
                    &self.encryption.key_delivery,
                    FileTransferKeyDelivery::ToDeviceWrappedKey { .. }
                ) {
                    return Err(Error::Protocol(
                        "device_bound file-transfer requires to_device_wrapped_key".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTransferAccess {
    pub visibility: FileTransferAccessVisibility,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipient_device_ids: Vec<String>,
}

impl FileTransferAccess {
    pub fn validate(&self) -> Result<()> {
        let mut seen = BTreeSet::new();
        for device_id in &self.recipient_device_ids {
            DeviceId::new(device_id.clone()).map_err(|_| {
                Error::Protocol(
                    "file-transfer recipient_device_ids must contain ck:device ids".to_owned(),
                )
            })?;
            if !seen.insert(device_id) {
                return Err(Error::Protocol(
                    "file-transfer recipient_device_ids must be unique".to_owned(),
                ));
            }
        }
        if self.recipient_device_ids.len() > 1_000 {
            return Err(Error::Protocol(
                "file-transfer recipient_device_ids must have at most 1000 entries".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileTransferAccessVisibility {
    ActorPrivate,
    DeviceBound,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTransferEncryption {
    pub scheme: String,
    pub aead_profile: String,
    pub nonce: String,
    pub aad: FileTransferAad,
    pub key_delivery: FileTransferKeyDelivery,
}

impl FileTransferEncryption {
    pub fn validate(&self) -> Result<()> {
        if self.scheme != "ck.file_transfer.encrypted_blob.v1" {
            return Err(Error::Protocol(
                "file-transfer encryption scheme mismatch".to_owned(),
            ));
        }
        if self.aead_profile != "ck.aead.xchacha20_poly1305.v1" {
            return Err(Error::Protocol(
                "file-transfer AEAD profile mismatch".to_owned(),
            ));
        }
        validate_base64url("file-transfer nonce", &self.nonce)?;
        self.aad.validate()?;
        self.key_delivery.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTransferAad {
    pub schema: String,
    pub purpose: String,
    pub transfer_id: String,
    pub origin_device_id: String,
    pub created_at: String,
}

impl FileTransferAad {
    pub fn validate(&self) -> Result<()> {
        if self.schema != FILE_TRANSFER_SCHEMA {
            return Err(Error::Protocol(
                "file-transfer AAD schema must be ck.schema.file_transfer.v1".to_owned(),
            ));
        }
        if self.purpose != "file_transfer" {
            return Err(Error::Protocol(
                "file-transfer AAD purpose must be file_transfer".to_owned(),
            ));
        }
        validate_file_transfer_id(&self.transfer_id)?;
        DeviceId::new(self.origin_device_id.clone()).map_err(|_| {
            Error::Protocol("file-transfer AAD origin_device_id must be a ck:device id".to_owned())
        })?;
        canonical::validate_timestamp_canonical(&self.created_at)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileTransferKeyDelivery {
    AccountDataWrappedKey { content_key: String },
    ToDeviceWrappedKey { key_message_kind: String },
}

impl FileTransferKeyDelivery {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::AccountDataWrappedKey { content_key } => {
                validate_base64url("file-transfer content_key", content_key)
            }
            Self::ToDeviceWrappedKey { key_message_kind } => {
                if key_message_kind == FILE_TRANSFER_KEY_MESSAGE_KIND {
                    Ok(())
                } else {
                    Err(Error::Protocol(
                        "to_device_wrapped_key key_message_kind must be ck.file_transfer.key.v1"
                            .to_owned(),
                    ))
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTransferKeyMessage {
    pub transfer_id: String,
    pub blob_ref: String,
    pub aead_profile: String,
    pub nonce: String,
    pub content_digest: String,
    pub key_envelope: FileTransferKeyEnvelope,
    pub expires_at: String,
}

impl FileTransferKeyMessage {
    pub fn validate(&self) -> Result<()> {
        validate_file_transfer_id(&self.transfer_id)?;
        validate_blob_ref(&self.blob_ref)?;
        Hash::new(self.content_digest.clone())?;
        validate_file_transfer_blob_digest_binding(&self.blob_ref, &self.content_digest)?;
        if self.aead_profile != "ck.aead.xchacha20_poly1305.v1" {
            return Err(Error::Protocol(
                "file-transfer key message AEAD profile mismatch".to_owned(),
            ));
        }
        validate_base64url("file-transfer key message nonce", &self.nonce)?;
        self.key_envelope.validate()?;
        canonical::validate_timestamp_canonical(&self.expires_at)
    }

    pub fn validate_record_binding(&self, record: &FileTransferRecord) -> Result<()> {
        self.validate()?;
        if self.transfer_id != record.transfer_id {
            return Err(Error::Protocol(
                "file-transfer key message transfer_id mismatch".to_owned(),
            ));
        }
        if self.blob_ref != record.blob_ref {
            return Err(Error::Protocol(
                "file-transfer key message blob_ref mismatch".to_owned(),
            ));
        }
        if self.aead_profile != record.encryption.aead_profile {
            return Err(Error::Protocol(
                "file-transfer key message aead_profile mismatch".to_owned(),
            ));
        }
        if self.nonce != record.encryption.nonce {
            return Err(Error::Protocol(
                "file-transfer key message nonce mismatch".to_owned(),
            ));
        }
        if self.content_digest != record.content_digest {
            return Err(Error::Protocol(
                "file-transfer key message content_digest mismatch".to_owned(),
            ));
        }
        if record.access.visibility != FileTransferAccessVisibility::DeviceBound {
            return Err(Error::Protocol(
                "file-transfer key message requires device_bound record".to_owned(),
            ));
        }
        if !matches!(
            &record.encryption.key_delivery,
            FileTransferKeyDelivery::ToDeviceWrappedKey { key_message_kind }
                if key_message_kind == FILE_TRANSFER_KEY_MESSAGE_KIND
        ) {
            return Err(Error::Protocol(
                "device_bound file-transfer requires to_device_wrapped_key".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTransferKeyEnvelope {
    pub scheme: String,
    pub enc: String,
    pub ciphertext: String,
    pub aad_digest: String,
}

impl FileTransferKeyEnvelope {
    pub fn validate(&self) -> Result<()> {
        if self.scheme != FILE_TRANSFER_KEY_ENVELOPE_SCHEME {
            return Err(Error::Protocol(
                "file-transfer key envelope scheme mismatch".to_owned(),
            ));
        }
        validate_base64url("file-transfer key envelope enc", &self.enc)?;
        validate_base64url("file-transfer key envelope ciphertext", &self.ciphertext)?;
        Hash::new(self.aad_digest.clone())?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileTransferState {
    Available,
    Downloaded,
    Dismissed,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindIndexQuery {
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub epoch_id: u64,
    pub index_generation: u64,
    pub blind_tokens: Vec<String>,
}

impl BlindIndexQuery {
    pub fn validate(&self) -> Result<()> {
        if self.effective_scope.realm_id() != &self.realm_id {
            return Err(Error::Protocol(
                "blind_index_query.effective_scope must be bound to realm_id".to_owned(),
            ));
        }
        if self.blind_tokens.is_empty() {
            return Err(Error::Protocol(
                "blind_index_query.blind_tokens must not be empty".to_owned(),
            ));
        }
        let mut seen = BTreeSet::new();
        for token in &self.blind_tokens {
            if !looks_derived_key(token) {
                return Err(Error::Protocol(
                    "blind_index_query.blind_tokens must be opaque derived tokens".to_owned(),
                ));
            }
            if !seen.insert(token) {
                return Err(Error::Protocol(
                    "blind_index_query.blind_tokens must be unique".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmRemarkSubject {
    pub kind: String,
    pub id: RealmId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmRemark {
    pub version: u32,
    pub subject: RealmRemarkSubject,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub local_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub pinned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_title_at_save: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_owning_organizations_at_save: Vec<Did>,
    pub saved_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmRemarkAccountDataUpdate {
    pub key: String,
    pub encrypted_payload: Value,
}

impl RealmRemark {
    pub fn new(realm_id: RealmId, saved_at: DateTime<Utc>) -> Self {
        Self {
            version: 1,
            subject: RealmRemarkSubject {
                kind: "realm".to_owned(),
                id: realm_id,
            },
            local_name: String::new(),
            note: String::new(),
            tags: Vec::new(),
            pinned: false,
            verified_title_at_save: None,
            verified_owning_organizations_at_save: Vec::new(),
            saved_at,
            updated_at: None,
        }
    }

    pub fn with_pinned_preserving_fields(
        realm_id: RealmId,
        existing: Option<&Self>,
        pinned: bool,
        updated_at: DateTime<Utc>,
    ) -> Self {
        let mut next = existing
            .cloned()
            .unwrap_or_else(|| Self::new(realm_id.clone(), updated_at));
        next.version = 1;
        next.subject = RealmRemarkSubject {
            kind: "realm".to_owned(),
            id: realm_id,
        };
        next.pinned = pinned;
        next.updated_at = Some(updated_at);
        next
    }

    pub fn is_empty(&self) -> bool {
        self.local_name.trim().is_empty()
            && self.note.trim().is_empty()
            && self.tags.is_empty()
            && !self.pinned
    }

    pub fn display_name<'a>(&'a self, fallback: &'a str) -> &'a str {
        let trimmed = self.local_name.trim();
        if trimmed.is_empty() {
            fallback
        } else {
            trimmed
        }
    }

    pub fn validate_for_account_data_key(&self, key: &str) -> Result<()> {
        let realm_id = parse_realm_remark_account_data_key(key)?;
        self.validate_for_realm(&realm_id)
    }

    pub fn validate_for_realm(&self, realm_id: &RealmId) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Protocol("realm remark version must be 1".to_owned()));
        }
        if self.subject.kind != "realm" {
            return Err(Error::Protocol(
                "realm remark subject.kind must be realm".to_owned(),
            ));
        }
        if &self.subject.id != realm_id {
            return Err(Error::Protocol(
                "realm remark subject.id must match account-data key realm_id".to_owned(),
            ));
        }
        if self.local_name.chars().count() > 128 {
            return Err(Error::Protocol(
                "realm remark local_name exceeds 128 chars".to_owned(),
            ));
        }
        if self.note.chars().count() > 4096 {
            return Err(Error::Protocol(
                "realm remark note exceeds 4096 chars".to_owned(),
            ));
        }
        for tag in &self.tags {
            if tag.trim().is_empty() {
                return Err(Error::Protocol(
                    "realm remark tags must not be empty".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

pub fn realm_remark_account_data_key(realm_id: &RealmId) -> String {
    format!("{ACCOUNT_DATA_TYPE_CONTACTS_REALM}.{realm_id}")
}

pub fn realm_id_from_realm_remark_account_data_key(key: &str) -> Option<RealmId> {
    key.strip_prefix("ck.contacts.realm.")
        .and_then(|realm_id| RealmId::new(realm_id.to_owned()).ok())
}

pub fn parse_realm_remark_account_data_key(key: &str) -> Result<RealmId> {
    realm_id_from_realm_remark_account_data_key(key).ok_or_else(|| {
        Error::Protocol("realm remark key must be ck.contacts.realm.<realm_id>".to_owned())
    })
}

pub fn validate_realm_remark_account_data_value(key: &str, value: &Value) -> Result<()> {
    parse_realm_remark_account_data_key(key)?;
    if value.as_object().is_some_and(|object| object.is_empty()) {
        return Ok(());
    }
    if value.as_object().is_some_and(|object| {
        object.len() == 1 && object.get("tombstone").and_then(Value::as_bool) == Some(true)
    }) {
        return Ok(());
    }
    let remark: RealmRemark = serde_json::from_value(value.clone()).map_err(|error| {
        Error::Protocol(format!(
            "realm remark account-data value is invalid: {error}"
        ))
    })?;
    remark.validate_for_account_data_key(key)
}

pub fn validate_no_realm_remark_private_fields_in_shared_payload(payload: &Value) -> Result<()> {
    fn visit(path: &str, value: &Value) -> Result<()> {
        match value {
            Value::Object(object) => {
                for key in object.keys() {
                    if key.starts_with("ck.contacts.realm.") || key == "realm_remark" {
                        return Err(Error::Protocol(format!(
                            "shared payload must not contain private realm remark at {path}.{key}"
                        )));
                    }
                }
                let realm_subject = object
                    .get("subject")
                    .and_then(Value::as_object)
                    .is_some_and(|subject| {
                        subject.get("kind").and_then(Value::as_str) == Some("realm")
                    });
                if realm_subject
                    && [
                        "local_name",
                        "note",
                        "pinned",
                        "verified_title_at_save",
                        "verified_owning_organizations_at_save",
                    ]
                    .iter()
                    .any(|field| object.contains_key(*field))
                {
                    return Err(Error::Protocol(format!(
                        "shared payload must not contain private realm remark fields at {path}"
                    )));
                }
                for (key, child) in object {
                    visit(&format!("{path}.{key}"), child)?;
                }
            }
            Value::Array(values) => {
                for (index, child) in values.iter().enumerate() {
                    visit(&format!("{path}[{index}]"), child)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    visit("$", payload)
}

pub fn set_realm_pinned(
    realm_id: RealmId,
    existing: Option<&RealmRemark>,
    pinned: bool,
    updated_at: DateTime<Utc>,
) -> Result<RealmRemarkAccountDataUpdate> {
    let key = realm_remark_account_data_key(&realm_id);
    let remark = RealmRemark::with_pinned_preserving_fields(realm_id, existing, pinned, updated_at);
    let encrypted_payload = if remark.is_empty() {
        json!({})
    } else {
        serde_json::to_value(&remark).map_err(|error| {
            Error::Protocol(format!("realm remark serialization failed: {error}"))
        })?
    };
    validate_realm_remark_account_data_value(&key, &encrypted_payload)?;
    Ok(RealmRemarkAccountDataUpdate {
        key,
        encrypted_payload,
    })
}

pub fn scheduled_send_message_payload_digest(message_payload: &Value) -> Result<String> {
    canonical::canonical_sha256(message_payload)
}

pub fn reminder_account_data_key(id: &str) -> Result<String> {
    validate_key_segment("reminder id", id)?;
    Ok(format!("{ACCOUNT_DATA_TYPE_REMINDER}:{id}"))
}

pub fn scheduled_send_account_data_key(planned_message_id: &MessageId) -> String {
    format!("{ACCOUNT_DATA_TYPE_SCHEDULED_SEND}:{planned_message_id}")
}

pub fn snooze_account_data_key(namespace_key: &[u8], target_ref: &str) -> Result<String> {
    Ok(format!(
        "{ACCOUNT_DATA_TYPE_SNOOZE}:{}",
        target_key(namespace_key, target_ref)?
    ))
}

pub fn saved_account_data_key(
    namespace_key: &[u8],
    collection_title: &str,
    target_ref: &str,
) -> Result<String> {
    let collection_key = collection_key(namespace_key, collection_title)?;
    let target_key = saved_target_key(namespace_key, &collection_key, target_ref)?;
    Ok(format!(
        "{ACCOUNT_DATA_TYPE_SAVED}:{collection_key}:{target_key}"
    ))
}

pub fn draft_account_data_key(
    namespace_key: &[u8],
    kind: DraftKind,
    target_ref: &str,
    draft_slot: &str,
) -> Result<String> {
    validate_key_segment("draft_slot", draft_slot)?;
    let kind = match kind {
        DraftKind::Message => "message",
        DraftKind::StrandField => "strand_field",
    };
    Ok(format!(
        "{ACCOUNT_DATA_TYPE_DRAFT}:{kind}:{}:{draft_slot}",
        target_key(namespace_key, target_ref)?
    ))
}

pub fn search_index_manifest_account_data_key(
    namespace_key: &[u8],
    realm_id: &RealmId,
) -> Result<String> {
    Ok(format!(
        "{ACCOUNT_DATA_TYPE_SEARCH_INDEX_MANIFEST}:{}",
        realm_key(namespace_key, realm_id.as_str())?
    ))
}

pub fn search_index_shard_key(
    index_key: &[u8],
    realm_id: &RealmId,
    index_generation: u64,
    shard_seed: &[u8],
) -> Result<String> {
    validate_search_index_key(index_key)?;
    if shard_seed.is_empty() {
        return Err(Error::Protocol(
            "search index shard_seed must not be empty".to_owned(),
        ));
    }
    let material = json!({
        "profile": PROFILE_SEARCH_CLIENT_INDEX,
        "realm_id": realm_id.as_str(),
        "index_generation": index_generation,
        "shard_seed_digest": canonical::sha256_digest(shard_seed),
    });
    Ok(base64url_encode(hmac_sha256(
        index_key,
        &canonical::canonical_json_bytes(&material)?,
    )))
}

pub fn blind_index_token(
    index_key: &[u8],
    realm_id: &RealmId,
    effective_scope: &EffectiveScope,
    epoch_id: u64,
    index_generation: u64,
    term: &str,
) -> Result<String> {
    validate_search_index_key(index_key)?;
    if effective_scope.realm_id() != realm_id {
        return Err(Error::Protocol(
            "blind index token effective_scope must be bound to realm_id".to_owned(),
        ));
    }
    let normalized_term = normalize_search_term(term)?;
    let material = json!({
        "profile": PROFILE_SEARCH_BLIND_INDEX,
        "realm_id": realm_id.as_str(),
        "effective_scope": effective_scope,
        "epoch_id": epoch_id,
        "index_generation": index_generation,
        "term_digest": canonical::sha256_digest(normalized_term.as_bytes()),
    });
    Ok(base64url_encode(hmac_sha256(
        index_key,
        &canonical::canonical_json_bytes(&material)?,
    )))
}

pub fn build_blind_index_query<I, S>(
    index_key: &[u8],
    realm_id: RealmId,
    effective_scope: EffectiveScope,
    epoch_id: u64,
    index_generation: u64,
    terms: I,
) -> Result<BlindIndexQuery>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let blind_tokens = terms
        .into_iter()
        .map(|term| {
            blind_index_token(
                index_key,
                &realm_id,
                &effective_scope,
                epoch_id,
                index_generation,
                term.as_ref(),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let query = BlindIndexQuery {
        realm_id,
        effective_scope,
        epoch_id,
        index_generation,
        blind_tokens,
    };
    query.validate()?;
    Ok(query)
}

pub fn file_transfer_account_data_key(namespace_key: &[u8], transfer_id: &str) -> Result<String> {
    validate_file_transfer_id(transfer_id)?;
    Ok(format!(
        "{ACCOUNT_DATA_TYPE_FILE_TRANSFER}:{}",
        base64url_encode(hmac_sha256(namespace_key, transfer_id.as_bytes()))
    ))
}

pub fn target_key(namespace_key: &[u8], target_ref: &str) -> Result<String> {
    validate_object_ref_string("target_ref", target_ref)?;
    Ok(base64url_encode(hmac_sha256(
        namespace_key,
        &canonical::canonical_json_bytes(&target_ref)?,
    )))
}

pub fn collection_key(namespace_key: &[u8], collection_title: &str) -> Result<String> {
    let normalized = normalize_collection_title(collection_title)?;
    Ok(base64url_encode(hmac_sha256(
        namespace_key,
        normalized.as_bytes(),
    )))
}

pub fn saved_target_key(
    namespace_key: &[u8],
    collection_key: &str,
    target_ref: &str,
) -> Result<String> {
    validate_key_segment("collection_key", collection_key)?;
    validate_object_ref_string("target_ref", target_ref)?;
    // Length-prefix each component (8-byte BE) so no (collection_key,
    // target_ref) pair can collide with another split of the same bytes.
    let target_bytes = canonical::canonical_json_bytes(&target_ref)?;
    let mut material =
        Vec::with_capacity(16 + collection_key.len() + target_bytes.len());
    material.extend_from_slice(&(collection_key.len() as u64).to_be_bytes());
    material.extend_from_slice(collection_key.as_bytes());
    material.extend_from_slice(&(target_bytes.len() as u64).to_be_bytes());
    material.extend_from_slice(&target_bytes);
    Ok(base64url_encode(hmac_sha256(namespace_key, &material)))
}

pub fn realm_key(namespace_key: &[u8], realm_id: &str) -> Result<String> {
    if !realm_id.starts_with("ck:realm:") {
        return Err(Error::Protocol(
            "realm_key input must be ck:realm typed id".to_owned(),
        ));
    }
    Ok(base64url_encode(hmac_sha256(
        namespace_key,
        &canonical::canonical_json_bytes(&realm_id)?,
    )))
}

pub fn validate_private_account_data_key(key: &str) -> Result<()> {
    if let Some(realm_id) = key.strip_prefix("ck.contacts.realm.") {
        return RealmId::new(realm_id.to_owned()).map(|_| ()).map_err(|_| {
            Error::Protocol("realm remark key must be ck.contacts.realm.<realm_id>".to_owned())
        });
    }
    if let Some(actor_id) = key.strip_prefix("ck.contacts.actor.") {
        return Did::new(actor_id.to_owned()).map(|_| ()).map_err(|_| {
            Error::Protocol("contact remark key must be ck.contacts.actor.<did>".to_owned())
        });
    }
    if let Some(id) = key.strip_prefix("ck.reminders.v1:") {
        return if !id.is_empty() && !contains_raw_object_ref(id) {
            Ok(())
        } else {
            private_key_error()
        };
    }
    if let Some(planned_message_id) = key.strip_prefix("ck.scheduled_send.v1:") {
        return MessageId::new(planned_message_id.to_owned())
            .map(|_| ())
            .map_err(|_| {
                Error::Protocol("scheduled-send key must end with planned_message_id".to_owned())
            });
    }
    if let Some(target_key) = key.strip_prefix("ck.snooze.v1:") {
        return if looks_derived_key(target_key) {
            Ok(())
        } else {
            private_key_error()
        };
    }
    if let Some(rest) = key.strip_prefix("ck.saved.v1:") {
        let parts = rest.split(':').collect::<Vec<_>>();
        return if matches!(parts.as_slice(), [collection_key, target_key] if looks_derived_key(collection_key) && looks_derived_key(target_key))
        {
            Ok(())
        } else {
            private_key_error()
        };
    }
    if let Some(rest) = key.strip_prefix("ck.draft.v1:") {
        let parts = rest.split(':').collect::<Vec<_>>();
        return if matches!(parts.as_slice(), ["message" | "strand_field", target_key, slot_key] if looks_derived_key(target_key) && !slot_key.is_empty() && !contains_raw_object_ref(slot_key))
        {
            Ok(())
        } else {
            private_key_error()
        };
    }
    if let Some(realm_key) = key.strip_prefix("ck.search.index_manifest.v1:") {
        return if looks_derived_key(realm_key) {
            Ok(())
        } else {
            private_key_error()
        };
    }
    if let Some(transfer_key) = key.strip_prefix("ck.file_transfer.v1:") {
        return if looks_derived_key(transfer_key) && !contains_raw_object_ref(transfer_key) {
            Ok(())
        } else {
            private_key_error()
        };
    }
    private_key_error()
}

fn private_key_error() -> Result<()> {
    Err(Error::Protocol(
        "account-data key must use the registered private key pattern and must not leak raw typed refs"
            .to_owned(),
    ))
}

fn contains_raw_object_ref(value: &str) -> bool {
    [
        "ck:strand:",
        "ck:message:",
        "ck:realm:",
        "ck:space:",
        "ck:morph:",
        "ck:relation:",
        "ck:view:",
        "ck:circle:",
        "ck:event:",
    ]
    .iter()
    .any(|needle| value.contains(needle))
}

fn normalize_collection_title(collection_title: &str) -> Result<String> {
    let normalized = collection_title.trim().nfc().collect::<String>();
    if normalized.is_empty() {
        return Err(Error::Protocol(
            "collection_title must not be empty".to_owned(),
        ));
    }
    Ok(normalized)
}

fn validate_object_ref_string(field: &str, value: &str) -> Result<()> {
    let valid = [
        "ck:realm:",
        "ck:space:",
        "ck:strand:",
        "ck:message:",
        "ck:morph:",
        "ck:relation:",
        "ck:view:",
        "ck:circle:",
        "ck:event:",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix));
    if valid {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "{field} must be a canonical object_ref typed id"
        )))
    }
}

fn validate_key_segment(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.contains(':') || value.contains('/') || value.contains('\\') {
        Err(Error::Protocol(format!(
            "{field} must be an opaque key segment"
        )))
    } else {
        Ok(())
    }
}

pub fn validate_file_transfer_id(value: &str) -> Result<()> {
    let valid = (22..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'=' | b'-')
        });
    if valid {
        Ok(())
    } else {
        Err(Error::Protocol(
            "transfer_id must be 22-128 chars from the ck.file_transfer.v1 alphabet".to_owned(),
        ))
    }
}

fn validate_blob_ref(value: &str) -> Result<()> {
    let valid_uuid = value.strip_prefix("ck:blob:").is_some_and(is_uuid_v7);
    let valid_digest = ["ck:blob:sha256:", "ck:blob:blake3:"].iter().any(|prefix| {
        value.strip_prefix(prefix).is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    });
    if valid_uuid || valid_digest {
        Ok(())
    } else {
        Err(Error::Protocol(
            "file-transfer blob_ref must be ck:blob:<uuidv7|digest>".to_owned(),
        ))
    }
}

fn validate_file_transfer_blob_digest_binding(blob_ref: &str, content_digest: &str) -> Result<()> {
    for (prefix, digest_prefix) in [
        ("ck:blob:sha256:", "sha256:"),
        ("ck:blob:blake3:", "blake3:"),
    ] {
        if let Some(hex) = blob_ref.strip_prefix(prefix) {
            let expected = format!("{digest_prefix}{hex}");
            if content_digest != expected {
                return Err(Error::Protocol(
                    "file-transfer blob_ref digest must match content_digest".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_media_type(value: &str) -> Result<()> {
    let Some((top, sub)) = value.split_once('/') else {
        return Err(Error::Protocol(
            "file-transfer media_type must be type/subtype".to_owned(),
        ));
    };
    let valid_part = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'+' | b'-')
            })
    };
    if valid_part(top) && valid_part(sub) {
        Ok(())
    } else {
        Err(Error::Protocol(
            "file-transfer media_type must match the v1 media type grammar".to_owned(),
        ))
    }
}

fn validate_base64url(field: &str, value: &str) -> Result<()> {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(Error::Protocol(format!("{field} must be base64url")))
    }
}

fn is_uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for index in [8, 13, 18, 23] {
        if bytes[index] != b'-' {
            return false;
        }
    }
    bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                || (byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

fn validate_search_index_key(index_key: &[u8]) -> Result<()> {
    if index_key.is_empty() {
        Err(Error::Protocol(
            "search index key material must not be empty".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn normalize_search_term(term: &str) -> Result<String> {
    let normalized = term.trim().nfc().collect::<String>();
    if normalized.is_empty() {
        Err(Error::Protocol(
            "blind index search term must not be empty".to_owned(),
        ))
    } else {
        Ok(normalized)
    }
}

fn looks_derived_key(value: &str) -> bool {
    value.len() >= 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn parse_calendar_timezone(value: &str) -> Result<Tz> {
    value
        .parse::<Tz>()
        .map_err(|_| Error::Protocol("calendar timezone must be an IANA timezone name".to_owned()))
}

fn parse_calendar_date(value: &str, field: &str) -> Result<NaiveDate> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| Error::Protocol(format!("{field} must be YYYY-MM-DD")))
}

fn parse_calendar_instant(value: &str, timezone: Tz, field: &str) -> Result<DateTime<Utc>> {
    if let Some((local, zone)) = parse_bracketed_calendar_datetime(value)? {
        if zone != timezone {
            return Err(Error::Protocol(format!(
                "{field} bracketed timezone must match calendar timezone"
            )));
        }
        return local_datetime_to_utc(local, timezone, field);
    }
    if let Ok(instant) = DateTime::parse_from_rfc3339(value) {
        return Ok(instant.with_timezone(&Utc));
    }
    let local = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S").map_err(|_| {
        Error::Protocol(format!(
            "{field} must be RFC3339 or YYYY-MM-DDTHH:mm:ss in calendar timezone"
        ))
    })?;
    local_datetime_to_utc(local, timezone, field)
}

fn parse_calendar_occurrence_date(value: &str, timezone: Tz) -> Result<NaiveDate> {
    if let Ok(date) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        return Ok(date);
    }
    if let Some((local, zone)) = parse_bracketed_calendar_datetime(value)? {
        if zone != timezone {
            return Err(Error::Protocol(
                "calendar occurrence timezone must match event timezone".to_owned(),
            ));
        }
        return Ok(local.date());
    }
    if let Ok(instant) = DateTime::parse_from_rfc3339(value) {
        return Ok(instant.with_timezone(&timezone).date_naive());
    }
    let local = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S").map_err(|_| {
        Error::Protocol("all_day calendar occurrence must canonicalize to YYYY-MM-DD".to_owned())
    })?;
    Ok(local.date())
}

fn parse_calendar_occurrence_datetime(value: &str, timezone: Tz) -> Result<NaiveDateTime> {
    if let Some((local, zone)) = parse_bracketed_calendar_datetime(value)? {
        if zone != timezone {
            return Err(Error::Protocol(
                "calendar occurrence timezone must match event timezone".to_owned(),
            ));
        }
        local_datetime_to_utc(local, timezone, "calendar occurrence")?;
        return Ok(local);
    }
    if let Ok(instant) = DateTime::parse_from_rfc3339(value) {
        return Ok(instant.with_timezone(&timezone).naive_local());
    }
    let local = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S").map_err(|_| {
        Error::Protocol(
            "calendar occurrence must be RFC3339, local datetime, or canonical bracketed datetime"
                .to_owned(),
        )
    })?;
    local_datetime_to_utc(local, timezone, "calendar occurrence")?;
    Ok(local)
}

fn parse_bracketed_calendar_datetime(value: &str) -> Result<Option<(NaiveDateTime, Tz)>> {
    let Some(zone_start) = value.rfind('[') else {
        return Ok(None);
    };
    if !value.ends_with(']') || zone_start == 0 {
        return Err(Error::Protocol(
            "calendar bracketed datetime must end with [Zone]".to_owned(),
        ));
    }
    let local = &value[..zone_start];
    let zone = &value[zone_start + 1..value.len() - 1];
    let timezone = parse_calendar_timezone(zone)?;
    let local = NaiveDateTime::parse_from_str(local, "%Y-%m-%dT%H:%M:%S").map_err(|_| {
        Error::Protocol("calendar bracketed datetime must be YYYY-MM-DDTHH:mm:ss[Zone]".to_owned())
    })?;
    Ok(Some((local, timezone)))
}

fn local_datetime_to_utc(local: NaiveDateTime, timezone: Tz, field: &str) -> Result<DateTime<Utc>> {
    let instant = timezone
        .from_local_datetime(&local)
        .single()
        .ok_or_else(|| {
            Error::Protocol(format!(
                "{field} must resolve unambiguously in calendar timezone"
            ))
        })?;
    Ok(instant.with_timezone(&Utc))
}

fn require_unique<T: Ord>(field: &str, values: &[T]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(Error::Protocol(format!(
                "{field} must not contain duplicates"
            )));
        }
    }
    Ok(())
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// HMAC-SHA256 (RFC 2104) via the audited RustCrypto `hmac` crate. Used for
/// blind search index token / shard key derivation; the output bytes are
/// covered by fixture tests and MUST stay stable.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn test_realm_id(seed: &str) -> RealmId {
        RealmId::new(format!("ck:realm:01904100-0000-7000-8000-{seed}")).unwrap()
    }

    fn test_circle_id(seed: &str) -> CircleId {
        CircleId::new(format!("ck:circle:01904100-0000-7000-8000-{seed}")).unwrap()
    }

    fn test_blob_id(seed: &str) -> BlobId {
        BlobId::new(format!("ck:blob:01904100-0000-7000-8000-{seed}")).unwrap()
    }

    fn test_time(second: u32) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&format!("2026-06-06T10:00:{second:02}Z"))
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn scheduled_send_validates_payload_id_and_digest() {
        let message_id = MessageId::new("ck:message:01904100-0000-7000-8000-000000000001").unwrap();
        let payload = json!({
            "strand_id": "ck:strand:01904100-0000-7000-8000-000000000002",
            "track_name": "discussion",
            "message_id": message_id.as_str(),
            "content": {"body": "hello"}
        });
        let value = ScheduledSendValue {
            planned_message_id: message_id,
            send_at: "2026-06-07T00:00:00Z".to_owned(),
            message_payload_digest: scheduled_send_message_payload_digest(&payload).unwrap(),
            message_payload: payload,
            updated_hlc: "01970e589d21-0000-a13f9c2e".to_owned(),
        };
        value.validate_message_id_and_digest().unwrap();
    }

    #[test]
    fn calendar_event_fields_validate_cross_field_constraints() {
        let fields = CalendarEventFields {
            start: "2026-06-22T09:00:00Z".to_owned(),
            end: "2026-06-22T10:00:00Z".to_owned(),
            timezone: "America/Los_Angeles".to_owned(),
            all_day: false,
            recurrence: Some(CalendarRecurrence {
                frequency: RecurrenceFrequency::Weekly,
                interval: Some(1),
                by_day: vec![RecurrenceWeekday::Mo],
                count: Some(10_000),
                expires_at: None,
            }),
            location: None,
            call_id: None,
            attendees: vec![CalendarAttendee {
                actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
                role: Some(CalendarAttendeeRole::Organizer),
                display_name_snapshot: None,
            }],
        };
        fields.validate().unwrap();

        let mut invalid = fields.clone();
        invalid.end = invalid.start.clone();
        assert!(invalid.validate().is_err());

        let mut invalid = fields;
        invalid.recurrence.as_mut().unwrap().count = Some(10_001);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn calendar_rsvp_occurrence_keys_are_canonicalized() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "start".to_owned(),
            Value::String("2026-06-22T16:00:00Z".to_owned()),
        );
        fields.insert(
            "end".to_owned(),
            Value::String("2026-06-22T17:00:00Z".to_owned()),
        );
        fields.insert(
            "timezone".to_owned(),
            Value::String("America/Los_Angeles".to_owned()),
        );
        fields.insert("all_day".to_owned(), Value::Bool(false));

        assert_eq!(
            canonical_calendar_rsvp_occurrence_key(&fields, Some("2026-06-22T16:00:00Z")).unwrap(),
            "2026-06-22T09:00:00[America/Los_Angeles]"
        );
        assert_eq!(
            canonical_calendar_rsvp_occurrence_key(&fields, None).unwrap(),
            "series"
        );
    }

    #[test]
    fn calendar_all_day_occurrence_keys_are_dates() {
        let mut fields = BTreeMap::new();
        fields.insert("start".to_owned(), Value::String("2026-06-22".to_owned()));
        fields.insert("end".to_owned(), Value::String("2026-06-23".to_owned()));
        fields.insert(
            "timezone".to_owned(),
            Value::String("Asia/Shanghai".to_owned()),
        );
        fields.insert("all_day".to_owned(), Value::Bool(true));

        assert_eq!(
            canonical_calendar_rsvp_occurrence_key(
                &fields,
                Some("2026-06-22T00:00:00[Asia/Shanghai]")
            )
            .unwrap(),
            "2026-06-22"
        );
    }

    #[test]
    fn private_key_builders_do_not_leak_raw_target_refs() {
        let ns = b"test namespace key";
        let target_ref = "ck:message:01904100-0000-7000-8000-000000000001";
        let snooze = snooze_account_data_key(ns, target_ref).unwrap();
        assert!(snooze.starts_with("ck.snooze.v1:"));
        assert!(!snooze.contains(target_ref));
        validate_private_account_data_key(&snooze).unwrap();

        let saved = saved_account_data_key(ns, "Inbox", target_ref).unwrap();
        assert!(saved.starts_with("ck.saved.v1:"));
        assert!(!saved.contains("Inbox"));
        assert!(!saved.contains(target_ref));
        validate_private_account_data_key(&saved).unwrap();

        let transfer_id = "0123456789abcdefghijkl";
        let transfer = file_transfer_account_data_key(ns, transfer_id).unwrap();
        assert!(transfer.starts_with("ck.file_transfer.v1:"));
        assert!(!transfer.contains(transfer_id));
        validate_private_account_data_key(&transfer).unwrap();
    }

    #[test]
    fn private_key_validator_rejects_raw_refs() {
        let err = validate_private_account_data_key(
            "ck.draft.v1:message:ck:message:01904100-0000-7000-8000-000000000001:main",
        )
        .unwrap_err();
        assert!(err.to_string().contains("must not leak raw typed refs"));

        assert!(file_transfer_account_data_key(b"ns", "short-transfer").is_err());
        assert!(
            validate_private_account_data_key("ck.file_transfer.v1:ck:blob:sha256:abc").is_err()
        );
    }

    fn file_transfer_record() -> FileTransferRecord {
        FileTransferRecord {
            kind: "file_transfer".to_owned(),
            transfer_id: "0123456789abcdefghijkl".to_owned(),
            blob_ref: format!("ck:blob:sha256:{}", "ab".repeat(32)),
            content_digest: format!("sha256:{}", "ab".repeat(32)),
            blob_size_bytes: 42,
            media_type: "text/plain".to_owned(),
            filename: Some("notes.txt".to_owned()),
            plaintext_size_bytes: 30,
            access: FileTransferAccess {
                visibility: FileTransferAccessVisibility::ActorPrivate,
                recipient_device_ids: Vec::new(),
            },
            encryption: FileTransferEncryption {
                scheme: "ck.file_transfer.encrypted_blob.v1".to_owned(),
                aead_profile: "ck.aead.xchacha20_poly1305.v1".to_owned(),
                nonce: "abc_DEF-012".to_owned(),
                aad: FileTransferAad {
                    schema: FILE_TRANSFER_SCHEMA.to_owned(),
                    purpose: "file_transfer".to_owned(),
                    transfer_id: "0123456789abcdefghijkl".to_owned(),
                    origin_device_id: "ck:device:01904100-0000-7000-8000-000000000002".to_owned(),
                    created_at: "2026-06-22T00:00:00Z".to_owned(),
                },
                key_delivery: FileTransferKeyDelivery::AccountDataWrappedKey {
                    content_key: "abc_DEF-012".to_owned(),
                },
            },
            origin_device_id: "ck:device:01904100-0000-7000-8000-000000000002".to_owned(),
            created_at: "2026-06-22T00:00:00Z".to_owned(),
            updated_hlc: "01970e589d21-0004-a13f9c2e".to_owned(),
            retention_expires_at: "2026-06-29T00:00:00Z".to_owned(),
            state: FileTransferState::Available,
        }
    }

    #[test]
    fn file_transfer_record_validates_and_serializes_canonical_shape() {
        let record = file_transfer_record();
        record.validate().unwrap();
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["kind"], "file_transfer");
        assert_eq!(value["access"]["visibility"], "actor_private");
        assert_eq!(
            value["encryption"]["key_delivery"]["method"],
            "account_data_wrapped_key"
        );
        assert_eq!(
            value["encryption"]["key_delivery"]["content_key"],
            "abc_DEF-012"
        );
        let decoded: FileTransferRecord = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn file_transfer_record_rejects_access_key_delivery_mismatch() {
        let mut record = file_transfer_record();
        record.access.visibility = FileTransferAccessVisibility::DeviceBound;
        record.access.recipient_device_ids =
            vec!["ck:device:01904100-0000-7000-8000-000000000003".to_owned()];
        let err = record.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("device_bound file-transfer requires to_device_wrapped_key")
        );
    }

    #[test]
    fn file_transfer_key_message_validates_record_binding() {
        let mut record = file_transfer_record();
        record.access.visibility = FileTransferAccessVisibility::DeviceBound;
        record.access.recipient_device_ids =
            vec!["ck:device:01904100-0000-7000-8000-000000000003".to_owned()];
        record.encryption.key_delivery = FileTransferKeyDelivery::ToDeviceWrappedKey {
            key_message_kind: FILE_TRANSFER_KEY_MESSAGE_KIND.to_owned(),
        };
        record.validate().unwrap();

        let message = FileTransferKeyMessage {
            transfer_id: record.transfer_id.clone(),
            blob_ref: record.blob_ref.clone(),
            aead_profile: record.encryption.aead_profile.clone(),
            nonce: record.encryption.nonce.clone(),
            content_digest: record.content_digest.clone(),
            key_envelope: FileTransferKeyEnvelope {
                scheme: FILE_TRANSFER_KEY_ENVELOPE_SCHEME.to_owned(),
                enc: "abc_DEF-012".to_owned(),
                ciphertext: "def_ABC-345".to_owned(),
                aad_digest: format!("sha256:{}", "cd".repeat(32)),
            },
            expires_at: "2026-06-22T00:30:00Z".to_owned(),
        };

        message.validate_record_binding(&record).unwrap();

        let mut drifted = message;
        drifted.nonce = "other_nonce".to_owned();
        assert!(
            drifted
                .validate_record_binding(&record)
                .unwrap_err()
                .to_string()
                .contains("nonce mismatch")
        );
    }

    #[test]
    fn file_transfer_record_rejects_blob_digest_drift() {
        let mut record = file_transfer_record();
        record.blob_ref = format!("ck:blob:sha256:{}", "cd".repeat(32));
        let err = record.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("blob_ref digest must match content_digest")
        );
    }

    #[test]
    fn realm_remark_key_and_value_validate_against_spec_shape() {
        let realm_id = test_realm_id("000000000101");
        let key = realm_remark_account_data_key(&realm_id);
        let remark = RealmRemark {
            version: 1,
            subject: RealmRemarkSubject {
                kind: "realm".to_owned(),
                id: realm_id.clone(),
            },
            local_name: "Acme Engineering".to_owned(),
            note: "private reminder".to_owned(),
            tags: vec!["work".to_owned(), "high_signal".to_owned()],
            pinned: true,
            verified_title_at_save: Some("Engineering".to_owned()),
            verified_owning_organizations_at_save: vec![
                Did::new("did:webvh:z6mkfixture:acme.example".to_owned()).unwrap(),
            ],
            saved_at: test_time(0),
            updated_at: Some(test_time(1)),
        };
        let value = serde_json::to_value(&remark).unwrap();

        assert_eq!(parse_realm_remark_account_data_key(&key).unwrap(), realm_id);
        validate_private_account_data_key(&key).unwrap();
        validate_realm_remark_account_data_value(&key, &value).unwrap();
        assert_eq!(value["pinned"], true);
        assert!(value.get("encrypted_payload").is_none());
    }

    #[test]
    fn realm_remark_validator_rejects_mismatch_namespace_and_shared_leak() {
        let realm_id = test_realm_id("000000000201");
        let other_realm_id = test_realm_id("000000000202");
        let key = realm_remark_account_data_key(&realm_id);
        let mut remark = RealmRemark::new(other_realm_id, test_time(0));
        remark.pinned = true;
        let value = serde_json::to_value(&remark).unwrap();

        assert!(validate_realm_remark_account_data_value(&key, &value).is_err());
        assert!(validate_realm_remark_account_data_value("ck.tags.realm.bad", &json!({})).is_err());
        assert!(
            validate_realm_remark_account_data_value(&key, &json!({"tombstone": true})).is_ok()
        );

        let leaked_shared_payload = json!({
            "event_kind": "ck.realm.update",
            "realm_remark": {
                "subject": {"kind": "realm", "id": realm_id.as_str()},
                "pinned": true
            }
        });
        assert!(
            validate_no_realm_remark_private_fields_in_shared_payload(&leaked_shared_payload)
                .is_err()
        );
    }

    #[test]
    fn set_realm_pinned_preserves_fields_and_tombstones_empty_remark() {
        let realm_id = test_realm_id("000000000301");
        let mut existing = RealmRemark::new(realm_id.clone(), test_time(0));
        existing.local_name = "Ops private alias".to_owned();
        existing.note = "keep me".to_owned();
        existing.pinned = true;

        let unpinned =
            set_realm_pinned(realm_id.clone(), Some(&existing), false, test_time(2)).unwrap();
        assert_eq!(unpinned.key, realm_remark_account_data_key(&realm_id));
        let unpinned_remark: RealmRemark =
            serde_json::from_value(unpinned.encrypted_payload.clone()).unwrap();
        assert!(!unpinned_remark.pinned);
        assert_eq!(unpinned_remark.local_name, "Ops private alias");
        assert_eq!(unpinned_remark.note, "keep me");
        validate_realm_remark_account_data_value(&unpinned.key, &unpinned.encrypted_payload)
            .unwrap();

        let pinned = set_realm_pinned(realm_id.clone(), None, true, test_time(3)).unwrap();
        assert_eq!(pinned.encrypted_payload["pinned"], true);
        validate_realm_remark_account_data_value(&pinned.key, &pinned.encrypted_payload).unwrap();

        let empty = set_realm_pinned(realm_id, None, false, test_time(4)).unwrap();
        assert_eq!(empty.encrypted_payload, json!({}));
        validate_realm_remark_account_data_value(&empty.key, &empty.encrypted_payload).unwrap();
    }

    #[test]
    fn wire_field_names_match_current_spec() {
        let draft = DraftSyncValue {
            target_ref: "ck:message:01904100-0000-7000-8000-000000000001".to_owned(),
            kind: DraftKind::Message,
            draft_slot: "main".to_owned(),
            content: json!({"body": "draft"}),
            updated_hlc: "01970e589d21-0000-a13f9c2e".to_owned(),
            origin_device_id: DeviceId::new("ck:device:01904100-0000-7000-8000-000000000002")
                .unwrap(),
            retention_expires_at: "2026-06-07T00:00:00Z".to_owned(),
        };
        let wire = serde_json::to_value(draft).unwrap();
        assert!(wire.get("origin_device_id").is_some());
        assert!(wire.get("device_origin").is_none());

        let search = SearchPolicy {
            enabled_profile_refs: vec![
                SearchProfileRef::ClientIndex,
                SearchProfileRef::BlindIndex,
                SearchProfileRef::ForwardPrivate,
            ],
            allowed_service_dids: vec![Did::new("did:webvh:z6mkfixture:search.example").unwrap()],
            data_classes: vec![
                SearchDataClass::EncryptedIndex,
                SearchDataClass::BlindTokens,
            ],
            index_retention_ms: Some(86_400_000),
            revocation_behavior: Some(SearchRevocationBehavior::FailClosed),
            leakage_class: Some(SearchLeakageClass::ForwardPrivate),
            token_rotation_cadence_ms: Some(3_600_000),
        };
        search.validate().unwrap();
        let wire = serde_json::to_value(search).unwrap();
        assert!(wire.get("enabled_profile_refs").is_some());
        assert!(wire.get("profile_refs").is_none());
        assert_eq!(
            wire["enabled_profile_refs"],
            json!([
                PROFILE_SEARCH_CLIENT_INDEX,
                PROFILE_SEARCH_BLIND_INDEX,
                PROFILE_SEARCH_FORWARD_PRIVATE
            ])
        );
        assert!(wire.get("epoch_id").is_none());
        assert_eq!(wire["leakage_class"], "forward_private");
        assert_eq!(wire["token_rotation_cadence_ms"], 3_600_000);
    }

    #[test]
    fn blind_index_tokens_bind_realm_scope_epoch_and_generation() {
        let index_key = b"realm local search index key";
        let realm_a = test_realm_id("000000000401");
        let realm_b = test_realm_id("000000000402");
        let scope_a = EffectiveScope::Realm {
            realm_id: realm_a.clone(),
        };
        let scope_b = EffectiveScope::Realm {
            realm_id: realm_b.clone(),
        };
        let token_a =
            blind_index_token(index_key, &realm_a, &scope_a, 7, 11, "Release Plan").unwrap();
        let token_b =
            blind_index_token(index_key, &realm_b, &scope_b, 7, 11, "Release Plan").unwrap();
        assert_ne!(token_a, token_b);
        assert_ne!(
            token_a,
            blind_index_token(index_key, &realm_a, &scope_a, 8, 11, "Release Plan").unwrap()
        );
        assert_ne!(
            token_a,
            blind_index_token(index_key, &realm_a, &scope_a, 7, 12, "Release Plan").unwrap()
        );

        let circle_scope = EffectiveScope::Circle {
            realm_id: realm_a.clone(),
            circle_id: test_circle_id("000000000501"),
        };
        assert_ne!(
            token_a,
            blind_index_token(index_key, &realm_a, &circle_scope, 7, 11, "Release Plan").unwrap()
        );
        assert!(blind_index_token(index_key, &realm_b, &scope_a, 7, 11, "Release Plan").is_err());
    }

    #[test]
    fn blind_index_query_uses_integer_epoch_and_unique_tokens() {
        let realm_id = test_realm_id("000000000601");
        let query = build_blind_index_query(
            b"query search index key",
            realm_id.clone(),
            EffectiveScope::Realm {
                realm_id: realm_id.clone(),
            },
            42,
            3,
            ["alpha", "beta"],
        )
        .unwrap();
        query.validate().unwrap();
        let wire = serde_json::to_value(&query).unwrap();
        assert_eq!(wire["epoch_id"].as_u64(), Some(42));
        assert!(wire["epoch_id"].as_str().is_none());
        assert_eq!(wire["blind_tokens"].as_array().unwrap().len(), 2);

        let duplicate = build_blind_index_query(
            b"query search index key",
            realm_id.clone(),
            EffectiveScope::Realm { realm_id },
            42,
            3,
            ["alpha", "alpha"],
        );
        assert!(duplicate.is_err());
    }

    #[test]
    fn encrypted_search_shard_keys_are_opaque_and_realm_bound() {
        let index_key = b"manifest search index key";
        let realm_a = test_realm_id("000000000701");
        let realm_b = test_realm_id("000000000702");
        let shard_a = search_index_shard_key(index_key, &realm_a, 1, b"random shard seed").unwrap();
        let shard_b = search_index_shard_key(index_key, &realm_b, 1, b"random shard seed").unwrap();
        assert_ne!(shard_a, shard_b);
        assert_ne!(
            shard_a,
            search_index_shard_key(index_key, &realm_a, 2, b"random shard seed").unwrap()
        );
        assert!(!shard_a.contains(realm_a.as_str()));

        let manifest = EncryptedIndexManifest {
            realm_id: realm_a,
            index_generation: 1,
            shards: vec![EncryptedShardRef {
                shard_key: shard_a,
                blob_ref: test_blob_id("000000000801"),
                ciphertext_digest:
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_owned(),
            }],
            updated_hlc: "01970e589d21-0000-a13f9c2e".to_owned(),
        };
        manifest.validate().unwrap();
    }
}
