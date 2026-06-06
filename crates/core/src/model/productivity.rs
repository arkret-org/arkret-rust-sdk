use super::*;
use crate::base64url_encode;
use unicode_normalization::UnicodeNormalization;

pub const PROFILE_CALENDAR_EVENT: &str = "ck.profile.calendar_event.v1";
pub const PROFILE_PERSONAL_PRODUCTIVITY: &str = "ck.profile.personal_productivity.v1";
pub const PROFILE_DRAFT_SYNC: &str = "ck.profile.draft_sync.v1";
pub const PROFILE_PINNED_ITEMS: &str = "ck.profile.pinned_items.v1";
pub const PROFILE_DISAPPEARING_MESSAGES: &str = "ck.profile.disappearing_messages.v1";
pub const PROFILE_SEARCH_CLIENT_INDEX: &str = "ck.profile.search.client_index.v1";
pub const PROFILE_SEARCH_BLIND_INDEX: &str = "ck.profile.search.blind_index.v1";

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
        let payload_message_id =
            self.message_payload.get("message_id").and_then(Value::as_str).ok_or_else(|| {
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
    FlowField,
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
    pub event_ref: FlowId,
    pub status: RsvpStatus,
    pub occurrence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<Value>,
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
    pub anchor_hlc: Option<String>,
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
    Flow { id: FlowId },
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchProfileRef {
    #[serde(rename = "ck.profile.search.client_index.v1")]
    ClientIndex,
    #[serde(rename = "ck.profile.search.blind_index.v1")]
    BlindIndex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchDataClass {
    EncryptedIndex,
    BlindTokens,
    Plaintext,
    ReversibleSummary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchRevocationBehavior {
    FailClosed,
    DropStale,
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedShardRef {
    pub shard_key: String,
    pub blob_ref: BlobId,
    pub ciphertext_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedIndexManifest {
    pub realm_id: RealmId,
    pub index_generation: u64,
    pub shards: Vec<EncryptedShardRef>,
    pub updated_hlc: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindIndexQuery {
    pub realm_id: RealmId,
    pub effective_scope: Value,
    pub epoch_id: u64,
    pub index_generation: u64,
    pub blind_tokens: Vec<String>,
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
    Ok(format!("{ACCOUNT_DATA_TYPE_SNOOZE}:{}", target_key(namespace_key, target_ref)?))
}

pub fn saved_account_data_key(
    namespace_key: &[u8],
    collection_title: &str,
    target_ref: &str,
) -> Result<String> {
    let collection_key = collection_key(namespace_key, collection_title)?;
    let target_key = saved_target_key(namespace_key, &collection_key, target_ref)?;
    Ok(format!("{ACCOUNT_DATA_TYPE_SAVED}:{collection_key}:{target_key}"))
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
        DraftKind::FlowField => "flow_field",
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

pub fn target_key(namespace_key: &[u8], target_ref: &str) -> Result<String> {
    validate_object_ref_string("target_ref", target_ref)?;
    Ok(base64url_encode(hmac_sha256(namespace_key, &canonical::canonical_json_bytes(&target_ref)?)))
}

pub fn collection_key(namespace_key: &[u8], collection_title: &str) -> Result<String> {
    let normalized = normalize_collection_title(collection_title)?;
    Ok(base64url_encode(hmac_sha256(namespace_key, normalized.as_bytes())))
}

pub fn saved_target_key(
    namespace_key: &[u8],
    collection_key: &str,
    target_ref: &str,
) -> Result<String> {
    validate_key_segment("collection_key", collection_key)?;
    validate_object_ref_string("target_ref", target_ref)?;
    let mut material = collection_key.as_bytes().to_vec();
    material.extend_from_slice(&canonical::canonical_json_bytes(&target_ref)?);
    Ok(base64url_encode(hmac_sha256(namespace_key, &material)))
}

pub fn realm_key(namespace_key: &[u8], realm_id: &str) -> Result<String> {
    if !realm_id.starts_with("ck:realm:") {
        return Err(Error::Protocol("realm_key input must be ck:realm typed id".to_owned()));
    }
    Ok(base64url_encode(hmac_sha256(namespace_key, &canonical::canonical_json_bytes(&realm_id)?)))
}

pub fn validate_private_account_data_key(key: &str) -> Result<()> {
    if let Some(id) = key.strip_prefix("ck.reminders.v1:") {
        return if !id.is_empty() && !contains_raw_object_ref(id) {
            Ok(())
        } else {
            private_key_error()
        };
    }
    if let Some(planned_message_id) = key.strip_prefix("ck.scheduled_send.v1:") {
        return MessageId::new(planned_message_id.to_owned()).map(|_| ()).map_err(|_| {
            Error::Protocol("scheduled-send key must end with planned_message_id".to_owned())
        });
    }
    if let Some(target_key) = key.strip_prefix("ck.snooze.v1:") {
        return if looks_derived_key(target_key) { Ok(()) } else { private_key_error() };
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
        return if matches!(parts.as_slice(), ["message" | "flow_field", target_key, slot_key] if looks_derived_key(target_key) && !slot_key.is_empty() && !contains_raw_object_ref(slot_key))
        {
            Ok(())
        } else {
            private_key_error()
        };
    }
    if let Some(realm_key) = key.strip_prefix("ck.search.index_manifest.v1:") {
        return if looks_derived_key(realm_key) { Ok(()) } else { private_key_error() };
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
        "ck:flow:",
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
        return Err(Error::Protocol("collection_title must not be empty".to_owned()));
    }
    Ok(normalized)
}

fn validate_object_ref_string(field: &str, value: &str) -> Result<()> {
    let valid = [
        "ck:realm:",
        "ck:space:",
        "ck:flow:",
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
        Err(Error::Protocol(format!("{field} must be a canonical object_ref typed id")))
    }
}

fn validate_key_segment(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.contains(':') || value.contains('/') || value.contains('\\') {
        Err(Error::Protocol(format!("{field} must be an opaque key segment")))
    } else {
        Ok(())
    }
}

fn looks_derived_key(value: &str) -> bool {
    value.len() >= 16
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        ipad[index] ^= key_block[index];
        opad[index] ^= key_block[index];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scheduled_send_validates_payload_id_and_digest() {
        let message_id = MessageId::new("ck:message:01904100-0000-7000-8000-000000000001").unwrap();
        let payload = json!({
            "flow_id": "ck:flow:01904100-0000-7000-8000-000000000002",
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
    }

    #[test]
    fn private_key_validator_rejects_raw_refs() {
        let err = validate_private_account_data_key(
            "ck.draft.v1:message:ck:message:01904100-0000-7000-8000-000000000001:main",
        )
        .unwrap_err();
        assert!(err.to_string().contains("must not leak raw typed refs"));
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
            enabled_profile_refs: vec![SearchProfileRef::ClientIndex],
            allowed_service_dids: vec![Did::new("did:web:search.example").unwrap()],
            data_classes: vec![SearchDataClass::EncryptedIndex],
            index_retention_ms: Some(86_400_000),
            revocation_behavior: Some(SearchRevocationBehavior::FailClosed),
        };
        let wire = serde_json::to_value(search).unwrap();
        assert!(wire.get("enabled_profile_refs").is_some());
        assert!(wire.get("profile_refs").is_none());
    }
}
