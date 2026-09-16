use std::collections::{BTreeMap, BTreeSet};

use arkret_models_crypto::encrypted_envelope::EncryptedEnvelope;
use arkret_wire::base64url::base64url_encode;
use arkret_wire::{
    AccountDataKey, ActorId, BlobId, CallId, CircleId, CommittedEventRef, DeviceId, DidCoreId,
    HPKE_SUITE_X25519_CHACHA20POLY1305_V1, Hash, Hlc, RealmId, Result, ScheduledSendId, SchemaId,
    ScopeRef, SpaceId, StrandId, WireError, canonical,
};
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;

use crate::events_payloads::{
    MessageCreatePayload, notification_inbox_account_data_key_notification_id,
    private_view_account_data_key_view_id,
};

pub const FILE_TRANSFER_KEY_MESSAGE_KIND: &str = "ak.file_transfer.key.v1";

pub const MAX_CALENDAR_ATTENDEES: usize = 1_000;
pub const MAX_CALENDAR_RECURRENCE_COUNT: u64 = 10_000;
/// Single namespace holding the Calendar schedule subtree inside Strand
/// `metadata.fields`. Flat schedule keys and `profile` / `profile_refs`
/// activation impostors are rejected by `strand.schema.json`.
pub const CALENDAR_METADATA_FIELDS_NAMESPACE: &str = "calendar";
/// Media type pinned on `RsvpEntry::encrypted_response`, so a receiver can
/// route the ciphertext to exactly one decrypted schema.
pub const RSVP_RESPONSE_CONTENT_TYPE: &str = "application/vnd.arkret.calendar-rsvp-response+json";
pub const MAX_RSVP_COMMENT_CODE_POINTS: usize = 2_000;
/// Bound on exact committed schedule revisions carried by an RSVP.
pub const MAX_RSVP_SCHEDULE_BASIS_REFS: usize = 128;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PersonalProductivityValue {
    Reminder(ReminderValue),
    ScheduledSend(Box<ScheduledSendValue>),
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledSendValue {
    pub scheduled_send_id: ScheduledSendId,
    pub send_at: String,
    pub message_payload: MessageCreatePayload,
    pub updated_hlc: String,
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
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DraftSyncValue {
    Message {
        target_ref: String,
        draft_slot: String,
        content: BTreeMap<String, Value>,
        updated_hlc: String,
        origin_device_id: DeviceId,
        retention_expires_at: String,
    },
    StrandField {
        target_ref: String,
        draft_slot: String,
        content: BTreeMap<String, Value>,
        updated_hlc: String,
        origin_device_id: DeviceId,
        retention_expires_at: String,
    },
}

impl DraftSyncValue {
    pub fn kind(&self) -> DraftKind {
        match self {
            Self::Message { .. } => DraftKind::Message,
            Self::StrandField { .. } => DraftKind::StrandField,
        }
    }

    pub fn content(&self) -> &BTreeMap<String, Value> {
        match self {
            Self::Message { content, .. } | Self::StrandField { content, .. } => content,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecurrenceFrequency {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecurrenceWeekday {
    Mo,
    Tu,
    We,
    Th,
    Fr,
    Sa,
    Su,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarRecurrenceDay {
    pub day: RecurrenceWeekday,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nth_of_period: Option<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarRecurrence {
    pub frequency: RecurrenceFrequency,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub by_day: Vec<CalendarRecurrenceDay>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_month: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_month_day: Option<Vec<i8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_set_position: Option<Vec<i16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_day_of_week: Option<RecurrenceWeekday>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CalendarEventLocation {
    Plaintext(CalendarLocation),
    Encrypted(Box<EncryptedEnvelope>),
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
    pub actor_id: ActorId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<CalendarAttendeeRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name_snapshot: Option<String>,
}

/// Whole-event schedule status. Orthogonal to the generic Strand `state`
/// (physical lifecycle) and `stage` (business progression) axes: it only says
/// whether the meeting itself stands. Required with no implicit default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarStatus {
    Confirmed,
    Tentative,
    Cancelled,
}

/// Calendar schedule subtree carried at `metadata.fields.calendar` and
/// activated by `ak.schema.calendar_event.v1` in `Strand.schema_refs`.
///
/// The schedule never carries an absolute instant: timed events use a
/// whole-second RFC 8984 `LocalDateTime` resolved through `timezone` plus
/// `tzdb_version`. Field order mirrors `calendar-event.schema.json`.
///
/// [`Self::validate`] covers every rule expressible without the TZDB registry.
/// Resolving `timezone` to the canonical Zone of the pinned release requires
/// that registry, so it lives in `arkret-schema`, which is the layer that
/// embeds spec artifacts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarEventFields {
    pub start: String,
    pub end: String,
    pub timezone: String,
    pub tzdb_version: String,
    pub all_day: bool,
    pub status: CalendarStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recurrence: Option<CalendarRecurrence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<CalendarEventLocation>,
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

/// Decrypted RSVP response. Used directly by [`RsvpEntry::response`] and as the
/// plaintext of [`RsvpEntry::encrypted_response`]; `status` and `comment`
/// therefore always share one encryption boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsvpResponse {
    pub status: RsvpStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl RsvpResponse {
    pub fn validate(&self) -> Result<()> {
        let Some(comment) = &self.comment else {
            return Ok(());
        };
        if comment.is_empty() {
            return Err(WireError::Protocol(
                "rsvp response comment must be omitted rather than empty".to_owned(),
            ));
        }
        if comment.chars().count() > MAX_RSVP_COMMENT_CODE_POINTS {
            return Err(WireError::Protocol(
                "rsvp response comment must be <= 2000 code points".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Complete RSVP value, including the exact committed schedule revisions the
/// responder observed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsvpEntry {
    /// Non-empty schedule revision checkpoint the responder actually observed, as
    /// committed Event references sorted in ascending canonical byte order.
    pub schedule_basis_refs: Vec<CommittedEventRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<RsvpResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_response: Option<Box<EncryptedEnvelope>>,
}

impl RsvpEntry {
    pub fn validate(&self) -> Result<()> {
        match (&self.response, &self.encrypted_response) {
            (Some(response), None) => response.validate()?,
            (None, Some(envelope)) => {
                envelope.validate()?;
                if envelope.content_type != RSVP_RESPONSE_CONTENT_TYPE {
                    return Err(WireError::Protocol(format!(
                        "rsvp encrypted_response content_type must be {RSVP_RESPONSE_CONTENT_TYPE}"
                    )));
                }
            }
            (Some(_), Some(_)) => {
                return Err(WireError::Protocol(
                    "rsvp entry must carry exactly one of response or encrypted_response"
                        .to_owned(),
                ));
            }
            (None, None) => {
                return Err(WireError::Protocol(
                    "rsvp entry must carry either response or encrypted_response".to_owned(),
                ));
            }
        }
        if self.schedule_basis_refs.is_empty() {
            return Err(WireError::Protocol(
                "rsvp entry schedule_basis_refs must be non-empty".to_owned(),
            ));
        }
        if self.schedule_basis_refs.len() > MAX_RSVP_SCHEDULE_BASIS_REFS {
            return Err(WireError::Protocol(
                "rsvp entry schedule_basis_refs must contain <= 128 entries".to_owned(),
            ));
        }
        // Canonical ascending byte order is a shape-admission condition that
        // JSON Schema cannot express; accepting an unsorted basis would fork
        // both the accepted set and the signed canonical bytes.
        let ordered = self
            .schedule_basis_refs
            .windows(2)
            .all(|pair| pair[0] < pair[1]);
        if !ordered {
            return Err(WireError::Protocol(
                "rsvp entry schedule_basis_refs must be unique and sorted in ascending canonical byte order"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsvpSetPayload {
    pub event_ref: StrandId,
    /// `None` is the whole series; `Some` is a canonical recurrence instance
    /// key produced by [`CalendarEventFields::canonical_occurrence_key`].
    pub occurrence: Option<String>,
    pub entry: RsvpEntry,
}

impl RsvpSetPayload {
    pub fn validate(&self) -> Result<()> {
        if let Some(occurrence) = &self.occurrence {
            validate_canonical_occurrence_key(occurrence)?;
        }
        self.entry.validate()
    }
}

impl CalendarRecurrence {
    pub fn validate(&self) -> Result<()> {
        if self.count.is_some() && self.until.is_some() {
            return Err(WireError::Protocol(
                "calendar recurrence count and until are mutually exclusive".to_owned(),
            ));
        }
        if self
            .count
            .is_some_and(|count| !(1..=MAX_CALENDAR_RECURRENCE_COUNT).contains(&count))
        {
            return Err(WireError::Protocol(
                "calendar recurrence count must be in 1..=10000".to_owned(),
            ));
        }
        if self.interval == Some(0) {
            return Err(WireError::Protocol(
                "calendar recurrence interval must be positive".to_owned(),
            ));
        }
        // `by_day` is `#[serde(default)]`, so an absent field and a wire `[]`
        // both deserialize to an empty Vec. The empty-array form is rejected by
        // `calendar-event.schema.json` (`minItems: 1`) before this validator
        // runs; only the wire-level check can tell the two apart.
        require_unique("calendar recurrence by_day", &self.by_day)?;
        for day in &self.by_day {
            if day.nth_of_period == Some(0)
                || day
                    .nth_of_period
                    .is_some_and(|nth| !(-366..=366).contains(&nth))
            {
                return Err(WireError::Protocol(
                    "calendar recurrence nth_of_period must be in -366..=-1 or 1..=366".to_owned(),
                ));
            }
        }
        if let Some(months) = &self.by_month {
            if months.is_empty()
                || months.iter().any(|month| {
                    month.parse::<u8>().map_or(true, |number| {
                        !(1..=12).contains(&number) || month != &number.to_string()
                    })
                })
            {
                return Err(WireError::Protocol(
                    "calendar recurrence by_month must contain canonical month numbers 1..=12"
                        .to_owned(),
                ));
            }
            require_unique("calendar recurrence by_month", months)?;
        }
        if let Some(days) = &self.by_month_day {
            if days.is_empty()
                || days
                    .iter()
                    .any(|day| *day == 0 || !(-31..=31).contains(day))
            {
                return Err(WireError::Protocol(
                    "calendar recurrence by_month_day must contain non-zero values in -31..=31"
                        .to_owned(),
                ));
            }
            require_unique("calendar recurrence by_month_day", days)?;
        }
        if let Some(positions) = &self.by_set_position {
            if positions.is_empty()
                || positions
                    .iter()
                    .any(|position| *position == 0 || !(-366..=366).contains(position))
            {
                return Err(WireError::Protocol(
                    "calendar recurrence by_set_position must contain non-zero values in -366..=366"
                        .to_owned(),
                ));
            }
            require_unique("calendar recurrence by_set_position", positions)?;
        }
        self.validate_field_combinations()?;
        Ok(())
    }

    /// RFC 8984 subset companion preconditions. Unsatisfied combinations are
    /// rejected outright rather than accepted-and-ignored.
    fn validate_field_combinations(&self) -> Result<()> {
        let daily_or_weekly = matches!(
            self.frequency,
            RecurrenceFrequency::Daily | RecurrenceFrequency::Weekly
        );
        if daily_or_weekly && self.by_day.iter().any(|day| day.nth_of_period.is_some()) {
            return Err(WireError::Protocol(
                "calendar recurrence nth_of_period is only allowed for monthly or yearly frequency"
                    .to_owned(),
            ));
        }
        if self.frequency == RecurrenceFrequency::Weekly && self.by_month_day.is_some() {
            return Err(WireError::Protocol(
                "calendar recurrence by_month_day must not be combined with weekly frequency"
                    .to_owned(),
            ));
        }
        if self.by_set_position.is_some()
            && self.by_day.is_empty()
            && self.by_month.is_none()
            && self.by_month_day.is_none()
        {
            return Err(WireError::Protocol(
                "calendar recurrence by_set_position requires at least one of by_day, by_month or by_month_day"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Validates `until` against the branch selected by `all_day`, and against
    /// the base start it must not precede.
    fn validate_until(&self, all_day: bool, base_start: &str) -> Result<()> {
        let Some(until) = &self.until else {
            return Ok(());
        };
        if all_day {
            let until_date = parse_calendar_date(until, "calendar recurrence until")?;
            let start_date = parse_calendar_date(base_start, "calendar start")?;
            if until_date < start_date {
                return Err(WireError::Protocol(
                    "calendar recurrence until must not precede the base start".to_owned(),
                ));
            }
        } else {
            let until_local = parse_calendar_local_date_time(until, "calendar recurrence until")?;
            let start_local = parse_calendar_local_date_time(base_start, "calendar start")?;
            if until_local < start_local {
                return Err(WireError::Protocol(
                    "calendar recurrence until must not precede the base start".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl CalendarLocation {
    pub fn validate(&self) -> Result<()> {
        let fields = [
            ("title", self.title.as_deref()),
            ("address", self.address.as_deref()),
            ("geo_uri", self.geo_uri.as_deref()),
            ("url", self.url.as_deref()),
        ];
        if fields.iter().all(|(_, value)| value.is_none()) {
            return Err(WireError::Protocol(
                "calendar location must contain at least one field".to_owned(),
            ));
        }
        for (field, value) in fields {
            let Some(value) = value else {
                continue;
            };
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(WireError::Protocol(format!(
                    "calendar location {field} must not be empty"
                )));
            }
            if field == "geo_uri" && !trimmed.starts_with("geo:") {
                return Err(WireError::Protocol(
                    "calendar location geo_uri must start with geo:".to_owned(),
                ));
            }
            if field == "url" && !looks_like_uri(trimmed) {
                return Err(WireError::Protocol(
                    "calendar location url must be a URI".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl CalendarEventLocation {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Plaintext(location) => location.validate(),
            Self::Encrypted(envelope) => Ok(envelope.validate()?),
        }
    }
}

impl CalendarEventFields {
    /// Every schedule rule expressible without the TZDB registry.
    ///
    /// Resolving `timezone` to the canonical Zone of the pinned release, and
    /// checking that `tzdb_version` names a registered release, require the
    /// registry and therefore live in `arkret-schema`.
    pub fn validate(&self) -> Result<()> {
        parse_calendar_timezone(&self.timezone)?;
        validate_tzdb_version(&self.tzdb_version)?;
        // Both branches are half-open [start, end), so end is strictly later
        // than start in each. v1 dropped the inclusive all-day `end == start`
        // special case.
        if self.all_day {
            let start = parse_calendar_date(&self.start, "calendar start")?;
            let end = parse_calendar_date(&self.end, "calendar end")?;
            if end <= start {
                return Err(WireError::Protocol(
                    "calendar all_day end must be strictly later than start; a single-day event spells end as the following date"
                        .to_owned(),
                ));
            }
        } else {
            let timezone = parse_calendar_timezone(&self.timezone)?;
            let start = resolve_local_to_instant(
                parse_calendar_local_date_time(&self.start, "calendar start")?,
                timezone,
            )?;
            let end = resolve_local_to_instant(
                parse_calendar_local_date_time(&self.end, "calendar end")?,
                timezone,
            )?;
            if end <= start {
                return Err(WireError::Protocol(
                    "calendar end instant must be later than start instant under the pinned timezone rules"
                        .to_owned(),
                ));
            }
        }
        if let Some(recurrence) = &self.recurrence {
            recurrence.validate()?;
            recurrence.validate_until(self.all_day, &self.start)?;
        }
        if let Some(location) = &self.location {
            location.validate()?;
        }
        if self.attendees.len() > MAX_CALENDAR_ATTENDEES {
            return Err(WireError::Protocol(
                "calendar attendees must contain <= 1000 entries".to_owned(),
            ));
        }
        let organizers = self
            .attendees
            .iter()
            .filter(|attendee| attendee.role == Some(CalendarAttendeeRole::Organizer))
            .count();
        if organizers > 1 {
            return Err(WireError::Protocol(
                "calendar attendees must contain at most one organizer".to_owned(),
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

    /// Canonical RSVP instance key for `occurrence`, or `None` for the whole
    /// series.
    ///
    /// Series is JSON `null` on the wire and `None` here; there is no `"series"`
    /// sentinel, because the signed composite cell subject keeps a real JSON
    /// null and a sentinel string would address a different cell.
    pub fn canonical_occurrence_key(&self, occurrence: Option<&str>) -> Result<Option<String>> {
        let Some(occurrence) = occurrence else {
            return Ok(None);
        };
        if self.all_day {
            let date = parse_calendar_date(occurrence, "calendar occurrence")?;
            return Ok(Some(date.format("%Y-%m-%d").to_string()));
        }
        let (local, zone) = split_bracketed_occurrence(occurrence)?;
        if zone != self.timezone {
            return Err(WireError::Protocol(
                "calendar occurrence zone must equal the signed calendar timezone".to_owned(),
            ));
        }
        Ok(Some(format!(
            "{}[{}]",
            local.format("%Y-%m-%dT%H:%M:%S"),
            self.timezone
        )))
    }

    /// Base interval length. Recurring timed events reuse this elapsed duration
    /// for every occurrence; v1 has no ISO duration wire field, so an
    /// implementation MUST NOT pick between elapsed and wall-clock deltas.
    pub fn base_duration(&self) -> Result<chrono::Duration> {
        let timezone = parse_calendar_timezone(&self.timezone)?;
        if self.all_day {
            let start = parse_calendar_date(&self.start, "calendar start")?;
            let end = parse_calendar_date(&self.end, "calendar end")?;
            return Ok(chrono::Duration::days((end - start).num_days()));
        }
        let start = resolve_local_to_instant(
            parse_calendar_local_date_time(&self.start, "calendar start")?,
            timezone,
        )?;
        let end = resolve_local_to_instant(
            parse_calendar_local_date_time(&self.end, "calendar end")?,
            timezone,
        )?;
        Ok(end - start)
    }
}

fn looks_like_uri(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
        && !rest.is_empty()
        && !value.chars().any(char::is_whitespace)
}

/// Flat schedule keys and activation impostors that MUST NOT appear at
/// the `metadata.fields` root. `strand.schema.json` rejects them on the wire;
/// this list lets reducers produce the same decision without re-running the
/// full JSON Schema.
pub const FORBIDDEN_CALENDAR_METADATA_FIELD_KEYS: &[&str] = &[
    "all_day",
    "attendees",
    "end",
    "profile",
    "profile_refs",
    "recurrence",
    "start",
    "timezone",
];

/// Reads the Calendar schedule subtree from Strand `metadata.fields`.
///
/// The single activation path is `schema_refs` containing
/// `ak.schema.calendar_event.v1` plus this `calendar` namespace; the two MUST
/// co-occur in both directions on the post-patch object. This helper only sees
/// `fields`, so it reports whether the subtree is present and well-formed —
/// the co-presence half is enforced by the caller that also holds
/// `schema_refs`.
pub fn calendar_event_fields_from_metadata_fields(
    fields: &BTreeMap<String, Value>,
) -> Result<Option<CalendarEventFields>> {
    for key in FORBIDDEN_CALENDAR_METADATA_FIELD_KEYS {
        if fields.contains_key(*key) {
            return Err(WireError::Protocol(format!(
                "metadata.fields.{key} is a forbidden calendar activation impostor; the canonical path is metadata.fields.{CALENDAR_METADATA_FIELDS_NAMESPACE}"
            )));
        }
    }
    let Some(subtree) = fields.get(CALENDAR_METADATA_FIELDS_NAMESPACE) else {
        return Ok(None);
    };
    let parsed = serde_json::from_value::<CalendarEventFields>(subtree.clone())
        .map_err(|error| WireError::Protocol(format!("calendar event fields invalid: {error}")))?;
    Ok(Some(parsed))
}

pub fn validate_calendar_event_metadata_fields(fields: &BTreeMap<String, Value>) -> Result<()> {
    if let Some(calendar_fields) = calendar_event_fields_from_metadata_fields(fields)? {
        calendar_fields.validate()?;
    }
    Ok(())
}

/// Producer-side canonicalization of an RSVP occurrence key.
///
/// Receivers MUST NOT call this to repair a signed value: a non-canonical key
/// on the wire is rejected with `rsvp_occurrence_not_canonical`, because the
/// cell subject derives from the signed bytes.
pub fn canonical_calendar_rsvp_occurrence_key(
    fields: &BTreeMap<String, Value>,
    occurrence: Option<&str>,
) -> Result<Option<String>> {
    let Some(calendar_fields) = calendar_event_fields_from_metadata_fields(fields)? else {
        return Err(WireError::Protocol(
            "rsvp event_ref must reference a calendar event".to_owned(),
        ));
    };
    calendar_fields.validate()?;
    calendar_fields.canonical_occurrence_key(occurrence)
}

/// Receiver-side syntax check for a signed `payload.occurrence`.
pub fn validate_canonical_occurrence_key(occurrence: &str) -> Result<()> {
    if parse_calendar_date(occurrence, "calendar occurrence").is_ok() {
        return Ok(());
    }
    let (local, zone) = split_bracketed_occurrence(occurrence)?;
    let rendered = format!("{}[{}]", local.format("%Y-%m-%dT%H:%M:%S"), zone);
    if rendered != occurrence {
        return Err(WireError::Protocol(
            "calendar occurrence key is not canonical".to_owned(),
        ));
    }
    Ok(())
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
    pub note: Option<EncryptedEnvelope>,
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
    #[serde(rename = "ak.profile.search.client_index.v1")]
    ClientIndex,
    #[serde(rename = "ak.profile.search.blind_index.v1")]
    BlindIndex,
    #[serde(rename = "ak.profile.search.forward_private.v1")]
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
    pub allowed_service_ids: Vec<DidCoreId>,
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
        require_unique("allowed_service_ids", &self.allowed_service_ids)?;
        require_unique("data_classes", &self.data_classes)?;
        if self.data_classes.is_empty() {
            return Err(WireError::Protocol(
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
            return Err(WireError::Protocol(
                "search_policy forward_private profile requires the blind_index profile".to_owned(),
            ));
        }
        let leakage_class = self
            .leakage_class
            .unwrap_or(SearchLeakageClass::DeterministicToken);
        if leakage_class == SearchLeakageClass::AccessHiding {
            return Err(WireError::Protocol(
                "search_policy.leakage_class access_hiding requires an explicit access-hiding profile"
                    .to_owned(),
            ));
        }
        if forward_private_enabled && leakage_class != SearchLeakageClass::ForwardPrivate {
            return Err(WireError::Protocol(
                "search_policy forward_private profile requires leakage_class forward_private"
                    .to_owned(),
            ));
        }
        if leakage_class == SearchLeakageClass::ForwardPrivate && !forward_private_enabled {
            return Err(WireError::Protocol(
                "search_policy leakage_class forward_private requires the forward_private profile"
                    .to_owned(),
            ));
        }
        if forward_private_enabled && self.token_rotation_cadence_ms.is_none() {
            return Err(WireError::Protocol(
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
            return Err(WireError::Protocol(
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
            return Err(WireError::Protocol(
                "encrypted index manifest requires at least one shard".to_owned(),
            ));
        }
        let mut shard_keys = BTreeSet::new();
        for shard in &self.shards {
            shard.validate()?;
            if !shard_keys.insert(&shard.shard_key) {
                return Err(WireError::Protocol(
                    "encrypted index manifest shard_key values must be unique".to_owned(),
                ));
            }
        }
        if self.updated_hlc.trim().is_empty() {
            return Err(WireError::Protocol(
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
    pub status: FileTransferStatus,
}

impl FileTransferRecord {
    pub fn validate(&self) -> Result<()> {
        if self.kind != "file_transfer" {
            return Err(WireError::Protocol(
                "file-transfer record kind must be file_transfer".to_owned(),
            ));
        }
        validate_file_transfer_id(&self.transfer_id)?;
        validate_blob_ref(&self.blob_ref)?;
        validate_media_type(&self.media_type)?;
        if let Some(filename) = &self.filename {
            let len = filename.chars().count();
            if filename.trim().is_empty() || len > 255 {
                return Err(WireError::Protocol(
                    "file-transfer filename must be 1-255 non-blank chars".to_owned(),
                ));
            }
        }
        self.access.validate()?;
        self.encryption.validate()?;
        if let Some(segment_bytes) = self.encryption.segment_bytes {
            arkret_models_crypto::stream_segment_count(self.plaintext_size_bytes, segment_bytes)?;
        }
        DeviceId::new(self.origin_device_id.clone()).map_err(|_| {
            WireError::Protocol("file-transfer origin_device_id must be a ak:device id".to_owned())
        })?;
        canonical::validate_timestamp_canonical(&self.created_at)?;
        Hlc::new(self.updated_hlc.clone()).map_err(|_| {
            WireError::Protocol("file-transfer updated_hlc must be a canonical HLC".to_owned())
        })?;
        canonical::validate_timestamp_canonical(&self.retention_expires_at)?;
        self.validate_aad_binding()?;
        self.validate_access_key_delivery_binding()
    }

    fn validate_aad_binding(&self) -> Result<()> {
        let aad = &self.encryption.aad;
        if aad.schema != SchemaId::FILE_TRANSFER_V1 {
            return Err(WireError::Protocol(
                "file-transfer AAD schema must be ak.schema.file_transfer.v1".to_owned(),
            ));
        }
        if aad.purpose != "file_transfer" {
            return Err(WireError::Protocol(
                "file-transfer AAD purpose must be file_transfer".to_owned(),
            ));
        }
        if aad.transfer_id != self.transfer_id {
            return Err(WireError::Protocol(
                "file-transfer AAD transfer_id must match record transfer_id".to_owned(),
            ));
        }
        if aad.origin_device_id != self.origin_device_id {
            return Err(WireError::Protocol(
                "file-transfer AAD origin_device_id must match record origin_device_id".to_owned(),
            ));
        }
        if aad.created_at != self.created_at {
            return Err(WireError::Protocol(
                "file-transfer AAD created_at must match record created_at".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_access_key_delivery_binding(&self) -> Result<()> {
        match self.access.visibility {
            FileTransferAccessVisibility::ActorPrivate => {
                if !self.access.recipient_device_ids.is_empty() {
                    return Err(WireError::Protocol(
                        "actor_private file-transfer access must not list recipient devices"
                            .to_owned(),
                    ));
                }
                if !matches!(
                    &self.encryption.key_delivery,
                    FileTransferKeyDelivery::AccountDataWrappedKey { .. }
                ) {
                    return Err(WireError::Protocol(
                        "actor_private file-transfer requires account_data_wrapped_key".to_owned(),
                    ));
                }
            }
            FileTransferAccessVisibility::DeviceBound => {
                if self.access.recipient_device_ids.is_empty() {
                    return Err(WireError::Protocol(
                        "device_bound file-transfer access requires recipient_device_ids"
                            .to_owned(),
                    ));
                }
                if !matches!(
                    &self.encryption.key_delivery,
                    FileTransferKeyDelivery::ToDeviceWrappedKey { .. }
                ) {
                    return Err(WireError::Protocol(
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
                WireError::Protocol(
                    "file-transfer recipient_device_ids must contain ak:device ids".to_owned(),
                )
            })?;
            if !seen.insert(device_id) {
                return Err(WireError::Protocol(
                    "file-transfer recipient_device_ids must be unique".to_owned(),
                ));
            }
        }
        if self.recipient_device_ids.len() > 1_000 {
            return Err(WireError::Protocol(
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
    #[serde(
        default,
        deserialize_with = "file_transfer_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub nonce: Option<String>,
    #[serde(
        default,
        deserialize_with = "file_transfer_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub nonce_prefix: Option<String>,
    #[serde(
        default,
        deserialize_with = "file_transfer_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub segment_bytes: Option<u32>,
    pub aad: FileTransferAad,
    pub key_delivery: FileTransferKeyDelivery,
}

fn file_transfer_present_value<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl FileTransferEncryption {
    pub fn validate(&self) -> Result<()> {
        if self.aead_profile != arkret_wire::AeadProfileId::XCHACHA20_POLY1305_V1 {
            return Err(WireError::Protocol(
                "file-transfer AEAD profile mismatch".to_owned(),
            ));
        }
        let (nonce, length) = match self.scheme.as_str() {
            arkret_wire::BLOB_SCHEME_WHOLE_FILE_AEAD_V1
                if self.nonce_prefix.is_none() && self.segment_bytes.is_none() =>
            {
                (self.nonce.as_deref(), 24)
            }
            arkret_wire::BLOB_SCHEME_STREAM_AEAD_V1 if self.nonce.is_none() => {
                let segment_bytes = self.segment_bytes.ok_or_else(|| {
                    WireError::Protocol("file-transfer stream requires segment_bytes".into())
                })?;
                arkret_models_crypto::stream_segment_count(0, segment_bytes)?;
                (self.nonce_prefix.as_deref(), 19)
            }
            _ => {
                return Err(WireError::Protocol(
                    "file-transfer encryption scheme/fields mismatch".into(),
                ));
            }
        };
        let nonce = nonce
            .ok_or_else(|| WireError::Protocol("file-transfer nonce material missing".into()))?;
        validate_base64url("file-transfer nonce material", nonce)?;
        if arkret_wire::base64url::base64url_decode(nonce)?.len() != length {
            return Err(WireError::Protocol(
                "file-transfer nonce material has invalid length".into(),
            ));
        }
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
        if self.schema != SchemaId::FILE_TRANSFER_V1 {
            return Err(WireError::Protocol(
                "file-transfer AAD schema must be ak.schema.file_transfer.v1".to_owned(),
            ));
        }
        if self.purpose != "file_transfer" {
            return Err(WireError::Protocol(
                "file-transfer AAD purpose must be file_transfer".to_owned(),
            ));
        }
        validate_file_transfer_id(&self.transfer_id)?;
        DeviceId::new(self.origin_device_id.clone()).map_err(|_| {
            WireError::Protocol(
                "file-transfer AAD origin_device_id must be a ak:device id".to_owned(),
            )
        })?;
        Ok(canonical::validate_timestamp_canonical(&self.created_at)?)
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
                    Err(WireError::Protocol(
                        "to_device_wrapped_key key_message_kind must be ak.file_transfer.key.v1"
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
    pub key_envelope: FileTransferKeyEnvelope,
    pub expires_at: String,
}

impl FileTransferKeyMessage {
    pub fn validate(&self) -> Result<()> {
        validate_file_transfer_id(&self.transfer_id)?;
        self.key_envelope.validate()?;
        Ok(canonical::validate_timestamp_canonical(&self.expires_at)?)
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
        if self.scheme != HPKE_SUITE_X25519_CHACHA20POLY1305_V1 {
            return Err(WireError::Protocol(
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
pub enum FileTransferStatus {
    Available,
    Downloaded,
    Dismissed,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindIndexQuery {
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub epoch: u64,
    pub index_generation: u64,
    pub blind_tokens: Vec<String>,
}

impl BlindIndexQuery {
    pub fn validate(&self) -> Result<()> {
        if self.effective_scope.realm_id() != &self.realm_id {
            return Err(WireError::Protocol(
                "blind_index_query.effective_scope must be bound to realm_id".to_owned(),
            ));
        }
        if self.blind_tokens.is_empty() {
            return Err(WireError::Protocol(
                "blind_index_query.blind_tokens must not be empty".to_owned(),
            ));
        }
        let mut seen = BTreeSet::new();
        for token in &self.blind_tokens {
            if !looks_derived_key(token) {
                return Err(WireError::Protocol(
                    "blind_index_query.blind_tokens must be opaque derived tokens".to_owned(),
                ));
            }
            if !seen.insert(token) {
                return Err(WireError::Protocol(
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
    pub verified_owning_organization_ids_at_save: Vec<DidCoreId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub saved_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRemarkSubject {
    pub kind: String,
    pub principal_id: DidCoreId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRemark {
    pub version: u32,
    pub subject: ContactRemarkSubject,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub petname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub pinned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_handle_at_save: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_display_name: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub saved_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl ContactRemark {
    pub fn new(
        principal_id: DidCoreId,
        petname: impl Into<String>,
        saved_at: DateTime<Utc>,
    ) -> Self {
        Self {
            version: 1,
            subject: ContactRemarkSubject {
                kind: "human".to_owned(),
                principal_id,
            },
            petname: petname.into(),
            note: String::new(),
            tags: Vec::new(),
            pinned: false,
            verified_handle_at_save: None,
            confirmed_display_name: None,
            saved_at,
            updated_at: None,
        }
    }

    pub fn with_pinned_preserving_fields(
        principal_id: DidCoreId,
        existing: Option<&Self>,
        pinned: bool,
        updated_at: DateTime<Utc>,
    ) -> Self {
        let mut next = existing
            .cloned()
            .unwrap_or_else(|| Self::new(principal_id.clone(), "", updated_at));
        next.version = 1;
        next.subject = ContactRemarkSubject {
            kind: "human".to_owned(),
            principal_id,
        };
        next.pinned = pinned;
        next.updated_at = Some(updated_at);
        next
    }

    /// Initializes the identity-confirmation baseline without inventing a
    /// holder-authored petname. The caller must already have validated the
    /// exact signed PCR profile Event behind the display value, through
    /// [`crate::actor_profile_resolution::validate_resolved_actor_profile`];
    /// ordinary profile state carries no independent finality artifact to wait for.
    pub fn new_with_confirmed_display_name(
        principal_id: DidCoreId,
        confirmed_display_name: impl Into<String>,
        saved_at: DateTime<Utc>,
    ) -> Self {
        let mut remark = Self::new(principal_id, "", saved_at);
        remark.confirmed_display_name = Some(confirmed_display_name.into());
        remark
    }

    /// Refreshes only the evidence-backed identity-confirmation baseline and
    /// preserves every holder-authored remark field for whole-value CAS.
    pub fn with_confirmed_display_name_preserving_fields(
        principal_id: DidCoreId,
        existing: Option<&Self>,
        confirmed_display_name: impl Into<String>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        let mut next = existing
            .cloned()
            .unwrap_or_else(|| Self::new(principal_id.clone(), "", updated_at));
        next.version = 1;
        next.subject = ContactRemarkSubject {
            kind: "human".to_owned(),
            principal_id,
        };
        next.confirmed_display_name = Some(confirmed_display_name.into());
        next.updated_at = Some(updated_at);
        next
    }

    pub fn is_empty(&self) -> bool {
        self.petname.trim().is_empty()
            && self.note.trim().is_empty()
            && self.tags.is_empty()
            && !self.pinned
            && self.verified_handle_at_save.is_none()
            && self.confirmed_display_name.is_none()
    }

    pub fn display_name<'a>(&'a self, fallback: &'a str) -> &'a str {
        let trimmed = self.petname.trim();
        if trimmed.is_empty() {
            fallback
        } else {
            trimmed
        }
    }

    pub fn validate_for_account_data_key(&self, namespace_key: &[u8], key: &str) -> Result<()> {
        parse_contact_remark_account_data_key(key)?;
        if self.version != 1 {
            return Err(WireError::Protocol(
                "contact remark version must be 1".to_owned(),
            ));
        }
        if self.subject.kind != "human" {
            return Err(WireError::Protocol(
                "contact remark subject.kind must be human".to_owned(),
            ));
        }
        let expected_key =
            contact_remark_account_data_key(namespace_key, &self.subject.principal_id)?;
        if key != expected_key {
            return Err(WireError::Protocol(
                "contact remark subject.principal_id does not recompute to its account-data key"
                    .to_owned(),
            ));
        }
        if !self.petname.is_empty() {
            arkret_wire::validate_single_line_display_text(&self.petname, 128)?;
        }
        if let Some(display_name) = self.confirmed_display_name.as_deref() {
            arkret_wire::validate_single_line_display_text(display_name, 128)?;
        }
        if self.note.chars().count() > 4_096 {
            return Err(WireError::Protocol(
                "contact remark note exceeds 4096 code points".to_owned(),
            ));
        }
        if let Some(handle) = self.verified_handle_at_save.as_deref() {
            arkret_wire::validate_canonical_handle(handle)?;
        }
        for tag in &self.tags {
            validate_contact_remark_tag(tag)?;
        }
        Ok(())
    }
}

/// Section 3.1 tag namespace, applied as a domain rule.
///
/// The registered schema only sees an array of strings, so passing it is not
/// evidence that the namespace holds: `ak.*` is reserved for the specification
/// and a client extension MUST use a reverse-domain `<vendor>.*` prefix. An
/// unrecognised `ak.*` tag is preserved rather than dropped, so this accepts
/// any well-formed reserved tag. Ruling
/// `review/spec-done/2026-09-05-1730-contact-remark-value-object-is-prose-only.md`.
fn validate_contact_remark_tag(tag: &str) -> Result<()> {
    let invalid =
        |reason: &str| WireError::Protocol(format!("contact remark tag {tag:?} {reason}"));
    if tag.is_empty() {
        return Err(invalid("is empty"));
    }
    let segments: Vec<&str> = tag.split('.').collect();
    if segments.len() < 2 {
        return Err(invalid(
            "is not namespaced: use a reserved ak.* tag or a reverse-domain <vendor>.* tag",
        ));
    }
    if segments.iter().any(|segment| {
        segment.is_empty()
            || !segment
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    }) {
        return Err(invalid("has an empty or non-canonical segment"));
    }
    Ok(())
}

pub fn contact_remark_account_data_key(
    namespace_key: &[u8],
    principal_id: &DidCoreId,
) -> Result<String> {
    let material = json!([AccountDataKey::CONTACTS_ACTOR, principal_id.as_str()]);
    let principal_key = base64url_encode(hmac_sha256(
        namespace_key,
        &canonical::canonical_json_bytes(&material)?,
    ));
    Ok(format!(
        "{}.{principal_key}",
        AccountDataKey::CONTACTS_ACTOR
    ))
}

pub fn parse_contact_remark_account_data_key(key: &str) -> Result<String> {
    let principal_key = key
        .strip_prefix(&format!(
            "{accountdatakey_contacts_actor}.",
            accountdatakey_contacts_actor = AccountDataKey::CONTACTS_ACTOR
        ))
        .ok_or_else(|| WireError::Protocol("invalid contact remark account-data key".to_owned()))?;
    if !looks_derived_key(principal_key) {
        return Err(WireError::Protocol(
            "contact remark key must end with a 43-character opaque base64url principal_key"
                .to_owned(),
        ));
    }
    Ok(principal_key.to_owned())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistPayload {
    pub version: u64,
    pub entries: Vec<AccountBlocklistPayloadEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistPayloadEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<arkret_wire::NonEmptyString>,
    pub target: AccountBlocklistTarget,
    pub mode: AccountBlocklistMode,
    pub applies_to: Vec<AccountBlocklistSurface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<arkret_wire::NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountBlocklistMode {
    Block,
    Mute,
    Hide,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountBlocklistSurface {
    Messages,
    Mentions,
    Dm,
    Calls,
    Contacts,
    Applets,
    Presence,
    Notifications,
    Directory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountBlocklistActorTargetKind {
    Actor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountBlocklistValueTargetKind {
    Handle,
    Domain,
    Keyword,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountBlocklistDeviceTargetKind {
    Device,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountBlocklistAppletTargetKind {
    Applet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistActorTarget {
    pub kind: AccountBlocklistActorTargetKind,
    pub actor_id: ActorId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistDeviceIdTarget {
    pub kind: AccountBlocklistDeviceTargetKind,
    pub object_ref: DeviceId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistDeviceVerificationMethodTarget {
    pub kind: AccountBlocklistDeviceTargetKind,
    pub value: arkret_wire::DidUrl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistAppletTarget {
    pub kind: AccountBlocklistAppletTargetKind,
    pub object_ref: arkret_wire::AppletId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistValueTarget {
    pub kind: AccountBlocklistValueTargetKind,
    pub value: arkret_wire::NonEmptyString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccountBlocklistTarget {
    Actor(AccountBlocklistActorTarget),
    DeviceId(AccountBlocklistDeviceIdTarget),
    DeviceVerificationMethod(AccountBlocklistDeviceVerificationMethodTarget),
    Applet(AccountBlocklistAppletTarget),
    Value(AccountBlocklistValueTarget),
}

impl AccountBlocklistPayload {
    pub fn validate(&self) -> Result<()> {
        if self.version == 0 {
            return Err(WireError::Protocol(
                "account blocklist version must be at least 1".to_owned(),
            ));
        }
        if self.entries.len() > 4096 {
            return Err(WireError::Protocol(
                "account blocklist entries exceed 4096".to_owned(),
            ));
        }
        let mut entry_ids = BTreeSet::new();
        let mut target_surfaces = BTreeSet::new();
        for entry in &self.entries {
            entry.validate()?;
            if let Some(entry_id) = &entry.entry_id
                && !entry_ids.insert(entry_id.as_str())
            {
                return Err(WireError::Protocol(
                    "account blocklist entry_id values must be unique".to_owned(),
                ));
            }
            let target = canonical::canonical_json_bytes(&entry.target)?;
            for surface in &entry.applies_to {
                if !target_surfaces.insert((target.clone(), *surface)) {
                    return Err(WireError::Protocol(
                        "account blocklist target surfaces must not overlap".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl AccountBlocklistPayloadEntry {
    pub fn validate(&self) -> Result<()> {
        if self.applies_to.is_empty() {
            return Err(WireError::Protocol(
                "account blocklist applies_to must not be empty".to_owned(),
            ));
        }
        let unique_surfaces = self.applies_to.iter().copied().collect::<BTreeSet<_>>();
        if unique_surfaces.len() != self.applies_to.len() {
            return Err(WireError::Protocol(
                "account blocklist applies_to must contain unique surfaces".to_owned(),
            ));
        }
        if let AccountBlocklistTarget::Value(target) = &self.target
            && target.value.as_str().chars().count() > 512
        {
            return Err(WireError::Protocol(
                "account blocklist target value exceeds 512 characters".to_owned(),
            ));
        }
        Ok(())
    }
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
            verified_owning_organization_ids_at_save: Vec::new(),
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
            return Err(WireError::Protocol(
                "realm remark version must be 1".to_owned(),
            ));
        }
        if self.subject.kind != "realm" {
            return Err(WireError::Protocol(
                "realm remark subject.kind must be realm".to_owned(),
            ));
        }
        if &self.subject.id != realm_id {
            return Err(WireError::Protocol(
                "realm remark subject.id must match account-data key realm_id".to_owned(),
            ));
        }
        if self.local_name.chars().count() > 128 {
            return Err(WireError::Protocol(
                "realm remark local_name exceeds 128 chars".to_owned(),
            ));
        }
        if self.note.chars().count() > 4096 {
            return Err(WireError::Protocol(
                "realm remark note exceeds 4096 chars".to_owned(),
            ));
        }
        for tag in &self.tags {
            if tag.trim().is_empty() {
                return Err(WireError::Protocol(
                    "realm remark tags must not be empty".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

pub fn realm_remark_account_data_key(realm_id: &RealmId) -> String {
    format!(
        "{accountdatakey_contacts_realm}.{realm_id}",
        accountdatakey_contacts_realm = AccountDataKey::CONTACTS_REALM
    )
}

pub fn realm_id_from_realm_remark_account_data_key(key: &str) -> Option<RealmId> {
    key.strip_prefix("ak.contacts.realm.")
        .and_then(|realm_id| RealmId::new(realm_id.to_owned()).ok())
}

pub fn parse_realm_remark_account_data_key(key: &str) -> Result<RealmId> {
    realm_id_from_realm_remark_account_data_key(key).ok_or_else(|| {
        WireError::Protocol("realm remark key must be ak.contacts.realm.<realm_id>".to_owned())
    })
}

pub fn reminder_account_data_key(id: &str) -> Result<String> {
    validate_key_segment("reminder id", id)?;
    Ok(format!(
        "{accountdatakey_reminders_v1}:{id}",
        accountdatakey_reminders_v1 = AccountDataKey::REMINDERS_V1
    ))
}

pub fn scheduled_send_account_data_key(scheduled_send_id: &ScheduledSendId) -> String {
    format!(
        "{accountdatakey_scheduled_send_v1}:{scheduled_send_id}",
        accountdatakey_scheduled_send_v1 = AccountDataKey::SCHEDULED_SEND_V1
    )
}

pub fn snooze_account_data_key(namespace_key: &[u8], target_ref: &str) -> Result<String> {
    Ok(format!(
        "{accountdatakey_snooze_v1}:{}",
        target_key(namespace_key, target_ref)?,
        accountdatakey_snooze_v1 = AccountDataKey::SNOOZE_V1
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
        "{accountdatakey_saved_v1}:{collection_key}:{target_key}",
        accountdatakey_saved_v1 = AccountDataKey::SAVED_V1
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
        "{accountdatakey_draft_v1}:{kind}:{}:{draft_slot}",
        target_key(namespace_key, target_ref)?,
        accountdatakey_draft_v1 = AccountDataKey::DRAFT_V1
    ))
}

pub fn search_index_manifest_account_data_key(
    namespace_key: &[u8],
    realm_id: &RealmId,
) -> Result<String> {
    Ok(format!(
        "{accountdatakey_search_index_manifest_v1}:{}",
        realm_key(namespace_key, realm_id.as_str())?,
        accountdatakey_search_index_manifest_v1 = AccountDataKey::SEARCH_INDEX_MANIFEST_V1
    ))
}

pub fn file_transfer_account_data_key(namespace_key: &[u8], transfer_id: &str) -> Result<String> {
    validate_file_transfer_id(transfer_id)?;
    Ok(format!(
        "{accountdatakey_file_transfer_v1}:{}",
        base64url_encode(hmac_sha256(namespace_key, transfer_id.as_bytes())),
        accountdatakey_file_transfer_v1 = AccountDataKey::FILE_TRANSFER_V1
    ))
}

/// Derive one opaque Account Data key segment from an RFC 8785 canonical
/// value using the account's namespace key.
pub fn derive_account_data_key<T: Serialize + ?Sized>(
    namespace_key: &[u8],
    value: &T,
) -> Result<String> {
    Ok(base64url_encode(hmac_sha256(
        namespace_key,
        &canonical::canonical_json_bytes(value)?,
    )))
}

pub fn target_key(namespace_key: &[u8], target_ref: &str) -> Result<String> {
    validate_object_ref_string("target_ref", target_ref)?;
    derive_account_data_key(namespace_key, target_ref)
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
    let mut material = Vec::with_capacity(16 + collection_key.len() + target_bytes.len());
    material.extend_from_slice(&(collection_key.len() as u64).to_be_bytes());
    material.extend_from_slice(collection_key.as_bytes());
    material.extend_from_slice(&(target_bytes.len() as u64).to_be_bytes());
    material.extend_from_slice(&target_bytes);
    Ok(base64url_encode(hmac_sha256(namespace_key, &material)))
}

pub fn realm_key(namespace_key: &[u8], realm_id: &str) -> Result<String> {
    if !realm_id.starts_with("ak:realm:") {
        return Err(WireError::Protocol(
            "realm_key input must be ak:realm typed id".to_owned(),
        ));
    }
    derive_account_data_key(namespace_key, realm_id)
}

pub fn validate_private_account_data_key(key: &str) -> Result<()> {
    if let Some(realm_id) = strip_dotted_namespace(key, AccountDataKey::CONTACTS_REALM) {
        return RealmId::new(realm_id.to_owned()).map(|_| ()).map_err(|_| {
            WireError::Protocol("realm remark key must be ak.contacts.realm.<realm_id>".to_owned())
        });
    }
    if strip_dotted_namespace(key, AccountDataKey::CONTACTS_ACTOR).is_some() {
        return parse_contact_remark_account_data_key(key).map(|_| ());
    }
    // `ak.views.private` / `ak.notifications.inbox` carry a full typed id in
    // the tail, exactly like the two `ak.contacts.*` namespaces above. The
    // `contains_raw_object_ref` rule below governs only the HMAC-derived
    // productivity namespaces, so it MUST NOT be applied here: the registry
    // accepts the existence-leak these two key patterns imply
    // (zh/models/views.md §3.1, zh/discovery/client-preferences.md §3.2).
    if strip_dotted_namespace(key, AccountDataKey::VIEWS_PRIVATE).is_some() {
        return if private_view_account_data_key_view_id(key).is_some() {
            Ok(())
        } else {
            Err(WireError::Protocol(
                "private view key must be ak.views.private.<view_id>".to_owned(),
            ))
        };
    }
    if strip_dotted_namespace(key, AccountDataKey::NOTIFICATIONS_INBOX).is_some() {
        return if notification_inbox_account_data_key_notification_id(key).is_some() {
            Ok(())
        } else {
            Err(WireError::Protocol(
                "notification inbox key must be ak.notifications.inbox.<notification_id>"
                    .to_owned(),
            ))
        };
    }
    if let Some(id) = key.strip_prefix("ak.reminders.v1:") {
        return if !id.is_empty() && !contains_raw_object_ref(id) {
            Ok(())
        } else {
            private_key_error()
        };
    }
    if let Some(scheduled_send_id) = key.strip_prefix("ak.scheduled_send.v1:") {
        return ScheduledSendId::new(scheduled_send_id.to_owned())
            .map(|_| ())
            .map_err(|_| {
                WireError::Protocol("scheduled-send key must end with scheduled_send_id".to_owned())
            });
    }
    if let Some(target_key) = key.strip_prefix("ak.snooze.v1:") {
        return if looks_derived_key(target_key) {
            Ok(())
        } else {
            private_key_error()
        };
    }
    if let Some(rest) = key.strip_prefix("ak.saved.v1:") {
        let parts = rest.split(':').collect::<Vec<_>>();
        return if matches!(parts.as_slice(), [collection_key, target_key] if looks_derived_key(collection_key) && looks_derived_key(target_key))
        {
            Ok(())
        } else {
            private_key_error()
        };
    }
    if let Some(rest) = key.strip_prefix("ak.draft.v1:") {
        let parts = rest.split(':').collect::<Vec<_>>();
        return if matches!(parts.as_slice(), ["message" | "strand_field", target_key, slot_key] if looks_derived_key(target_key) && !slot_key.is_empty() && !contains_raw_object_ref(slot_key))
        {
            Ok(())
        } else {
            private_key_error()
        };
    }
    if let Some(realm_key) = key.strip_prefix("ak.search.index_manifest.v1:") {
        return if looks_derived_key(realm_key) {
            Ok(())
        } else {
            private_key_error()
        };
    }
    if let Some(transfer_key) = key.strip_prefix("ak.file_transfer.v1:") {
        return if looks_derived_key(transfer_key) && !contains_raw_object_ref(transfer_key) {
            Ok(())
        } else {
            private_key_error()
        };
    }
    private_key_error()
}

/// Tail of a registered account-data namespace whose key pattern separates the
/// namespace from its parameter with `.`. The registry namespaces themselves
/// never carry a trailing separator, so it is spelled once here instead of at
/// every call site.
fn strip_dotted_namespace<'a>(key: &'a str, namespace: &str) -> Option<&'a str> {
    key.strip_prefix(namespace)?.strip_prefix('.')
}

fn private_key_error() -> Result<()> {
    Err(WireError::Protocol(
        "account-data key must use the registered private key pattern and must not leak raw typed refs"
            .to_owned(),
    ))
}

fn contains_raw_object_ref(value: &str) -> bool {
    [
        "ak:strand:",
        "ak:message:",
        "ak:realm:",
        "ak:space:",
        "ak:morph:",
        "ak:relation:",
        "ak:view:",
        "ak:circle:",
        "ak:event:",
    ]
    .iter()
    .any(|needle| value.contains(needle))
}

fn normalize_collection_title(collection_title: &str) -> Result<String> {
    let normalized = collection_title.trim().nfc().collect::<String>();
    if normalized.is_empty() {
        return Err(WireError::Protocol(
            "collection_title must not be empty".to_owned(),
        ));
    }
    Ok(normalized)
}

fn validate_object_ref_string(field: &str, value: &str) -> Result<()> {
    let valid = [
        "ak:realm:",
        "ak:space:",
        "ak:strand:",
        "ak:message:",
        "ak:morph:",
        "ak:relation:",
        "ak:view:",
        "ak:circle:",
        "ak:event:",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix));
    if valid {
        Ok(())
    } else {
        Err(WireError::Protocol(format!(
            "{field} must be a canonical object_ref typed id"
        )))
    }
}

fn validate_key_segment(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.contains(':') || value.contains('/') || value.contains('\\') {
        Err(WireError::Protocol(format!(
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
        Err(WireError::Protocol(
            "transfer_id must be 22-128 chars from the ak.file_transfer.v1 alphabet".to_owned(),
        ))
    }
}

fn validate_blob_ref(value: &str) -> Result<()> {
    let valid_digest = ["ak:blob:sha256:", "ak:blob:blake3:"].iter().any(|prefix| {
        value.strip_prefix(prefix).is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    });
    if valid_digest {
        Ok(())
    } else {
        Err(WireError::Protocol(
            "file-transfer blob_ref must be content-addressed ak:blob:<suite>:<digest>".to_owned(),
        ))
    }
}

fn validate_media_type(value: &str) -> Result<()> {
    let Some((top, sub)) = value.split_once('/') else {
        return Err(WireError::Protocol(
            "file-transfer media_type must be type/constraint_subkind".to_owned(),
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
        Err(WireError::Protocol(
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
        Err(WireError::Protocol(format!("{field} must be base64url")))
    }
}

fn looks_derived_key(value: &str) -> bool {
    value.len() >= 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn parse_calendar_timezone(value: &str) -> Result<Tz> {
    value.parse::<Tz>().map_err(|_| {
        WireError::Protocol("calendar timezone must be an IANA timezone name".to_owned())
    })
}

pub(crate) fn parse_calendar_date(value: &str, field: &str) -> Result<NaiveDate> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| WireError::Protocol(format!("{field} must be YYYY-MM-DD")))
}

/// Strict RFC 8984 `LocalDateTime` narrowed to whole seconds.
///
/// Offsets, a trailing `Z`, bracketed zones and fractional seconds are all
/// rejected: the schedule never carries an absolute instant, and accepting a
/// second spelling would let two producers sign different bytes for the same
/// wall-clock time.
pub(crate) fn parse_calendar_local_date_time(value: &str, field: &str) -> Result<NaiveDateTime> {
    if value.len() != 19 || value.as_bytes()[10] != b'T' {
        return Err(WireError::Protocol(format!(
            "{field} must be a whole-second local date-time YYYY-MM-DDTHH:mm:ss"
        )));
    }
    let parsed = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S").map_err(|_| {
        WireError::Protocol(format!(
            "{field} must be a whole-second local date-time YYYY-MM-DDTHH:mm:ss"
        ))
    })?;
    if parsed.format("%Y-%m-%dT%H:%M:%S").to_string() != value {
        return Err(WireError::Protocol(format!("{field} is not canonical")));
    }
    Ok(parsed)
}

fn validate_tzdb_version(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let well_formed = bytes.len() == 5
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4].is_ascii_lowercase();
    if !well_formed {
        return Err(WireError::Protocol(
            "calendar tzdb_version must be an IANA release tag such as 2026a".to_owned(),
        ));
    }
    Ok(())
}

/// Splits a canonical timed occurrence key `YYYY-MM-DDTHH:mm:ss[Zone]`.
fn split_bracketed_occurrence(value: &str) -> Result<(NaiveDateTime, String)> {
    let Some(zone_start) = value.find('[') else {
        return Err(WireError::Protocol(
            "timed calendar occurrence must be YYYY-MM-DDTHH:mm:ss[Zone]".to_owned(),
        ));
    };
    if !value.ends_with(']') || zone_start == 0 {
        return Err(WireError::Protocol(
            "timed calendar occurrence must end with [Zone]".to_owned(),
        ));
    }
    let zone = &value[zone_start + 1..value.len() - 1];
    parse_calendar_timezone(zone)?;
    let local = parse_calendar_local_date_time(&value[..zone_start], "calendar occurrence")?;
    Ok((local, zone.to_owned()))
}

/// Resolves a local wall-clock time to an instant using the RFC 8984
/// discontinuity rule: both the gap and the fold take the offset in effect
/// *before* the transition, so a fixed local meeting time never drifts and an
/// ambiguous time yields exactly one occurrence.
pub(crate) fn resolve_local_to_instant(
    local: NaiveDateTime,
    timezone: Tz,
) -> Result<DateTime<Utc>> {
    use chrono::LocalResult;

    match timezone.from_local_datetime(&local) {
        LocalResult::Single(instant) => Ok(instant.with_timezone(&Utc)),
        // Fold: two valid instants. RFC 8984 selects the earlier one, which is
        // the offset in effect before the transition.
        LocalResult::Ambiguous(earlier, _later) => Ok(earlier.with_timezone(&Utc)),
        // Gap: the local time does not exist. Interpreting it with the
        // pre-transition offset maps it to a real instant just after the
        // transition, which is what RFC 8984 requires instead of rejecting.
        LocalResult::None => {
            let probe = local - chrono::Duration::days(1);
            let before = timezone
                .from_local_datetime(&probe)
                .earliest()
                .ok_or_else(|| {
                    WireError::Protocol(
                        "calendar local time could not be resolved in the event timezone"
                            .to_owned(),
                    )
                })?;
            let offset = *before.offset();
            let utc = local
                - chrono::TimeDelta::seconds(i64::from(
                    chrono::Offset::fix(&offset).local_minus_utc(),
                ));
            Ok(DateTime::<Utc>::from_naive_utc_and_offset(utc, Utc))
        }
    }
}

fn require_unique<T: Ord>(field: &str, values: &[T]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(WireError::Protocol(format!(
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
