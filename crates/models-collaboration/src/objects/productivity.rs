use std::collections::{BTreeMap, BTreeSet};

use arkret_models_crypto::encrypted_envelope::EncryptedEnvelope;
use arkret_wire::base64url::base64url_encode;
use arkret_wire::{
    AccountDataKey, BlobId, CallId, CircleId, DeviceId, Did, Error, EventId,
    HPKE_SUITE_X25519_CHACHA20POLY1305_V1, Hash, Hlc, MessageId, ProfileId, RealmId, Result,
    SchemaId, ScopeRef, SpaceId, StrandId, canonical,
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

pub const PROFILE_DISAPPEARING_MESSAGES: &str = "ak.profile.disappearing_messages.v1";
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
/// Shared with the envelope `causal_refs` bound: the basis MUST be a subset of
/// `causal_refs[]`, so it can never be larger.
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
    pub planned_message_id: MessageId,
    pub send_at: String,
    pub message_payload: MessageCreatePayload,
    pub message_payload_digest: String,
    pub updated_hlc: String,
}

impl ScheduledSendValue {
    pub fn planned_event_id(&self) -> EventId {
        self.planned_message_id.event_id()
    }

    pub fn validate_digest(&self) -> Result<()> {
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
    pub content: BTreeMap<String, Value>,
    pub updated_hlc: String,
    pub origin_device_id: DeviceId,
    pub retention_expires_at: String,
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
    pub actor_id: Did,
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
            return Err(Error::Protocol(
                "rsvp response comment must be omitted rather than empty".to_owned(),
            ));
        }
        if comment.chars().count() > MAX_RSVP_COMMENT_CODE_POINTS {
            return Err(Error::Protocol(
                "rsvp response comment must be <= 2000 code points".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Complete RSVP cell value. The whole entry is the `mv_register` set value, so
/// every head independently carries the schedule the responder observed plus
/// the response itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsvpEntry {
    /// Non-empty schedule revision frontier the responder actually observed, as
    /// `event_digest` values sorted in ascending canonical byte order. It MUST
    /// be a subset of the envelope `causal_refs[]`; that cross-field check
    /// belongs to the envelope validator, while [`Self::validate`] enforces the
    /// shape rules decidable from the entry alone.
    pub schedule_basis_refs: Vec<Hash>,
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
                    return Err(Error::Protocol(format!(
                        "rsvp encrypted_response content_type must be {RSVP_RESPONSE_CONTENT_TYPE}"
                    )));
                }
            }
            (Some(_), Some(_)) => {
                return Err(Error::Protocol(
                    "rsvp entry must carry exactly one of response or encrypted_response"
                        .to_owned(),
                ));
            }
            (None, None) => {
                return Err(Error::Protocol(
                    "rsvp entry must carry either response or encrypted_response".to_owned(),
                ));
            }
        }
        if self.schedule_basis_refs.is_empty() {
            return Err(Error::Protocol(
                "rsvp entry schedule_basis_refs must be non-empty".to_owned(),
            ));
        }
        if self.schedule_basis_refs.len() > MAX_RSVP_SCHEDULE_BASIS_REFS {
            return Err(Error::Protocol(
                "rsvp entry schedule_basis_refs must contain <= 128 entries".to_owned(),
            ));
        }
        // Canonical ascending byte order is a shape-admission condition that
        // JSON Schema cannot express; accepting an unsorted basis would fork
        // both the accepted set and the signed canonical bytes.
        let ordered = self
            .schedule_basis_refs
            .windows(2)
            .all(|pair| pair[0].as_str().as_bytes() < pair[1].as_str().as_bytes());
        if !ordered {
            return Err(Error::Protocol(
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
            return Err(Error::Protocol(
                "calendar recurrence count and until are mutually exclusive".to_owned(),
            ));
        }
        if self
            .count
            .is_some_and(|count| !(1..=MAX_CALENDAR_RECURRENCE_COUNT).contains(&count))
        {
            return Err(Error::Protocol(
                "calendar recurrence count must be in 1..=10000".to_owned(),
            ));
        }
        if self.interval == Some(0) {
            return Err(Error::Protocol(
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
                return Err(Error::Protocol(
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
                return Err(Error::Protocol(
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
                return Err(Error::Protocol(
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
                return Err(Error::Protocol(
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
            return Err(Error::Protocol(
                "calendar recurrence nth_of_period is only allowed for monthly or yearly frequency"
                    .to_owned(),
            ));
        }
        if self.frequency == RecurrenceFrequency::Weekly && self.by_month_day.is_some() {
            return Err(Error::Protocol(
                "calendar recurrence by_month_day must not be combined with weekly frequency"
                    .to_owned(),
            ));
        }
        if self.by_set_position.is_some()
            && self.by_day.is_empty()
            && self.by_month.is_none()
            && self.by_month_day.is_none()
        {
            return Err(Error::Protocol(
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
                return Err(Error::Protocol(
                    "calendar recurrence until must not precede the base start".to_owned(),
                ));
            }
        } else {
            let until_local = parse_calendar_local_date_time(until, "calendar recurrence until")?;
            let start_local = parse_calendar_local_date_time(base_start, "calendar start")?;
            if until_local < start_local {
                return Err(Error::Protocol(
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
            return Err(Error::Protocol(
                "calendar location must contain at least one field".to_owned(),
            ));
        }
        for (field, value) in fields {
            let Some(value) = value else {
                continue;
            };
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(Error::Protocol(format!(
                    "calendar location {field} must not be empty"
                )));
            }
            if field == "geo_uri" && !trimmed.starts_with("geo:") {
                return Err(Error::Protocol(
                    "calendar location geo_uri must start with geo:".to_owned(),
                ));
            }
            if field == "url" && !looks_like_uri(trimmed) {
                return Err(Error::Protocol(
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
                return Err(Error::Protocol(
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
                return Err(Error::Protocol(
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
            return Err(Error::Protocol(
                "calendar attendees must contain <= 1000 entries".to_owned(),
            ));
        }
        let organizers = self
            .attendees
            .iter()
            .filter(|attendee| attendee.role == Some(CalendarAttendeeRole::Organizer))
            .count();
        if organizers > 1 {
            return Err(Error::Protocol(
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
            return Err(Error::Protocol(
                "calendar occurrence zone must equal the signed calendar timezone".to_owned(),
            ));
        }
        Ok(Some(format!(
            "{}[{}]",
            local.format("%Y-%m-%dT%H:%M:%S"),
            self.timezone
        )))
    }

    /// Local wall-clock start of the base occurrence, i.e. the recurrence
    /// anchor, as an instant in the event timezone under the pinned release.
    pub fn base_start_instant(&self) -> Result<DateTime<Utc>> {
        let timezone = parse_calendar_timezone(&self.timezone)?;
        if self.all_day {
            let date = parse_calendar_date(&self.start, "calendar start")?;
            return resolve_local_to_instant(
                date.and_hms_opt(0, 0, 0).expect("midnight is always valid"),
                timezone,
            );
        }
        let local = parse_calendar_local_date_time(&self.start, "calendar start")?;
        resolve_local_to_instant(local, timezone)
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

/// Legacy flat schedule keys and activation impostors that MUST NOT appear at
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
            return Err(Error::Protocol(format!(
                "metadata.fields.{key} is a forbidden calendar activation impostor; the canonical path is metadata.fields.{CALENDAR_METADATA_FIELDS_NAMESPACE}"
            )));
        }
    }
    let Some(subtree) = fields.get(CALENDAR_METADATA_FIELDS_NAMESPACE) else {
        return Ok(None);
    };
    let parsed = serde_json::from_value::<CalendarEventFields>(subtree.clone())
        .map_err(|error| Error::Protocol(format!("calendar event fields invalid: {error}")))?;
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
        return Err(Error::Protocol(
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
        return Err(Error::Protocol(
            "calendar occurrence key is not canonical".to_owned(),
        ));
    }
    Ok(())
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
    pub plaintext_realms_allowed: Option<bool>,
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
    pub allowed_service_ids: Vec<Did>,
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
    pub status: FileTransferStatus,
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
            Error::Protocol("file-transfer origin_device_id must be a ak:device id".to_owned())
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
        if aad.schema != SchemaId::FILE_TRANSFER_V1 {
            return Err(Error::Protocol(
                "file-transfer AAD schema must be ak.schema.file_transfer.v1".to_owned(),
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
                    "file-transfer recipient_device_ids must contain ak:device ids".to_owned(),
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
        if self.scheme != "ak.file_transfer.encrypted_blob.v1" {
            return Err(Error::Protocol(
                "file-transfer encryption scheme mismatch".to_owned(),
            ));
        }
        if self.aead_profile != "ak.aead.xchacha20_poly1305.v1" {
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
        if self.schema != SchemaId::FILE_TRANSFER_V1 {
            return Err(Error::Protocol(
                "file-transfer AAD schema must be ak.schema.file_transfer.v1".to_owned(),
            ));
        }
        if self.purpose != "file_transfer" {
            return Err(Error::Protocol(
                "file-transfer AAD purpose must be file_transfer".to_owned(),
            ));
        }
        validate_file_transfer_id(&self.transfer_id)?;
        DeviceId::new(self.origin_device_id.clone()).map_err(|_| {
            Error::Protocol("file-transfer AAD origin_device_id must be a ak:device id".to_owned())
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
                    Err(Error::Protocol(
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
        if self.aead_profile != "ak.aead.xchacha20_poly1305.v1" {
            return Err(Error::Protocol(
                "file-transfer key message AEAD profile mismatch".to_owned(),
            ));
        }
        validate_base64url("file-transfer key message nonce", &self.nonce)?;
        self.key_envelope.validate()?;
        Ok(canonical::validate_timestamp_canonical(&self.expires_at)?)
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
        if self.scheme != HPKE_SUITE_X25519_CHACHA20POLY1305_V1 {
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
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub saved_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmRemarkAccountDataUpdate {
    pub key: String,
    pub remark: Option<RealmRemark>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRemarkSubject {
    pub kind: String,
    pub did: Did,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRemark {
    pub version: u32,
    pub subject: ContactRemarkSubject,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub local_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub pinned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_handle_at_save: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub saved_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl ContactRemark {
    pub fn new(actor_did: Did, local_name: impl Into<String>, saved_at: DateTime<Utc>) -> Self {
        Self {
            version: 1,
            subject: ContactRemarkSubject {
                kind: "actor".to_owned(),
                did: actor_did,
            },
            local_name: local_name.into(),
            note: String::new(),
            tags: Vec::new(),
            pinned: false,
            verified_handle_at_save: None,
            saved_at,
            updated_at: None,
        }
    }

    pub fn with_pinned_preserving_fields(
        actor_did: Did,
        existing: Option<&Self>,
        pinned: bool,
        updated_at: DateTime<Utc>,
    ) -> Self {
        let mut next = existing
            .cloned()
            .unwrap_or_else(|| Self::new(actor_did.clone(), "", updated_at));
        next.version = 1;
        next.subject = ContactRemarkSubject {
            kind: "actor".to_owned(),
            did: actor_did,
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
        let actor_did = parse_contact_remark_account_data_key(key)?;
        if self.version != 1 {
            return Err(Error::Protocol(
                "contact remark version must be 1".to_owned(),
            ));
        }
        if self.subject.kind != "actor" {
            return Err(Error::Protocol(
                "contact remark subject.kind must be actor".to_owned(),
            ));
        }
        if self.subject.did != actor_did {
            return Err(Error::Protocol(
                "contact remark subject.did must match its account-data key".to_owned(),
            ));
        }
        if self.local_name.chars().count() > 128 {
            return Err(Error::Protocol(
                "contact remark local_name exceeds 128 characters".to_owned(),
            ));
        }
        if self.note.chars().count() > 4_096 {
            return Err(Error::Protocol(
                "contact remark note exceeds 4096 characters".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn contact_remark_account_data_key(actor_did: &Did) -> String {
    format!(
        "{accountdatakey_contacts_actor}.{actor_did}",
        accountdatakey_contacts_actor = AccountDataKey::CONTACTS_ACTOR
    )
}

pub fn parse_contact_remark_account_data_key(key: &str) -> Result<Did> {
    let raw = key
        .strip_prefix(&format!(
            "{accountdatakey_contacts_actor}.",
            accountdatakey_contacts_actor = AccountDataKey::CONTACTS_ACTOR
        ))
        .ok_or_else(|| Error::Protocol("invalid contact remark account-data key".to_owned()))?;
    Ok(Did::new(raw.to_owned())?)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistPayload {
    pub version: u32,
    #[serde(default)]
    pub entries: Vec<AccountBlocklistPayloadEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistPayloadEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<arkret_wire::NonEmptyString>,
    pub target: AccountBlocklistTarget,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applies_to: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<arkret_wire::NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistTarget {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<arkret_wire::NonEmptyString>,
}

impl AccountBlocklistPayload {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Protocol(
                "account blocklist version must be 1".to_owned(),
            ));
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        Ok(())
    }
}

impl AccountBlocklistPayloadEntry {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.mode.as_str(), "block" | "mute" | "hide") {
            return Err(Error::Protocol(
                "account blocklist mode must be block, mute, or hide".to_owned(),
            ));
        }
        let target_count = usize::from(self.target.did.is_some())
            + usize::from(self.target.object_ref.is_some())
            + usize::from(self.target.value.is_some());
        if target_count != 1 {
            return Err(Error::Protocol(
                "account blocklist target must contain exactly one identifier".to_owned(),
            ));
        }
        if !matches!(
            self.target.kind.as_str(),
            "actor"
                | "device"
                | "service"
                | "handle"
                | "domain"
                | "organization"
                | "applet"
                | "keyword"
        ) {
            return Err(Error::Protocol(
                "account blocklist target.kind is not recognized".to_owned(),
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
        Error::Protocol("realm remark key must be ak.contacts.realm.<realm_id>".to_owned())
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
                    if key.starts_with("ak.contacts.realm.") || key == "realm_remark" {
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
    let value = if remark.is_empty() {
        json!({})
    } else {
        serde_json::to_value(&remark).map_err(|error| {
            Error::Protocol(format!("realm remark serialization failed: {error}"))
        })?
    };
    validate_realm_remark_account_data_value(&key, &value)?;
    Ok(RealmRemarkAccountDataUpdate {
        key,
        remark: (!remark.is_empty()).then_some(remark),
    })
}

pub fn scheduled_send_message_payload_digest(
    message_payload: &MessageCreatePayload,
) -> Result<String> {
    Ok(canonical::canonical_sha256(message_payload)?)
}

pub fn reminder_account_data_key(id: &str) -> Result<String> {
    validate_key_segment("reminder id", id)?;
    Ok(format!(
        "{accountdatakey_reminders_v1}:{id}",
        accountdatakey_reminders_v1 = AccountDataKey::REMINDERS_V1
    ))
}

pub fn scheduled_send_account_data_key(planned_message_id: &MessageId) -> String {
    format!(
        "{accountdatakey_scheduled_send_v1}:{planned_message_id}",
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
        "profile": ProfileId::SEARCH_CLIENT_INDEX_V1,
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
    effective_scope: &ScopeRef,
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
        "profile": ProfileId::SEARCH_BLIND_INDEX_V1,
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
    effective_scope: ScopeRef,
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
        "{accountdatakey_file_transfer_v1}:{}",
        base64url_encode(hmac_sha256(namespace_key, transfer_id.as_bytes())),
        accountdatakey_file_transfer_v1 = AccountDataKey::FILE_TRANSFER_V1
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
    let mut material = Vec::with_capacity(16 + collection_key.len() + target_bytes.len());
    material.extend_from_slice(&(collection_key.len() as u64).to_be_bytes());
    material.extend_from_slice(collection_key.as_bytes());
    material.extend_from_slice(&(target_bytes.len() as u64).to_be_bytes());
    material.extend_from_slice(&target_bytes);
    Ok(base64url_encode(hmac_sha256(namespace_key, &material)))
}

pub fn realm_key(namespace_key: &[u8], realm_id: &str) -> Result<String> {
    if !realm_id.starts_with("ak:realm:") {
        return Err(Error::Protocol(
            "realm_key input must be ak:realm typed id".to_owned(),
        ));
    }
    Ok(base64url_encode(hmac_sha256(
        namespace_key,
        &canonical::canonical_json_bytes(&realm_id)?,
    )))
}

pub fn validate_private_account_data_key(key: &str) -> Result<()> {
    if let Some(realm_id) = strip_dotted_namespace(key, AccountDataKey::CONTACTS_REALM) {
        return RealmId::new(realm_id.to_owned()).map(|_| ()).map_err(|_| {
            Error::Protocol("realm remark key must be ak.contacts.realm.<realm_id>".to_owned())
        });
    }
    if let Some(actor_id) = strip_dotted_namespace(key, AccountDataKey::CONTACTS_ACTOR) {
        return Did::new(actor_id.to_owned()).map(|_| ()).map_err(|_| {
            Error::Protocol("contact remark key must be ak.contacts.actor.<did>".to_owned())
        });
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
            Err(Error::Protocol(
                "private view key must be ak.views.private.<view_id>".to_owned(),
            ))
        };
    }
    if strip_dotted_namespace(key, AccountDataKey::NOTIFICATIONS_INBOX).is_some() {
        return if notification_inbox_account_data_key_notification_id(key).is_some() {
            Ok(())
        } else {
            Err(Error::Protocol(
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
    if let Some(planned_message_id) = key.strip_prefix("ak.scheduled_send.v1:") {
        return MessageId::new(planned_message_id.to_owned())
            .map(|_| ())
            .map_err(|_| {
                Error::Protocol("scheduled-send key must end with planned_message_id".to_owned())
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
    Err(Error::Protocol(
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
        return Err(Error::Protocol(
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
            "transfer_id must be 22-128 chars from the ak.file_transfer.v1 alphabet".to_owned(),
        ))
    }
}

fn validate_blob_ref(value: &str) -> Result<()> {
    let valid_uuid = value.strip_prefix("ak:blob:").is_some_and(is_uuid_v7);
    let valid_digest = ["ak:blob:sha256:", "ak:blob:blake3:"].iter().any(|prefix| {
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
            "file-transfer blob_ref must be ak:blob:<uuidv7|digest>".to_owned(),
        ))
    }
}

fn validate_file_transfer_blob_digest_binding(blob_ref: &str, content_digest: &str) -> Result<()> {
    for (prefix, digest_prefix) in [
        ("ak:blob:sha256:", "sha256:"),
        ("ak:blob:blake3:", "blake3:"),
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

pub(crate) fn parse_calendar_timezone(value: &str) -> Result<Tz> {
    value
        .parse::<Tz>()
        .map_err(|_| Error::Protocol("calendar timezone must be an IANA timezone name".to_owned()))
}

pub(crate) fn parse_calendar_date(value: &str, field: &str) -> Result<NaiveDate> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| Error::Protocol(format!("{field} must be YYYY-MM-DD")))
}

/// Strict RFC 8984 `LocalDateTime` narrowed to whole seconds.
///
/// Offsets, a trailing `Z`, bracketed zones and fractional seconds are all
/// rejected: the schedule never carries an absolute instant, and accepting a
/// second spelling would let two producers sign different bytes for the same
/// wall-clock time.
pub(crate) fn parse_calendar_local_date_time(value: &str, field: &str) -> Result<NaiveDateTime> {
    if value.len() != 19 || value.as_bytes()[10] != b'T' {
        return Err(Error::Protocol(format!(
            "{field} must be a whole-second local date-time YYYY-MM-DDTHH:mm:ss"
        )));
    }
    let parsed = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S").map_err(|_| {
        Error::Protocol(format!(
            "{field} must be a whole-second local date-time YYYY-MM-DDTHH:mm:ss"
        ))
    })?;
    if parsed.format("%Y-%m-%dT%H:%M:%S").to_string() != value {
        return Err(Error::Protocol(format!("{field} is not canonical")));
    }
    Ok(parsed)
}

fn validate_tzdb_version(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let well_formed = bytes.len() == 5
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4].is_ascii_lowercase();
    if !well_formed {
        return Err(Error::Protocol(
            "calendar tzdb_version must be an IANA release tag such as 2026a".to_owned(),
        ));
    }
    Ok(())
}

/// Splits a canonical timed occurrence key `YYYY-MM-DDTHH:mm:ss[Zone]`.
fn split_bracketed_occurrence(value: &str) -> Result<(NaiveDateTime, String)> {
    let Some(zone_start) = value.find('[') else {
        return Err(Error::Protocol(
            "timed calendar occurrence must be YYYY-MM-DDTHH:mm:ss[Zone]".to_owned(),
        ));
    };
    if !value.ends_with(']') || zone_start == 0 {
        return Err(Error::Protocol(
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
                    Error::Protocol(
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
    use arkret_wire::{ProfileId, SchemaId};
    use serde_json::json;

    use super::*;
    use crate::events_payloads::ContentBlock;

    fn test_realm_id(seed: &str) -> RealmId {
        RealmId::new(format!("ak:realm:01904100-0000-7000-8000-{seed}")).unwrap()
    }

    fn test_circle_id(seed: &str) -> CircleId {
        CircleId::new(format!("ak:circle:01904100-0000-7000-8000-{seed}")).unwrap()
    }

    fn test_blob_id(seed: &str) -> BlobId {
        BlobId::new(format!("ak:blob:01904100-0000-7000-8000-{seed}")).unwrap()
    }

    fn test_time(second: u32) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&format!("2026-06-06T10:00:{second:02}Z"))
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn scheduled_send_validates_payload_digest_without_second_message_identity() {
        let message_id = MessageId::new("ak:message:01904100-0000-7000-8000-000000000001").unwrap();
        let payload = MessageCreatePayload::with_content(
            StrandId::new("ak:strand:01904100-0000-7000-8000-000000000002").unwrap(),
            "discussion",
            ContentBlock::text("hello"),
        );
        let value = ScheduledSendValue {
            planned_message_id: message_id,
            send_at: "2026-06-07T00:00:00.000Z".to_owned(),
            message_payload_digest: scheduled_send_message_payload_digest(&payload).unwrap(),
            message_payload: payload,
            updated_hlc: "01970e589d21-0000-a13f9c2e".to_owned(),
        };
        value.validate_digest().unwrap();
    }

    #[test]
    fn calendar_event_fields_validate_cross_field_constraints() {
        let fields = CalendarEventFields {
            start: "2026-06-22T09:00:00".to_owned(),
            end: "2026-06-22T10:00:00".to_owned(),
            timezone: "America/Los_Angeles".to_owned(),
            tzdb_version: "2025a".to_owned(),
            all_day: false,
            status: CalendarStatus::Confirmed,
            recurrence: Some(CalendarRecurrence {
                frequency: RecurrenceFrequency::Weekly,
                interval: Some(1),
                by_day: vec![CalendarRecurrenceDay {
                    day: RecurrenceWeekday::Mo,
                    nth_of_period: None,
                }],
                by_month: None,
                by_month_day: None,
                by_set_position: None,
                first_day_of_week: Some(RecurrenceWeekday::Mo),
                count: Some(10_000),
                until: None,
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

        let mut invalid = fields.clone();
        invalid.recurrence.as_mut().unwrap().count = Some(10_001);
        assert!(invalid.validate().is_err());

        // Timed anchors are whole-second LocalDateTime; a UTC instant, an
        // offset and a fractional second are all rejected spellings.
        for spelling in [
            "2026-06-22T09:00:00.000Z",
            "2026-06-22T09:00:00-07:00",
            "2026-06-22T09:00:00.000",
        ] {
            let mut invalid = fields.clone();
            invalid.start = spelling.to_owned();
            assert!(invalid.validate().is_err(), "accepted {spelling}");
        }

        // nth_of_period is meaningless for weekly recurrence.
        let mut invalid = fields.clone();
        invalid.recurrence.as_mut().unwrap().by_day[0].nth_of_period = Some(1);
        assert!(invalid.validate().is_err());

        // by_set_position needs a candidate-producing companion.
        let mut invalid = fields.clone();
        let recurrence = invalid.recurrence.as_mut().unwrap();
        recurrence.by_day.clear();
        recurrence.by_set_position = Some(vec![-1]);
        assert!(invalid.validate().is_err());

        // At most one organizer.
        let mut invalid = fields;
        invalid.attendees.push(CalendarAttendee {
            actor_id: Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            role: Some(CalendarAttendeeRole::Organizer),
            display_name_snapshot: None,
        });
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn calendar_recurrence_matches_current_wire_shape() {
        let recurrence: CalendarRecurrence = serde_json::from_value(serde_json::json!({
            "frequency": "monthly",
            "interval": 1,
            "by_day": [{"day": "mo", "nth_of_period": -1}],
            "by_month": ["1", "12"],
            "by_month_day": [-1, 15],
            "by_set_position": [1],
            "first_day_of_week": "mo",
            "until": "2026-12-31T23:59:59"
        }))
        .unwrap();
        recurrence.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&recurrence).unwrap()["frequency"],
            "monthly"
        );
        assert!(
            serde_json::from_value::<CalendarRecurrence>(serde_json::json!({
                "frequency": "MONTHLY",
                "expires_at": "2026-12-31T23:59:59.000Z"
            }))
            .is_err()
        );
    }

    #[test]
    fn calendar_rsvp_occurrence_keys_are_canonicalized() {
        let mut fields = BTreeMap::new();
        fields.insert(
            CALENDAR_METADATA_FIELDS_NAMESPACE.to_owned(),
            serde_json::json!({
                "start": "2026-06-22T09:00:00",
                "end": "2026-06-22T10:00:00",
                "timezone": "America/Los_Angeles",
                "tzdb_version": "2025a",
                "all_day": false,
                "status": "confirmed"
            }),
        );

        assert_eq!(
            canonical_calendar_rsvp_occurrence_key(
                &fields,
                Some("2026-06-22T09:00:00[America/Los_Angeles]")
            )
            .unwrap(),
            Some("2026-06-22T09:00:00[America/Los_Angeles]".to_owned())
        );
        // Series is JSON null, never a "series" sentinel string: the sentinel
        // would address a different composite cell.
        assert_eq!(
            canonical_calendar_rsvp_occurrence_key(&fields, None).unwrap(),
            None
        );
        // A UTC instant is not a canonical instance key.
        assert!(
            canonical_calendar_rsvp_occurrence_key(&fields, Some("2026-06-22T16:00:00.000Z"))
                .is_err()
        );
    }

    #[test]
    fn calendar_all_day_occurrence_keys_are_dates() {
        let mut fields = BTreeMap::new();
        fields.insert(
            CALENDAR_METADATA_FIELDS_NAMESPACE.to_owned(),
            serde_json::json!({
                "start": "2026-06-22",
                "end": "2026-06-23",
                "timezone": "Asia/Shanghai",
                "tzdb_version": "2025a",
                "all_day": true,
                "status": "confirmed"
            }),
        );

        assert_eq!(
            canonical_calendar_rsvp_occurrence_key(&fields, Some("2026-06-22")).unwrap(),
            Some("2026-06-22".to_owned())
        );
    }

    #[test]
    fn calendar_metadata_rejects_flat_activation_impostors() {
        for key in ["start", "timezone", "profile", "profile_refs", "attendees"] {
            let mut fields = BTreeMap::new();
            fields.insert(key.to_owned(), Value::String("whatever".to_owned()));
            assert!(
                calendar_event_fields_from_metadata_fields(&fields).is_err(),
                "accepted flat metadata.fields.{key}"
            );
        }
        // A Strand with no calendar subtree is simply not a calendar event.
        assert!(
            calendar_event_fields_from_metadata_fields(&BTreeMap::new())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn private_key_builders_do_not_leak_raw_target_refs() {
        let ns = b"test namespace key";
        let target_ref = "ak:message:01904100-0000-7000-8000-000000000001";
        let snooze = snooze_account_data_key(ns, target_ref).unwrap();
        assert!(snooze.starts_with("ak.snooze.v1:"));
        assert!(!snooze.contains(target_ref));
        validate_private_account_data_key(&snooze).unwrap();

        let saved = saved_account_data_key(ns, "Inbox", target_ref).unwrap();
        assert!(saved.starts_with("ak.saved.v1:"));
        assert!(!saved.contains("Inbox"));
        assert!(!saved.contains(target_ref));
        validate_private_account_data_key(&saved).unwrap();

        let transfer_id = "0123456789abcdefghijkl";
        let transfer = file_transfer_account_data_key(ns, transfer_id).unwrap();
        assert!(transfer.starts_with("ak.file_transfer.v1:"));
        assert!(!transfer.contains(transfer_id));
        validate_private_account_data_key(&transfer).unwrap();
    }

    #[test]
    fn private_key_validator_accepts_typed_id_tail_namespaces() {
        let view_id =
            arkret_wire::ViewId::new("ak:view:0196419b-0000-7000-8000-000000000001".to_owned())
                .unwrap();
        let notification_id = arkret_wire::NotificationId::new(
            "ak:notification:0196419b-0000-7000-8000-000000000002".to_owned(),
        )
        .unwrap();

        // The raw `ak:view:` id in the tail is registry-sanctioned here, so
        // the derived-key rule that rejects it elsewhere must not fire.
        validate_private_account_data_key(&crate::events_payloads::private_view_account_data_key(
            &view_id,
        ))
        .unwrap();
        validate_private_account_data_key(
            &crate::events_payloads::notification_inbox_account_data_key(&notification_id),
        )
        .unwrap();
    }

    #[test]
    fn private_key_validator_rejects_malformed_typed_id_tails() {
        for (key, expected) in [
            ("ak.views.private", "must not leak raw typed refs"),
            ("ak.views.private.", "ak.views.private.<view_id>"),
            (
                "ak.views.private.ak:realm:0196419b-0000-7000-8000-000000000001",
                "ak.views.private.<view_id>",
            ),
            ("ak.notifications.inbox", "must not leak raw typed refs"),
            (
                "ak.notifications.inbox.",
                "ak.notifications.inbox.<notification_id>",
            ),
            (
                "ak.notifications.inbox.ak:view:0196419b-0000-7000-8000-000000000001",
                "ak.notifications.inbox.<notification_id>",
            ),
        ] {
            let err = validate_private_account_data_key(key).unwrap_err();
            assert!(err.to_string().contains(expected), "{key}: {err}");
        }
    }

    #[test]
    fn private_key_validator_rejects_raw_refs() {
        let err = validate_private_account_data_key(
            "ak.draft.v1:message:ak:message:01904100-0000-7000-8000-000000000001:main",
        )
        .unwrap_err();
        assert!(err.to_string().contains("must not leak raw typed refs"));

        assert!(file_transfer_account_data_key(b"ns", "short-transfer").is_err());
        assert!(
            validate_private_account_data_key("ak.file_transfer.v1:ak:blob:sha256:abc").is_err()
        );
    }

    fn file_transfer_record() -> FileTransferRecord {
        FileTransferRecord {
            kind: "file_transfer".to_owned(),
            transfer_id: "0123456789abcdefghijkl".to_owned(),
            blob_ref: format!("ak:blob:sha256:{}", "ab".repeat(32)),
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
                scheme: "ak.file_transfer.encrypted_blob.v1".to_owned(),
                aead_profile: "ak.aead.xchacha20_poly1305.v1".to_owned(),
                nonce: "abc_DEF-012".to_owned(),
                aad: FileTransferAad {
                    schema: SchemaId::FILE_TRANSFER_V1.to_owned(),
                    purpose: "file_transfer".to_owned(),
                    transfer_id: "0123456789abcdefghijkl".to_owned(),
                    origin_device_id: "ak:device:01904100-0000-7000-8000-000000000002".to_owned(),
                    created_at: "2026-06-22T00:00:00.000Z".to_owned(),
                },
                key_delivery: FileTransferKeyDelivery::AccountDataWrappedKey {
                    content_key: "abc_DEF-012".to_owned(),
                },
            },
            origin_device_id: "ak:device:01904100-0000-7000-8000-000000000002".to_owned(),
            created_at: "2026-06-22T00:00:00.000Z".to_owned(),
            updated_hlc: "01970e589d21-0004-a13f9c2e".to_owned(),
            retention_expires_at: "2026-06-29T00:00:00.000Z".to_owned(),
            status: FileTransferStatus::Available,
        }
    }

    #[test]
    fn file_transfer_record_validates_and_serializes_canonical_shape() {
        let record = file_transfer_record();
        record.validate().unwrap();
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["kind"], "file_transfer");
        assert_eq!(value["status"], "available");
        assert!(value.get("state").is_none());
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
            vec!["ak:device:01904100-0000-7000-8000-000000000003".to_owned()];
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
            vec!["ak:device:01904100-0000-7000-8000-000000000003".to_owned()];
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
                scheme: HPKE_SUITE_X25519_CHACHA20POLY1305_V1.to_owned(),
                enc: "abc_DEF-012".to_owned(),
                ciphertext: "def_ABC-345".to_owned(),
                aad_digest: format!("sha256:{}", "cd".repeat(32)),
            },
            expires_at: "2026-06-22T00:30:00.000Z".to_owned(),
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
        record.blob_ref = format!("ak:blob:sha256:{}", "cd".repeat(32));
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
        assert!(validate_realm_remark_account_data_value("ak.tags.realm.bad", &json!({})).is_err());
        assert!(
            validate_realm_remark_account_data_value(&key, &json!({"tombstone": true})).is_ok()
        );

        let leaked_shared_payload = json!({
            "event_kind": "ak.realm.update",
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
        let unpinned_remark = unpinned.remark.as_ref().unwrap();
        assert!(!unpinned_remark.pinned);
        assert_eq!(unpinned_remark.local_name, "Ops private alias");
        assert_eq!(unpinned_remark.note, "keep me");
        validate_realm_remark_account_data_value(
            &unpinned.key,
            &serde_json::to_value(unpinned_remark).unwrap(),
        )
        .unwrap();

        let pinned = set_realm_pinned(realm_id.clone(), None, true, test_time(3)).unwrap();
        assert!(pinned.remark.as_ref().unwrap().pinned);
        validate_realm_remark_account_data_value(
            &pinned.key,
            &serde_json::to_value(pinned.remark.as_ref().unwrap()).unwrap(),
        )
        .unwrap();

        let empty = set_realm_pinned(realm_id, None, false, test_time(4)).unwrap();
        assert!(empty.remark.is_none());
        validate_realm_remark_account_data_value(&empty.key, &json!({})).unwrap();
    }

    #[test]
    fn wire_field_names_match_current_spec() {
        let draft = DraftSyncValue {
            target_ref: "ak:message:01904100-0000-7000-8000-000000000001".to_owned(),
            kind: DraftKind::Message,
            draft_slot: "main".to_owned(),
            content: BTreeMap::from([("body".to_owned(), json!("draft"))]),
            updated_hlc: "01970e589d21-0000-a13f9c2e".to_owned(),
            origin_device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002")
                .unwrap(),
            retention_expires_at: "2026-06-07T00:00:00.000Z".to_owned(),
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
            allowed_service_ids: vec![Did::new("did:webvh:z6mkfixture:search.example").unwrap()],
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
                ProfileId::SEARCH_CLIENT_INDEX_V1,
                ProfileId::SEARCH_BLIND_INDEX_V1,
                ProfileId::SEARCH_FORWARD_PRIVATE_V1
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
        let scope_a = ScopeRef::Realm {
            realm_id: realm_a.clone(),
        };
        let scope_b = ScopeRef::Realm {
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

        let circle_scope = ScopeRef::Circle {
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
            ScopeRef::Realm {
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
            ScopeRef::Realm { realm_id },
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
