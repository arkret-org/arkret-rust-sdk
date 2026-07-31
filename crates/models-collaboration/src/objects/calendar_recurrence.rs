//! Shared Calendar recurrence expansion.
//!
//! Calendar producers, agenda renderers and conformance runners use this
//! module so recurrence defaults, DST discontinuities and continuation
//! validity are decided once. The API expands a finite local-time range and
//! never substitutes a nearby TZDB release for the one signed by the schedule.

use std::collections::BTreeSet;

use arkret_canonical::base64url::{base64url_decode, base64url_encode};
use arkret_wire::Hash;
use chrono::{DateTime, Datelike, Days, Months, NaiveDate, NaiveDateTime, NaiveTime, Utc, Weekday};
use chrono_tz::IANA_TZDB_VERSION;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::productivity::{
    CalendarEventFields, CalendarRecurrence, CalendarRecurrenceDay, RecurrenceFrequency,
    RecurrenceWeekday, parse_calendar_date, parse_calendar_local_date_time,
    parse_calendar_timezone, resolve_local_to_instant,
};

pub const MAX_CALENDAR_EXPANSION_OCCURRENCES: usize = 10_000;
pub const MAX_CALENDAR_EXPANSION_CANDIDATE_PERIODS: usize = 100_000;
/// Exact IANA release compiled into this build. Services and clients may
/// advertise this value as executable; other signed releases remain valid
/// wire data but cannot be expanded by this build.
pub const EXECUTABLE_CALENDAR_TZDB_VERSION: &str = IANA_TZDB_VERSION;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarExpansionRequest {
    /// Finite local range lower bound. It uses the schedule branch: a date for
    /// all-day events and a whole-second LocalDateTime for timed events.
    pub range_start: String,
    /// Exclusive local range upper bound.
    pub range_end: String,
    /// Maximum occurrences returned by this page.
    pub limit: usize,
    /// Current settled schedule revision frontier. Continuations are bound to
    /// the complete frontier, including equal-valued concurrent heads.
    pub schedule_revision_heads: Vec<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarExpansionStatus {
    Complete,
    LimitExceeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarExpansionLimit {
    OccurrenceLimit,
    CandidatePeriodBudget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarOccurrence {
    /// Canonical RSVP occurrence key.
    pub occurrence: String,
    /// Local start in the same branch and spelling as the schedule.
    pub local_start: String,
    /// All-day end date, or the local rendering of the elapsed-duration end.
    pub local_end: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub start_instant: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub end_instant: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarOccurrencePage {
    pub occurrences: Vec<CalendarOccurrence>,
    pub status: CalendarExpansionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limited_by: Option<CalendarExpansionLimit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<String>,
    pub candidate_periods_scanned: usize,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CalendarExpansionError {
    #[error("invalid calendar expansion request: {0}")]
    InvalidRequest(String),
    #[error(
        "calendar_tzdb_mismatch: schedule pins {requested}, but this build executes {executable}"
    )]
    TzdbMismatch {
        requested: String,
        executable: String,
    },
    #[error("invalid_cursor: {0}")]
    InvalidCursor(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContinuationPayload {
    cursor_version: u8,
    schedule_revision_heads: Vec<Hash>,
    tzdb_version: String,
    range_start: String,
    range_end: String,
    next_period_index: u64,
    occurrences_seen: u64,
    sort_key: String,
}

#[derive(Clone, Copy)]
struct ExpansionPosition {
    next_period_index: u64,
    occurrences_seen: u64,
}

impl CalendarEventFields {
    /// Converts an instant range to the schedule's local branch and delegates
    /// to [`Self::expand_occurrences`]. Agenda renderers use this instead of
    /// slicing wire strings or independently resolving time zones.
    pub fn expand_occurrences_between_instants(
        &self,
        range_start: DateTime<Utc>,
        range_end: DateTime<Utc>,
        limit: usize,
        schedule_revision_heads: Vec<Hash>,
    ) -> Result<CalendarOccurrencePage, CalendarExpansionError> {
        if range_end <= range_start {
            return Err(CalendarExpansionError::InvalidRequest(
                "range_end must be later than range_start".to_owned(),
            ));
        }
        if self.tzdb_version != IANA_TZDB_VERSION {
            return Err(CalendarExpansionError::TzdbMismatch {
                requested: self.tzdb_version.clone(),
                executable: IANA_TZDB_VERSION.to_owned(),
            });
        }
        let timezone = parse_calendar_timezone(&self.timezone)
            .map_err(|error| CalendarExpansionError::InvalidRequest(error.to_string()))?;
        let local_start = range_start.with_timezone(&timezone).naive_local();
        let local_end = range_end.with_timezone(&timezone).naive_local();
        let (range_start, range_end) = if self.all_day {
            // This helper selects all-day occurrences whose local calendar
            // interval overlaps the instant range. A non-midnight upper bound
            // therefore includes its local date, while an exact midnight is
            // already the exclusive boundary and must not include that date.
            let end_date = if local_end.time() == NaiveTime::MIN {
                local_end.date()
            } else {
                local_end
                    .date()
                    .checked_add_days(Days::new(1))
                    .ok_or_else(date_overflow)?
            };
            (
                local_start.date().format("%Y-%m-%d").to_string(),
                end_date.format("%Y-%m-%d").to_string(),
            )
        } else {
            (
                local_start.format("%Y-%m-%dT%H:%M:%S").to_string(),
                local_end.format("%Y-%m-%dT%H:%M:%S").to_string(),
            )
        };
        self.expand_occurrences(&CalendarExpansionRequest {
            range_start,
            range_end,
            limit,
            schedule_revision_heads,
            continuation: None,
        })
    }

    /// Expands one finite page using the exact TZDB release compiled into this
    /// build. A schedule pinned to any other release fails closed.
    pub fn expand_occurrences(
        &self,
        request: &CalendarExpansionRequest,
    ) -> Result<CalendarOccurrencePage, CalendarExpansionError> {
        if self.tzdb_version != IANA_TZDB_VERSION {
            return Err(CalendarExpansionError::TzdbMismatch {
                requested: self.tzdb_version.clone(),
                executable: IANA_TZDB_VERSION.to_owned(),
            });
        }
        self.validate()
            .map_err(|error| CalendarExpansionError::InvalidRequest(error.to_string()))?;
        validate_request(self, request)?;

        let range = LocalRange::parse(self.all_day, &request.range_start, &request.range_end)?;
        let base = LocalValue::parse(self.all_day, &self.start, "calendar start")?;
        let Some(recurrence) = self.recurrence.as_ref() else {
            let occurrences = if range.contains(base) {
                vec![build_occurrence(self, base)?]
            } else {
                Vec::new()
            };
            return Ok(CalendarOccurrencePage {
                occurrences,
                status: CalendarExpansionStatus::Complete,
                limited_by: None,
                continuation: None,
                candidate_periods_scanned: 0,
            });
        };

        let mut position = ExpansionPosition {
            next_period_index: 0,
            occurrences_seen: 1,
        };
        let mut sort_key = base.render(self.all_day);
        let mut include_base = true;
        if let Some(cursor) = &request.continuation {
            let payload = decode_continuation(cursor)?;
            validate_continuation(self, request, &payload)?;
            position = ExpansionPosition {
                next_period_index: payload.next_period_index,
                occurrences_seen: payload.occurrences_seen,
            };
            sort_key = payload.sort_key;
            include_base = false;
        }

        let mut occurrences = Vec::new();
        if include_base && range.contains(base) {
            occurrences.push(build_occurrence(self, base)?);
            if occurrences.len() == request.limit {
                return limited_page(
                    self,
                    request,
                    occurrences,
                    CalendarExpansionLimit::OccurrenceLimit,
                    position,
                    sort_key,
                    0,
                );
            }
        }

        let mut scanned = 0usize;
        loop {
            if scanned == MAX_CALENDAR_EXPANSION_CANDIDATE_PERIODS {
                return limited_page(
                    self,
                    request,
                    occurrences,
                    CalendarExpansionLimit::CandidatePeriodBudget,
                    position,
                    sort_key,
                    scanned,
                );
            }
            let period = recurrence_period(base, recurrence, position.next_period_index)?;
            if period.start >= range.end {
                return Ok(complete_page(occurrences, scanned));
            }
            scanned += 1;

            let candidates = recurrence_candidates(base, recurrence, period)?;
            let mut completed_period = true;
            for candidate in candidates {
                let candidate_key = candidate.render(self.all_day);
                if candidate <= base || candidate_key <= sort_key {
                    continue;
                }
                if recurrence
                    .until
                    .as_deref()
                    .is_some_and(|until| candidate.after_wire_value(until, self.all_day))
                {
                    return Ok(complete_page(occurrences, scanned));
                }
                if recurrence
                    .count
                    .is_some_and(|count| position.occurrences_seen >= count)
                {
                    return Ok(complete_page(occurrences, scanned));
                }
                position.occurrences_seen += 1;
                sort_key = candidate_key;
                if candidate >= range.end {
                    return Ok(complete_page(occurrences, scanned));
                }
                if range.contains(candidate) {
                    occurrences.push(build_occurrence(self, candidate)?);
                    if occurrences.len() == request.limit {
                        completed_period = false;
                        break;
                    }
                }
            }
            if completed_period {
                position.next_period_index =
                    position.next_period_index.checked_add(1).ok_or_else(|| {
                        CalendarExpansionError::InvalidRequest(
                            "recurrence period index overflowed".to_owned(),
                        )
                    })?;
            } else {
                return limited_page(
                    self,
                    request,
                    occurrences,
                    CalendarExpansionLimit::OccurrenceLimit,
                    position,
                    sort_key,
                    scanned,
                );
            }
        }
    }
}

fn validate_request(
    fields: &CalendarEventFields,
    request: &CalendarExpansionRequest,
) -> Result<(), CalendarExpansionError> {
    if request.limit == 0 || request.limit > MAX_CALENDAR_EXPANSION_OCCURRENCES {
        return Err(CalendarExpansionError::InvalidRequest(
            "limit must be in 1..=10000".to_owned(),
        ));
    }
    if request.schedule_revision_heads.is_empty() {
        return Err(CalendarExpansionError::InvalidRequest(
            "schedule_revision_heads must be non-empty".to_owned(),
        ));
    }
    if !request
        .schedule_revision_heads
        .windows(2)
        .all(|pair| pair[0].as_str().as_bytes() < pair[1].as_str().as_bytes())
    {
        return Err(CalendarExpansionError::InvalidRequest(
            "schedule_revision_heads must be unique and canonically sorted".to_owned(),
        ));
    }
    let range = LocalRange::parse(fields.all_day, &request.range_start, &request.range_end)?;
    if range.start >= range.end {
        return Err(CalendarExpansionError::InvalidRequest(
            "range_end must be later than range_start".to_owned(),
        ));
    }
    Ok(())
}

fn validate_continuation(
    fields: &CalendarEventFields,
    request: &CalendarExpansionRequest,
    payload: &ContinuationPayload,
) -> Result<(), CalendarExpansionError> {
    if payload.cursor_version != 1
        || payload.schedule_revision_heads != request.schedule_revision_heads
        || payload.tzdb_version != fields.tzdb_version
        || payload.range_start != request.range_start
        || payload.range_end != request.range_end
    {
        return Err(CalendarExpansionError::InvalidCursor(
            "continuation binding no longer matches schedule revision, tzdb_version or range"
                .to_owned(),
        ));
    }
    let sort_key = LocalValue::parse(fields.all_day, &payload.sort_key, "continuation sort_key")
        .map_err(|_| {
            CalendarExpansionError::InvalidCursor(
                "continuation carries an invalid sort key".to_owned(),
            )
        })?;
    let base = LocalValue::parse(fields.all_day, &fields.start, "calendar start")?;
    if sort_key < base || payload.occurrences_seen == 0 {
        return Err(CalendarExpansionError::InvalidCursor(
            "continuation position precedes the recurrence anchor".to_owned(),
        ));
    }
    Ok(())
}

fn limited_page(
    fields: &CalendarEventFields,
    request: &CalendarExpansionRequest,
    occurrences: Vec<CalendarOccurrence>,
    limited_by: CalendarExpansionLimit,
    position: ExpansionPosition,
    sort_key: String,
    scanned: usize,
) -> Result<CalendarOccurrencePage, CalendarExpansionError> {
    let payload = ContinuationPayload {
        cursor_version: 1,
        schedule_revision_heads: request.schedule_revision_heads.clone(),
        tzdb_version: fields.tzdb_version.clone(),
        range_start: request.range_start.clone(),
        range_end: request.range_end.clone(),
        next_period_index: position.next_period_index,
        occurrences_seen: position.occurrences_seen,
        sort_key,
    };
    Ok(CalendarOccurrencePage {
        occurrences,
        status: CalendarExpansionStatus::LimitExceeded,
        limited_by: Some(limited_by),
        continuation: Some(encode_continuation(&payload)?),
        candidate_periods_scanned: scanned,
    })
}

fn complete_page(occurrences: Vec<CalendarOccurrence>, scanned: usize) -> CalendarOccurrencePage {
    CalendarOccurrencePage {
        occurrences,
        status: CalendarExpansionStatus::Complete,
        limited_by: None,
        continuation: None,
        candidate_periods_scanned: scanned,
    }
}

fn encode_continuation(payload: &ContinuationPayload) -> Result<String, CalendarExpansionError> {
    let bytes = serde_json::to_vec(payload).map_err(|error| {
        CalendarExpansionError::InvalidRequest(format!(
            "continuation serialization failed: {error}"
        ))
    })?;
    let checksum = Sha256::digest(&bytes);
    Ok(format!(
        "v1.{}.{}",
        base64url_encode(&bytes),
        base64url_encode(checksum)
    ))
}

fn decode_continuation(value: &str) -> Result<ContinuationPayload, CalendarExpansionError> {
    let mut parts = value.split('.');
    let (Some("v1"), Some(payload), Some(checksum), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(CalendarExpansionError::InvalidCursor(
            "continuation is not a v1 cursor".to_owned(),
        ));
    };
    let bytes = base64url_decode(payload).map_err(|_| {
        CalendarExpansionError::InvalidCursor("continuation payload is not base64url".to_owned())
    })?;
    let expected_checksum = base64url_decode(checksum).map_err(|_| {
        CalendarExpansionError::InvalidCursor("continuation checksum is not base64url".to_owned())
    })?;
    if Sha256::digest(&bytes).as_slice() != expected_checksum {
        return Err(CalendarExpansionError::InvalidCursor(
            "continuation checksum mismatch".to_owned(),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        CalendarExpansionError::InvalidCursor(format!("continuation payload is invalid: {error}"))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LocalValue(NaiveDateTime);

impl LocalValue {
    fn parse(all_day: bool, value: &str, field: &str) -> Result<Self, CalendarExpansionError> {
        let local = if all_day {
            parse_calendar_date(value, field)
                .map_err(|error| CalendarExpansionError::InvalidRequest(error.to_string()))?
                .and_time(NaiveTime::MIN)
        } else {
            parse_calendar_local_date_time(value, field)
                .map_err(|error| CalendarExpansionError::InvalidRequest(error.to_string()))?
        };
        Ok(Self(local))
    }

    fn render(self, all_day: bool) -> String {
        if all_day {
            self.0.format("%Y-%m-%d").to_string()
        } else {
            self.0.format("%Y-%m-%dT%H:%M:%S").to_string()
        }
    }

    fn after_wire_value(self, value: &str, all_day: bool) -> bool {
        Self::parse(all_day, value, "calendar recurrence until")
            .map(|until| self > until)
            .unwrap_or(true)
    }
}

#[derive(Clone, Copy)]
struct LocalRange {
    start: LocalValue,
    end: LocalValue,
}

impl LocalRange {
    fn parse(all_day: bool, start: &str, end: &str) -> Result<Self, CalendarExpansionError> {
        Ok(Self {
            start: LocalValue::parse(all_day, start, "calendar expansion range_start")?,
            end: LocalValue::parse(all_day, end, "calendar expansion range_end")?,
        })
    }

    fn contains(self, value: LocalValue) -> bool {
        value >= self.start && value < self.end
    }
}

#[derive(Clone, Copy)]
struct RecurrencePeriod {
    start: LocalValue,
    end: LocalValue,
}

fn recurrence_period(
    base: LocalValue,
    recurrence: &CalendarRecurrence,
    index: u64,
) -> Result<RecurrencePeriod, CalendarExpansionError> {
    let interval = recurrence.interval.unwrap_or(1);
    let step = index.checked_mul(interval).ok_or_else(|| {
        CalendarExpansionError::InvalidRequest("recurrence interval overflowed".to_owned())
    })?;
    let date = base.0.date();
    let time = base.0.time();
    let (start_date, end_date) = match recurrence.frequency {
        RecurrenceFrequency::Daily => {
            let start = add_days(date, step)?;
            (start, add_days(start, 1)?)
        }
        RecurrenceFrequency::Weekly => {
            let first = recurrence
                .first_day_of_week
                .unwrap_or(RecurrenceWeekday::Mo);
            let week_start = date
                .checked_sub_days(Days::new(u64::from(weekday_distance(
                    first.into(),
                    date.weekday(),
                ))))
                .ok_or_else(date_overflow)?;
            let start = add_days(week_start, step.checked_mul(7).ok_or_else(date_overflow)?)?;
            (start, add_days(start, 7)?)
        }
        RecurrenceFrequency::Monthly => {
            let month_start = date.with_day(1).ok_or_else(date_overflow)?;
            let start = add_months(month_start, step)?;
            (start, add_months(start, 1)?)
        }
        RecurrenceFrequency::Yearly => {
            let year = i64::from(date.year())
                .checked_add(i64::try_from(step).map_err(|_| date_overflow())?)
                .ok_or_else(date_overflow)?;
            let year = i32::try_from(year).map_err(|_| date_overflow())?;
            let start = NaiveDate::from_ymd_opt(year, 1, 1).ok_or_else(date_overflow)?;
            let next_year = year.checked_add(1).ok_or_else(date_overflow)?;
            let end = NaiveDate::from_ymd_opt(next_year, 1, 1).ok_or_else(date_overflow)?;
            (start, end)
        }
    };
    Ok(RecurrencePeriod {
        start: LocalValue(start_date.and_time(time)),
        end: LocalValue(end_date.and_time(time)),
    })
}

fn recurrence_candidates(
    base: LocalValue,
    recurrence: &CalendarRecurrence,
    period: RecurrencePeriod,
) -> Result<Vec<LocalValue>, CalendarExpansionError> {
    let mut dates = Vec::new();
    let mut date = period.start.0.date();
    while date < period.end.0.date() {
        if matches_filters(date, base.0.date(), recurrence) {
            dates.push(date);
        }
        date = date
            .checked_add_days(Days::new(1))
            .ok_or_else(date_overflow)?;
    }
    if let Some(positions) = &recurrence.by_set_position {
        let mut selected = BTreeSet::new();
        for position in positions {
            let index = if *position > 0 {
                i64::from(*position) - 1
            } else {
                i64::try_from(dates.len()).map_err(|_| date_overflow())? + i64::from(*position)
            };
            if let Ok(index) = usize::try_from(index)
                && let Some(date) = dates.get(index)
            {
                selected.insert(*date);
            }
        }
        dates = selected.into_iter().collect();
    }
    Ok(dates
        .into_iter()
        .map(|date| LocalValue(date.and_time(base.0.time())))
        .collect())
}

fn matches_filters(date: NaiveDate, base: NaiveDate, recurrence: &CalendarRecurrence) -> bool {
    let implicit_yearly_month =
        recurrence.frequency == RecurrenceFrequency::Yearly && recurrence.by_month.is_none();
    if let Some(months) = &recurrence.by_month {
        if !months
            .iter()
            .any(|month| month.parse::<u32>().ok() == Some(date.month()))
        {
            return false;
        }
    } else if implicit_yearly_month && date.month() != base.month() {
        return false;
    }

    if let Some(month_days) = &recurrence.by_month_day {
        if !month_days.iter().any(|day| matches_month_day(date, *day)) {
            return false;
        }
    } else {
        let implicit_month_day = (recurrence.frequency == RecurrenceFrequency::Monthly
            || recurrence.frequency == RecurrenceFrequency::Yearly)
            && recurrence.by_day.is_empty();
        if implicit_month_day && date.day() != base.day() {
            return false;
        }
    }

    if !recurrence.by_day.is_empty() {
        if !recurrence
            .by_day
            .iter()
            .any(|rule| matches_by_day(date, recurrence, rule))
        {
            return false;
        }
    } else if recurrence.frequency == RecurrenceFrequency::Weekly
        && date.weekday() != base.weekday()
    {
        return false;
    }
    true
}

fn matches_month_day(date: NaiveDate, requested: i8) -> bool {
    if requested > 0 {
        return date.day() == u32::from(requested as u8);
    }
    let Some(last) = last_day_of_month(date.year(), date.month()) else {
        return false;
    };
    let from_end = i64::from(last.day()) + i64::from(requested) + 1;
    i64::from(date.day()) == from_end
}

fn matches_by_day(
    date: NaiveDate,
    recurrence: &CalendarRecurrence,
    rule: &CalendarRecurrenceDay,
) -> bool {
    let weekday: Weekday = rule.day.into();
    if date.weekday() != weekday {
        return false;
    }
    let Some(nth) = rule.nth_of_period else {
        return true;
    };
    let within_month = recurrence.frequency == RecurrenceFrequency::Monthly
        || (recurrence.frequency == RecurrenceFrequency::Yearly && recurrence.by_month.is_some());
    let bounds = if within_month {
        date.with_day(1)
            .zip(last_day_of_month(date.year(), date.month()))
    } else {
        NaiveDate::from_ymd_opt(date.year(), 1, 1).zip(NaiveDate::from_ymd_opt(date.year(), 12, 31))
    };
    bounds.is_some_and(|(start, end)| nth_weekday_matches(date, start, end, nth))
}

fn nth_weekday_matches(
    date: NaiveDate,
    period_start: NaiveDate,
    period_end: NaiveDate,
    nth: i16,
) -> bool {
    if nth > 0 {
        let ordinal = ((date - period_start).num_days() / 7) + 1;
        ordinal == i64::from(nth)
    } else {
        let ordinal_from_end = -(((period_end - date).num_days() / 7) + 1);
        ordinal_from_end == i64::from(nth)
    }
}

fn build_occurrence(
    fields: &CalendarEventFields,
    start: LocalValue,
) -> Result<CalendarOccurrence, CalendarExpansionError> {
    if fields.all_day {
        let duration = fields
            .base_duration()
            .map_err(|error| CalendarExpansionError::InvalidRequest(error.to_string()))?;
        let end = start.0 + duration;
        let local_start = start.render(true);
        return Ok(CalendarOccurrence {
            occurrence: local_start.clone(),
            local_start,
            local_end: end.format("%Y-%m-%d").to_string(),
            start_instant: None,
            end_instant: None,
        });
    }
    let timezone = parse_calendar_timezone(&fields.timezone)
        .map_err(|error| CalendarExpansionError::InvalidRequest(error.to_string()))?;
    let start_instant = resolve_local_to_instant(start.0, timezone)
        .map_err(|error| CalendarExpansionError::InvalidRequest(error.to_string()))?;
    let duration = fields
        .base_duration()
        .map_err(|error| CalendarExpansionError::InvalidRequest(error.to_string()))?;
    let end_instant = start_instant + duration;
    let local_start = start.render(false);
    Ok(CalendarOccurrence {
        occurrence: format!("{local_start}[{}]", fields.timezone),
        local_start,
        local_end: end_instant
            .with_timezone(&timezone)
            .naive_local()
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string(),
        start_instant: Some(start_instant),
        end_instant: Some(end_instant),
    })
}

fn add_days(date: NaiveDate, days: u64) -> Result<NaiveDate, CalendarExpansionError> {
    date.checked_add_days(Days::new(days))
        .ok_or_else(date_overflow)
}

fn add_months(date: NaiveDate, months: u64) -> Result<NaiveDate, CalendarExpansionError> {
    let months = u32::try_from(months).map_err(|_| date_overflow())?;
    date.checked_add_months(Months::new(months))
        .ok_or_else(date_overflow)
}

fn last_day_of_month(year: i32, month: u32) -> Option<NaiveDate> {
    let next = if month == 12 {
        NaiveDate::from_ymd_opt(year.checked_add(1)?, 1, 1)?
    } else {
        NaiveDate::from_ymd_opt(year, month.checked_add(1)?, 1)?
    };
    next.checked_sub_days(Days::new(1))
}

fn weekday_distance(first: Weekday, day: Weekday) -> u8 {
    let first = first.num_days_from_monday() as i8;
    let day = day.num_days_from_monday() as i8;
    (day - first).rem_euclid(7) as u8
}

fn date_overflow() -> CalendarExpansionError {
    CalendarExpansionError::InvalidRequest("recurrence date overflowed".to_owned())
}

impl From<RecurrenceWeekday> for Weekday {
    fn from(value: RecurrenceWeekday) -> Self {
        match value {
            RecurrenceWeekday::Mo => Self::Mon,
            RecurrenceWeekday::Tu => Self::Tue,
            RecurrenceWeekday::We => Self::Wed,
            RecurrenceWeekday::Th => Self::Thu,
            RecurrenceWeekday::Fr => Self::Fri,
            RecurrenceWeekday::Sa => Self::Sat,
            RecurrenceWeekday::Su => Self::Sun,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::productivity::CalendarStatus;

    fn digest(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn request(start: &str, end: &str, limit: usize) -> CalendarExpansionRequest {
        CalendarExpansionRequest {
            range_start: start.to_owned(),
            range_end: end.to_owned(),
            limit,
            schedule_revision_heads: vec![digest(1)],
            continuation: None,
        }
    }

    fn timed(
        start: &str,
        end: &str,
        timezone: &str,
        recurrence: CalendarRecurrence,
    ) -> CalendarEventFields {
        CalendarEventFields {
            start: start.to_owned(),
            end: end.to_owned(),
            timezone: timezone.to_owned(),
            tzdb_version: IANA_TZDB_VERSION.to_owned(),
            all_day: false,
            status: CalendarStatus::Confirmed,
            recurrence: Some(recurrence),
            location: None,
            call_id: None,
            attendees: Vec::new(),
        }
    }

    fn recurrence(frequency: RecurrenceFrequency) -> CalendarRecurrence {
        CalendarRecurrence {
            frequency,
            interval: None,
            by_day: Vec::new(),
            by_month: None,
            by_month_day: None,
            by_set_position: None,
            first_day_of_week: None,
            count: None,
            until: None,
        }
    }

    #[test]
    fn weekly_monthly_and_yearly_implicit_filters_are_expanded() {
        let mut weekly = recurrence(RecurrenceFrequency::Weekly);
        weekly.count = Some(3);
        let page = timed(
            "2026-06-22T09:00:00",
            "2026-06-22T10:00:00",
            "America/Los_Angeles",
            weekly,
        )
        .expand_occurrences(&request("2026-06-01T00:00:00", "2026-08-01T00:00:00", 100))
        .unwrap();
        assert_eq!(
            page.occurrences
                .iter()
                .map(|value| value.local_start.as_str())
                .collect::<Vec<_>>(),
            [
                "2026-06-22T09:00:00",
                "2026-06-29T09:00:00",
                "2026-07-06T09:00:00"
            ]
        );

        let mut monthly = recurrence(RecurrenceFrequency::Monthly);
        monthly.count = Some(3);
        let page = timed(
            "2026-01-31T09:00:00",
            "2026-01-31T10:00:00",
            "Etc/UTC",
            monthly,
        )
        .expand_occurrences(&request("2026-01-01T00:00:00", "2026-06-01T00:00:00", 100))
        .unwrap();
        assert_eq!(
            page.occurrences
                .iter()
                .map(|value| value.local_start.as_str())
                .collect::<Vec<_>>(),
            [
                "2026-01-31T09:00:00",
                "2026-03-31T09:00:00",
                "2026-05-31T09:00:00"
            ]
        );

        let mut yearly = recurrence(RecurrenceFrequency::Yearly);
        yearly.count = Some(3);
        let page = timed(
            "2024-02-29T09:00:00",
            "2024-02-29T10:00:00",
            "Etc/UTC",
            yearly,
        )
        .expand_occurrences(&request("2024-01-01T00:00:00", "2036-01-01T00:00:00", 100))
        .unwrap();
        assert_eq!(
            page.occurrences
                .iter()
                .map(|value| value.local_start.as_str())
                .collect::<Vec<_>>(),
            [
                "2024-02-29T09:00:00",
                "2028-02-29T09:00:00",
                "2032-02-29T09:00:00"
            ]
        );
    }

    #[test]
    fn base_is_first_even_when_it_does_not_match_by_day() {
        let mut rule = recurrence(RecurrenceFrequency::Weekly);
        rule.by_day = vec![CalendarRecurrenceDay {
            day: RecurrenceWeekday::We,
            nth_of_period: None,
        }];
        rule.count = Some(3);
        let page = timed(
            "2026-06-22T09:00:00",
            "2026-06-22T10:00:00",
            "Etc/UTC",
            rule,
        )
        .expand_occurrences(&request("2026-06-01T00:00:00", "2026-07-31T00:00:00", 100))
        .unwrap();
        assert_eq!(
            page.occurrences
                .iter()
                .map(|value| value.local_start.as_str())
                .collect::<Vec<_>>(),
            [
                "2026-06-22T09:00:00",
                "2026-06-24T09:00:00",
                "2026-07-01T09:00:00"
            ]
        );
    }

    #[test]
    fn gap_and_fold_use_the_pre_transition_offset_and_keep_local_keys() {
        let mut rule = recurrence(RecurrenceFrequency::Daily);
        rule.count = Some(3);
        let spring = timed(
            "2026-03-07T02:30:00",
            "2026-03-07T03:30:00",
            "America/New_York",
            rule.clone(),
        )
        .expand_occurrences(&request("2026-03-07T00:00:00", "2026-03-10T00:00:00", 100))
        .unwrap();
        assert_eq!(
            arkret_canonical::format_timestamp_canonical(
                spring.occurrences[1].start_instant.unwrap()
            ),
            "2026-03-08T07:30:00.000Z"
        );
        assert_eq!(
            spring.occurrences[1].occurrence,
            "2026-03-08T02:30:00[America/New_York]"
        );

        rule.count = Some(3);
        let fall = timed(
            "2026-10-31T01:30:00",
            "2026-10-31T02:30:00",
            "America/New_York",
            rule,
        )
        .expand_occurrences(&request("2026-10-31T00:00:00", "2026-11-03T00:00:00", 100))
        .unwrap();
        assert_eq!(
            arkret_canonical::format_timestamp_canonical(
                fall.occurrences[1].start_instant.unwrap()
            ),
            "2026-11-01T05:30:00.000Z"
        );
        assert_eq!(fall.occurrences.len(), 3);
    }

    #[test]
    fn continuation_pages_and_invalidates_on_schedule_revision_change() {
        let mut rule = recurrence(RecurrenceFrequency::Daily);
        rule.count = Some(4);
        let event = timed(
            "2026-01-01T09:00:00",
            "2026-01-01T10:00:00",
            "Etc/UTC",
            rule,
        );
        let first = event
            .expand_occurrences(&request("2026-01-01T00:00:00", "2026-01-10T00:00:00", 2))
            .unwrap();
        assert_eq!(first.status, CalendarExpansionStatus::LimitExceeded);
        let mut resumed = request("2026-01-01T00:00:00", "2026-01-10T00:00:00", 2);
        resumed.continuation = first.continuation;
        let second = event.expand_occurrences(&resumed).unwrap();
        assert_eq!(
            second
                .occurrences
                .iter()
                .map(|value| value.local_start.as_str())
                .collect::<Vec<_>>(),
            ["2026-01-03T09:00:00", "2026-01-04T09:00:00"]
        );

        resumed.schedule_revision_heads = vec![digest(2)];
        assert!(matches!(
            event.expand_occurrences(&resumed),
            Err(CalendarExpansionError::InvalidCursor(_))
        ));
    }

    #[test]
    fn expansion_fails_closed_for_a_different_signed_tzdb_release() {
        let mut rule = recurrence(RecurrenceFrequency::Daily);
        rule.count = Some(2);
        let mut event = timed(
            "2026-01-01T09:00:00",
            "2026-01-01T10:00:00",
            "Etc/UTC",
            rule,
        );
        event.tzdb_version = "2025a".to_owned();
        assert!(matches!(
            event.expand_occurrences(&request("2026-01-01T00:00:00", "2026-01-10T00:00:00", 10)),
            Err(CalendarExpansionError::TzdbMismatch { .. })
        ));
    }

    #[test]
    fn candidate_budget_returns_bound_continuation_and_limit_is_capped() {
        let mut rule = recurrence(RecurrenceFrequency::Daily);
        rule.by_month = Some(vec!["2".to_owned()]);
        rule.by_month_day = Some(vec![30]);
        let event = timed(
            "2026-03-01T09:00:00",
            "2026-03-01T10:00:00",
            "Etc/UTC",
            rule,
        );
        let page = event
            .expand_occurrences(&request("2026-03-01T00:00:00", "2400-01-01T00:00:00", 100))
            .unwrap();
        assert_eq!(page.status, CalendarExpansionStatus::LimitExceeded);
        assert_eq!(
            page.limited_by,
            Some(CalendarExpansionLimit::CandidatePeriodBudget)
        );
        assert_eq!(
            page.candidate_periods_scanned,
            MAX_CALENDAR_EXPANSION_CANDIDATE_PERIODS
        );
        assert!(page.continuation.is_some());

        assert!(
            event
                .expand_occurrences(&request(
                    "2026-03-01T00:00:00",
                    "2026-03-02T00:00:00",
                    MAX_CALENDAR_EXPANSION_OCCURRENCES + 1,
                ))
                .is_err()
        );
    }

    #[test]
    fn all_day_instant_range_keeps_midnight_as_the_exclusive_boundary() {
        let event = CalendarEventFields {
            start: "2026-07-29".to_owned(),
            end: "2026-07-30".to_owned(),
            timezone: "Etc/UTC".to_owned(),
            tzdb_version: IANA_TZDB_VERSION.to_owned(),
            all_day: true,
            status: CalendarStatus::Confirmed,
            recurrence: Some(CalendarRecurrence {
                frequency: RecurrenceFrequency::Daily,
                interval: None,
                by_day: Vec::new(),
                by_month: None,
                by_month_day: None,
                by_set_position: None,
                first_day_of_week: None,
                count: Some(3),
                until: None,
            }),
            location: None,
            call_id: None,
            attendees: Vec::new(),
        };
        let page = event
            .expand_occurrences_between_instants(
                "2026-07-29T12:00:00Z".parse().unwrap(),
                "2026-07-30T00:00:00Z".parse().unwrap(),
                100,
                vec![digest(1)],
            )
            .unwrap();
        assert_eq!(
            page.occurrences
                .iter()
                .map(|occurrence| occurrence.local_start.as_str())
                .collect::<Vec<_>>(),
            ["2026-07-29"]
        );
    }
}
