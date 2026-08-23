use arkret_models_collaboration::governance::grant_constraint::GrantConstraintSubkind;
use arkret_wire::{AppletId, DidCoreId, Hash, HistoryAccess};

use super::*;

/// Resource being accessed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    /// Realm resource.
    Realm { realm_id: String },
    /// Space resource.
    Space { realm_id: String, space_id: String },
    /// Strand resource
    Strand { realm_id: String, strand_id: String },
    /// Message resource.
    Message {
        realm_id: String,
        message_id: String,
    },
    /// Relation resource
    Relation {
        realm_id: String,
        relation_kind: String,
    },
    /// View resource
    View { realm_id: String, view_id: String },
    /// Schema resource
    Schema { realm_id: String, schema_id: String },
    /// Policy resource
    Policy { realm_id: String, policy_id: String },
    /// Invite resource
    Invite { realm_id: String, invite_id: String },
    /// Read marker resource
    ReadCursor { realm_id: String },
    /// Morph resource (canonical open-typed object).
    Morph {
        realm_id: String,
        morph_id: String,
        morph_kind: String,
    },
    /// Notification resource (per-actor private channel).
    Notification {
        realm_id: String,
        actor_id: String,
        notification_id: String,
    },
    /// Blob resource. `realm_id` may be `*` for global blobs.
    Blob { realm_id: String, blob_id: String },
    /// Event resource (audit / redaction / state-resolution targets).
    Event {
        realm_id: String,
        event_kind: String,
        event_id: String,
    },
    /// Actor resource (account-lifecycle, profile updates).
    Actor { actor_id: String },
    /// Circle resource.
    Circle {
        realm_id: String,
        circle_id: crate::CircleId,
    },
}

impl Resource {
    /// Get the Realm ID for this resource. Returns the wildcard string only for
    /// actor resources, which are not Realm-bound.
    pub fn realm_id(&self) -> &str {
        match self {
            Self::Realm { realm_id } => realm_id,
            Self::Space { realm_id, .. } => realm_id,
            Self::Strand { realm_id, .. } => realm_id,
            Self::Message { realm_id, .. } => realm_id,
            Self::Relation { realm_id, .. } => realm_id,
            Self::View { realm_id, .. } => realm_id,
            Self::Schema { realm_id, .. } => realm_id,
            Self::Policy { realm_id, .. } => realm_id,
            Self::Invite { realm_id, .. } => realm_id,
            Self::ReadCursor { realm_id } => realm_id,
            Self::Morph { realm_id, .. } => realm_id,
            Self::Notification { realm_id, .. } => realm_id,
            Self::Blob { realm_id, .. } => realm_id,
            Self::Event { realm_id, .. } => realm_id,
            Self::Circle { realm_id, .. } => realm_id,
            Self::Actor { .. } => "*",
        }
    }
}

/// Constraint types.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Constraint {
    /// Temporal constraint
    Temporal {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
        not_before: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
        expires_at: Option<DateTime<Utc>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        recurrence: Option<Recurrence>,
    },
    /// Field access constraint
    FieldAccess {
        effect: ConstraintEffect,
        scope: FieldScope,
        fields: Vec<String>,
    },
    /// Type restriction constraint
    KindRestriction {
        #[serde(skip_serializing_if = "Option::is_none")]
        allowed_object_kinds: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        denied_object_kinds: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        allowed_morph_kinds: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        denied_morph_kinds: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_facets: Vec<Facet>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        denied_facets: Vec<Facet>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope_limitation: Option<ScopeLimitation>,
    },
    /// Re-grant control. `authority_regrant_allowed` defaults to `false` per
    /// `constraint-schema.md` §7.2, so a grant must opt in explicitly before it
    /// can be named by another grant's `issuer_authority_refs`.
    AuthorityControl {
        #[serde(skip_serializing_if = "Option::is_none")]
        max_authority_depth: Option<u32>,
        #[serde(default)]
        authority_regrant_allowed: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        constraint_subkind: Option<GrantConstraintSubkind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        applet_id: Option<AppletId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        executed_by: Option<DidCoreId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        registration_epoch: Option<Hash>,
    },
    /// Rate limiting constraint
    RateLimiting {
        max_operations: u64,
        period: ConstraintDuration,
        #[serde(default = "default_rate_limit_scope")]
        scope: GrantRateLimitScope,
    },
    /// Approval workflow constraint
    ApprovalWorkflow {
        #[serde(default = "default_false")]
        approval_required: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        approval_actor_ids: Option<Vec<DidCoreId>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout: Option<ConstraintDuration>,
        #[serde(skip_serializing_if = "Option::is_none")]
        approval_mode: Option<ApprovalMode>,
        #[serde(skip_serializing_if = "Option::is_none")]
        approval_relation: Option<String>,
        #[serde(default)]
        guardian_approval_required: bool,
        #[serde(default)]
        controller_approval_required: bool,
    },
    /// Claim-based constraint
    ClaimBased {
        required_claims: Vec<ClaimRequirement>,
        trusted_issuers: Vec<DidCoreId>,
        #[serde(default)]
        claim_refresh_required: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        claim_max_age: Option<ConstraintDuration>,
    },
    /// Accountability constraint
    Accountability {
        #[serde(default = "default_false")]
        accountability_required: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        responsible_actor: Option<DidCoreId>,
    },
    /// Encryption requirement constraint
    EncryptionRequirement {
        #[serde(default = "default_false")]
        encryption_required: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        min_encryption_level: Option<String>,
    },
    /// Visibility control constraint (`confidentiality{constraint_subkind=visibility}`).
    /// See `constraint-schema.md` §13.
    VisibilityControl {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_history_access_values: Vec<HistoryAccess>,
        #[serde(default = "default_false")]
        redacted_history_allowed: bool,
    },
    /// Resource quota constraint (`quota{constraint_subkind=resource}`).
    /// See `constraint-schema.md` §8.2 / §14.1.
    ResourceLimit {
        #[serde(skip_serializing_if = "Option::is_none")]
        blob_max_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max_total_blob_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max_resources: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        resource_kind: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        period: Option<ConstraintDuration>,
        #[serde(default = "default_rate_limit_scope")]
        scope: GrantRateLimitScope,
    },
    /// Edit / redact temporal window for messages
    /// (`temporal{constraint_subkind=edit_window}`). See `constraint-schema.md` §14.2.
    EditWindow {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        applies_to_actions: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message_edit_window: Option<ConstraintDuration>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message_redact_window: Option<ConstraintDuration>,
        #[serde(default = "default_false")]
        redact_after_window_allowed: bool,
    },
    /// Container move scope (`scope_limitation` with container refs).
    /// See `constraint-schema.md` §6.3.
    ContainerMove {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_relation_kinds: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_view_ids: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_from_container_refs: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_to_container_refs: Vec<String>,
        #[serde(default = "default_false")]
        wip_limit_override: bool,
    },
    /// Generic scope limitation (`scope_limitation`).
    /// See `constraint-schema.md` §6.1 / §6.2.
    ScopeLimitation {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_strand_ids: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        denied_strand_ids: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_tracks: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        denied_tracks: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_view_kinds: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_view_renderers: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        denied_view_kinds: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        denied_view_renderers: Vec<String>,
    },
    /// AKP-0007 (spec b7d35be) — narrow a Circle-management capability
    /// (`ak.circle.manage`, `ak.circle.member.manage`,
    /// `ak.circle.member.add.others`, `ak.circle.audit`) to a specific set
    /// of Circle ids. Spec `capability-action-registry.json` declares
    /// `required_constraints=["allowed_circle_ids"]` on each gated action;
    /// unconstrained Realm-wide grants for these actions MUST be rejected.
    AllowedCircleIds {
        allowed_circle_ids: std::collections::BTreeSet<crate::CircleId>,
    },
    /// Limits applet interop-session writes to explicit session ids.
    AllowedSessionIds {
        allowed_session_ids: std::collections::BTreeSet<String>,
    },
}

/// Constraint effect.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintEffect {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
}

/// Field scope for access control.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldScope {
    Read,
    Write,
}

/// Recurrence pattern for temporal constraints.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Recurrence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_end: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

/// Duration representation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstraintDuration {
    pub value: u64,
    pub unit: String, // "s", "m", "h", "d"
}

/// Grant-constraint-local rate limit scope (quota constraint evaluation).
///
/// Distinct from the wire `arkret::RateLimitScope`
/// (service-description `rate_limit_scope`: `string | string[]`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrantRateLimitScope {
    PerActor,
    PerSpace,
    PerRealm,
    #[default]
    Global,
}

/// Scope limitation type for grant constraints.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeLimitation {
    Space,
    Strand,
    Message,
    Morph,
    View,
    Relation,
    Policy,
    Circle,
}

/// Approval semantics for approval workflow constraints.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    Any,
    All,
    Threshold { count: u32 },
    Guardian,
    Controller,
}

fn default_rate_limit_scope() -> GrantRateLimitScope {
    GrantRateLimitScope::Global
}

fn default_false() -> bool {
    false
}

pub fn max_age_contains(age: chrono::Duration, max_age: &ConstraintDuration) -> bool {
    let allowed = match max_age.unit.as_str() {
        "s" => chrono::Duration::seconds(max_age.value as i64),
        "m" => chrono::Duration::minutes(max_age.value as i64),
        "h" => chrono::Duration::hours(max_age.value as i64),
        "d" => chrono::Duration::days(max_age.value as i64),
        _ => return false,
    };
    age <= allowed
}

#[derive(Clone, Copy)]
enum RecurrenceZone {
    Named(Tz),
    Fixed(FixedOffset),
}

impl RecurrenceZone {
    fn local_parts(&self, now: DateTime<Utc>) -> (NaiveDate, Weekday, NaiveTime) {
        match self {
            Self::Named(tz) => {
                let local = now.with_timezone(tz);
                (local.date_naive(), local.weekday(), local.time())
            }
            Self::Fixed(offset) => {
                let local = now.with_timezone(offset);
                (local.date_naive(), local.weekday(), local.time())
            }
        }
    }
}

/// Structured failure modes for the recurrence parsing helpers.
///
/// This is an internal type — kept `pub(super)` so the engine can pattern
/// match on failure kind instead of string-comparing. The public API of
/// `authz::engine` and `authz::constraints` is unchanged; at the engine
/// boundary the error is rendered via [`std::fmt::Display`] which produces
/// the same human-readable strings the previous `Result<_, String>` API
/// returned, so observable behavior (deny reasons, error messages) is
/// byte-equivalent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConstraintParseError {
    /// Timezone string could not be parsed as IANA or fixed offset.
    InvalidTimezone(String),
    /// Day-of-week string could not be parsed.
    InvalidDay(String),
    /// Time-of-day string could not be parsed.
    InvalidTime(String),
    /// Frequency string is not one of the supported keywords.
    InvalidFrequency(String),
    /// Current weekday is outside the configured weekday frequency.
    OutsideWeekdayRecurrence(Weekday),
    /// Current weekday is outside the configured weekend frequency.
    OutsideWeekendRecurrence(Weekday),
    /// Current weekday is not in the explicit `days` allow-list.
    OutsideRecurrenceDays(Weekday),
    /// Current local time is outside the configured window.
    OutsideWindow,
}

impl std::fmt::Display for ConstraintParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTimezone(value) => {
                write!(f, "unsupported recurrence timezone: {}", value)
            }
            Self::InvalidDay(value) => write!(f, "unsupported recurrence day: {}", value),
            Self::InvalidTime(value) => write!(f, "unsupported recurrence time: {}", value),
            Self::InvalidFrequency(value) => {
                write!(f, "unsupported recurrence frequency: {}", value)
            }
            Self::OutsideWeekdayRecurrence(weekday) => {
                write!(f, "outside weekday recurrence: {:?}", weekday)
            }
            Self::OutsideWeekendRecurrence(weekday) => {
                write!(f, "outside weekend recurrence: {:?}", weekday)
            }
            Self::OutsideRecurrenceDays(weekday) => {
                write!(f, "outside recurrence days: {:?}", weekday)
            }
            Self::OutsideWindow => f.write_str("outside recurrence window"),
        }
    }
}

impl std::error::Error for ConstraintParseError {}

pub fn recurrence_allows(
    now: DateTime<Utc>,
    recurrence: &Recurrence,
) -> std::result::Result<(), ConstraintParseError> {
    let zone = parse_recurrence_zone(recurrence.timezone.as_deref())?;
    let (_, weekday, local_time) = zone.local_parts(now);

    recurrence_frequency_allows(recurrence.frequency.as_deref(), weekday)?;

    if let Some(days) = &recurrence.days
        && !days.is_empty()
    {
        let allowed_days = days
            .iter()
            .map(|day| parse_recurrence_day(day))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !allowed_days.contains(&weekday) {
            return Err(ConstraintParseError::OutsideRecurrenceDays(weekday));
        }
    }

    let window_start = recurrence
        .window_start
        .as_deref()
        .map(parse_recurrence_time)
        .transpose()?;
    let window_end = recurrence
        .window_end
        .as_deref()
        .map(parse_recurrence_time)
        .transpose()?;

    if !recurrence_window_contains(local_time, window_start, window_end) {
        return Err(ConstraintParseError::OutsideWindow);
    }

    Ok(())
}

fn parse_recurrence_zone(
    timezone: Option<&str>,
) -> std::result::Result<RecurrenceZone, ConstraintParseError> {
    let value = timezone.unwrap_or("UTC").trim();
    if value.is_empty()
        || value.eq_ignore_ascii_case("utc")
        || value.eq_ignore_ascii_case("etc/utc")
        || value == "Z"
    {
        return Ok(RecurrenceZone::Fixed(
            FixedOffset::east_opt(0).expect("zero offset must be valid"),
        ));
    }

    if let Ok(tz) = value.parse::<Tz>() {
        return Ok(RecurrenceZone::Named(tz));
    }

    parse_fixed_offset(value)
        .map(RecurrenceZone::Fixed)
        .ok_or_else(|| ConstraintParseError::InvalidTimezone(value.to_owned()))
}

fn parse_fixed_offset(value: &str) -> Option<FixedOffset> {
    let value = value.trim();
    let without_utc = if value.len() >= 3 && value[..3].eq_ignore_ascii_case("utc") {
        &value[3..]
    } else {
        value
    };
    let (sign, rest) = if let Some(rest) = without_utc.strip_prefix('+') {
        (1, rest)
    } else {
        (-1, without_utc.strip_prefix('-')?)
    };

    let (hours, minutes) = if let Some((hours, minutes)) = rest.split_once(':') {
        (hours.parse::<i32>().ok()?, minutes.parse::<i32>().ok()?)
    } else if rest.len() == 4 {
        (
            rest[..2].parse::<i32>().ok()?,
            rest[2..].parse::<i32>().ok()?,
        )
    } else {
        (rest.parse::<i32>().ok()?, 0)
    };

    if !(0..=23).contains(&hours) || !(0..=59).contains(&minutes) {
        return None;
    }

    FixedOffset::east_opt(sign * ((hours * 60 * 60) + (minutes * 60)))
}

fn parse_recurrence_day(day: &str) -> std::result::Result<Weekday, ConstraintParseError> {
    match day.trim().to_ascii_lowercase().as_str() {
        "mon" | "monday" | "1" => Ok(Weekday::Mon),
        "tue" | "tues" | "tuesday" | "2" => Ok(Weekday::Tue),
        "wed" | "wednesday" | "3" => Ok(Weekday::Wed),
        "thu" | "thur" | "thurs" | "thursday" | "4" => Ok(Weekday::Thu),
        "fri" | "friday" | "5" => Ok(Weekday::Fri),
        "sat" | "saturday" | "6" => Ok(Weekday::Sat),
        "sun" | "sunday" | "0" | "7" => Ok(Weekday::Sun),
        _ => Err(ConstraintParseError::InvalidDay(day.to_owned())),
    }
}

fn parse_recurrence_time(value: &str) -> std::result::Result<NaiveTime, ConstraintParseError> {
    let value = value.trim();
    NaiveTime::parse_from_str(value, "%H:%M:%S")
        .or_else(|_| NaiveTime::parse_from_str(value, "%H:%M"))
        .map_err(|_| ConstraintParseError::InvalidTime(value.to_owned()))
}

fn recurrence_frequency_allows(
    frequency: Option<&str>,
    weekday: Weekday,
) -> std::result::Result<(), ConstraintParseError> {
    let Some(frequency) = frequency.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };

    match frequency.to_ascii_lowercase().as_str() {
        "always" | "daily" | "weekly" => Ok(()),
        "weekdays" => {
            if matches!(
                weekday,
                Weekday::Mon | Weekday::Tue | Weekday::Wed | Weekday::Thu | Weekday::Fri
            ) {
                Ok(())
            } else {
                Err(ConstraintParseError::OutsideWeekdayRecurrence(weekday))
            }
        }
        "weekends" => {
            if matches!(weekday, Weekday::Sat | Weekday::Sun) {
                Ok(())
            } else {
                Err(ConstraintParseError::OutsideWeekendRecurrence(weekday))
            }
        }
        _ => Err(ConstraintParseError::InvalidFrequency(frequency.to_owned())),
    }
}

fn recurrence_window_contains(
    time: NaiveTime,
    start: Option<NaiveTime>,
    end: Option<NaiveTime>,
) -> bool {
    match (start, end) {
        (None, None) => true,
        (Some(start), None) => time >= start,
        (None, Some(end)) => time < end,
        (Some(start), Some(end)) if start == end => true,
        (Some(start), Some(end)) if start < end => time >= start && time < end,
        (Some(start), Some(end)) => time >= start || time < end,
    }
}

/// Claim requirement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimRequirement {
    pub claim_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

/// Verified claim evidence supplied by the caller during authorization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedClaim {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    pub subject: DidCoreId,
    pub claim_kind: String,
    pub issuer: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub issued_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub refreshed_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod constraint_parse_error_tests {
    //! Unit tests for the structured [`ConstraintParseError`] enum returned
    //! by the recurrence parsing helpers. These exercise the failure paths
    //! that were previously only checkable via string matching, plus the
    //! [`std::fmt::Display`] impl that the engine relies on to render
    //! byte-equivalent deny reasons.
    use super::*;

    #[test]
    fn parse_recurrence_zone_invalid_returns_invalid_timezone_variant() {
        // RecurrenceZone is not Debug, so use a match instead of unwrap_err().
        let Err(err) = parse_recurrence_zone(Some("UTC99")) else {
            panic!("expected InvalidTimezone error for UTC99");
        };
        assert!(
            matches!(err, ConstraintParseError::InvalidTimezone(ref value) if value == "UTC99")
        );
        // Display must keep the pre-refactor wording so engine deny reasons
        // remain byte-equivalent.
        assert_eq!(err.to_string(), "unsupported recurrence timezone: UTC99");
    }

    #[test]
    fn parse_recurrence_day_invalid_returns_invalid_day_variant() {
        let err = parse_recurrence_day("funday").unwrap_err();
        assert!(matches!(err, ConstraintParseError::InvalidDay(ref value) if value == "funday"));
        assert_eq!(err.to_string(), "unsupported recurrence day: funday");
    }

    #[test]
    fn parse_recurrence_time_invalid_returns_invalid_time_variant() {
        let err = parse_recurrence_time("25:99").unwrap_err();
        assert!(matches!(err, ConstraintParseError::InvalidTime(ref value) if value == "25:99"));
        assert_eq!(err.to_string(), "unsupported recurrence time: 25:99");
    }

    #[test]
    fn recurrence_frequency_allows_unknown_returns_invalid_frequency_variant() {
        let err = recurrence_frequency_allows(Some("hourly"), Weekday::Wed).unwrap_err();
        assert!(
            matches!(err, ConstraintParseError::InvalidFrequency(ref value) if value == "hourly")
        );
        assert_eq!(err.to_string(), "unsupported recurrence frequency: hourly");
    }

    #[test]
    fn recurrence_frequency_allows_weekdays_on_sunday_returns_outside_weekday_variant() {
        let err = recurrence_frequency_allows(Some("weekdays"), Weekday::Sun).unwrap_err();
        assert!(matches!(
            err,
            ConstraintParseError::OutsideWeekdayRecurrence(Weekday::Sun)
        ));
        assert_eq!(err.to_string(), "outside weekday recurrence: Sun");
    }

    #[test]
    fn recurrence_frequency_allows_weekends_on_wednesday_returns_outside_weekend_variant() {
        let err = recurrence_frequency_allows(Some("weekends"), Weekday::Wed).unwrap_err();
        assert!(matches!(
            err,
            ConstraintParseError::OutsideWeekendRecurrence(Weekday::Wed)
        ));
        assert_eq!(err.to_string(), "outside weekend recurrence: Wed");
    }

    #[test]
    fn recurrence_allows_outside_window_returns_outside_window_variant() {
        // 02:00 UTC on a Wednesday is outside a 09:00-17:00 UTC window.
        let now = "2026-04-29T02:00:00.000Z".parse::<DateTime<Utc>>().unwrap();
        let recurrence = Recurrence {
            frequency: Some("daily".to_owned()),
            days: None,
            window_start: Some("09:00".to_owned()),
            window_end: Some("17:00".to_owned()),
            timezone: Some("UTC".to_owned()),
        };
        let err = recurrence_allows(now, &recurrence).unwrap_err();
        assert!(matches!(err, ConstraintParseError::OutsideWindow));
        assert_eq!(err.to_string(), "outside recurrence window");
    }

    #[test]
    fn recurrence_allows_outside_days_returns_outside_recurrence_days_variant() {
        // 2026-04-29 is a Wednesday; allow-list only Monday.
        let now = "2026-04-29T12:00:00.000Z".parse::<DateTime<Utc>>().unwrap();
        let recurrence = Recurrence {
            frequency: Some("weekly".to_owned()),
            days: Some(vec!["mon".to_owned()]),
            window_start: None,
            window_end: None,
            timezone: Some("UTC".to_owned()),
        };
        let err = recurrence_allows(now, &recurrence).unwrap_err();
        assert!(matches!(
            err,
            ConstraintParseError::OutsideRecurrenceDays(Weekday::Wed)
        ));
        assert_eq!(err.to_string(), "outside recurrence days: Wed");
    }
}

#[cfg(test)]
mod optional_timestamp_serde_tests {
    use super::*;

    #[test]
    fn verified_claim_omitted_optional_timestamps_round_trip() {
        let claim = VerifiedClaim {
            claim_id: Some("claim-1".to_owned()),
            subject: DidCoreId::new("ak:did_core:webvh:z6mkfixture:bob.example").unwrap(),
            claim_kind: "verified_handle".to_owned(),
            issuer: DidCoreId::new("ak:did_core:webvh:z6mkfixture:issuer.example").unwrap(),
            organization: None,
            status: None,
            roles: Vec::new(),
            issued_at: None,
            expires_at: None,
            revoked_at: None,
            refreshed_at: None,
        };

        let serialized = serde_json::to_value(&claim).unwrap();
        let object = serialized.as_object().unwrap();
        for key in ["issued_at", "expires_at", "revoked_at", "refreshed_at"] {
            assert!(!object.contains_key(key), "serialized claim omits {key}");
        }

        let restored: VerifiedClaim = serde_json::from_value(serialized).unwrap();
        assert!(restored.issued_at.is_none());
        assert!(restored.expires_at.is_none());
        assert!(restored.revoked_at.is_none());
        assert!(restored.refreshed_at.is_none());
        assert_eq!(restored.claim_id, claim.claim_id);
    }

    #[test]
    fn temporal_constraint_omitted_optional_timestamps_round_trip() {
        let constraint = Constraint::Temporal {
            not_before: None,
            expires_at: None,
            recurrence: None,
        };

        let serialized = serde_json::to_value(&constraint).unwrap();
        let variant = serialized
            .as_object()
            .and_then(|object| object.get("temporal"))
            .and_then(serde_json::Value::as_object)
            .unwrap();
        assert!(!variant.contains_key("not_before"));
        assert!(!variant.contains_key("expires_at"));

        let restored: Constraint = serde_json::from_value(serialized).unwrap();
        let Constraint::Temporal {
            not_before,
            expires_at,
            ..
        } = restored
        else {
            panic!("temporal constraint variant must survive the round trip")
        };
        assert!(not_before.is_none());
        assert!(expires_at.is_none());
    }
}
