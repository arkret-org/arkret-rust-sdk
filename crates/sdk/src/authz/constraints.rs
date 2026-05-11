use super::*;

/// Resource being accessed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    /// Space resource
    Space { space_id: String },
    /// Flow resource
    Flow { space_id: String, flow_id: String },
    /// Message resource.
    Message { space_id: String, message_id: String },
    /// Relation resource
    Relation { space_id: String, relation_kind: String },
    /// View resource
    View { space_id: String, view_id: String },
    /// Schema resource
    Schema { space_id: String, schema_id: String },
    /// Policy resource
    Policy { space_id: String, policy_id: String },
    /// Invite resource
    Invite { space_id: String, invite_id: String },
    /// Read marker resource
    ReadMarker { space_id: String },
    /// Morph resource (canonical open-typed object).
    Morph { space_id: String, morph_id: String, morph_type: String },
    /// Notification resource (per-actor private channel).
    Notification { actor_did: String, notification_id: String },
    /// Blob resource. `space_id` may be `*` for global blobs.
    Blob { space_id: String, blob_id: String },
    /// Event resource (audit / redaction / state-resolution targets).
    Event { space_id: String, event_kind: String, event_id: String },
    /// Actor resource (account-lifecycle, profile updates).
    Actor { actor_did: String },
}

impl Resource {
    /// Get the space ID for this resource. Returns the wildcard string for
    /// non-Space-bound resources (Notification, Actor) so callers retain a
    /// consistent shape.
    pub fn space_id(&self) -> &str {
        match self {
            Self::Space { space_id } => space_id,
            Self::Flow { space_id, .. } => space_id,
            Self::Message { space_id, .. } => space_id,
            Self::Relation { space_id, .. } => space_id,
            Self::View { space_id, .. } => space_id,
            Self::Schema { space_id, .. } => space_id,
            Self::Policy { space_id, .. } => space_id,
            Self::Invite { space_id, .. } => space_id,
            Self::ReadMarker { space_id } => space_id,
            Self::Morph { space_id, .. } => space_id,
            Self::Blob { space_id, .. } => space_id,
            Self::Event { space_id, .. } => space_id,
            Self::Notification { .. } | Self::Actor { .. } => "*",
        }
    }
}

/// Constraint types.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Constraint {
    /// Temporal constraint
    Temporal {
        #[serde(skip_serializing_if = "Option::is_none")]
        not_before: Option<DateTime<Utc>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expires_at: Option<DateTime<Utc>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        recurrence: Option<Recurrence>,
    },
    /// Field access constraint
    FieldAccess { effect: ConstraintEffect, scope: FieldScope, fields: Vec<String> },
    /// Type restriction constraint
    TypeRestriction {
        #[serde(skip_serializing_if = "Option::is_none")]
        object_type_allow: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        object_type_deny: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        morph_type_allow: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        morph_type_deny: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        facet_allow: Vec<Facet>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        facet_deny: Vec<Facet>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope_limitation: Option<ScopeLimitation>,
    },
    /// Delegation control constraint
    DelegationControl {
        #[serde(skip_serializing_if = "Option::is_none")]
        max_delegation_depth: Option<u32>,
        #[serde(default = "default_false")]
        prohibit_subdelegation: bool,
    },
    /// Rate limiting constraint
    RateLimiting {
        max_operations: u64,
        period: ConstraintDuration,
        #[serde(default = "default_rate_limit_scope")]
        scope: RateLimitScope,
    },
    /// Approval workflow constraint
    ApprovalWorkflow {
        #[serde(default = "default_false")]
        approval_required: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        approval_actor_refs: Option<Vec<Did>>,
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
        requires_claims: Vec<ClaimRequirement>,
        trusted_issuers: Vec<Did>,
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
        responsible_actor: Option<Did>,
    },
    /// Encryption requirement constraint
    EncryptionRequirement {
        #[serde(default = "default_false")]
        encryption_required: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        min_encryption_level: Option<String>,
    },
    /// Visibility control constraint (`confidentiality{subtype=visibility}`).
    /// See `constraint-schema.md` §13.
    VisibilityControl {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        visibility_allow: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        visibility_deny: Vec<String>,
        #[serde(default = "default_false")]
        deny_redacted_history: bool,
    },
    /// Resource quota constraint (`quota{subtype=resource}`).
    /// See `constraint-schema.md` §8.2 / §14.1.
    ResourceLimit {
        #[serde(skip_serializing_if = "Option::is_none")]
        blob_max_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max_total_blob_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max_resources: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        resource_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        period: Option<ConstraintDuration>,
        #[serde(default = "default_rate_limit_scope")]
        scope: RateLimitScope,
    },
    /// Edit / redact temporal window for messages
    /// (`temporal{subtype=edit_window}`). See `constraint-schema.md` §14.2.
    EditWindow {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        applies_to_actions: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message_edit_window: Option<ConstraintDuration>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message_redact_window: Option<ConstraintDuration>,
        #[serde(default = "default_false")]
        allow_redact_after_window: bool,
    },
    /// Container move scope (`scope_limitation` with container refs).
    /// See `constraint-schema.md` §6.3.
    ContainerMove {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        relation_kind_allow: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_view_refs: Vec<String>,
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
        allowed_flow_refs: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        denied_flow_refs: Vec<String>,
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstraintDuration {
    pub value: u64,
    pub unit: String, // "s", "m", "h", "d"
}

/// Rate limit scope.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    PerSpace,
    #[default]
    Global,
}

/// Scope limitation type for grant constraints.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeLimitation {
    Space,
    Flow,
    Message,
    Morph,
    View,
    Relation,
    Policy,
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

fn default_rate_limit_scope() -> RateLimitScope {
    RateLimitScope::Global
}

fn default_false() -> bool {
    false
}

pub(super) fn max_age_contains(age: chrono::Duration, max_age: &ConstraintDuration) -> bool {
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

    fn local_to_utc_candidates(&self, date: NaiveDate, time: NaiveTime) -> Vec<DateTime<Utc>> {
        let local = date.and_time(time);
        match self {
            Self::Named(tz) => match tz.from_local_datetime(&local) {
                LocalResult::Single(value) => vec![value.with_timezone(&Utc)],
                LocalResult::Ambiguous(first, second) => {
                    vec![first.with_timezone(&Utc), second.with_timezone(&Utc)]
                }
                LocalResult::None => Vec::new(),
            },
            Self::Fixed(offset) => match offset.from_local_datetime(&local) {
                LocalResult::Single(value) => vec![value.with_timezone(&Utc)],
                LocalResult::Ambiguous(first, second) => {
                    vec![first.with_timezone(&Utc), second.with_timezone(&Utc)]
                }
                LocalResult::None => Vec::new(),
            },
        }
    }
}

pub(super) fn recurrence_allows(
    now: DateTime<Utc>,
    recurrence: &Recurrence,
) -> std::result::Result<(), String> {
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
            return Err(format!("outside recurrence days: {:?}", weekday));
        }
    }

    let window_start = recurrence.window_start.as_deref().map(parse_recurrence_time).transpose()?;
    let window_end = recurrence.window_end.as_deref().map(parse_recurrence_time).transpose()?;

    if !recurrence_window_contains(local_time, window_start, window_end) {
        return Err("outside recurrence window".to_owned());
    }

    Ok(())
}

pub(super) fn recurrence_next_transition_after(
    now: DateTime<Utc>,
    recurrence: &Recurrence,
) -> std::result::Result<Option<DateTime<Utc>>, String> {
    let zone = parse_recurrence_zone(recurrence.timezone.as_deref())?;
    let (local_date, _, _) = zone.local_parts(now);
    let window_start = recurrence.window_start.as_deref().map(parse_recurrence_time).transpose()?;
    let window_end = recurrence.window_end.as_deref().map(parse_recurrence_time).transpose()?;
    let has_window = window_start.is_some() || window_end.is_some();
    let has_day_boundary = has_window || recurrence_uses_day_boundaries(recurrence);
    let midnight =
        NaiveTime::from_hms_opt(0, 0, 0).expect("00:00:00 must be a valid recurrence boundary");

    let mut candidates = Vec::new();
    for day_offset in 0..=8 {
        let Some(date) = local_date.checked_add_signed(chrono::Duration::days(day_offset)) else {
            continue;
        };

        if day_offset > 0 && has_day_boundary {
            candidates.extend(zone.local_to_utc_candidates(date, midnight));
        }
        if let Some(start) = window_start {
            candidates.extend(zone.local_to_utc_candidates(date, start));
        }
        if let Some(end) = window_end {
            candidates.extend(zone.local_to_utc_candidates(date, end));
        }
    }

    Ok(candidates.into_iter().filter(|candidate| *candidate > now).min())
}

fn parse_recurrence_zone(timezone: Option<&str>) -> std::result::Result<RecurrenceZone, String> {
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
        .ok_or_else(|| format!("unsupported recurrence timezone: {}", value))
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
    } else if let Some(rest) = without_utc.strip_prefix('-') {
        (-1, rest)
    } else {
        return None;
    };

    let (hours, minutes) = if let Some((hours, minutes)) = rest.split_once(':') {
        (hours.parse::<i32>().ok()?, minutes.parse::<i32>().ok()?)
    } else if rest.len() == 4 {
        (rest[..2].parse::<i32>().ok()?, rest[2..].parse::<i32>().ok()?)
    } else {
        (rest.parse::<i32>().ok()?, 0)
    };

    if !(0..=23).contains(&hours) || !(0..=59).contains(&minutes) {
        return None;
    }

    FixedOffset::east_opt(sign * ((hours * 60 * 60) + (minutes * 60)))
}

fn parse_recurrence_day(day: &str) -> std::result::Result<Weekday, String> {
    match day.trim().to_ascii_lowercase().as_str() {
        "mon" | "monday" | "1" => Ok(Weekday::Mon),
        "tue" | "tues" | "tuesday" | "2" => Ok(Weekday::Tue),
        "wed" | "wednesday" | "3" => Ok(Weekday::Wed),
        "thu" | "thur" | "thurs" | "thursday" | "4" => Ok(Weekday::Thu),
        "fri" | "friday" | "5" => Ok(Weekday::Fri),
        "sat" | "saturday" | "6" => Ok(Weekday::Sat),
        "sun" | "sunday" | "0" | "7" => Ok(Weekday::Sun),
        _ => Err(format!("unsupported recurrence day: {}", day)),
    }
}

fn parse_recurrence_time(value: &str) -> std::result::Result<NaiveTime, String> {
    let value = value.trim();
    NaiveTime::parse_from_str(value, "%H:%M:%S")
        .or_else(|_| NaiveTime::parse_from_str(value, "%H:%M"))
        .map_err(|_| format!("unsupported recurrence time: {}", value))
}

fn recurrence_frequency_allows(
    frequency: Option<&str>,
    weekday: Weekday,
) -> std::result::Result<(), String> {
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
                Err(format!("outside weekday recurrence: {:?}", weekday))
            }
        }
        "weekends" => {
            if matches!(weekday, Weekday::Sat | Weekday::Sun) {
                Ok(())
            } else {
                Err(format!("outside weekend recurrence: {:?}", weekday))
            }
        }
        _ => Err(format!("unsupported recurrence frequency: {}", frequency)),
    }
}

fn recurrence_uses_day_boundaries(recurrence: &Recurrence) -> bool {
    recurrence.days.as_ref().is_some_and(|days| !days.is_empty())
        || recurrence.frequency.as_deref().is_some_and(|frequency| {
            matches!(frequency.trim().to_ascii_lowercase().as_str(), "weekdays" | "weekends")
        })
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

pub(super) fn update_earliest_future(
    earliest: &mut Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    candidate: Option<DateTime<Utc>>,
) {
    if let Some(candidate) = candidate
        && candidate > now
        && earliest.is_none_or(|current| candidate < current)
    {
        *earliest = Some(candidate);
    }
}

/// Claim requirement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimRequirement {
    pub claim_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<Did>,
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
    pub subject: Did,
    pub claim_type: String,
    pub issuer: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refreshed_at: Option<DateTime<Utc>>,
}

/// Grant constraint with priority.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstraintEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraint_id: Option<String>,
    pub constraint: Constraint,
    #[serde(default)]
    pub priority: i32,
}

impl ConstraintEntry {
    /// Create a new constraint entry.
    pub fn new(constraint: Constraint) -> Self {
        Self { constraint_id: None, constraint, priority: 0 }
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Get the effect of this constraint.
    pub fn effect(&self) -> ConstraintEffect {
        match &self.constraint {
            Constraint::Temporal { .. } => ConstraintEffect::Allow,
            Constraint::FieldAccess { effect, .. } => effect.clone(),
            Constraint::TypeRestriction { .. } => ConstraintEffect::Allow,
            Constraint::DelegationControl { .. } => ConstraintEffect::Allow,
            Constraint::RateLimiting { .. } => ConstraintEffect::Allow,
            Constraint::ApprovalWorkflow { .. } => ConstraintEffect::RequireReview,
            Constraint::ClaimBased { .. } => ConstraintEffect::Allow,
            Constraint::Accountability { .. } => ConstraintEffect::Allow,
            Constraint::EncryptionRequirement { .. } => ConstraintEffect::Allow,
            Constraint::VisibilityControl { .. } => ConstraintEffect::Allow,
            Constraint::ResourceLimit { .. } => ConstraintEffect::Allow,
            Constraint::EditWindow { .. } => ConstraintEffect::Allow,
            Constraint::ContainerMove { .. } => ConstraintEffect::Allow,
            Constraint::ScopeLimitation { .. } => ConstraintEffect::Allow,
        }
    }

    /// Derive the canonical [`crate::EvaluationClass`] for this constraint per
    /// `constraint-schema.md` §2.3. The class controls whether the
    /// authorization engine may use a fast-path cache:
    ///
    /// - `Stateless` — pure inputs (clock, calendar). Safe to cache.
    /// - `GrantLocal` — inputs from the grant itself. Safe to cache as long
    ///   as the cache key binds the grant id and the constraint priority.
    /// - `SpaceState` — depends on Space membership/policy/capability state.
    ///   MUST be re-evaluated on every frontier change.
    /// - `External` — depends on out-of-band signals (policy server, claim
    ///   issuer, presentation). MUST NOT be cached without explicit TTL.
    pub fn evaluation_class(&self) -> crate::EvaluationClass {
        use crate::EvaluationClass;
        match &self.constraint {
            Constraint::Temporal { .. } => EvaluationClass::Stateless,
            Constraint::FieldAccess { .. } => EvaluationClass::GrantLocal,
            Constraint::TypeRestriction { .. } => EvaluationClass::GrantLocal,
            Constraint::DelegationControl { .. } => EvaluationClass::GrantLocal,
            Constraint::RateLimiting { .. } => EvaluationClass::SpaceState,
            Constraint::ApprovalWorkflow { .. } => EvaluationClass::SpaceState,
            Constraint::ClaimBased { .. } => EvaluationClass::External,
            Constraint::Accountability { .. } => EvaluationClass::GrantLocal,
            Constraint::EncryptionRequirement { .. } => EvaluationClass::SpaceState,
            Constraint::VisibilityControl { .. } => EvaluationClass::SpaceState,
            // single-call blob_max_bytes is stateless; per-scope total is external.
            // Default to SpaceState because the SDK can't tell at type-level.
            Constraint::ResourceLimit { .. } => EvaluationClass::SpaceState,
            Constraint::EditWindow { .. } => EvaluationClass::Stateless,
            Constraint::ContainerMove { .. } => EvaluationClass::SpaceState,
            Constraint::ScopeLimitation { .. } => EvaluationClass::Stateless,
        }
    }
}
