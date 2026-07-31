//! Shared presence validation and aggregation for Arkret v1
//! (`discovery/profiles-presence.md`).
//!
//! This module is the single home for the receiver- and sender-side
//! MUSTs that every stack layer (server admission, client send loop,
//! client display) has to agree on:
//!
//! - the closed `state` wire set ([`PresenceStatus::parse_wire`]);
//! - `last_active_at` bucket / timestamp validation with the fail-closed alignment and `PT60S`
//!   floor rules (§3.3);
//! - `status_message` length / NFC / control-character constraints (§3.3, shared with the durable
//!   profile field §2.2);
//! - the `ak.presence.preference` account-data payload (§3.6) that pins a manual state across
//!   devices;
//! - the deterministic multi-device aggregation order (§3.3).

use arkret_wire::canonical::is_nfc;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Account Data key holding the principal-private manual presence
/// preference (profiles-presence.md §3.6). Written through
/// `ak.account_data.set`; enforced client-side at send time. Servers
/// MUST NOT require plaintext or a projection of this key.
pub const PRESENCE_PREFERENCE_ACCOUNT_DATA_KEY: &str = "ak.presence.preference";

/// Account Data key holding the principal-private presence visibility
/// policy (profiles-presence.md §3.4).
pub const PRESENCE_VISIBILITY_ACCOUNT_DATA_KEY: &str = "ak.presence.visibility";

/// Protocol floor for `last_active_at` bucket granularity (§3.3):
/// finer buckets degrade into a near-second activity timing side
/// channel.
pub const LAST_ACTIVE_BUCKET_FLOOR_SECONDS: i64 = 60;

/// Maximum `status_message` length in Unicode code points (§3.3 /
/// §2.2 — the transient presence override and the durable profile
/// field share the constraint).
pub const STATUS_MESSAGE_MAX_CODE_POINTS: usize = 256;

/// Presence status — the closed v1 wire set from
/// `discovery/profiles-presence.md` §3.2. Receivers MUST treat any
/// other wire value as a schema violation and drop the update
/// (fail closed) instead of guessing a nearby state; use
/// [`PresenceStatus::parse_wire`] for that strict path.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PresenceStatus {
    Online,
    Idle,
    Dnd,
    Offline,
}

impl PresenceStatus {
    /// Strict closed-set wire parse (§3.2). Unknown values return
    /// `None` — the receiver MUST drop the update / fail closed with
    /// `schema_violation`, never guess a nearby state (historic
    /// `unavailable` / `busy` are not v1 wire values).
    pub fn parse_wire(value: &str) -> Option<Self> {
        match value {
            "online" => Some(Self::Online),
            "idle" => Some(Self::Idle),
            "dnd" => Some(Self::Dnd),
            "offline" => Some(Self::Offline),
            _ => None,
        }
    }

    /// Canonical wire string for this state.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Idle => "idle",
            Self::Dnd => "dnd",
            Self::Offline => "offline",
        }
    }

    /// Multi-device aggregation priority (§3.3): `dnd > online >
    /// idle > offline`. `dnd` only appears when pinned manually, so
    /// it wins; an actively-used device beats an idle one.
    pub fn aggregation_rank(self) -> u8 {
        match self {
            Self::Dnd => 3,
            Self::Online => 2,
            Self::Idle => 1,
            Self::Offline => 0,
        }
    }
}

/// Aggregate the unexpired per-device states of one actor into the
/// single displayed state (§3.3): highest priority wins
/// (`dnd > online > idle`); no unexpired signal at all means
/// `offline`. Callers filter expiry (`expires_at` / `ttl_ms`) before
/// calling.
pub fn aggregate_presence_states<I>(states: I) -> PresenceStatus
where
    I: IntoIterator<Item = PresenceStatus>,
{
    states
        .into_iter()
        .max_by_key(|state| state.aggregation_rank())
        .unwrap_or(PresenceStatus::Offline)
}

/// Validation failures for presence wire fields. All of them are
/// fail-closed: the caller MUST drop the offending presence update
/// (or reject the submission with `schema_violation`) instead of
/// repairing or downgrading the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PresenceValidationError {
    #[error("presence state is not in the closed v1 wire set")]
    UnknownState,
    #[error("last_active_at is not a valid RFC 3339 UTC timestamp or bucket interval")]
    MalformedLastActiveAt,
    #[error("last_active_at bucket duration is below the PT60S protocol floor")]
    BucketBelowFloor,
    #[error("last_active_at bucket start is not aligned to its duration")]
    BucketUnaligned,
    #[error("status_message exceeds 256 Unicode code points")]
    StatusMessageTooLong,
    #[error("status_message is not NFC-normalized")]
    StatusMessageNotNfc,
    #[error("status_message contains a forbidden control character")]
    StatusMessageControlChar,
    #[error("manual_state cannot be `offline`")]
    ManualStateOffline,
}

/// Validate a `last_active_at` wire value (§3.3).
///
/// The two mutually exclusive forms are discriminated by `/`:
/// - no `/` → RFC 3339 UTC timestamp (`...Z`);
/// - exactly one `/` → bucket interval `<start>/<duration>` where `start` is an RFC 3339 UTC
///   timestamp, `duration` is a positive fixed ISO 8601 time duration (`PT...`, so calendar
///   durations like `P1M` are rejected structurally), `duration >= PT60S`, and `start` is aligned
///   to the duration on the Unix-epoch UTC grid.
///
/// Any failure MUST make the caller drop the presence update — never
/// repair, guess, or downgrade to a more precise display.
pub fn validate_last_active_at(value: &str) -> Result<(), PresenceValidationError> {
    if let Some((start, duration)) = value.split_once('/') {
        if duration.contains('/') {
            return Err(PresenceValidationError::MalformedLastActiveAt);
        }
        let start = parse_utc_timestamp(start)?;
        let bucket_seconds = parse_iso_time_duration_seconds(duration)?;
        if bucket_seconds < LAST_ACTIVE_BUCKET_FLOOR_SECONDS {
            return Err(PresenceValidationError::BucketBelowFloor);
        }
        if start.timestamp().rem_euclid(bucket_seconds) != 0 {
            return Err(PresenceValidationError::BucketUnaligned);
        }
        return Ok(());
    }
    parse_utc_timestamp(value).map(|_| ())
}

fn parse_utc_timestamp(value: &str) -> Result<DateTime<Utc>, PresenceValidationError> {
    // encoding.md §2.1: wire timestamps are UTC with the `Z`
    // designator; local-offset forms are rejected rather than
    // converted.
    if !value.ends_with('Z') {
        return Err(PresenceValidationError::MalformedLastActiveAt);
    }
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| PresenceValidationError::MalformedLastActiveAt)
}

/// Parse a fixed ISO 8601 time duration (`PT<n>H<n>M<n>S`) into
/// seconds. Calendar durations (`P1D`, `P1M`, `P1Y`) do not have a
/// fixed length and are rejected by the mandatory `PT` prefix.
fn parse_iso_time_duration_seconds(value: &str) -> Result<i64, PresenceValidationError> {
    let rest = value
        .strip_prefix("PT")
        .filter(|rest| !rest.is_empty())
        .ok_or(PresenceValidationError::MalformedLastActiveAt)?;
    let mut total = 0i64;
    let mut digits = String::new();
    for ch in rest.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }
        let amount = digits
            .parse::<i64>()
            .map_err(|_| PresenceValidationError::MalformedLastActiveAt)?;
        digits.clear();
        total = total.saturating_add(match ch {
            'H' => amount.saturating_mul(60 * 60),
            'M' => amount.saturating_mul(60),
            'S' => amount,
            _ => return Err(PresenceValidationError::MalformedLastActiveAt),
        });
    }
    if !digits.is_empty() || total <= 0 {
        return Err(PresenceValidationError::MalformedLastActiveAt);
    }
    Ok(total)
}

/// Validate a `status_message` (§3.3 / §2.2): at most 256 Unicode
/// code points, NFC-normalized, and no C0/C1 control characters
/// except `U+0009` (tab) and `U+000A` (newline).
pub fn validate_status_message(value: &str) -> Result<(), PresenceValidationError> {
    if value.chars().count() > STATUS_MESSAGE_MAX_CODE_POINTS {
        return Err(PresenceValidationError::StatusMessageTooLong);
    }
    if !is_nfc(value) {
        return Err(PresenceValidationError::StatusMessageNotNfc);
    }
    let forbidden_control = value.chars().any(|ch| {
        let code = ch as u32;
        let is_c0 = code < 0x20 && ch != '\t' && ch != '\n';
        let is_del_or_c1 = (0x7F..=0x9F).contains(&code);
        is_c0 || is_del_or_c1
    });
    if forbidden_control {
        return Err(PresenceValidationError::StatusMessageControlChar);
    }
    Ok(())
}

/// `ak.presence.preference` payload (profiles-presence.md §3.6):
/// the principal-private manual presence preference. Enforced on the
/// send side — every device of the principal reads the same account
/// data and pins its broadcast `state` to `manual_state` while the
/// preference is active.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresencePreference {
    /// Pinned manual state: `online`, `idle` or `dnd`. `offline` is
    /// expressed by ceasing broadcasts / TTL expiry and is not a
    /// pinnable value; "invisible" is `ak.presence.visibility =
    /// "nobody"`, not a state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_state: Option<PresenceStatus>,
    /// Transient status-message override used as the broadcast
    /// `status_message` source while active. Same constraints as the
    /// wire field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    /// Expiry: past this instant the whole preference is treated as
    /// absent and clients revert to automatic state detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub clears_at: Option<DateTime<Utc>>,
}

impl PresencePreference {
    /// Structural validation (§3.6): `manual_state` must not be
    /// `offline` and any `status_message` must satisfy the shared
    /// wire constraints.
    pub fn validate(&self) -> Result<(), PresenceValidationError> {
        if self.manual_state == Some(PresenceStatus::Offline) {
            return Err(PresenceValidationError::ManualStateOffline);
        }
        if let Some(message) = self.status_message.as_deref() {
            validate_status_message(message)?;
        }
        Ok(())
    }

    /// Whether the preference is active at `now` (expiry is decided
    /// on the send side; an expired preference is equivalent to the
    /// key being absent).
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        match self.clears_at {
            Some(clears_at) => now < clears_at,
            None => true,
        }
    }

    /// The manual state to pin broadcasts to at `now`, if any.
    pub fn effective_manual_state(&self, now: DateTime<Utc>) -> Option<PresenceStatus> {
        if self.is_active(now) {
            self.manual_state
        } else {
            None
        }
    }

    /// The status-message override to broadcast at `now`, if any.
    pub fn effective_status_message(&self, now: DateTime<Utc>) -> Option<&str> {
        if self.is_active(now) {
            self.status_message.as_deref()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wire_is_a_strict_closed_set() {
        assert_eq!(
            PresenceStatus::parse_wire("online"),
            Some(PresenceStatus::Online)
        );
        assert_eq!(
            PresenceStatus::parse_wire("idle"),
            Some(PresenceStatus::Idle)
        );
        assert_eq!(PresenceStatus::parse_wire("dnd"), Some(PresenceStatus::Dnd));
        assert_eq!(
            PresenceStatus::parse_wire("offline"),
            Some(PresenceStatus::Offline)
        );
        // Matrix-legacy and ad-hoc values fail closed instead of
        // mapping to a nearby state.
        assert_eq!(PresenceStatus::parse_wire("unavailable"), None);
        assert_eq!(PresenceStatus::parse_wire("busy"), None);
        assert_eq!(PresenceStatus::parse_wire("Online"), None);
        assert_eq!(PresenceStatus::parse_wire(""), None);
    }

    #[test]
    fn wire_round_trip() {
        for state in [
            PresenceStatus::Online,
            PresenceStatus::Idle,
            PresenceStatus::Dnd,
            PresenceStatus::Offline,
        ] {
            assert_eq!(PresenceStatus::parse_wire(state.as_wire()), Some(state));
        }
    }

    #[test]
    fn aggregation_prefers_dnd_then_online_then_idle() {
        use PresenceStatus::*;
        assert_eq!(aggregate_presence_states([Idle, Online]), Online);
        assert_eq!(aggregate_presence_states([Online, Dnd, Idle]), Dnd);
        assert_eq!(aggregate_presence_states([Idle]), Idle);
        assert_eq!(aggregate_presence_states([Offline, Idle]), Idle);
        assert_eq!(
            aggregate_presence_states(std::iter::empty::<PresenceStatus>()),
            Offline
        );
    }

    #[test]
    fn last_active_at_accepts_exact_utc_timestamp() {
        assert_eq!(validate_last_active_at("2026-04-26T10:00:00.000Z"), Ok(()));
    }

    #[test]
    fn last_active_at_rejects_local_offset() {
        assert!(validate_last_active_at("2026-04-26T10:00:00+08:00").is_err());
        assert!(validate_last_active_at("2026-04-26T10:00:00").is_err());
    }

    #[test]
    fn last_active_at_accepts_aligned_bucket() {
        assert_eq!(
            validate_last_active_at("2026-04-26T10:00:00.000Z/PT1H"),
            Ok(())
        );
        assert_eq!(
            validate_last_active_at("2026-04-26T10:05:00.000Z/PT5M"),
            Ok(())
        );
    }

    #[test]
    fn last_active_at_rejects_unaligned_bucket_start() {
        assert_eq!(
            validate_last_active_at("2026-04-26T10:34:00.000Z/PT1H"),
            Err(PresenceValidationError::BucketUnaligned)
        );
        assert_eq!(
            validate_last_active_at("2026-04-26T10:00:30.000Z/PT1M"),
            Err(PresenceValidationError::BucketUnaligned)
        );
    }

    #[test]
    fn last_active_at_rejects_bucket_below_pt60s_floor() {
        assert_eq!(
            validate_last_active_at("2026-04-26T10:00:00.000Z/PT30S"),
            Err(PresenceValidationError::BucketBelowFloor)
        );
        assert_eq!(
            validate_last_active_at("2026-04-26T10:00:01.000Z/PT1S"),
            Err(PresenceValidationError::BucketBelowFloor)
        );
    }

    #[test]
    fn last_active_at_rejects_calendar_and_malformed_durations() {
        // Calendar durations have no fixed length.
        assert!(validate_last_active_at("2026-04-26T00:00:00.000Z/P1M").is_err());
        assert!(validate_last_active_at("2026-04-26T00:00:00.000Z/P1D").is_err());
        // Zero / negative / empty / trailing digits.
        assert!(validate_last_active_at("2026-04-26T00:00:00.000Z/PT0S").is_err());
        assert!(validate_last_active_at("2026-04-26T00:00:00.000Z/PT").is_err());
        assert!(validate_last_active_at("2026-04-26T00:00:00.000Z/PT5").is_err());
        // More than one slash.
        assert!(validate_last_active_at("2026-04-26T00:00:00.000Z/PT1H/PT1H").is_err());
    }

    #[test]
    fn status_message_accepts_reasonable_text() {
        assert_eq!(validate_status_message("开会中，稍后回复"), Ok(()));
        assert_eq!(validate_status_message("On vacation\nback May 5"), Ok(()));
        assert_eq!(validate_status_message(""), Ok(()));
    }

    #[test]
    fn status_message_rejects_over_256_code_points() {
        let long = "字".repeat(257);
        assert_eq!(
            validate_status_message(&long),
            Err(PresenceValidationError::StatusMessageTooLong)
        );
        assert_eq!(validate_status_message(&"字".repeat(256)), Ok(()));
    }

    #[test]
    fn status_message_rejects_non_nfc() {
        // "é" as decomposed e + combining acute (NFD).
        assert_eq!(
            validate_status_message("Caf\u{0065}\u{0301}"),
            Err(PresenceValidationError::StatusMessageNotNfc)
        );
    }

    #[test]
    fn status_message_rejects_control_chars_except_tab_and_newline() {
        assert_eq!(
            validate_status_message("a\u{0000}b"),
            Err(PresenceValidationError::StatusMessageControlChar)
        );
        assert_eq!(
            validate_status_message("a\rb"),
            Err(PresenceValidationError::StatusMessageControlChar)
        );
        assert_eq!(
            validate_status_message("a\u{009F}b"),
            Err(PresenceValidationError::StatusMessageControlChar)
        );
        assert_eq!(validate_status_message("a\tb\nc"), Ok(()));
    }

    #[test]
    fn preference_rejects_manual_offline() {
        let preference = PresencePreference {
            manual_state: Some(PresenceStatus::Offline),
            ..Default::default()
        };
        assert_eq!(
            preference.validate(),
            Err(PresenceValidationError::ManualStateOffline)
        );
    }

    #[test]
    fn preference_expires_at_clears_at() {
        let preference = PresencePreference {
            manual_state: Some(PresenceStatus::Dnd),
            status_message: Some("开会中".to_owned()),
            clears_at: Some("2026-07-03T12:00:00.000Z".parse().unwrap()),
        };
        let before = "2026-07-03T11:59:59.000Z".parse().unwrap();
        let after = "2026-07-03T12:00:00.000Z".parse().unwrap();
        assert_eq!(
            preference.effective_manual_state(before),
            Some(PresenceStatus::Dnd)
        );
        assert_eq!(preference.effective_status_message(before), Some("开会中"));
        assert_eq!(preference.effective_manual_state(after), None);
        assert_eq!(preference.effective_status_message(after), None);
    }

    #[test]
    fn preference_round_trips_through_account_data_json() {
        let preference = PresencePreference {
            manual_state: Some(PresenceStatus::Dnd),
            status_message: Some("开会中，稍后回复".to_owned()),
            clears_at: Some("2026-07-03T12:00:00.000Z".parse().unwrap()),
        };
        let json = serde_json::to_value(&preference).unwrap();
        assert_eq!(json["manual_state"], "dnd");
        let back: PresencePreference = serde_json::from_value(json).unwrap();
        assert_eq!(back, preference);
    }
}
