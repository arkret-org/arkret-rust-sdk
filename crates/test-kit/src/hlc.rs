//! The pinned HLC template.
//!
//! `01970e589d21-{logical}-a13f9c2e` was hard-coded in five places with two
//! different logical-counter formats (`{:04x}` in one repository, `{:04}` in
//! another). The two agree below ten and diverge above it, so a fixture that
//! crossed repositories changed its HLC — and therefore every content-bound
//! identifier derived from it — only for sequence numbers past nine.
//!
//! One template, one format. `encoding.md` section 7 requires a four-digit
//! lowercase hexadecimal logical counter.

use arkret_wire::Hlc;
use chrono::{DateTime, Utc};

/// Physical component of the pinned HLC.
pub const PINNED_HLC_PHYSICAL: &str = "01970e589d21";
/// Node component of the pinned HLC.
pub const PINNED_HLC_NODE: &str = "a13f9c2e";

/// The pinned HLC at one logical counter value.
///
/// # Panics
///
/// Panics if the composed string is not a valid HLC, which would be a defect
/// in this crate rather than a caller error.
#[must_use]
pub fn pinned_hlc(logical: u16) -> Hlc {
    Hlc::new(format!(
        "{PINNED_HLC_PHYSICAL}-{logical:04x}-{PINNED_HLC_NODE}"
    ))
    .expect("the pinned HLC template composes a valid HLC")
}

/// An HLC whose physical component is a wall-clock instant.
///
/// The HLC is advisory and independent of `Event.created_at`. Callers that
/// need a current authoring timestamp must inject a clock into their Event
/// builder separately; choosing this HLC does not update that timestamp.
///
/// # Panics
///
/// Panics if the instant precedes the Unix epoch.
#[must_use]
pub fn wall_hlc(at: DateTime<Utc>, logical: u16) -> Hlc {
    let millis = u64::try_from(at.timestamp_millis())
        .expect("a fixture instant is at or after the Unix epoch");
    Hlc::new(format!("{millis:012x}-{logical:04x}-{PINNED_HLC_NODE}"))
        .expect("a wall-clock HLC composes a valid HLC")
}

/// A clock that never goes backwards.
///
/// Live submission paths need both a real instant and a guarantee that two
/// Events authored in the same millisecond still order. This returns a closure
/// over an interior floor rather than a type so it drops straight into
/// [`crate::signed_event::SignedEventFixtureBuilder::with_clock`].
pub fn monotonic_floor_clock() -> impl Fn() -> DateTime<Utc> + Send + Sync + 'static {
    monotonic_floor_clock_from(Utc::now)
}

fn monotonic_floor_clock_from(
    clock: impl Fn() -> DateTime<Utc> + Send + Sync + 'static,
) -> impl Fn() -> DateTime<Utc> + Send + Sync + 'static {
    let floor = std::sync::Mutex::new(None);
    move || {
        let mut floor = floor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = clock();
        let next = match *floor {
            Some(previous) if now <= previous => previous + chrono::TimeDelta::milliseconds(1),
            _ => now,
        };
        *floor = Some(next);
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_advances_for_equal_and_backwards_clock_samples_then_catches_up() {
        let start = "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let samples = std::sync::Mutex::new(
            [
                start,
                start,
                start - chrono::TimeDelta::seconds(1),
                start + chrono::TimeDelta::seconds(1),
            ]
            .into_iter(),
        );
        let clock = monotonic_floor_clock_from(move || samples.lock().unwrap().next().unwrap());
        assert_eq!(clock(), start);
        assert_eq!(clock(), start + chrono::TimeDelta::milliseconds(1));
        assert_eq!(clock(), start + chrono::TimeDelta::milliseconds(2));
        assert_eq!(clock(), start + chrono::TimeDelta::seconds(1));
    }
}
