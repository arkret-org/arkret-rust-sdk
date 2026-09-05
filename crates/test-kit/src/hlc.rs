//! The pinned HLC template.
//!
//! `01970e589d21-{logical}-a13f9c2e` was hard-coded in five places with two
//! different logical-counter formats (`{:04x}` in one repository, `{:04}` in
//! another). The two agree below ten and diverge above it, so a fixture that
//! crossed repositories changed its HLC — and therefore every content-bound
//! identifier derived from it — only for sequence numbers past nine.
//!
//! One template, one format. Hexadecimal wins because it is what the HLC
//! grammar itself uses for the physical and node components.

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
/// A test that submits to a live service cannot use [`pinned_hlc`]: a static
/// physical component lands before the Realm bootstrap the service already
/// accepted, and the submission is rejected as
/// `created_at_before_causal_predecessor`. Such a test needs a real instant,
/// which is why the clock is an input to the fixture builder rather than a
/// constant inside it.
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
    let floor = std::sync::Mutex::new(DateTime::<Utc>::UNIX_EPOCH);
    move || {
        let mut floor = floor
            .lock()
            .expect("the fixture clock floor is not poisoned");
        let now = Utc::now();
        let next = if now > *floor {
            now
        } else {
            *floor + chrono::TimeDelta::milliseconds(1)
        };
        *floor = next;
        next
    }
}
