/// Profile id whose Realms are subject to the SEC-08 minimal-metadata
/// hardening (epoch lifetime ≤ 1h MUST).
use chrono::Utc;

/// SEC-08 — maximum MLS epoch lifetime for a `minimal_metadata_realm` Realm,
/// per `crypto-media/encryption-and-audit.md` §2.9.
///
/// For Realms declaring `ak.profile.mls.minimal_metadata_realm.v1` the §2.9 SHOULD on
/// epoch lifetime is raised to a MUST: a commit MUST be forced at least every
/// hour to bound within-epoch reaction-frequency observability. Stored as whole
/// seconds (3600), matching the core crate's numeric-ceiling convention. An
/// implementation MAY declare a shorter lifetime, never a longer one.
pub const MINIMAL_METADATA_MAX_EPOCH_LIFETIME_SECS: i64 = 3600;

/// SEC-08 — [`MINIMAL_METADATA_MAX_EPOCH_LIFETIME_SECS`] as a
/// [`chrono::Duration`] (1 hour).
pub fn minimal_metadata_max_epoch_lifetime() -> chrono::Duration {
    chrono::Duration::seconds(MINIMAL_METADATA_MAX_EPOCH_LIFETIME_SECS)
}

/// SEC-08 — has a `minimal_metadata_realm` epoch outlived the 1h MUST cap, per
/// `crypto-media/encryption-and-audit.md` §2.9.
///
/// Pure, non-mutating predicate: it takes the externally supplied epoch start
/// timestamp and the current time and returns `true` once the epoch age exceeds
/// [`minimal_metadata_max_epoch_lifetime`] (1h). When `true` the caller MUST
/// force-advance the group with a fresh `ak.mls.commit`; this helper
/// deliberately does **not** touch group state, leaving the commit decision to
/// the caller (the least-invasive integration point). A `now` earlier than
/// `epoch_started_at` (clock skew) is never reported as overdue.
pub fn minimal_metadata_epoch_overdue(
    epoch_started_at: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
) -> bool {
    now.signed_duration_since(epoch_started_at) > minimal_metadata_max_epoch_lifetime()
}
