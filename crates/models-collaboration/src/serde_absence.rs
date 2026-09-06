//! Absence-vs-null deserialization helpers shared by the payload modules.
//!
//! The protocol distinguishes three states for an optional wire member: the
//! key is absent, the key is present with `null`, and the key is present with
//! a value. `Option<T>` alone collapses the first two, so payloads that must
//! tell them apart pair `#[serde(default)]` with one of these helpers.
//!
//! - [`deserialize_present_nullable`] targets `Option<Option<T>>`: the outer layer records
//!   presence, the inner one records `null`. Used where an explicit `null` is a meaningful
//!   instruction (clear the field) that must not be confused with "the author said nothing".
//! - [`deserialize_non_null_optional`] targets `Option<T>` on a member whose schema forbids `null`:
//!   absence stays `None`, while a present `null` is a deserialization error instead of being
//!   silently accepted as absence.
//!
//! Both were previously copied into `events_payloads::call`,
//! `events_payloads::state` and `governance::invite_addressing`; they are
//! defined once here so the absence contract cannot drift between payloads.

use serde::Deserialize;

/// Deserialize a present-but-nullable member into `Option<Option<T>>`.
///
/// `Some(None)` means the key was present and `null`; `None` (produced by
/// `#[serde(default)]` when the key is absent) means the author said nothing.
pub(crate) fn deserialize_present_nullable<'de, D, T>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// Deserialize an optional member whose schema forbids an explicit `null`.
///
/// Absence is handled by `#[serde(default)]`; reaching this function means the
/// key was present, so `null` fails against `T` rather than degrading to
/// `None`.
pub(crate) fn deserialize_non_null_optional<'de, D, T>(
    deserializer: D,
) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}
