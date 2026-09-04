//! Deliberately invalid wire bodies.
//!
//! The workspace had exactly one general negative-case builder, in `cotest`.
//! Everything else hand-wrote a whole `json!` body, which means the negative
//! case drifts away from the positive one it is supposed to be one mutation
//! away from: the moment the real type gains a field, the hand-written body
//! stops being "the valid body with one thing wrong" and becomes "a different
//! invalid body", and the case silently stops testing the rejection it names.
//!
//! Starting from a serialized SDK value and applying one explicit mutation
//! keeps the two in step.

use arkret_wire::{Result, WireError};
use serde::{Serialize, Serializer};
use serde_json::Value;

/// A raw body for one named wire-negative case.
///
/// It serializes as the mutated JSON verbatim: a caller must not re-encode it
/// through a typed model, because a typed round trip would repair exactly the
/// mutation the case exists to send.
pub struct WireNegativeBody(Value);

impl WireNegativeBody {
    /// Borrow the mutated JSON.
    #[must_use]
    pub const fn as_value(&self) -> &Value {
        &self.0
    }

    /// Take the mutated JSON.
    #[must_use]
    pub fn into_value(self) -> Value {
        self.0
    }
}

impl Serialize for WireNegativeBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

/// Serialize an SDK value and apply one deliberate mutation to it.
///
/// # Errors
///
/// Returns a wire error if the baseline does not serialize.
pub fn wire_negative_from_sdk<T: Serialize>(
    baseline: &T,
    mutate: impl FnOnce(&mut Value),
) -> Result<WireNegativeBody> {
    let mut value = serde_json::to_value(baseline).map_err(|error| {
        WireError::Protocol(format!("wire-negative baseline encode failed: {error}"))
    })?;
    mutate(&mut value);
    Ok(WireNegativeBody(value))
}
