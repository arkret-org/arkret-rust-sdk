//! Named wire-negative bodies.
//!
//! A negative case is only meaningful when the baseline it mutates is the
//! canonical SDK value: hand-written JSON drifts from the wire shape and then
//! proves nothing about the rejection under test. Every constructor here starts
//! from a serializable SDK type and applies exactly one deliberate mutation.

use serde::{Serialize, Serializer};
use serde_json::Value;

/// Failure to build a wire-negative body from an SDK baseline.
#[derive(Debug, thiserror::Error)]
pub enum WireNegativeError {
    /// The SDK baseline could not be encoded to JSON.
    #[error("wire-negative baseline encode failed: {0}")]
    Encode(#[from] serde_json::Error),
}

/// Raw body for a named wire-negative case.
///
/// It serializes as the mutated value verbatim, so the deliberate mutation
/// reaches the server instead of being normalised away by a typed re-encode.
pub struct WireNegativeBody(Value);

impl WireNegativeBody {
    /// The mutated value, for assertions that inspect what will be sent.
    pub fn as_value(&self) -> &Value {
        &self.0
    }
}

impl Serialize for WireNegativeBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

/// Encode `baseline` as the SDK produces it, then apply one mutation.
pub fn wire_negative_from_sdk<T: Serialize>(
    baseline: &T,
    mutate: impl FnOnce(&mut Value),
) -> Result<WireNegativeBody, WireNegativeError> {
    let mut value = serde_json::to_value(baseline)?;
    mutate(&mut value);
    Ok(WireNegativeBody(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mutation_reaches_the_serialized_body() {
        let baseline = json!({"kept": 1, "replaced": "before"});
        let body = wire_negative_from_sdk(&baseline, |value| {
            value["replaced"] = json!("after");
        })
        .expect("baseline encodes");
        assert_eq!(
            serde_json::to_value(&body).expect("body serializes"),
            json!({"kept": 1, "replaced": "after"})
        );
    }
}
