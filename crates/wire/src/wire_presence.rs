//! Lossless wire-property presence for patch and optimistic-concurrency fields.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Distinguishes an omitted JSON property from explicit `null` and a value.
///
/// Attach `#[serde(default, skip_serializing_if = "WirePresence::is_missing")]`
/// to containing struct fields. JSON cannot represent [`Self::Missing`] as a
/// standalone value, so serializing it outside a skipped field produces null.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WirePresence<T> {
    #[default]
    Missing,
    Null,
    Value(T),
}

impl<T> WirePresence<T> {
    #[must_use]
    pub const fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }

    #[must_use]
    pub const fn as_ref(&self) -> WirePresence<&T> {
        match self {
            Self::Missing => WirePresence::Missing,
            Self::Null => WirePresence::Null,
            Self::Value(value) => WirePresence::Value(value),
        }
    }

    #[must_use]
    pub fn map<U>(self, map: impl FnOnce(T) -> U) -> WirePresence<U> {
        match self {
            Self::Missing => WirePresence::Missing,
            Self::Null => WirePresence::Null,
            Self::Value(value) => WirePresence::Value(map(value)),
        }
    }
}

impl<T> Serialize for WirePresence<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Missing | Self::Null => serializer.serialize_none(),
            Self::Value(value) => value.serialize(serializer),
        }
    }
}

impl<'de, T> Deserialize<'de> for WirePresence<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(|value| match value {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Example {
        #[serde(default, skip_serializing_if = "WirePresence::is_missing")]
        field: WirePresence<String>,
    }

    #[test]
    fn containing_field_round_trips_all_three_presence_states() {
        let missing: Example = serde_json::from_value(json!({})).unwrap();
        let null: Example = serde_json::from_value(json!({"field": null})).unwrap();
        let value: Example = serde_json::from_value(json!({"field": "value"})).unwrap();

        assert_eq!(missing.field, WirePresence::Missing);
        assert_eq!(null.field, WirePresence::Null);
        assert_eq!(value.field, WirePresence::Value("value".to_owned()));
        assert_eq!(serde_json::to_value(missing).unwrap(), json!({}));
        assert_eq!(serde_json::to_value(null).unwrap(), json!({"field": null}));
        assert_eq!(
            serde_json::to_value(value).unwrap(),
            json!({"field": "value"})
        );
    }
}
