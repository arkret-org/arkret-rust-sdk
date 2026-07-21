//! Shared serde helpers for protocol wire types.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use crate::canonical;

/// Deserialize an `Option<Value>` field while preserving an explicit wire
/// `null` as `Some(Value::Null)` rather than collapsing it to `None`.
pub fn deserialize_optional_value_preserving_null<'de, D>(
    deserializer: D,
) -> Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

pub fn serialize_canonical_timestamp<S>(
    value: &DateTime<Utc>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&canonical::format_timestamp_canonical(*value))
}

pub fn deserialize_canonical_timestamp<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    canonical::parse_timestamp_canonical(&value).map_err(serde::de::Error::custom)
}

pub fn serialize_optional_canonical_timestamp<S>(
    value: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(value) => serializer.serialize_str(&canonical::format_timestamp_canonical(*value)),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize_optional_canonical_timestamp<'de, D>(
    deserializer: D,
) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(value) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    canonical::parse_timestamp_canonical(&value)
        .map(Some)
        .map_err(serde::de::Error::custom)
}

/// `#[serde(with = ...)]` adapter for a required Arkret timestamp.
pub mod canonical_timestamp {
    pub use super::{
        deserialize_canonical_timestamp as deserialize, serialize_canonical_timestamp as serialize,
    };
}

/// `#[serde(with = ...)]` adapter for an optional Arkret timestamp.
pub mod optional_canonical_timestamp {
    pub use super::{
        deserialize_optional_canonical_timestamp as deserialize,
        serialize_optional_canonical_timestamp as serialize,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, serde::Serialize)]
    struct RequiredTimestamp {
        #[serde(
            serialize_with = "serialize_canonical_timestamp",
            deserialize_with = "deserialize_canonical_timestamp"
        )]
        at: DateTime<Utc>,
    }

    #[test]
    fn wire_deserializer_rejects_before_normalization() {
        for input in [
            r#"{"at":"2026-07-21T10:00:00Z"}"#,
            r#"{"at":"2026-07-21T10:00:00.000+00:00"}"#,
            r#"{"at":"2026-07-21T10:00:00.000000Z"}"#,
            r#"{"at":1784628000734}"#,
        ] {
            assert!(serde_json::from_str::<RequiredTimestamp>(input).is_err());
        }
    }

    #[test]
    fn wire_serializer_floors_and_emits_fixed_milliseconds() {
        let at = DateTime::parse_from_rfc3339("1969-12-31T23:59:59.999500Z")
            .unwrap()
            .with_timezone(&Utc);
        let encoded = serde_json::to_string(&RequiredTimestamp { at }).unwrap();
        assert_eq!(encoded, r#"{"at":"1969-12-31T23:59:59.999Z"}"#);
    }
}
