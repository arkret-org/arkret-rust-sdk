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
    canonical::validate_timestamp_canonical(&value).map_err(serde::de::Error::custom)?;
    DateTime::parse_from_rfc3339(&value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(serde::de::Error::custom)
}

/// Serialize an Event, proof, or Agent pairing transcript timestamp with
/// exactly three UTC millisecond digits.
pub fn serialize_canonical_timestamp_millis<S>(
    value: &DateTime<Utc>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&canonical::format_timestamp_millis_canonical(*value))
}

/// Deserialize the fixed-width Event/proof/Agent-pairing millisecond profile.
pub fn deserialize_canonical_timestamp_millis<'de, D>(
    deserializer: D,
) -> Result<DateTime<Utc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    canonical::validate_timestamp_millis_canonical(&value).map_err(serde::de::Error::custom)?;
    DateTime::parse_from_rfc3339(&value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(serde::de::Error::custom)
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
    canonical::validate_timestamp_canonical(&value).map_err(serde::de::Error::custom)?;
    DateTime::parse_from_rfc3339(&value)
        .map(|parsed| Some(parsed.with_timezone(&Utc)))
        .map_err(serde::de::Error::custom)
}
