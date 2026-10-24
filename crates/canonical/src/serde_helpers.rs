//! Shared serde helpers for protocol wire types.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use crate::canonical;

/// Full-width logical integers use canonical decimal strings in JSON and
/// native unsigned integers in binary formats such as CBOR.
pub mod uint64_decimal {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&value.to_string())
        } else {
            serializer.serialize_u64(*value)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        if !deserializer.is_human_readable() {
            return u64::deserialize(deserializer);
        }
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(serde::de::Error::custom(
                "expected a canonical uint64 decimal string",
            ));
        }
        value.parse().map_err(serde::de::Error::custom)
    }
}

pub mod nonnegative_int64_decimal {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        if *value > i64::MAX as u64 {
            return Err(serde::ser::Error::custom(
                "nonnegative int64 decimal overflow",
            ));
        }
        super::uint64_decimal::serialize(value, serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = super::uint64_decimal::deserialize(deserializer)?;
        if value > i64::MAX as u64 {
            return Err(serde::de::Error::custom(
                "nonnegative int64 decimal overflow",
            ));
        }
        Ok(value)
    }
}

pub mod optional_uint64_decimal {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    struct Decimal(u64);
    impl Serialize for Decimal {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            super::uint64_decimal::serialize(&self.0, serializer)
        }
    }
    impl<'de> Deserialize<'de> for Decimal {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            super::uint64_decimal::deserialize(deserializer).map(Self)
        }
    }
    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        value.map(Decimal).serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        Decimal::deserialize(deserializer).map(|value| Some(value.0))
    }
}

/// Read a full-width integer at a dynamic JSON boundary without accepting a
/// rounded number or a second spelling of the wire terminal.
pub fn parse_uint64_decimal_value(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse().ok()
}

/// Decode an explicitly present nullable member. Without a serde default,
/// this adapter rejects absence and retains a schema-permitted null.
pub fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Deserialize a present non-null member; `serde(default)` handles absence.
pub fn deserialize_non_null_optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Canonical timestamp counterpart of a present non-null optional member.
pub fn deserialize_non_null_optional_timestamp<'de, D>(
    deserializer: D,
) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_canonical_timestamp(deserializer).map(Some)
}

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
