use chrono::{DateTime, Utc};

use crate::canonical;

pub(crate) fn now_utc_seconds() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(Utc::now().timestamp(), 0).unwrap_or_else(Utc::now)
}

pub(crate) fn serialize_canonical_timestamp<S>(
    value: &DateTime<Utc>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&canonical::format_timestamp_canonical(value.to_owned()))
}

pub(crate) fn serialize_optional_canonical_timestamp<S>(
    value: &Option<DateTime<Utc>>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(ts) => serializer.serialize_str(&canonical::format_timestamp_canonical(ts.to_owned())),
        None => serializer.serialize_none(),
    }
}

pub(crate) fn deserialize_canonical_timestamp<'de, D>(
    deserializer: D,
) -> std::result::Result<DateTime<Utc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    let value = String::deserialize(deserializer)?;
    canonical::validate_timestamp_canonical(&value).map_err(serde::de::Error::custom)?;
    DateTime::parse_from_rfc3339(&value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(serde::de::Error::custom)
}
