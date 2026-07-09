use chrono::{DateTime, Utc};

pub(crate) use crate::serde_helpers::{
    deserialize_canonical_timestamp, serialize_canonical_timestamp,
    serialize_optional_canonical_timestamp,
};

pub(crate) fn now_utc_seconds() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(Utc::now().timestamp(), 0).unwrap_or_else(Utc::now)
}
