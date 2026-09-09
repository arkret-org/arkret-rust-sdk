//! Optional wire members whose schemas forbid explicit null.
use serde::Deserialize;

pub(crate) fn deserialize_non_null_optional<'de, D, T>(
    deserializer: D,
) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}
