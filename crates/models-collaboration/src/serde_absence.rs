pub(crate) use arkret_canonical::serde_helpers::deserialize_non_null_optional;
use serde::Deserialize;

pub(crate) fn deserialize_present_nullable<'de, D, T>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}
