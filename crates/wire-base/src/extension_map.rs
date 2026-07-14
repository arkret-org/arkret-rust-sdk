use std::collections::BTreeMap;
use std::ops::Deref;

use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;

/// JSON object whose members are restricted to the protocol `x_*` extension
/// namespace (`^x_[a-z][a-z0-9_]{0,63}$`).
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(transparent)]
pub struct XExtensionMap(BTreeMap<String, Value>);

impl XExtensionMap {
    pub fn new(values: BTreeMap<String, Value>) -> Result<Self, &'static str> {
        if values.keys().all(|key| is_x_extension_key(key)) {
            Ok(Self(values))
        } else {
            Err("extension keys must match ^x_[a-z][a-z0-9_]{0,63}$")
        }
    }

    pub fn as_map(&self) -> &BTreeMap<String, Value> {
        &self.0
    }

    pub fn into_map(self) -> BTreeMap<String, Value> {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Deref for XExtensionMap {
    type Target = BTreeMap<String, Value>;

    fn deref(&self) -> &Self::Target {
        self.as_map()
    }
}

impl TryFrom<BTreeMap<String, Value>> for XExtensionMap {
    type Error = &'static str;

    fn try_from(values: BTreeMap<String, Value>) -> Result<Self, Self::Error> {
        Self::new(values)
    }
}

impl<'de> Deserialize<'de> for XExtensionMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BTreeMap::<String, Value>::deserialize(deserializer)?;
        Self::new(values).map_err(de::Error::custom)
    }
}

fn is_x_extension_key(key: &str) -> bool {
    let Some(suffix) = key.strip_prefix("x_") else {
        return false;
    };
    let mut characters = suffix.chars();
    matches!(characters.next(), Some(first) if first.is_ascii_lowercase())
        && suffix.len() <= 64
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_members_outside_the_extension_namespace() {
        assert!(serde_json::from_str::<XExtensionMap>(r#"{"x_vendor":true}"#).is_ok());
        assert!(serde_json::from_str::<XExtensionMap>(r#"{"vendor":true}"#).is_err());
        assert!(serde_json::from_str::<XExtensionMap>(r#"{"x_Vendor":true}"#).is_err());
    }
}
