//! Validated string scalars used by closed wire models.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::Value;

/// Counterpart for JSON Schema string definitions with `minLength: 1`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct NonEmptyString(String);

impl NonEmptyString {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty() {
            return Err("value must not be empty");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for NonEmptyString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for NonEmptyString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for NonEmptyString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for NonEmptyString {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<NonEmptyString> for String {
    fn from(value: NonEmptyString) -> Self {
        value.into_string()
    }
}

impl Serialize for NonEmptyString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NonEmptyString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Arkret protocol kind matching `^ak\.[a-z0-9_]+(\.[a-z0-9_]+)*$`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ProtocolKind(String);

impl ProtocolKind {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        let Some(suffix) = value.strip_prefix("ak.") else {
            return Err("protocol kind must start with ak.");
        };
        if suffix.split('.').any(|segment| {
            segment.is_empty()
                || !segment.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
                })
        }) {
            return Err("protocol kind contains an invalid segment");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for ProtocolKind {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for ProtocolKind {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for ProtocolKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl PartialEq<str> for ProtocolKind {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for ProtocolKind {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl TryFrom<String> for ProtocolKind {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProtocolKind> for String {
    fn from(value: ProtocolKind) -> Self {
        value.into_string()
    }
}

impl<'de> Deserialize<'de> for ProtocolKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

macro_rules! non_empty_wire_string {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
        #[serde(transparent)]
        pub struct $name(NonEmptyString);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
                NonEmptyString::new(value).map(Self)
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }

            pub fn into_string(self) -> String {
                self.0.into_string()
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl TryFrom<String> for $name {
            type Error = &'static str;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.into_string()
            }
        }
    };
}

non_empty_wire_string!(
    /// Non-empty MLS group identifier carried by event payloads and governance bindings.
    MlsGroupId
);

non_empty_wire_string!(
    /// Non-empty identifier for the selected MIMI interoperability profile.
    MimiInteropProfileId
);

non_empty_wire_string!(
    /// Non-empty identifier for a MIMI content profile.
    ContentProfileId
);

/// Non-empty unpadded base64url value (`[A-Za-z0-9_-]+`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct Base64UrlString(String);

impl Base64UrlString {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty()
            || !value.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err("value must be non-empty unpadded base64url");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for Base64UrlString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for Base64UrlString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for Base64UrlString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for Base64UrlString {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Base64UrlString> for String {
    fn from(value: Base64UrlString) -> Self {
        value.into_string()
    }
}

impl<'de> Deserialize<'de> for Base64UrlString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Open JSON object that is required to contain at least one property.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(transparent)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct NonEmptyJsonObject(BTreeMap<String, Value>);

impl NonEmptyJsonObject {
    pub fn new(values: BTreeMap<String, Value>) -> Result<Self, &'static str> {
        if values.is_empty() {
            return Err("JSON object must contain at least one property");
        }
        Ok(Self(values))
    }

    pub fn as_map(&self) -> &BTreeMap<String, Value> {
        &self.0
    }

    pub fn into_map(self) -> BTreeMap<String, Value> {
        self.0
    }
}

impl<'de> Deserialize<'de> for NonEmptyJsonObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BTreeMap::<String, Value>::deserialize(deserializer)?;
        Self::new(values).map_err(de::Error::custom)
    }
}

/// MIMI room URI accepted by `mimi_room_binding_payload`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiRoomUri(String);

impl MimiRoomUri {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        let Some(room) = value.strip_prefix("mimi://") else {
            return Err("MIMI room URI must start with mimi://");
        };
        if room.is_empty() || room.chars().any(char::is_whitespace) {
            return Err("MIMI room URI must contain a non-whitespace room identifier");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for MimiRoomUri {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for MimiRoomUri {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for MimiRoomUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MimiRoomUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// DID URL with a required verification-method fragment.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DidUrl(String);

impl DidUrl {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        let Some(without_scheme) = value.strip_prefix("did:") else {
            return Err("DID URL must start with did:");
        };
        let Some((method, method_specific)) = without_scheme.split_once(':') else {
            return Err("DID URL must include a method-specific identifier");
        };
        if method.is_empty()
            || !method
                .chars()
                .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        {
            return Err("DID URL method must contain lowercase ASCII letters or digits");
        }
        let Some((identifier, fragment)) = method_specific.split_once('#') else {
            return Err("DID URL must include a verification-method fragment");
        };
        if identifier.is_empty()
            || identifier.chars().any(char::is_whitespace)
            || identifier.contains('#')
            || fragment.is_empty()
            || !fragment.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
            })
        {
            return Err("DID URL identifier or fragment is invalid");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for DidUrl {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for DidUrl {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for DidUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DidUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Ed25519 public key encoded as a `did:key` multibase value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DidKey(String);

impl DidKey {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        let Some(multibase) = value.strip_prefix("did:key:z") else {
            return Err("Ed25519 DID key must start with did:key:z");
        };
        if multibase.is_empty()
            || !multibase.chars().all(|character| {
                character.is_ascii_alphanumeric() && !matches!(character, '0' | 'O' | 'I' | 'l')
            })
        {
            return Err("Ed25519 DID key must contain a base58btc multibase value");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for DidKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for DidKey {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for DidKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DidKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_empty_wire_strings_reject_empty_input() {
        assert!(serde_json::from_str::<NonEmptyString>(r#"""#).is_err());
        assert!(serde_json::from_str::<MlsGroupId>(r#"""#).is_err());
        assert!(MimiInteropProfileId::new("").is_err());
        assert!(ContentProfileId::new("").is_err());
        assert!(MimiRoomUri::new("mimi://").is_err());
        assert!(MimiRoomUri::new("https://example.test/room").is_err());
        assert!(DidUrl::new("did:webvh:z6mkfixture:alice.example").is_err());
        assert!(DidUrl::new("did:webvh:z6mkfixture:alice.example#device-1").is_ok());
        assert!(Base64UrlString::new("").is_err());
        assert!(Base64UrlString::new("YWJjZA==").is_err());
        assert!(Base64UrlString::new("YWJjZA").is_ok());
        assert!(DidKey::new("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x").is_ok());
        assert!(DidKey::new("did:web:example.test#device").is_err());
        assert!(serde_json::from_str::<NonEmptyJsonObject>("{}").is_err());
        assert!(ProtocolKind::new("ak.key.verification.request").is_ok());
        assert!(ProtocolKind::new("ak.key..request").is_err());
        assert!(ProtocolKind::new("ak.Key.request").is_err());
        assert!(ProtocolKind::new("vendor.key.request").is_err());
    }

    #[test]
    fn non_empty_wire_strings_round_trip_as_strings() {
        let group_id = MlsGroupId::new("Z3JvdXA").unwrap();
        assert_eq!(serde_json::to_string(&group_id).unwrap(), r#""Z3JvdXA""#);
        assert_eq!(
            serde_json::from_str::<MlsGroupId>(r#""Z3JvdXA""#).unwrap(),
            group_id
        );
    }
}
