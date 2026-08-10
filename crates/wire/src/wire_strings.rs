//! Validated string scalars used by closed wire models.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;

use arkret_identifiers::{EventId, GrantId};
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

fn split_versioned_ref(value: &str) -> Option<&str> {
    let (prefix, version) = value.rsplit_once(".v")?;
    if prefix.is_empty() || version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(prefix)
}

macro_rules! validated_wire_string {
    ($(#[$meta:meta])* $name:ident, $validator:expr, $error:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        #[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
                let value = value.into();
                if !$validator(&value) {
                    return Err($error);
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

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

fn is_profile_ref(value: &str) -> bool {
    let Some(prefix) = split_versioned_ref(value) else {
        return false;
    };
    prefix
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && prefix.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

fn is_feature_ref(value: &str) -> bool {
    let Some(prefix) = split_versioned_ref(value) else {
        return false;
    };
    let segments = prefix.split('.').collect::<Vec<_>>();
    let domain_segment = |segment: &&str| {
        segment
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    let feature_segment = |segment: &&str| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    };

    if segments.first() == Some(&"cx") {
        return segments.len() >= 2 && segments[1..].iter().all(feature_segment);
    }
    (2..segments.len()).any(|feature_start| {
        segments[..feature_start].iter().all(domain_segment)
            && segments[feature_start..].iter().all(feature_segment)
    })
}

validated_wire_string!(
    /// Open profile identifier matching the Event Envelope `profile_ref` grammar.
    ///
    /// Unknown but well-formed profile IDs are preserved so registry evolution
    /// remains forward compatible; admission decides whether they are supported.
    ProfileRef,
    is_profile_ref,
    "profile reference must match ^[a-z0-9][a-z0-9_.-]*\\.v[0-9]+$"
);

validated_wire_string!(
    /// Open feature identifier matching the Event Envelope `feature_ref` grammar.
    ///
    /// Unknown but well-formed feature IDs survive decoding. Event admission
    /// still fails closed when a required feature is unsupported.
    FeatureRef,
    is_feature_ref,
    "feature reference does not match the Event Envelope feature_ref grammar"
);

fn is_authorization_ref(value: &str) -> bool {
    value == crate::REALM_AUTHORITY_ROOT_CELL
        || value == "ak.authority.direct_conversation_participant.v1"
        || value == "ak.authority.direct_conversation_repair.v1"
        || crate::MembershipCompensationDelegationRef::new(value).is_ok()
        || GrantId::new(value).is_ok()
        || EventId::new(value).is_ok()
        || DidUrl::new(value).is_ok()
}

validated_wire_string!(
    /// Closed Event Envelope authorization source reference.
    ///
    /// The schema admits a grant, an accepted authorization Event, a DID
    /// delegation URL, membership-compensation delegation, or a registered
    /// authority-source constant.
    AuthorizationRef,
    is_authorization_ref,
    "authorization reference must be a grant, event, DID delegation URL, or registered authority constant"
);

impl From<GrantId> for AuthorizationRef {
    fn from(value: GrantId) -> Self {
        Self(value.into_string())
    }
}

impl From<EventId> for AuthorizationRef {
    fn from(value: EventId) -> Self {
        Self(value.into_string())
    }
}

impl From<DidUrl> for AuthorizationRef {
    fn from(value: DidUrl) -> Self {
        Self(value.to_string())
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

/// Deployment-local short-lived account/auth artifact identifier matching
/// `^[A-Za-z0-9._:-]{1,128}$`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OpaqueLocalId(String);

impl OpaqueLocalId {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 {
            return Err("opaque local id must contain 1 to 128 ASCII characters");
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        {
            return Err("opaque local id contains a character outside [A-Za-z0-9._:-]");
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

impl AsRef<str> for OpaqueLocalId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for OpaqueLocalId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for OpaqueLocalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for OpaqueLocalId {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<OpaqueLocalId> for String {
    fn from(value: OpaqueLocalId) -> Self {
        value.into_string()
    }
}

impl<'de> Deserialize<'de> for OpaqueLocalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

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
///
/// Mirrors `common-ids.schema.json#/$defs/did_url`
/// (`^did:[a-z0-9]+:[^\s#?]+#[A-Za-z0-9._:-]+$`): the method-specific
/// identifier rejects whitespace, `#` and `?`, while the fragment is limited to
/// `[A-Za-z0-9._:-]`.
///
/// Note: a few other v1 schemas spell the fragment as `[^\s]+` / `[^\s#]+`,
/// which is wider than `common-ids#/$defs/did_url`. That inconsistency is
/// registered as a spec gap; this type deliberately enforces the strictest of
/// the published patterns (`common-ids#/$defs/did_url`), which every existing
/// fixture already satisfies.
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
        // `split_once('#')` already cut at the first `#`, so `identifier` can
        // never carry another one; extra `#` land in `fragment` and are caught
        // by the fragment charset check below. `?` must be rejected explicitly:
        // the spec identifier class is `[^\s#?]+`.
        if identifier.is_empty()
            || identifier.chars().any(char::is_whitespace)
            || identifier.contains('?')
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

impl PartialEq<str> for DidUrl {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for DidUrl {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for DidUrl {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}

impl PartialEq<DidUrl> for str {
    fn eq(&self, other: &DidUrl) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<DidUrl> for &str {
    fn eq(&self, other: &DidUrl) -> bool {
        *self == other.as_str()
    }
}

impl PartialEq<DidUrl> for String {
    fn eq(&self, other: &DidUrl) -> bool {
        self.as_str() == other.as_str()
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
    fn open_profile_and_feature_refs_validate_shape_without_closing_the_registry() {
        let profile = ProfileRef::new("vendor.profile.future_mode.v42").unwrap();
        assert_eq!(profile.as_str(), "vendor.profile.future_mode.v42");
        assert!(ProfileRef::new("Vendor.profile.v1").is_err());
        assert!(ProfileRef::new("ak.profile.missing_version").is_err());

        let feature = FeatureRef::new("example.vendor.future_mode.v7").unwrap();
        assert_eq!(feature.as_str(), "example.vendor.future_mode.v7");
        assert!(FeatureRef::new("ak.feature.future_mode").is_err());
        assert!(FeatureRef::new("single.future_mode.v1").is_err());
    }

    #[test]
    fn authorization_ref_accepts_only_the_schema_union() {
        for value in [
            "ak:grant:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM",
            "ak:event:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM",
            "did:web:alice.example#managed-controller",
            crate::REALM_AUTHORITY_ROOT_CELL,
            "ak.authority.direct_conversation_participant.v1",
            "ak.authority.direct_conversation_repair.v1",
        ] {
            assert!(AuthorizationRef::new(value).is_ok(), "{value}");
        }
        for value in [
            crate::REALM_GENESIS_CELL,
            "ak:grant:not-a-uuid",
            "did:web:alice.example",
            "future.authorization.source.v1",
        ] {
            assert!(AuthorizationRef::new(value).is_err(), "{value}");
        }
    }

    #[test]
    fn non_empty_wire_strings_reject_empty_input() {
        assert!(serde_json::from_str::<NonEmptyString>(r#"""#).is_err());
        assert!(serde_json::from_str::<MlsGroupId>(r#"""#).is_err());
        assert!(MimiInteropProfileId::new("").is_err());
        assert!(ContentProfileId::new("").is_err());
        assert!(OpaqueLocalId::new("").is_err());
        assert!(OpaqueLocalId::new("contains a space").is_err());
        assert!(OpaqueLocalId::new("a".repeat(129)).is_err());
        assert!(OpaqueLocalId::new("agent_runtime_approval:request-1").is_ok());
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
        let local_id = OpaqueLocalId::new("agent_pairing_request:request-1").unwrap();
        assert_eq!(
            serde_json::from_str::<OpaqueLocalId>(&serde_json::to_string(&local_id).unwrap())
                .unwrap(),
            local_id
        );
    }

    /// DID URL samples that MUST be accepted, matching
    /// `common-ids.schema.json#/$defs/did_url`.
    const DID_URL_ACCEPTED: &[&str] = &[
        "did:webvh:z6mkfixture:alice.example#device-1",
        "did:web:alice.example#key.1",
        "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
        "did:webvh:z6mkfixture:alice.example#ak:device:0198c4d2-af00-7000-8000-aabbccddeeff",
        "did:webvh:z6mkfixture:alice.example#ak_device_signing_v1",
        "did:webvh:example.test:orgs:org1#k1",
        "did:key2:abc#k",
        // The spec identifier class `[^\s#?]+` allows `/`; staying no stricter
        // than the schema is deliberate.
        "did:webvh:example.test/tenant1#k1",
    ];

    /// DID URL samples that MUST be rejected.
    const DID_URL_REJECTED: &[&str] = &[
        // Bare DIDs carry no verification-method fragment.
        "did:webvh:z6mkfixture:alice.example",
        "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
        // Query markers are outside the identifier class `[^\s#?]+`.
        "did:web:example.com?service=files",
        "did:web:example.com?service=files#key-1",
        // Empty fragment / empty identifier.
        "did:web:example.com#",
        "did:web:#key-1",
        // Missing or malformed scheme, method or method-specific identifier.
        "#key-1",
        "did:web#key-1",
        "did::abc#k",
        "did:WEB:example.com#key-1",
        "did:web-vh:example.com#key-1",
        "not-a-did",
        "",
        "did:",
        "ak:device:0198c4d2-af00-7000-8000-aabbccddeeff",
        "example.com#key-1",
        // Whitespace anywhere.
        "did:web:exa mple.com#key-1",
        "did:web:example.com#key 1",
        // A second `#` lands in the fragment and fails the fragment charset.
        "did:web:example.com#a#b",
        // Fragment charset is `[A-Za-z0-9._:-]`, stricter than the `[^\s]+` /
        // `[^\s#]+` spelled by some sibling schemas (registered spec gap).
        "did:web:example.com#key/1",
        "did:web:example.com#key%201",
    ];

    #[test]
    fn did_url_accepts_every_spec_conformant_sample() {
        for sample in DID_URL_ACCEPTED {
            let parsed =
                DidUrl::new(*sample).unwrap_or_else(|error| panic!("{sample:?} rejected: {error}"));
            assert_eq!(parsed.as_str(), *sample, "round-trip changed {sample:?}");
        }
    }

    #[test]
    fn did_url_rejects_every_non_conformant_sample() {
        for sample in DID_URL_REJECTED {
            assert!(
                DidUrl::new(*sample).is_err(),
                "{sample:?} must be rejected by DidUrl"
            );
        }
    }

    #[test]
    fn did_url_rejects_query_markers() {
        // Regression guard: the identifier segment used to accept `?`, so a
        // query-bearing DID URL slipped through even though the spec pattern
        // `[^\s#?]+` forbids it.
        assert!(DidUrl::new("did:web:example.com?service=files#key-1").is_err());
        assert!(DidUrl::new("did:webvh:z6mkfixture:alice.example?versionId=1#key-1").is_err());
    }

    #[test]
    fn did_url_rejects_repeated_fragment_markers() {
        // Proves the removed `identifier.contains('#')` branch was dead: the
        // fragment charset check is what rejects a second `#`.
        assert!(DidUrl::new("did:web:example.com#a#b").is_err());
        assert!(DidUrl::new("did:web:example.com#a#").is_err());
    }

    #[test]
    fn did_url_keeps_accepting_path_segments() {
        // D2: the spec identifier class allows `/`; do not tighten this without
        // tightening `common-ids.schema.json#/$defs/did_url` first.
        assert!(DidUrl::new("did:webvh:example.test/tenant1#k1").is_ok());
        assert!(DidUrl::new("did:web:example.test/a/b/c#key-1").is_ok());
    }

    #[test]
    fn did_url_serde_round_trips_accepted_samples() {
        for sample in DID_URL_ACCEPTED {
            let encoded = format!("\"{sample}\"");
            let decoded = serde_json::from_str::<DidUrl>(&encoded)
                .unwrap_or_else(|error| panic!("{sample:?} failed to deserialize: {error}"));
            assert_eq!(decoded.as_str(), *sample);
            assert_eq!(
                serde_json::to_string(&decoded).unwrap(),
                encoded,
                "serialization changed {sample:?}"
            );
        }
    }

    #[test]
    fn did_url_serde_rejects_non_conformant_samples() {
        for sample in DID_URL_REJECTED {
            let encoded = format!("\"{sample}\"");
            assert!(
                serde_json::from_str::<DidUrl>(&encoded).is_err(),
                "{sample:?} must fail to deserialize"
            );
        }
    }

    #[test]
    fn did_and_did_url_value_domains_are_disjoint() {
        use arkret_identifiers::DidFullId;

        // Every accepted DID URL carries a fragment, so it is never a bare DID.
        for sample in DID_URL_ACCEPTED {
            assert!(
                DidUrl::new(*sample).is_ok(),
                "{sample:?} must be a valid DidUrl"
            );
            assert!(
                DidFullId::new(*sample).is_err(),
                "{sample:?} must not be a valid DidFullId"
            );
        }

        // Every bare DID is rejected by `DidUrl` for lack of a fragment.
        const BARE_DIDS: &[&str] = &[
            "did:web:x",
            "did:webvh:z6mkfixture:alice.example",
            "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
            "did:webvh:example.test:orgs:org1",
            "did:webvh:example.test:tenant1",
        ];
        for sample in BARE_DIDS {
            assert!(
                DidFullId::new(*sample).is_ok(),
                "{sample:?} must be a valid DidFullId"
            );
            assert!(
                DidUrl::new(*sample).is_err(),
                "{sample:?} must not be a valid DidUrl"
            );
        }

        // The two headline cases, spelled out.
        assert!(DidFullId::new("did:web:x#key-1").is_err());
        assert!(DidUrl::new("did:web:x#key-1").is_ok());
        assert!(DidFullId::new("did:web:x").is_ok());
        assert!(DidUrl::new("did:web:x").is_err());
    }

    // The owned operands are the point: this case exists to exercise the
    // `DidUrl`/`String` `PartialEq` impls in both directions. Taking clippy's
    // "compare against the borrow instead" advice would silently collapse each
    // of those two lines into a duplicate of the `&str` case above it and drop
    // the impl from coverage.
    #[allow(clippy::cmp_owned)]
    #[test]
    fn did_url_compares_against_string_types_in_both_directions() {
        let did_url = DidUrl::new("did:webvh:z6mkfixture:alice.example#device-1").unwrap();
        let owned = String::from("did:webvh:z6mkfixture:alice.example#device-1");
        let other = "did:webvh:z6mkfixture:alice.example#device-2";

        // DidUrl on the left.
        assert!(did_url == *"did:webvh:z6mkfixture:alice.example#device-1");
        assert!(did_url == "did:webvh:z6mkfixture:alice.example#device-1");
        assert!(did_url == owned);
        assert!(did_url != *other);
        assert!(did_url != other);
        assert!(did_url != String::from(other));

        // DidUrl on the right.
        assert!(*"did:webvh:z6mkfixture:alice.example#device-1" == did_url);
        assert!("did:webvh:z6mkfixture:alice.example#device-1" == did_url);
        assert!(owned == did_url);
        assert!(*other != did_url);
        assert!(other != did_url);
        assert!(String::from(other) != did_url);
    }
}
