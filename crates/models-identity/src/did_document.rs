//! DID Document data shape and did:web helpers.
//!
//! Migrated verbatim from `arkret-core` (`arkret_core::identity`) so the
//! identity behavior crates (`arkret-identity`, `arkret-auth`) can operate on
//! the DID Document data model without reaching up into the core facade. Core
//! keeps a `pub use` shim over these symbols, so `arkret_core::identity::*` and
//! `arkret::identity::*` are unchanged for existing consumers.
//!
//! Behavior that needs signature verification, DID resolution, or state
//! reduction stays in `arkret-core` and the behavior crates; this module holds
//! the DID Document serde shape, its type-local helpers, and the pure did:web
//! document-URL derivation only.

use std::collections::BTreeMap;

use arkret_wire::{Did, Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DID_WEB_MAX_DOCUMENT_BYTES: usize = 64 * 1024;
pub const DID_WEBVH_V1_METHOD: &str = "did:webvh:1.0";

pub fn validate_did_webvh_v1_method(parameters: &Value) -> Result<()> {
    if parameters.get("method").and_then(Value::as_str) != Some(DID_WEBVH_V1_METHOD) {
        return Err(Error::Protocol(
            "unsupported_did_method: expected did:webvh:1.0".to_owned(),
        ));
    }
    Ok(())
}

pub fn did_web_document_url(did: &Did) -> Result<String> {
    if did.method() != "web" {
        return Err(Error::Protocol("DID method is not did:web".to_owned()));
    }
    let method_id = did
        .as_str()
        .strip_prefix("did:web:")
        .ok_or_else(|| Error::Protocol("invalid did:web identifier".to_owned()))?;
    let mut parts = method_id.split(':');
    let encoded_authority = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Protocol("did:web authority is empty".to_owned()))?;
    let authority = encoded_authority.replace("%3A", ":").replace("%3a", ":");
    let path: Vec<&str> = parts.collect();
    if path.iter().any(|segment| {
        segment.is_empty()
            || segment.contains('/')
            || segment.contains("..")
            || segment.contains('?')
            || segment.contains('#')
    }) {
        return Err(Error::Protocol(
            "did:web contains an invalid path segment".to_owned(),
        ));
    }
    let raw = if path.is_empty() {
        format!("https://{authority}/.well-known/did.json")
    } else {
        format!("https://{authority}/{}/did.json", path.join("/"))
    };
    let parsed =
        url::Url::parse(&raw).map_err(|_| Error::Protocol("invalid did:web URL".to_owned()))?;
    let host = parsed
        .host_str()
        .filter(|host| host.contains('.'))
        .ok_or_else(|| Error::Protocol("invalid did:web host".to_owned()))?;
    if !host.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
    }) {
        return Err(Error::Protocol("invalid did:web host".to_owned()));
    }
    Ok(parsed.to_string())
}

/// Issuer proof attached to a handle-claim challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleAttestation {
    pub issuer: Did,
    pub proof: String,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
}

/// Shared identity wire helper for DID resolution producers/consumers.
///
/// This is intentionally a product/shared contract, not the normative DID
/// data model for `arkret-core`. Core keeps the protocol response envelope
/// (`IdentityResolveOutcome`) while this type provides the
/// serde shape and convenience helpers used by identity resolvers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DidDocument {
    pub id: Did,
    pub verification_methods: BTreeMap<String, String>,
    pub also_known_as: Vec<String>,
    pub updated_at: Option<DateTime<Utc>>,
    /// Exact DID Document properties received on the wire. This preserves
    /// standard relationships, services, contexts, controller declarations,
    /// and extension properties that the convenience indexes above do not
    /// interpret.
    pub raw_properties: BTreeMap<String, Value>,
}

fn verification_method_index(
    value: &Value,
) -> std::result::Result<BTreeMap<String, String>, String> {
    match value {
        Value::Object(methods) => Ok(methods
            .iter()
            .map(|(key_id, key_value)| {
                let public_key = key_value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| key_value.to_string());
                (key_id.clone(), public_key)
            })
            .collect()),
        Value::Array(methods) => {
            let mut out = BTreeMap::new();
            for method in methods {
                if let Value::Object(object) = method {
                    let Some(key_id) = object
                        .get("id")
                        .and_then(|value| value.as_str())
                        .map(ToOwned::to_owned)
                    else {
                        continue;
                    };
                    let public_key = object
                        .get("publicKeyMultibase")
                        .or_else(|| object.get("publicKeyJwk"))
                        .map(|value| {
                            value
                                .as_str()
                                .map(ToOwned::to_owned)
                                .unwrap_or_else(|| value.to_string())
                        })
                        .unwrap_or_default();
                    out.insert(key_id, public_key);
                }
            }
            Ok(out)
        }
        Value::Null => Ok(BTreeMap::new()),
        other => Err(format!(
            "verificationMethod must be an object or array, got {other}"
        )),
    }
}

impl Serialize for DidDocument {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut properties = self.raw_properties.clone();
        properties.insert("id".to_owned(), Value::String(self.id.to_string()));

        let keep_raw_verification_methods = properties
            .get("verificationMethod")
            .and_then(|value| verification_method_index(value).ok())
            .is_some_and(|index| index == self.verification_methods);
        if !keep_raw_verification_methods {
            if self.verification_methods.is_empty() {
                properties.remove("verificationMethod");
            } else {
                properties.insert(
                    "verificationMethod".to_owned(),
                    serde_json::to_value(&self.verification_methods)
                        .map_err(serde::ser::Error::custom)?,
                );
            }
        }

        let keep_raw_aliases = properties
            .get("alsoKnownAs")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items.iter().map(Value::as_str).collect::<Option<Vec<_>>>()
                    == Some(self.also_known_as.iter().map(String::as_str).collect())
            });
        if !keep_raw_aliases {
            if self.also_known_as.is_empty() {
                properties.remove("alsoKnownAs");
            } else {
                properties.insert(
                    "alsoKnownAs".to_owned(),
                    serde_json::to_value(&self.also_known_as).map_err(serde::ser::Error::custom)?,
                );
            }
        }

        let keep_raw_updated = properties
            .get("updated")
            .cloned()
            .and_then(|value| serde_json::from_value::<DateTime<Utc>>(value).ok())
            .as_ref()
            == self.updated_at.as_ref();
        match (self.updated_at.as_ref(), keep_raw_updated) {
            (Some(_), true) => {}
            (Some(updated_at), false) => {
                properties.insert(
                    "updated".to_owned(),
                    serde_json::to_value(updated_at).map_err(serde::ser::Error::custom)?,
                );
            }
            (None, _) => {
                properties.remove("updated");
            }
        }
        properties.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DidDocument {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw_properties = BTreeMap::<String, Value>::deserialize(deserializer)?;
        let id = raw_properties
            .get("id")
            .cloned()
            .ok_or_else(|| serde::de::Error::missing_field("id"))
            .and_then(|value| serde_json::from_value(value).map_err(serde::de::Error::custom))?;
        let verification_methods = raw_properties
            .get("verificationMethod")
            .map(verification_method_index)
            .transpose()
            .map_err(serde::de::Error::custom)?
            .unwrap_or_default();
        let also_known_as = raw_properties
            .get("alsoKnownAs")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?
            .unwrap_or_default();
        let updated_at = raw_properties
            .get("updated")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            id,
            verification_methods,
            also_known_as,
            updated_at,
            raw_properties,
        })
    }
}

impl DidDocument {
    pub fn new(id: Did, key_id: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            id,
            verification_methods: BTreeMap::from([(key_id.into(), public_key.into())]),
            also_known_as: Vec::new(),
            updated_at: Some(Utc::now()),
            raw_properties: BTreeMap::new(),
        }
    }

    pub fn to_wire_document(&self) -> BTreeMap<String, Value> {
        serde_json::to_value(self)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .map(|object| object.into_iter().collect())
            .unwrap_or_default()
    }

    pub fn validate(&self) -> Result<()> {
        if self
            .raw_properties
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|raw_id| raw_id != self.id.as_str())
        {
            return Err(Error::Protocol("did document id mismatch".to_owned()));
        }
        Ok(())
    }

    pub fn method(&self) -> &str {
        self.id.method()
    }

    pub fn control_keys(&self) -> &BTreeMap<String, String> {
        &self.verification_methods
    }

    pub fn primary_key(&self) -> Option<(&str, &str)> {
        self.verification_methods
            .iter()
            .next()
            .map(|(key_id, public_key)| (key_id.as_str(), public_key.as_str()))
    }

    pub fn handles(&self) -> Vec<&str> {
        self.also_known_as
            .iter()
            .filter(|entry| !entry.starts_with("http://") && !entry.starts_with("https://"))
            .map(String::as_str)
            .collect()
    }

    pub fn service_urls(&self) -> Vec<&str> {
        self.also_known_as
            .iter()
            .filter(|entry| entry.starts_with("http://") || entry.starts_with("https://"))
            .map(String::as_str)
            .collect()
    }
}

/// Derive the deterministic principal-control Realm ID for a principal DID.
pub fn principal_control_realm_id(principal_id: &Did) -> String {
    let digest = arkret_canonical::canonical::sha256_bytes_from_slices(&[
        b"ak:realm:principal-control:v1:",
        principal_id.as_str().as_bytes(),
    ]);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let group =
        |slice: &[u8]| -> String { slice.iter().map(|byte| format!("{byte:02x}")).collect() };
    format!(
        "ak:realm:{}-{}-{}-{}-{}",
        group(&bytes[0..4]),
        group(&bytes[4..6]),
        group(&bytes[6..8]),
        group(&bytes[8..10]),
        group(&bytes[10..16])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    #[test]
    fn did_webvh_v1_method_marker_is_closed() {
        validate_did_webvh_v1_method(&serde_json::json!({
            "method": DID_WEBVH_V1_METHOD
        }))
        .unwrap();
        assert!(
            validate_did_webvh_v1_method(&serde_json::json!({
                "method": "did:webvh:2.0"
            }))
            .is_err()
        );
    }

    #[test]
    fn did_document_preserves_relationships_and_allows_empty_verification_methods() {
        let value = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:z6mkfixture:alice.example",
            "capabilityDelegation": [
                "did:webvh:z6mkfixture:alice.example#device-enrollment-authority"
            ],
            "service": [{
                "id": "did:webvh:z6mkfixture:alice.example#principal-server",
                "type": "ArkretPrincipalServer",
                "serviceEndpoint": "https://principal.example"
            }],
            "x-vendor": {"preserve": true}
        });
        let document: DidDocument = serde_json::from_value(value.clone()).unwrap();
        assert!(document.verification_methods.is_empty());
        document.validate().unwrap();
        assert_eq!(serde_json::to_value(document).unwrap(), value);
    }

    #[test]
    fn did_document_helpers_cover_sdk_usage() {
        let mut document = DidDocument::new(did("alice"), "key-1", "pub");
        document.also_known_as = vec![
            "@alice:example".to_owned(),
            "https://example.test/users/alice".to_owned(),
        ];

        assert_eq!(document.method(), "webvh");
        assert_eq!(
            document.control_keys().get("key-1"),
            Some(&"pub".to_owned())
        );
        assert_eq!(document.primary_key(), Some(("key-1", "pub")));
        assert_eq!(document.handles(), vec!["@alice:example"]);
        assert_eq!(
            document.service_urls(),
            vec!["https://example.test/users/alice"]
        );
    }

    #[test]
    fn did_web_url_supports_encoded_ports_and_paths() {
        let did = Did::new("did:web:example.test%3A8443:users:alice").unwrap();
        assert_eq!(
            did_web_document_url(&did).unwrap(),
            "https://example.test:8443/users/alice/did.json"
        );
    }
}
