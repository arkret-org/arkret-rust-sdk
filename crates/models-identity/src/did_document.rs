//! DID Document data shape and did:web helpers.
//!
//! Identity behavior crates (`arkret-identity`, `arkret-auth`) operate directly
//! on this owner-defined model. The `arkret::identity::*` surface remains
//! available to application consumers.
//!
//! Behavior that needs signature verification, DID resolution, or state
//! reduction lives in the behavior crates; this module holds
//! the DID Document serde shape, its type-local helpers, and the pure did:web
//! document-URL derivation only.

use std::collections::BTreeMap;

use arkret_wire::{Did, DidCoreId, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DID_WEB_MAX_DOCUMENT_BYTES: usize = 64 * 1024;
pub const DID_WEBVH_V1_METHOD: &str = "did:webvh:1.0";

pub fn validate_did_webvh_v1_method(parameters: &Value) -> Result<()> {
    if parameters.get("method").and_then(Value::as_str) != Some(DID_WEBVH_V1_METHOD) {
        return Err(WireError::Protocol(
            "unsupported_did_method: expected did:webvh:1.0".to_owned(),
        ));
    }
    Ok(())
}

pub fn did_web_document_url(did: &Did) -> Result<String> {
    if did.method() != "web" {
        return Err(WireError::Protocol("DID method is not did:web".to_owned()));
    }
    let method_id = did
        .as_str()
        .strip_prefix("did:web:")
        .ok_or_else(|| WireError::Protocol("invalid did:web identifier".to_owned()))?;
    let mut parts = method_id.split(':');
    let encoded_authority = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| WireError::Protocol("did:web authority is empty".to_owned()))?;
    let authority = encoded_authority.replace("%3A", ":").replace("%3a", ":");
    let path: Vec<&str> = parts.collect();
    if path.iter().any(|segment| {
        segment.is_empty()
            || segment.contains('/')
            || segment.contains("..")
            || segment.contains('?')
            || segment.contains('#')
    }) {
        return Err(WireError::Protocol(
            "did:web contains an invalid path segment".to_owned(),
        ));
    }
    let raw = if path.is_empty() {
        format!("https://{authority}/.well-known/did.json")
    } else {
        format!("https://{authority}/{}/did.json", path.join("/"))
    };
    let parsed =
        url::Url::parse(&raw).map_err(|_| WireError::Protocol("invalid did:web URL".to_owned()))?;
    let host = parsed
        .host_str()
        .filter(|host| host.contains('.'))
        .ok_or_else(|| WireError::Protocol("invalid did:web host".to_owned()))?;
    if !host.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
    }) {
        return Err(WireError::Protocol("invalid did:web host".to_owned()));
    }
    Ok(parsed.to_string())
}

/// Issuer proof attached to a handle-claim challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleAttestation {
    pub issuer_id: DidCoreId,
    pub proof: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

/// Shared identity wire helper for DID resolution producers/consumers.
///
/// This is intentionally a product/shared contract, not the normative DID
/// data model for the SDK. The protocol response envelope
/// (`IdentityResolveOutcome`) while this type provides the
/// serde shape and convenience helpers used by identity resolvers.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

fn normalized_verification_method_index(
    value: &Value,
) -> std::result::Result<BTreeMap<String, String>, String> {
    let Value::Array(methods) = value else {
        return Err("verification_methods must be an array".to_owned());
    };
    let mut out = BTreeMap::new();
    for method in methods {
        let Value::Object(object) = method else {
            continue;
        };
        let Some(key_id) = object
            .get("verification_method")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        let public_key = object
            .get("public_key_material")
            .and_then(Value::as_object)
            .and_then(|material| {
                material
                    .get("publicKeyMultibase")
                    .or_else(|| material.get("publicKeyJwk"))
                    .or_else(|| material.values().next())
            })
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| value.to_string())
            })
            .unwrap_or_default();
        out.insert(key_id, public_key);
    }
    Ok(out)
}

impl Serialize for DidDocument {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut properties = self.raw_properties.clone();
        if properties.contains_key("did") && !properties.contains_key("id") {
            properties.insert("did".to_owned(), Value::String(self.id.to_string()));
            return properties.serialize(serializer);
        }
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
            .or_else(|| raw_properties.get("did"))
            .cloned()
            .ok_or_else(|| serde::de::Error::custom("missing field `id` or `did`"))
            .and_then(|value| serde_json::from_value(value).map_err(serde::de::Error::custom))?;
        let verification_methods = raw_properties
            .get("verificationMethod")
            .map(verification_method_index)
            .or_else(|| {
                raw_properties
                    .get("verification_methods")
                    .map(normalized_verification_method_index)
            })
            .transpose()
            .map_err(serde::de::Error::custom)?
            .unwrap_or_default();
        let also_known_as = raw_properties
            .get("alsoKnownAs")
            .or_else(|| raw_properties.get("also_known_as"))
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

    pub fn validate(&self) -> Result<()> {
        if self
            .raw_properties
            .get("id")
            .or_else(|| self.raw_properties.get("did"))
            .and_then(Value::as_str)
            .is_some_and(|raw_id| raw_id != self.id.as_str())
        {
            return Err(WireError::Protocol("did document id mismatch".to_owned()));
        }
        Ok(())
    }

    pub fn method(&self) -> &str {
        self.id.method()
    }

    pub fn handles(&self) -> Vec<&str> {
        self.also_known_as
            .iter()
            .filter(|entry| !entry.starts_with("http://") && !entry.starts_with("https://"))
            .map(String::as_str)
            .collect()
    }
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
                "did:webvh:z6mkfixture:alice.example#invalid-device-authority"
            ],
            "service": [{
                "id": "did:webvh:z6mkfixture:alice.example#station",
                "type": "ArkretStation",
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
    fn did_document_preserves_canonical_normalized_projection() {
        let value = serde_json::json!({
            "did": "did:webvh:z6mkfixture:alice.example",
            "contexts": ["https://www.w3.org/ns/did/v1"],
            "controller_dids": [],
            "also_known_as": ["acct:alice@example.test"],
            "verification_methods": [{
                "verification_method": "did:webvh:z6mkfixture:alice.example#key-1",
                "controller_did": "did:webvh:z6mkfixture:alice.example",
                "verification_method_suite": "Multikey",
                "public_key_material": {"publicKeyMultibase": "z6Mkfixture"},
                "extensions": []
            }],
            "authentication": [],
            "assertion_methods": [{
                "verification_method": "did:webvh:z6mkfixture:alice.example#key-1"
            }],
            "key_agreements": [],
            "capability_invocations": [],
            "capability_delegations": [],
            "services": [],
            "metadata": {},
            "extensions": []
        });
        let document: DidDocument = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(document.id.as_str(), "did:webvh:z6mkfixture:alice.example");
        assert_eq!(
            document
                .verification_methods
                .get("did:webvh:z6mkfixture:alice.example#key-1"),
            Some(&"z6Mkfixture".to_owned())
        );
        assert_eq!(document.also_known_as, vec!["acct:alice@example.test"]);
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
            document.verification_methods.get("key-1"),
            Some(&"pub".to_owned())
        );
        assert_eq!(document.handles(), vec!["@alice:example"]);
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
