//! Arkret identity surface models and helpers.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Did, Hash, IdentityReceipt, IdentityResolveOutcome, Proof, Result};

/// §3.2.1 deterministic primary-handle selection, `claim_digest`, and
/// §3.8.2 mention/subject rendering. wasm-safe, dependency-free helpers
/// shared by inkson / sodmin / soland / cotest (SOD-05-001 / SPEC-CR-019).
pub mod primary_handle;

pub const DID_WEB_MAX_DOCUMENT_BYTES: usize = 64 * 1024;
pub const DID_WEBVH_V1_METHOD: &str = "did:webvh:1.0";

pub fn validate_did_webvh_v1_method(parameters: &Value) -> Result<()> {
    if parameters.get("method").and_then(Value::as_str) != Some(DID_WEBVH_V1_METHOD) {
        return Err(crate::Error::Protocol(
            "unsupported_did_method: expected did:webvh:1.0".to_owned(),
        ));
    }
    Ok(())
}

/// Derive the deterministic principal-control Realm ID for a principal DID.
pub fn principal_control_realm_id(principal_id: &Did) -> String {
    let digest = crate::canonical::sha256_bytes_from_slices(&[
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

/// Issuer proof attached to a handle-claim challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleAttestation {
    pub issuer: Did,
    pub proof: String,
    pub created_at: DateTime<Utc>,
}

/// Shared identity wire helper for DID resolution producers/consumers.
///
/// This is intentionally a product/shared contract, not the normative DID
/// data model for `arkret-core`. Core keeps the protocol response envelope
/// (`IdentityResolveOutcome`) while this type provides the
/// serde shape and convenience helpers used by identity resolvers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: Did,
    #[serde(
        rename = "verificationMethod",
        default,
        deserialize_with = "deserialize_verification_methods",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub verification_methods: BTreeMap<String, String>,
    #[serde(rename = "alsoKnownAs", default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<String>,
    #[serde(rename = "updated", default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

fn deserialize_verification_methods<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Object(methods) => Ok(methods
            .into_iter()
            .map(|(key_id, key_value)| {
                let public_key = key_value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| key_value.to_string());
                (key_id, public_key)
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
        other => Err(serde::de::Error::custom(format!(
            "verificationMethod must be an object or array, got {other}"
        ))),
    }
}

impl DidDocument {
    pub fn new(id: Did, key_id: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            id,
            verification_methods: BTreeMap::from([(key_id.into(), public_key.into())]),
            also_known_as: Vec::new(),
            updated_at: Utc::now(),
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
        if self.verification_methods.is_empty() {
            return Err(crate::Error::Protocol(
                "did document has no verification methods".to_owned(),
            ));
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyIdentifierKind {
    Email,
    Phone,
    Handle,
    Domain,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThirdPartyIdentifierBinding {
    pub kind: ThirdPartyIdentifierKind,
    pub address: String,
    pub did: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
    pub bound_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityInvitationLookupRequestBody {
    pub medium: ThirdPartyIdentifierKind,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityInvitationLookupOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    #[serde(default)]
    pub privacy_preserving: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyLogHead {
    pub did: Did,
    pub seq: u64,
    pub head_event_digest: Hash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<IdentityReceipt>,
}

pub fn resolve_response_from_document(
    document: DidDocument,
    key_log_head: Option<KeyLogHead>,
) -> IdentityResolveOutcome {
    IdentityResolveOutcome {
        did_document: document.to_wire_document(),
        key_log_head: key_log_head
            .as_ref()
            .map(|head| head.head_event_digest.clone()),
        seq: key_log_head.as_ref().map(|head| head.seq),
        receipts: key_log_head.map(|head| head.receipts).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    #[test]
    fn did_document_validates_and_builds_resolve_response() {
        let document = DidDocument {
            id: did("alice"),
            verification_methods: BTreeMap::from([("key-1".to_owned(), "pub".to_owned())]),
            also_known_as: vec!["@alice:example".to_owned()],
            updated_at: Utc::now(),
        };
        document.validate().unwrap();

        let response = resolve_response_from_document(document.clone(), None);
        assert_eq!(response.did_document["id"], document.id.as_str());
        assert!(response.did_document.get("verificationMethod").is_some());
        assert!(response.did_document.get("alsoKnownAs").is_some());
        assert!(response.did_document.get("updated").is_some());
        assert!(response.did_document.get("verification_methods").is_none());
        assert!(response.did_document.get("also_known_as").is_none());
    }

    #[test]
    fn invitation_lookup_can_return_privacy_preserving_empty_result() {
        let response = IdentityInvitationLookupOutcome {
            did: None,
            invite_token: None,
            privacy_preserving: true,
        };
        assert!(response.privacy_preserving);
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
}
