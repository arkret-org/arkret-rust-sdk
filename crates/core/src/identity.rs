//! Arkret identity surface models and helpers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Did, Hash, IdentityReceipt, IdentityResolveOutcome, Proof, Result};

/// §3.2.1 deterministic primary-handle selection, `claim_digest`, and
/// §3.8.2 mention/subject rendering. wasm-safe, dependency-free helpers
/// shared by inkson / sodmin / soland / cotest (SOD-05-001 / SPEC-CR-019).
pub mod primary_handle;

// DID Document data shapes + did:web helpers migrated to
// arkret-models-identity (1B-a: the top-level `core/src/identity.rs`
// counterpart of the earlier `core/src/models/identity.rs` move). Core
// re-exports them so `arkret_core::identity::*` (and `arkret::identity::*`)
// stay unchanged for existing consumers.
pub use arkret_models_identity::{
    DID_WEB_MAX_DOCUMENT_BYTES, DID_WEBVH_V1_METHOD, DidDocument, HandleAttestation,
    did_web_document_url, principal_control_realm_id,
};

pub fn validate_did_webvh_v1_method(parameters: &Value) -> Result<()> {
    if parameters.get("method").and_then(Value::as_str) != Some(DID_WEBVH_V1_METHOD) {
        return Err(crate::Error::Protocol(
            "unsupported_did_method: expected did:webvh:1.0".to_owned(),
        ));
    }
    Ok(())
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
    use std::collections::BTreeMap;

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
            updated_at: Some(Utc::now()),
            raw_properties: BTreeMap::new(),
        };
        document.validate().unwrap();

        let response = resolve_response_from_document(document.clone(), None);
        assert_eq!(response.did_document["id"], document.id.as_str());
        assert!(response.did_document.contains_key("verificationMethod"));
        assert!(response.did_document.contains_key("alsoKnownAs"));
        assert!(response.did_document.contains_key("updated"));
        assert!(!response.did_document.contains_key("verification_methods"));
        assert!(!response.did_document.contains_key("also_known_as"));
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

    #[test]
    fn did_web_url_supports_encoded_ports_and_paths() {
        let did = Did::new("did:web:example.test%3A8443:users:alice").unwrap();
        assert_eq!(
            did_web_document_url(&did).unwrap(),
            "https://example.test:8443/users/alice/did.json"
        );
    }
}
