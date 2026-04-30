//! Contrix identity service API models.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use contrix_core::{Did, DidDocumentRef, Hash, IdentityResolveResponse, Proof, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod protocol {
    pub use contrix_core::{
        DidDocumentRef, IdentityDescription, IdentityDocumentResponse, IdentityLogResponse,
        IdentityReceiptsResponse, IdentityResolveRequest, IdentityResolveResponse,
        SubmitDidOperationRequest, SubmitDidOperationResponse,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IdentityMethod {
    Get,
    Post,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityEndpoint {
    pub operation_id: &'static str,
    pub method: IdentityMethod,
    pub path: &'static str,
    pub request_schema: &'static str,
    pub response_schema: &'static str,
}

pub const IDENTITY_ENDPOINTS: &[IdentityEndpoint] = &[
    IdentityEndpoint {
        operation_id: "cx.identity.describe_registry",
        method: IdentityMethod::Get,
        path: "/api/v1/identity/describe",
        request_schema: "IdentityDescribeRequest",
        response_schema: "IdentityDescription",
    },
    IdentityEndpoint {
        operation_id: "cx.identity.resolve",
        method: IdentityMethod::Post,
        path: "/api/v1/identity/resolve",
        request_schema: "IdentityResolveRequest",
        response_schema: "IdentityResolveResponse",
    },
    IdentityEndpoint {
        operation_id: "cx.identity.get_document",
        method: IdentityMethod::Get,
        path: "/api/v1/identity/document",
        request_schema: "IdentityDocumentQuery",
        response_schema: "IdentityDocumentResponse",
    },
    IdentityEndpoint {
        operation_id: "cx.identity.get_log",
        method: IdentityMethod::Get,
        path: "/api/v1/identity/log",
        request_schema: "IdentityLogQuery",
        response_schema: "IdentityLogResponse",
    },
    IdentityEndpoint {
        operation_id: "cx.identity.submit_did_operation",
        method: IdentityMethod::Post,
        path: "/api/v1/identity/submit-did-operation",
        request_schema: "SubmitDidOperationRequest",
        response_schema: "SubmitDidOperationResponse",
    },
    IdentityEndpoint {
        operation_id: "cx.identity.get_receipts",
        method: IdentityMethod::Get,
        path: "/api/v1/identity/receipts",
        request_schema: "IdentityReceiptsQuery",
        response_schema: "IdentityReceiptsResponse",
    },
];

pub fn identity_endpoints() -> &'static [IdentityEndpoint] {
    IDENTITY_ENDPOINTS
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: Did,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub verification_methods: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

impl DidDocument {
    pub fn to_ref(&self) -> DidDocumentRef {
        DidDocumentRef {
            did: self.id.clone(),
            document: serde_json::to_value(self).unwrap_or(Value::Null),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.verification_methods.is_empty() {
            return Err(contrix_core::Error::Protocol(
                "did document has no verification methods".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HandleBinding {
    pub handle: String,
    pub did: Did,
    pub proof_profile: HandleProofProfile,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub proof: Value,
    pub verified_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleProofProfile {
    DnsTxt,
    WellKnown,
    RegistryReceipt,
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
pub struct IdentityInvitationLookupRequest {
    pub medium: ThirdPartyIdentifierKind,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityInvitationLookupResponse {
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
    pub head_event_hash: Hash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
}

pub fn resolve_response_from_document(
    document: DidDocument,
    key_log_head: Option<KeyLogHead>,
) -> IdentityResolveResponse {
    IdentityResolveResponse {
        did_document: document.to_ref(),
        key_log_head: key_log_head.as_ref().map(|head| head.head_event_hash.clone()),
        seq: key_log_head.as_ref().map(|head| head.seq),
        receipts: key_log_head.map(|head| head.receipts).unwrap_or_default(),
        method_evidence: Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn endpoint_catalog_covers_identity_service() {
        let operations = identity_endpoints()
            .iter()
            .map(|endpoint| endpoint.operation_id)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(operations.contains("cx.identity.resolve"));
        assert!(operations.contains("cx.identity.submit_did_operation"));
        assert!(operations.contains("cx.identity.get_receipts"));
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
        assert_eq!(response.did_document.did, document.id);
    }

    #[test]
    fn invitation_lookup_can_return_privacy_preserving_empty_result() {
        let response = IdentityInvitationLookupResponse {
            did: None,
            invite_token: None,
            privacy_preserving: true,
        };
        assert!(response.privacy_preserving);
    }
}
