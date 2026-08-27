use std::collections::BTreeMap;

use arkret_wire::{DidFullId, Hash, NonEmptyString, Result, WireError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifacts_device_identity::{IdentityReceipt, IdentityReceiptEvidence};

/// Closed DID method name used by method-adapter dispatch.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DidMethodName {
    Webvh,
    Web,
}

impl DidMethodName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Webvh => "webvh",
            Self::Web => "web",
        }
    }
}

/// Closed absolute DID method identifier returned by history endpoints.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DidMethodUri {
    #[serde(rename = "did:webvh")]
    Webvh,
    #[serde(rename = "did:web")]
    Web,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityResolveRequestBody {
    pub did: DidFullId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_evidence_kinds: Vec<IdentityMethodEvidenceKind>,
}

/// Closed method-native evidence kinds a caller may require from resolution.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMethodEvidenceKind {
    DidWebvh,
}

/// Method-native evidence emitted only after the corresponding resolver has
/// verified the complete history that produced these pins.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityMethodEvidence {
    DidWebvh {
        version_id: NonEmptyString,
        log_head_digest: Hash,
        control_key_digest: Hash,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityResolveOutcome {
    pub did_document: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_log_head: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_evidence: Option<IdentityMethodEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub receipts: Vec<IdentityReceipt>,
}

#[cfg(test)]
mod identity_resolve_tests {
    use super::*;

    #[test]
    fn webvh_method_evidence_is_closed_and_requires_all_pins() {
        let complete = serde_json::json!({
            "kind": "did_webvh",
            "version_id": "2-zQmHead",
            "log_head_digest": format!("sha256:{}", "1".repeat(64)),
            "control_key_digest": format!("sha256:{}", "2".repeat(64)),
        });
        assert!(serde_json::from_value::<IdentityMethodEvidence>(complete.clone()).is_ok());

        let mut missing = complete.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("control_key_digest");
        assert!(serde_json::from_value::<IdentityMethodEvidence>(missing).is_err());

        let mut mixed = complete;
        mixed["document_key"] = Value::String("not-method-evidence".to_owned());
        assert!(serde_json::from_value::<IdentityMethodEvidence>(mixed).is_err());
        assert!(
            serde_json::from_value::<IdentityMethodEvidence>(serde_json::json!({
                "kind": "did_web"
            }))
            .is_err()
        );
    }

    #[test]
    fn requested_evidence_kind_is_closed() {
        assert!(
            serde_json::from_value::<IdentityResolveRequestBody>(serde_json::json!({
                "did": "did:webvh:z6mkfixture:example.com",
                "requested_evidence_kinds": ["did_webvh"]
            }))
            .is_ok()
        );
        assert!(
            serde_json::from_value::<IdentityResolveRequestBody>(serde_json::json!({
                "did": "did:webvh:z6mkfixture:example.com",
                "requested_evidence_kinds": ["caller_defined"]
            }))
            .is_err()
        );
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityDocumentView {
    pub did_document: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_event_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub receipts: Vec<IdentityReceipt>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidOperationSubmitRequestBody {
    pub did: DidFullId,
    pub did_method: DidMethodName,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_event_digest: Option<Hash>,
    pub operation: BTreeMap<String, Value>,
}

impl DidOperationSubmitRequestBody {
    /// Validate wrapper constraints before dispatching the complete native
    /// operation to a DID-method adapter. Controller/update/recovery proof
    /// verification remains entirely method-native.
    pub fn validate(&self) -> Result<()> {
        if self.did_method.as_str() != self.did.method() {
            return Err(WireError::Protocol(format!(
                "DID operation did_method {:?} does not match DID method {:?}",
                self.did_method,
                self.did.method()
            )));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidOperationSubmitStatus {
    Accepted,
    Duplicate,
    Pending,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DidOperationSubmitOutcome {
    pub status: DidOperationSubmitStatus,
    pub did: DidFullId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_event_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub receipts: Vec<IdentityReceipt>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityReceiptListOutcome {
    #[serde(default)]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub receipts: Vec<IdentityReceiptEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_met: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityLogListOutcome {
    pub did: DidFullId,
    pub method: DidMethodUri,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_history: Option<bool>,
    #[serde(default)]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub entries: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}

#[cfg(test)]
mod did_operation_tests {
    use super::*;

    fn native_request() -> DidOperationSubmitRequestBody {
        DidOperationSubmitRequestBody {
            did: DidFullId::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            did_method: DidMethodName::Webvh,
            seq: Some(0),
            prev_event_digest: None,
            operation: BTreeMap::from([
                ("versionId".to_owned(), Value::String("1-zabc".to_owned())),
                (
                    "state".to_owned(),
                    serde_json::json!({
                        "id": "did:webvh:z6mkfixture:alice.example"
                    }),
                ),
            ]),
        }
    }

    #[test]
    fn did_operation_request_validates_matching_method() {
        let mut request = native_request();
        request.validate().unwrap();

        request.did_method = DidMethodName::Web;
        assert!(request.validate().is_err());
    }

    #[test]
    fn did_operation_wrapper_rejects_method_neutral_authorization_fields() {
        let mut value = serde_json::to_value(native_request()).unwrap();
        value["proofs"] = serde_json::json!([]);
        assert!(serde_json::from_value::<DidOperationSubmitRequestBody>(value).is_err());

        let mut value = serde_json::to_value(native_request()).unwrap();
        value["policy_context"] = serde_json::json!({"purpose": "did_update"});
        assert!(serde_json::from_value::<DidOperationSubmitRequestBody>(value).is_err());
    }
}
