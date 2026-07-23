use std::collections::BTreeMap;

use arkret_wire::{Did, Error, Hash, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifacts_device_identity::IdentityReceipt;
use crate::identity_key_log::DidKeyLogEntry;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityDescription {
    pub service_id: Did,
    pub registry_mode: String,
    #[serde(default)]
    pub supported_receipts: Vec<String>,
    pub protocol_version: String,
    #[serde(default)]
    pub profiles: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityResolveRequestBody {
    pub did: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_evidence_kinds: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityResolveOutcome {
    pub did_document: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_log_head: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<IdentityReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityDocumentView {
    pub did_document: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_event_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<IdentityReceipt>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidOperationSubmitRequestBody {
    pub did: Did,
    pub did_method: String,
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
        if self.did_method != self.did.method() {
            return Err(Error::Protocol(format!(
                "DID operation did_method {:?} does not match DID method {:?}",
                self.did_method,
                self.did.method()
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DidOperationSubmitOutcome {
    pub status: String,
    pub did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_event_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<IdentityReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityReceiptListOutcome {
    #[serde(default)]
    pub receipts: Vec<IdentityReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_met: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityLogListOutcome {
    #[serde(default)]
    pub events: Vec<DidKeyLogEntry>,
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
            did: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            did_method: "webvh".to_owned(),
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

        request.did_method = "web".to_owned();
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
