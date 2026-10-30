use std::collections::BTreeMap;

use arkret_wire::{Did, Hash, NonEmptyString, Result, WireError};
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
/// Wire boundary: `service-operation-dtos.schema.json#/$defs/IdentityResolveRequestBody`.
#[serde(deny_unknown_fields)]
pub struct IdentityResolveRequestBody {
    pub did: Did,
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
        control_key_digest: Hash,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
/// Wire boundary: `service-operation-dtos.schema.json#/$defs/IdentityResolveResponseBody`.
#[serde(deny_unknown_fields)]
pub struct IdentityResolveResponseBody {
    pub did_document: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_log_head: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
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
            "control_key_digest": format!("sha256:{}", "2".repeat(64)),
        });
        assert!(serde_json::from_value::<IdentityMethodEvidence>(complete.clone()).is_ok());

        let mut missing = complete.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("control_key_digest");
        assert!(serde_json::from_value::<IdentityMethodEvidence>(missing).is_err());

        let mut old_mirror = complete.clone();
        old_mirror["log_head_digest"] = serde_json::json!(format!("sha256:{}", "1".repeat(64)));
        assert!(serde_json::from_value::<IdentityMethodEvidence>(old_mirror).is_err());

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
#[serde(deny_unknown_fields)]
pub struct IdentityDocumentView {
    pub did_document: BTreeMap<String, Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub normalized_view: Option<BTreeMap<String, Value>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub method_evidence: Option<crate::identity_resolution::ResolutionMethodHistoryEvidence>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub cached_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidOperationSubmitRequestBody {
    pub did: Did,
    pub did_method: DidMethodName,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_event_digest: Option<Hash>,
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
#[serde(deny_unknown_fields)]
pub struct DidOperationSubmitResponseBody {
    pub status: DidOperationSubmitStatus,
    pub did: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    pub operation_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub receipts: Vec<IdentityReceipt>,
}

impl DidOperationSubmitResponseBody {
    /// Bind an authenticated registry acceptance to the frozen native request.
    pub fn validate_accepted_for_request(
        &self,
        request: &DidOperationSubmitRequestBody,
    ) -> Result<()> {
        if self.status == DidOperationSubmitStatus::Pending {
            return Err(WireError::Protocol(
                "pending native operation is not an acceptance".to_owned(),
            ));
        }
        self.validate_for_request(request)
    }

    /// Bind the response to the request without promoting pending to accepted.
    pub fn validate_for_request(&self, request: &DidOperationSubmitRequestBody) -> Result<()> {
        request.validate()?;
        let version = request
            .operation
            .get("versionId")
            .and_then(Value::as_str)
            .filter(|version| !version.is_empty())
            .ok_or_else(|| {
                WireError::Protocol("accepted operation has no native version".to_owned())
            })?;
        let native_seq = version
            .split_once('-')
            .and_then(|(sequence, _)| sequence.parse::<u64>().ok());
        if request.did_method != DidMethodName::Webvh
            || self.did != request.did
            || self.operation_ref != format!("{}?versionId={version}", request.did)
            || native_seq.is_none()
            || self.sequence != native_seq
            || request
                .sequence
                .is_some_and(|sequence| Some(sequence) != native_seq)
        {
            return Err(WireError::Protocol(
                "registry acceptance differs from frozen native operation".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
/// Wire boundary: `service-operation-dtos.schema.json#/$defs/IdentityReceiptListResponseBody`.
#[serde(deny_unknown_fields)]
pub struct IdentityReceiptListResponseBody {
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
/// Wire boundary: `service-operation-dtos.schema.json#/$defs/IdentityLogListResponseBody`.
#[serde(deny_unknown_fields)]
pub struct IdentityLogListResponseBody {
    pub did: Did,
    pub method: DidMethodUri,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_history: Option<bool>,
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub entries: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[cfg(test)]
mod did_operation_tests {
    use super::*;

    fn native_request() -> DidOperationSubmitRequestBody {
        DidOperationSubmitRequestBody {
            did: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            did_method: DidMethodName::Webvh,
            sequence: Some(0),
            previous_event_digest: None,
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
    fn accepted_operation_rejects_substituted_native_version_and_sequence() {
        let mut request = native_request();
        request.sequence = Some(1);
        let mut outcome = DidOperationSubmitResponseBody {
            status: DidOperationSubmitStatus::Accepted,
            did: request.did.clone(),
            accepted_at: chrono::Utc::now(),
            sequence: Some(1),
            operation_ref: format!("{}?versionId=1-zabc", request.did),
            receipts: Vec::new(),
        };
        outcome.validate_accepted_for_request(&request).unwrap();
        outcome.status = DidOperationSubmitStatus::Pending;
        outcome.validate_for_request(&request).unwrap();
        assert!(outcome.validate_accepted_for_request(&request).is_err());
        outcome.status = DidOperationSubmitStatus::Accepted;
        outcome.operation_ref = format!("{}?versionId=1-zother", request.did);
        assert!(outcome.validate_accepted_for_request(&request).is_err());
        outcome.operation_ref = format!("{}?versionId=1-zabc", request.did);
        outcome.sequence = Some(2);
        assert!(outcome.validate_accepted_for_request(&request).is_err());
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

#[cfg(test)]
mod document_view_contract_tests {
    use serde_json::json;

    use super::IdentityDocumentView;

    #[test]
    fn document_view_matches_the_closed_read_projection() {
        let value = json!({"did_document":{"id":"did:web:example.com"},"normalized_view":{"principal_id":"example"},"cached_at":"2026-10-24T00:00:00.000Z"});
        let view: IdentityDocumentView = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(view).unwrap(), value);
        for (name, extra) in [
            ("sequence", json!(1)),
            ("receipts", json!([])),
            ("normalized_view", json!(null)),
            ("method_evidence", json!(null)),
        ] {
            let mut changed = value.clone();
            changed[name] = extra;
            assert!(
                serde_json::from_value::<IdentityDocumentView>(changed).is_err(),
                "{name}"
            );
        }
    }
}

#[cfg(test)]
mod identity_list_contract_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn native_history_and_receipt_lists_require_their_registered_members() {
        let complete =
            json!({"did":"did:web:example.test","method":"did:web","entries":[],"has_more":false});
        let value: IdentityLogListResponseBody = serde_json::from_value(complete.clone()).unwrap();
        assert_eq!(serde_json::to_value(value).unwrap(), complete);
        for field in ["did", "method", "entries", "has_more"] {
            let mut missing = complete.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<IdentityLogListResponseBody>(missing).is_err(),
                "{field}"
            );
        }
        let mut extra = complete;
        extra["unexpected"] = json!(true);
        assert!(serde_json::from_value::<IdentityLogListResponseBody>(extra).is_err());
        assert!(
            serde_json::from_value::<IdentityReceiptListResponseBody>(json!({"receipts":[]}))
                .is_ok()
        );
        assert!(serde_json::from_value::<IdentityReceiptListResponseBody>(json!({})).is_err());
        assert!(
            serde_json::from_value::<IdentityReceiptListResponseBody>(
                json!({"receipts":[],"unexpected":true})
            )
            .is_err()
        );
    }
}
