use super::*;
use crate::DidKeyLogEntry;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityResolveRequestBody {
    pub did: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_evidence_kinds: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityDocumentView {
    pub did_document: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_event_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<IdentityReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityLogListOutcome {
    #[serde(default)]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub events: Vec<DidKeyLogEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DidOperationSubmitRequestBody {
    pub did: Did,
    pub did_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_event_digest: Option<Hash>,
    pub operation: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_context: Option<BTreeMap<String, Value>>,
    #[serde(default)]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityReceiptListOutcome {
    #[serde(default)]
    pub receipts: Vec<IdentityReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_met: Option<bool>,
}
