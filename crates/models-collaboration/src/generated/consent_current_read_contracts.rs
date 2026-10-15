// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/typed-current-result.schema.json
// sha256=fe2f5aa29f51e9d6243e74433c0ee027e4d15f04b8e01c3354a423f069b285a5
//
// Input: schemas/consent-operations.schema.json
// sha256=90c045bc2fadaa4481370039731723349f25656f7d89c24668082fe0a0a5fd48
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Bindings: tools/closed-model-bindings.json
// sha256=b381c96b67ab466bbb82afb539a5bf9f04c5809ca15139346195d6a0eed4e539

/// Counterpart:
/// `typed-current-result.schema.json#/$defs/consent_result/properties/selector/properties/kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentCurrentKind {
    #[serde(rename = "consent")]
    Consent,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/consent_result/properties/selector`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentCurrentSelector {
    pub kind: ConsentCurrentKind,
    pub consent_id: arkret_wire::ConsentId,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/consent_result`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentCurrentRow {
    pub selector: ConsentCurrentSelector,
    pub source_stream_ref: arkret_wire::CommitStreamRef,
    pub revision: arkret_wire::CurrentRevision,
    pub value: crate::consent_operations::ConsentValue,
}

/// Counterpart: `consent-operations.schema.json#/$defs/consent_current_read_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentCurrentReadRequestBody {
    pub holder_account_id: arkret_wire::AccountId,
    pub peer: crate::events_payloads::consent::ConsentPeer,
    pub consent_scope: arkret_wire::ConsentScope,
    pub audience_actor_id: arkret_wire::ActorId,
    pub nonce: String,
}

/// Counterpart: `consent-operations.schema.json#/$defs/consent_current_read_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentCurrentReadProof {
    pub verification_method: arkret_wire::DidUrl,
    pub jws: String,
}

/// Counterpart: `consent-operations.schema.json#/$defs/consent_current_read_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentCurrentReadOutcome {
    pub request_digest: arkret_wire::Hash,
    pub realm_id: arkret_wire::RealmId,
    pub governance_generation: u64,
    pub effective_stream_head: arkret_wire::CommitStreamHead,
    pub consents: Vec<ConsentCurrentRow>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub proof: ConsentCurrentReadProof,
}
