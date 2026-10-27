// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/erasure-receipt.schema.json
// sha256=20db9f3012cf1a34fede86383a90b16d005ac53aa6071a5f200dd72c9fae9eca
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Bindings: tools/closed-model-bindings.json
// sha256=3c8b4ad76a778828f23891614ed9c259161da8c53eb669c8825b9bb8a5da8ff2

/// Counterpart: `erasure-receipt.schema.json#/properties/peer_receipts/items`.
/// One per-peer fanout acknowledgement record maintained by the issuing server
/// (mirrors `erasure-receipt.schema.json` `peer_receipts[]`). One entry per peer
/// Station that ever held this Realm's content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ErasurePeerReceipt {
    pub peer_id: DidCoreId,
    pub status: ErasurePeerStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub acknowledged_at: Option<DateTime<Utc>>,
}
