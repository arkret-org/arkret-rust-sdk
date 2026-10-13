//! Object and productivity schema artifact counterparts.

use std::collections::BTreeMap;

use arkret_models_crypto::encrypted_envelope::EncryptedEnvelope;
use arkret_wire::SchemaId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::ContentBlock;
use crate::objects::productivity::{
    BlindIndexQuery, EncryptedIndexManifest, PinAddPayload, PinRemovePayload, PinReorderPayload,
    SearchPolicy,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Display {
    pub short_name: String,
    pub color_token: String,
    pub symbol: DisplaySymbol,
}

/// Counterpart for `spec/v1/artifacts/schemas/morph-customer-risk.schema.json#/properties/fields`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MorphCustomerRiskFields {
    pub status: String,
    pub severity: String,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphCustomerRisk {
    pub morph_kind: String,
    pub fields: MorphCustomerRiskFields,
}

impl MorphCustomerRisk {
    pub const SCHEMA: &'static str = SchemaId::MORPH_CUSTOMER_RISK_V1;
}

/// Counterpart for `spec/v1/artifacts/schemas/pin.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Pin {
    PinAddPayload(Box<PinAddPayload>),
    PinRemovePayload(PinRemovePayload),
    PinReorderPayload(PinReorderPayload),
}

impl Pin {
    pub const SCHEMA: &'static str = SchemaId::PIN_V1;
}

/// Counterpart for `spec/v1/artifacts/schemas/search-service.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StationSearchArtifacts {
    EncryptedIndexManifest(EncryptedIndexManifest),
    BlindIndexQuery(BlindIndexQuery),
    SearchPolicy(SearchPolicy),
}

impl StationSearchArtifacts {
    pub const SCHEMA: &'static str = SchemaId::SEARCH_SERVICE_V1;
}

include!("generated/object_facets_contracts.rs");
