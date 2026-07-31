//! Object and productivity schema artifact counterparts.

use std::collections::BTreeMap;

use arkret_wire::SchemaId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::objects::productivity::{
    BlindIndexQuery, EncryptedIndexManifest, PersonalProductivityValue, PinAddPayload,
    PinRemovePayload, PinReorderPayload, ReminderValue, RsvpSetPayload, SavedItemValue,
    ScheduledSendValue, SearchPolicy, SnoozeValue,
};

/// Counterpart for `spec/v1/artifacts/schemas/circle.schema.json#/$defs/display`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplaySymbol {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emoji: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glyph: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Display {
    pub short_name: String,
    pub color_token: String,
    pub symbol: DisplaySymbol,
}

/// Counterpart for `spec/v1/artifacts/schemas/strand.schema.json#/$defs/strand_track`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandTrack {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_primary: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, Value>>,
}

/// Counterpart for `spec/v1/artifacts/schemas/strand.schema.json#/$defs/metadata_fields`.
pub type MetadataFields = BTreeMap<String, Value>;

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

/// Counterpart for `spec/v1/artifacts/schemas/morph-customer-risk-ext.schema.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MorphCustomerRiskExtPriority {
    Low,
    Normal,
    High,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MorphCustomerRiskExtFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<MorphCustomerRiskExtPriority>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MorphCustomerRiskExt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<MorphCustomerRiskExtFields>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl MorphCustomerRiskExt {
    pub const SCHEMA: &'static str = SchemaId::MORPH_CUSTOMER_RISK_EXT_V1;
}

/// Counterpart for `spec/v1/artifacts/schemas/morph.schema.json#/$defs/facet_config`.
pub type FacetConfig = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/personal-productivity.schema.json`.
pub type PersonalProductivity = PersonalProductivityValue;

/// Counterpart for `spec/v1/artifacts/schemas/personal-productivity.schema.json#/$defs/reminder`.
pub type Reminder = ReminderValue;

/// Counterpart for `spec/v1/artifacts/schemas/personal-productivity.schema.json#/$defs/saved_item`.
pub type SavedItem = SavedItemValue;

/// Counterpart for
/// `spec/v1/artifacts/schemas/personal-productivity.schema.json#/$defs/scheduled_send`.
pub type ScheduledSend = ScheduledSendValue;

/// Counterpart for `spec/v1/artifacts/schemas/personal-productivity.schema.json#/$defs/snooze`.
pub type Snooze = SnoozeValue;

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

/// Counterpart for `spec/v1/artifacts/schemas/query.schema.json`.
pub type Query = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/relation.schema.json#/$defs/ref`.
pub type Ref = String;

/// Counterpart for `spec/v1/artifacts/schemas/rsvp.schema.json`.
pub type Rsvp = RsvpSetPayload;

/// Counterpart for `spec/v1/artifacts/schemas/search-service.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SearchService {
    EncryptedIndexManifest(EncryptedIndexManifest),
    BlindIndexQuery(BlindIndexQuery),
    SearchPolicy(SearchPolicy),
}

impl SearchService {
    pub const SCHEMA: &'static str = SchemaId::SEARCH_SERVICE_V1;
}
