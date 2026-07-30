use arkret_wire::serde_helpers::serialize_optional_canonical_timestamp;
use arkret_wire::{Did, Error, PlaintextDataClassKind, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Closed machine-checkable class of plaintext / reversible-derived content a
/// service may receive
/// (`event-payload.schema.json#/$defs/plaintext_data_class`).
/// Plaintext exposure level for a declared service
/// (`plaintext_visible_services_payload` item `visibility`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaintextServiceVisibility {
    PrivatePlaintext,
    DerivedPlaintext,
}

/// One declared plaintext-visible service
/// (`plaintext_visible_services_payload` `services[]` item).
///
/// The spec item is `additionalProperties:true`, so this struct does NOT use
/// `deny_unknown_fields`; the required fields are strongly typed and any future
/// extension keys remain wire-compatible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaintextVisibleService {
    pub service_id: Did,
    pub service_kind: String,
    pub purposes: Vec<String>,
    pub data_classes: Vec<PlaintextDataClassKind>,
    pub visibility: PlaintextServiceVisibility,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl PlaintextVisibleService {
    pub fn new(
        service_id: Did,
        service_kind: impl Into<String>,
        data_classes: Vec<PlaintextDataClassKind>,
        purposes: Vec<String>,
        visibility: PlaintextServiceVisibility,
    ) -> Self {
        Self {
            service_id,
            service_kind: service_kind.into(),
            data_classes,
            purposes,
            visibility,
            expires_at: None,
        }
    }
}

/// Strong type for `ak.realm.plaintext_visible_services` payloads
/// (`event-payload.schema.json#/$defs/plaintext_visible_services_payload`).
///
/// `{ services: [...] }`, top-level `additionalProperties:false`. Declares the
/// services allowed to receive plaintext / reversible-derived content outside
/// the E2EE boundary.
///
/// Note: like [`HistoryVisibilityPayload`], the SDK kind→def resolver currently
/// routes `ak.realm.plaintext_visible_services` to `generic_standard_payload`;
/// this type still gives compile-time field safety, and the guard test
/// validates directly against the named def schema_ref.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaintextVisibleServicesPayload {
    pub services: Vec<PlaintextVisibleService>,
}

impl PlaintextVisibleServicesPayload {
    pub fn new(services: Vec<PlaintextVisibleService>) -> Self {
        Self { services }
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|err| {
            Error::Protocol(format!(
                "plaintext visible services payload serialize: {err}"
            ))
        })
    }
}
