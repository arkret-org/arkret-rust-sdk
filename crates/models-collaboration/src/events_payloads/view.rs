//! View event payloads.

use crate::internal_prelude::*;
use crate::objects::queries::View;

fn schema_violation<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Protocol(format!(
        "schema_violation: {}",
        message.into()
    )))
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/view_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<ObjectSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_id: Option<ViewId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<Patch>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/view_reconcile_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ViewReconcilePayload {
    pub view_id: ViewId,
    pub definition: View,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewReconcilePayloadWire {
    view_id: ViewId,
    definition: View,
}

impl ViewReconcilePayload {
    pub fn validate(&self) -> Result<()> {
        if self.definition.id != self.view_id {
            return schema_violation("reconciled View definition id must equal payload view_id");
        }
        self.definition.validate()
    }
}

impl<'de> Deserialize<'de> for ViewReconcilePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ViewReconcilePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            view_id: wire.view_id,
            definition: wire.definition,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}
