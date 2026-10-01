//! Read-receipt policy event payloads.

use crate::internal_prelude::*;
use crate::objects::read_receipts::{ReadReceiptDisclosure, ReadReceiptVisibility};
use crate::serde_absence::deserialize_non_null_optional;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/read_receipt_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadReceiptPolicyPayload {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_optional"
    )]
    pub disclosure: Option<ReadReceiptDisclosure>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_optional"
    )]
    pub visibility: Option<ReadReceiptVisibility>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_optional"
    )]
    pub scope_overrides_allowed: Option<bool>,
}

// `realm_archive_payload` uses `models::operation_payloads::RealmArchivePayload`.

impl ReadReceiptPolicyPayload {
    /// Preserve absent fields while enforcing the nonempty registered value.
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.disclosure.is_none()
            && self.visibility.is_none()
            && self.scope_overrides_allowed.is_none()
        {
            return Err(WireError::Protocol(
                "read receipt policy must set at least one field".to_owned(),
            ));
        }
        Ok(())
    }
}
