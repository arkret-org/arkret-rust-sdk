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
    pub fn validate(&self) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn policy_value_matches_the_closed_registered_payload() {
        for value in [
            json!({"disclosure":"required"}),
            json!({"visibility":"members"}),
            json!({"scope_overrides_allowed":false}),
        ] {
            let policy: ReadReceiptPolicyPayload = serde_json::from_value(value.clone()).unwrap();
            policy.validate().unwrap();
            assert_eq!(serde_json::to_value(policy).unwrap(), value);
        }
        for value in [
            json!({}),
            json!({"visibility":"track_scoped"}),
            json!({"disclosure":"on"}),
            json!({"disclosure":null}),
            json!({"visibility":null}),
            json!({"scope_overrides_allowed":null}),
            json!({"realm_id":"extra","disclosure":"required"}),
        ] {
            assert!(
                serde_json::from_value::<ReadReceiptPolicyPayload>(value)
                    .map(|policy| policy.validate().is_err())
                    .unwrap_or(true)
            );
        }
    }
}
