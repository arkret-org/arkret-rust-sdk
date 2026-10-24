//! Read-receipt policy event payloads.

use crate::internal_prelude::*;
use crate::objects::read_receipts::{ReadReceiptDisclosure, ReadReceiptVisibility};
use crate::serde_absence::deserialize_non_null_optional;

// `realm_archive_payload` uses `models::operation_payloads::RealmArchivePayload`.

impl ReadReceiptPolicyPayload {
    /// Resolve defaults for this scope only after its current/absence proof succeeds.
    pub fn resolved(&self) -> crate::objects::read_receipts::ReadReceiptPolicy {
        crate::objects::read_receipts::ReadReceiptPolicy {
            disclosure: self.disclosure.unwrap_or_default(),
            visibility: self.visibility.unwrap_or_default(),
        }
    }

    /// Preserve absent fields while enforcing the nonempty registered value.
    pub fn validate(&self) -> Result<()> {
        if self.disclosure.is_none() && self.visibility.is_none() {
            return Err(WireError::Protocol(
                "read receipt policy must set at least one field".to_owned(),
            ));
        }
        Ok(())
    }
}

impl CurrentScopeReadReceiptPolicy {
    /// Enforce the selector/source binding after current proof verification.
    pub fn validate(&self) -> Result<()> {
        let CurrentSelector::ScopeReadReceiptPolicy { scope_ref } = &self.selector else {
            return Err(WireError::Protocol(
                "read receipt policy selector required".to_owned(),
            ));
        };
        if !matches!(scope_ref, ScopeRef::Realm { .. } | ScopeRef::Circle { .. })
            || &self.source_stream_ref.scope_ref() != scope_ref
        {
            return Err(WireError::Protocol(
                "read receipt policy scope/source mismatch".to_owned(),
            ));
        }
        self.value.validate()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn current_binds_the_exact_scope_and_resolves_only_its_own_defaults() {
        let realm = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";
        let scope = json!({"kind":"circle","realm_id":realm,"circle_id":"ak:circle:AUD2WOhX-Xh47vBHtRJPMRfXRQXGiOWQqOrJGJnE8CaI"});
        let wire = json!({
            "selector":{"kind":"scope_read_receipt_policy","scope_ref":scope},
            "source_stream_ref":scope,
            "revision":{"commit_id":"ak:realm_commit:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5","stream_position":1},
            "value":{"visibility":"private"}
        });
        let current: CurrentScopeReadReceiptPolicy = serde_json::from_value(wire.clone()).unwrap();
        current.validate().unwrap();
        assert_eq!(serde_json::to_value(&current).unwrap(), wire);
        assert_eq!(
            current.value.resolved().disclosure,
            ReadReceiptDisclosure::Optional
        );
        assert_eq!(
            current.value.resolved().visibility,
            ReadReceiptVisibility::Private
        );
        let mut wrong_stream = wire.clone();
        wrong_stream["source_stream_ref"] = json!({"kind":"realm","realm_id":realm});
        let current: CurrentScopeReadReceiptPolicy = serde_json::from_value(wrong_stream).unwrap();
        assert!(current.validate().is_err());
        let mut empty = wire;
        empty["value"] = json!({});
        let current: CurrentScopeReadReceiptPolicy = serde_json::from_value(empty).unwrap();
        assert!(current.validate().is_err());
    }

    #[test]
    fn policy_value_matches_the_closed_registered_payload() {
        for value in [
            json!({"disclosure":"required"}),
            json!({"visibility":"members"}),
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
            json!({"scope_overrides_allowed":false}),
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

include!("generated/read_receipt_contracts.rs");
