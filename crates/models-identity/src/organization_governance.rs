//! Existing Organization DID metadata; no delegation identity or scope mirror.

use std::collections::BTreeSet;

use arkret_wire::{DidCoreId, DidUrl, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationGovernanceThreshold {
    pub min_signature_count: u64,
    pub allowed_kids: Vec<DidUrl>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationServiceDelegation {
    pub service_id: DidCoreId,
    pub purposes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationGovernance {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub threshold: Option<OrganizationGovernanceThreshold>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub delegations: Option<Vec<OrganizationServiceDelegation>>,
}

fn invalid() -> WireError {
    WireError::Protocol(
        "Organization governance metadata has invalid threshold, delegation identity or validity"
            .into(),
    )
}

impl OrganizationGovernance {
    pub fn validate(&self) -> Result<()> {
        if let Some(threshold) = &self.threshold {
            let methods = threshold.allowed_kids.iter().collect::<BTreeSet<_>>();
            if threshold.min_signature_count == 0
                || usize::try_from(threshold.min_signature_count)
                    .ok()
                    .is_none_or(|n| n > methods.len())
                || methods.len() != threshold.allowed_kids.len()
            {
                return Err(invalid());
            }
        }
        let mut services = BTreeSet::new();
        for delegation in self.delegations.iter().flatten() {
            let purposes = delegation.purposes.iter().collect::<BTreeSet<_>>();
            if !services.insert(&delegation.service_id)
                || purposes.is_empty()
                || purposes.len() != delegation.purposes.len()
                || purposes.iter().any(|purpose| purpose.is_empty())
                || delegation
                    .expires_at
                    .is_some_and(|end| end <= delegation.not_before)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    /// Read the same retained normalized extension, never a current service row.
    pub fn from_document(document: &crate::DidDocument) -> Result<Option<Self>> {
        Self::from_normalized(&crate::normalized_did_document(document)?)
    }

    pub(crate) fn from_normalized(document: &Value) -> Result<Option<Self>> {
        let Some(value) = document
            .get("extensions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|row| row.get("name").and_then(Value::as_str) == Some("arkret_governance"))
            .and_then(|row| row.get("value"))
        else {
            return Ok(None);
        };
        let governance: Self = serde_json::from_value(value.clone())?;
        governance.validate()?;
        Ok(Some(governance))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn only_registered_governance_is_closed_and_other_extensions_are_lossless() {
        let raw = json!({"id":"did:web:organization.example",
            "arkret_governance":{"delegations":[]},
            "vendorMetadata":{"opaque":["preserved", 7]}});
        let document: crate::DidDocument = serde_json::from_value(raw.clone()).unwrap();
        let normalized = crate::normalized_did_document(&document).unwrap();
        assert_eq!(
            normalized["extensions"],
            json!([
                {"name":"arkret_governance", "value":{"delegations":[]}},
                {"name":"vendorMetadata", "value":raw["vendorMetadata"]}
            ])
        );
        let projection: crate::DidDocument = serde_json::from_value(normalized.clone()).unwrap();
        assert_eq!(
            crate::normalized_did_document(&projection).unwrap(),
            normalized
        );
        let mut unknown = raw;
        unknown["arkret_governance"]["scope"] = json!("all");
        let document: crate::DidDocument = serde_json::from_value(unknown).unwrap();
        assert!(crate::normalized_did_document(&document).is_err());
    }

    #[test]
    fn canonical_governance_names_reject_old_key_aliases() {
        let value = json!({"threshold":{"min_signature_count":1,
            "allowed_kids":["did:web:organization.example#governance"]}, "delegations":[]});
        let governance: OrganizationGovernance = serde_json::from_value(value.clone()).unwrap();
        governance.validate().unwrap();
        assert_eq!(serde_json::to_value(governance).unwrap(), value);
        let mut legacy = value.clone();
        let object = legacy.as_object_mut().unwrap();
        let delegations = object.remove("delegations").unwrap();
        object.insert("service_delegations".into(), delegations);
        assert!(serde_json::from_value::<OrganizationGovernance>(legacy).is_err());
        let mut legacy = value;
        let threshold = legacy["threshold"].as_object_mut().unwrap();
        let kids = threshold.remove("allowed_kids").unwrap();
        threshold.insert("allowed_verification_methods".into(), kids);
        assert!(serde_json::from_value::<OrganizationGovernance>(legacy).is_err());
    }

    #[test]
    fn delegation_keeps_original_four_fields_and_unique_service() {
        let row = json!({"service_id":"ak:did_core:web:station.example",
            "purposes":["principal_control_realm_bootstrap"],
            "not_before":"2026-11-16T00:00:00.000Z"});
        let value = json!({"delegations":[row]});
        let governance: OrganizationGovernance = serde_json::from_value(value.clone()).unwrap();
        governance.validate().unwrap();
        assert_eq!(serde_json::to_value(&governance).unwrap(), value);
        for member in ["scope", "id", "station_id"] {
            let mut changed = value.clone();
            changed["delegations"][0][member] = json!("unexpected");
            assert!(serde_json::from_value::<OrganizationGovernance>(changed).is_err());
        }
        let mut duplicate = value.clone();
        duplicate["delegations"]
            .as_array_mut()
            .unwrap()
            .push(value["delegations"][0].clone());
        assert!(
            serde_json::from_value::<OrganizationGovernance>(duplicate)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut expired = value.clone();
        expired["delegations"][0]["expires_at"] = json!("2026-11-15T00:00:00.000Z");
        assert!(
            serde_json::from_value::<OrganizationGovernance>(expired)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut null = value;
        null["delegations"][0]["expires_at"] = Value::Null;
        assert!(serde_json::from_value::<OrganizationGovernance>(null).is_err());
    }
}
