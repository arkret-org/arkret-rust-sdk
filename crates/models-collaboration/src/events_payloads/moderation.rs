//! Moderation event payloads.

use arkret_wire::{
    ActorId, CurrentRevision, DeviceId, DidCoreId, EventId, Hash, NonEmptyString, ObjectRef,
    PolicyId, RealmId, Result, TrustDomainId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The sole v1 Organization moderation-policy family, keyed by Organization DID.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationModerationPolicyStatePayload {
    pub organization_id: DidCoreId,
    pub value: OrganizationModerationPolicyDocument,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationModerationPolicyDocument {
    pub policy_id: PolicyId,
    pub policy_scope: OrganizationModerationPolicyScope,
    pub rules: Vec<OrganizationModerationPolicyRule>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

impl OrganizationModerationPolicyDocument {
    pub fn validate(&self) -> Result<()> {
        self.policy_scope.validate()?;
        if self.rules.is_empty() {
            return Err(WireError::Protocol(
                "Organization moderation policy requires rules".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationModerationPolicyScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_ids: Option<Vec<RealmId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_to_owned_realms: Option<bool>,
}

impl OrganizationModerationPolicyScope {
    pub fn validate(&self) -> Result<()> {
        if self.realm_ids.is_none()
            && self.service_ids.is_none()
            && self.applies_to_owned_realms.is_none()
        {
            return Err(WireError::Protocol(
                "Organization moderation policy scope must name a target".to_owned(),
            ));
        }
        if self.realm_ids.as_ref().is_some_and(|ids| {
            ids.is_empty()
                || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len()
        }) || self.service_ids.as_ref().is_some_and(|ids| {
            ids.is_empty()
                || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len()
        }) {
            return Err(WireError::Protocol(
                "Organization moderation policy scope lists must be nonempty and unique".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationModerationPolicyRule {
    pub target: ModerationPolicyTarget,
    pub action: OrganizationModerationAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationModerationAction {
    DenyJoin,
    DenyRestrictedJoin,
    DenyInvite,
    DenyWrite,
    DenyFederation,
    QuarantineMessage,
    RequireReview,
    RedactOnAccept,
    ShadowCollapse,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModerationPolicyTarget {
    Actor {
        actor_id: ActorId,
    },
    Organization {
        organization_id: DidCoreId,
    },
    Device {
        device_id: DeviceId,
    },
    Service {
        service_id: DidCoreId,
    },
    Domain {
        domain: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        match_subdomains: Option<bool>,
    },
    TrustDomain {
        trust_domain: TrustDomainId,
    },
    ClaimSelector {
        claim_kind: NonEmptyString,
        issuer_id: DidCoreId,
    },
    MediaDigest {
        digest: Hash,
    },
    ContentLabel {
        label: NonEmptyString,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationDecisionLiftPayload {
    pub target_ref: ObjectRef,
    pub decision_ref: EventId,
    /// Typed revision of the moderation-target value the producer read. The
    /// compare is field-for-field.
    pub expected_revision: CurrentRevision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationDecisionPayload {
    pub target_ref: ObjectRef,
    pub decision: String,
    pub issuer_id: DidCoreId,
    pub request_canonical_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod moderation_decision_payload_tests {
    use super::*;

    #[test]
    fn optional_nullable_expiry_matches_formal_payload() {
        let base = serde_json::json!({
            "target_ref": "ak:event:ASo6zC5lXw3GKOieKXlXJYfKoQKng4sYXtvdUAaE9WRB",
            "decision": "quarantine",
            "issuer_id": "ak:did_core:webvh:z6mkfixtureissuer",
            "request_canonical_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });
        let absent: ModerationDecisionPayload = serde_json::from_value(base.clone()).unwrap();
        assert!(absent.expires_at.is_none());
        assert!(
            serde_json::to_value(&absent)
                .unwrap()
                .get("expires_at")
                .is_none()
        );

        let mut explicit_null = base.clone();
        explicit_null["expires_at"] = serde_json::Value::Null;
        let null_value: ModerationDecisionPayload = serde_json::from_value(explicit_null).unwrap();
        assert!(null_value.expires_at.is_none());

        let mut with_expiry = base;
        with_expiry["expires_at"] = serde_json::json!("2026-09-21T00:00:00.000Z");
        let dated: ModerationDecisionPayload = serde_json::from_value(with_expiry).unwrap();
        assert_eq!(
            serde_json::to_value(&dated).unwrap()["expires_at"],
            "2026-09-21T00:00:00.000Z"
        );
    }
}
