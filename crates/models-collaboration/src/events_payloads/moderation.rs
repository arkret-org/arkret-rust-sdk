//! Moderation event payloads.

use arkret_wire::{
    ActorId, CurrentRevision, DeviceId, DidCoreId, DidUrl, EventId, Hash, NonEmptyString,
    ObjectRef, PolicyId, RealmId, Result, ScopeRef, TrustDomainId, WireError,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ModerationEvidencePackage {
    pub target_refs: Vec<ObjectRef>,
    pub encryption: String,
    pub recipient_public_key_ref: DidUrl,
    pub encrypted_to_kid: DidUrl,
    pub ciphertext: String,
    pub ciphertext_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_digest: Option<Hash>,
    pub reporter_signature: String,
}

impl ModerationEvidencePackage {
    pub fn validate_for_target(&self, target_ref: &str) -> Result<()> {
        if self.target_refs.len() != 1
            || self.target_refs[0] != target_ref
            || self.encryption.trim().is_empty()
            || self.ciphertext.is_empty()
            || self.reporter_signature.trim().is_empty()
            || self.recipient_public_key_ref != self.encrypted_to_kid
        {
            return Err(WireError::Protocol(
                "moderation evidence does not bind the target and recipient".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Service receipt for one observed Event. Its durable existence is proven by
/// resolving the Event's exact [`arkret_wire::CommittedEventRef`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct FrankingProof {
    pub realm_id: RealmId,
    pub event_id: EventId,
    pub received_by: DidCoreId,
    pub verification_method: DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub replay_nonce: String,
    pub signature: String,
}

impl FrankingProof {
    pub const SIGNATURE_DOMAIN: &'static str = "ak.franking_proof.signature.v1";

    /// Return the exact seven-field RFC 8785 transcript signed by the
    /// receiving service.
    ///
    /// `signature` is the only payload member excluded. The domain is a
    /// sibling of the six payload fields rather than a wrapper: the formal
    /// transcript is
    /// `{domain,realm_id,event_id,received_by,verification_method,received_at,replay_nonce}`.
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        let mut transcript = arkret_canonical::unsigned_value(self, &["signature"])?;
        transcript
            .as_object_mut()
            .expect("FrankingProof serializes as an object")
            .insert(
                "domain".to_owned(),
                serde_json::Value::String(Self::SIGNATURE_DOMAIN.to_owned()),
            );
        arkret_canonical::canonical_json_bytes(&transcript).map_err(Into::into)
    }
}

#[cfg(test)]
mod franking_proof_tests {
    use super::*;

    fn fixture() -> serde_json::Value {
        let artifacts = arkret_schema_conformance::default_spec_artifacts_dir()
            .expect("franking-proof KAT requires the spec artifacts");
        serde_json::from_str(
            &std::fs::read_to_string(
                artifacts.join("fixtures/franking-proof-transcript-fixture.json"),
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_signing_bytes_are_the_formal_flat_seven_field_transcript() {
        let fixture = fixture();
        let proof: FrankingProof =
            serde_json::from_value(fixture["case"]["source_payload"].clone()).unwrap();
        let bytes = proof.canonical_signing_bytes().unwrap();

        assert_eq!(
            bytes,
            fixture["case"]["transcript_jcs"]
                .as_str()
                .unwrap()
                .as_bytes()
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 7);
        assert!(value.get("domain").is_some());
        assert!(value.get("signature").is_none());
        assert!(value.get("context").is_none());
        assert!(value.get("proof").is_none());
    }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationReportPayload {
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<ScopeRef>,
    pub target_ref: ObjectRef,
    pub report_reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub reporter_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ModerationReportProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_provider_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<Vec<ObjectRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_package: Option<ModerationEvidencePackage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub franking_proof: Option<FrankingProof>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationReportProvenance {
    #[serde(rename = "self")]
    SelfAuthored,
    MimiFacade,
}

impl ModerationReportPayload {
    pub fn validate_self_endpoint(
        &self,
        actor_id: &DidCoreId,
    ) -> std::result::Result<(), &'static str> {
        if actor_id != &self.reporter_id
            || self.provenance == Some(ModerationReportProvenance::MimiFacade)
            || self.source_provider_id.is_some()
        {
            return Err("self moderation report must be directly authored by its reporter");
        }
        Ok(())
    }
}
