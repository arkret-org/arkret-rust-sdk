//! Event publication wrappers (`zh/authz/offline-publication.md` §2.1).
//!
//! The Event stays the only signed business fact. The lease, the ingress
//! receipts and the CBA bundles travel beside it as independently verified
//! publication evidence; none of them is an Event field and none of them
//! enters the Event digest. A service MUST NOT copy this transport evidence
//! into the Event, and MUST NOT rewrite `received_at` because it happened to
//! see the Event later.

use serde::{Deserialize, Serialize};

use crate::cba_proof_bundle::CbaProofBundle;
use crate::control_proposal::ControlProposalReceipt;
use crate::error::{Error, Result};
use crate::event_envelope::{Event, EventSubmitContext};
use crate::offline_publication::{
    AnchorUnitLeaseBasis, AuthorizationLease, IngressReceipt, LeaseBasisRef,
};
use crate::{RiskTier, ScopeRef};

pub const MAX_SUBMISSION_CBA_BUNDLES: usize = 64;

/// Batch `ak.self.events.command.submit` request used by account clients.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSubmitBatchRequestBody {
    pub events: Vec<EventInitialSubmission>,
}

/// Signed Events presented to the actor's Principal Server for publication
/// lease issuance. Issuance validates but does not commit these Events.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLeaseIssueRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intents: Vec<AuthorizationLeaseIssueIntent>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLeaseIssueIntent {
    pub scope_ref: ScopeRef,
    pub action: String,
    pub authorization_rule_id: String,
    pub risk_tier: RiskTier,
    pub basis_ref: LeaseBasisRef,
}

/// One authority-issued lease per requested Event, preserving request order.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLeaseIssueOutcome {
    pub authorization_leases: Vec<AuthorizationLease>,
}

impl AuthorizationLeaseIssueRequest {
    pub fn validate_structural(&self) -> Result<()> {
        let target_count = self.events.len() + self.intents.len();
        if target_count == 0 || target_count > 500 {
            return Err(Error::Protocol(
                "authorization lease issuance requires between 1 and 500 targets".to_owned(),
            ));
        }
        if !self.events.is_empty() && !self.intents.is_empty() {
            return Err(Error::Protocol(
                "authorization lease issuance requires exactly one of events or intents".to_owned(),
            ));
        }
        Ok(())
    }
}

impl AuthorizationLeaseIssueOutcome {
    /// Verify that an issuer preserved target order and returned an exact lease
    /// binding for every requested Event or non-Event intent.
    pub fn validate_against_request(&self, request: &AuthorizationLeaseIssueRequest) -> Result<()> {
        request.validate_structural()?;
        if self.authorization_leases.len() != request.events.len() + request.intents.len() {
            return Err(Error::Protocol(
                "authorization lease outcome cardinality changed".to_owned(),
            ));
        }
        for lease in &self.authorization_leases {
            lease.validate_structural()?;
        }
        if !request.events.is_empty() {
            self.validate_event_bindings(&request.events)
        } else {
            for (lease, intent) in self.authorization_leases.iter().zip(&request.intents) {
                if lease.scope_ref != intent.scope_ref
                    || lease.action != intent.action
                    || lease.authorization_rule_id != intent.authorization_rule_id
                    || lease.risk_tier != intent.risk_tier
                    || lease.basis_ref != intent.basis_ref
                {
                    return Err(Error::Protocol(
                        "authorization lease outcome changed an ordered intent binding".to_owned(),
                    ));
                }
            }
            Ok(())
        }
    }

    fn validate_event_bindings(&self, events: &[Event]) -> Result<()> {
        let anchor_unit = events
            .iter()
            .all(|event| event.seal_ref.is_none() && event.seal_basis.is_none());
        if anchor_unit {
            validate_anchor_unit_lease_bindings(events, &self.authorization_leases)?;
        }
        for (lease, event) in self.authorization_leases.iter().zip(events) {
            validate_lease_binds_event(event, lease)?;
            if !anchor_unit {
                let basis_matches = match (&event.seal_ref, &event.seal_basis, &lease.basis_ref) {
                    (Some(expected), None, LeaseBasisRef::Seal(actual)) => expected == actual,
                    (None, Some(expected), LeaseBasisRef::Joined(actual)) => expected == actual,
                    _ => false,
                };
                if !basis_matches {
                    return Err(Error::Protocol(
                        "authorization lease outcome changed an ordered Event basis".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}
pub const MAX_FEDERATION_INGRESS_RECEIPTS: usize = 32;

/// Bind every lease in a caller-recognized closed genesis request to the
/// complete ordered Event unit. Selecting anchor context is the caller's
/// responsibility; this function only makes that selection non-replayable.
pub fn validate_anchor_unit_lease_bindings(
    events: &[Event],
    leases: &[AuthorizationLease],
) -> Result<()> {
    if events.is_empty() || events.len() != leases.len() {
        return Err(Error::Protocol(
            "anchor-unit Event and lease cardinality must match and be non-empty".to_owned(),
        ));
    }
    let realm_id = events[0].realm_id.clone();
    if events.iter().any(|event| event.realm_id != realm_id) {
        return Err(Error::Protocol(
            "anchor-unit Events must share one realm_id".to_owned(),
        ));
    }
    let event_digests = events
        .iter()
        .map(|event| {
            let digest = event.event_digest()?;
            crate::Hash::new(digest).map_err(|error| {
                Error::Protocol(format!("anchor Event digest is invalid: {error}"))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut expected = AnchorUnitLeaseBasis {
        realm_id,
        event_digests,
        unit_digest: crate::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
    };
    expected.unit_digest = expected.expected_unit_digest()?;
    for lease in leases {
        let LeaseBasisRef::AnchorUnit(reference) = &lease.basis_ref else {
            return Err(Error::Protocol(
                "closed anchor-unit submission requires an anchor_unit lease basis".to_owned(),
            ));
        };
        if reference.anchor_unit != expected {
            return Err(Error::Protocol(
                "authorization lease anchor_unit does not match the submitted Event unit"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

/// First durable publication of an Event.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventInitialSubmission {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub event: Event,
    pub authorization_lease: AuthorizationLease,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cba_proof_bundles: Vec<CbaProofBundle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_proposal_receipt: Option<ControlProposalReceipt>,
}

/// Previously receipted publication evidence transported between peers.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventFederationSubmission {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub event: Event,
    pub authorization_lease: AuthorizationLease,
    pub ingress_receipts: Vec<IngressReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_proposal_receipt: Option<ControlProposalReceipt>,
}

/// Bindings that hold for every submission regardless of Realm policy.
///
/// Deliberately absent: any `lease.action == event.kind` equality. Capability
/// actions and Event kinds are separate namespaces — `ak.member.state` is
/// admitted by the action `ak.realm.admin`, and only some kinds share a name
/// with their action. Matching the lease action against the kind's registered
/// admission capabilities (and its risk tier against the registered tier) needs
/// `capability-action-registry.json`, so it belongs to the registry-aware
/// caller, not to this wire-level gate.
fn validate_lease_binds_event(event: &Event, lease: &AuthorizationLease) -> Result<()> {
    if lease.actor_id != event.actor_id {
        return Err(Error::Protocol(
            "authorization lease actor_id does not match the Event actor".to_owned(),
        ));
    }
    if lease.scope_ref != event.scope_ref {
        return Err(Error::Protocol(
            "authorization lease scope_ref does not match the signed Event scope".to_owned(),
        ));
    }
    Ok(())
}

fn validate_control_proposal_receipt(
    event: &Event,
    receipt: Option<&ControlProposalReceipt>,
    context: EventSubmitContext,
) -> Result<()> {
    let requires_receipt = context == EventSubmitContext::Standard && event.seal_basis.is_some();
    if requires_receipt != receipt.is_some() {
        return Err(Error::Protocol(
            "non-genesis Control Move requires exactly one proposal receipt; DataEvent and anchor units forbid it"
                .to_owned(),
        ));
    }
    if let Some(receipt) = receipt {
        let event_digest = crate::Hash::new(event.event_digest()?)?;
        if receipt.realm_id != event.realm_id || receipt.proposal_digest != event_digest {
            return Err(Error::Protocol(
                "control proposal receipt does not bind the submitted Event".to_owned(),
            ));
        }
    }
    Ok(())
}

impl EventInitialSubmission {
    /// Structural gate an ingress runs before it will mint a receipt.
    ///
    /// Key material, accepted CBA basis and Realm issuer policy are checked by
    /// the caller; this covers only what the wrapper alone can decide.
    pub fn validate_structural(&self) -> Result<()> {
        self.validate_structural_in_context(EventSubmitContext::Standard)
    }

    /// Structural validation under an explicit Event submit context.
    ///
    /// `AnchorUnit` is safe only after the caller has recognized and will
    /// validate a complete closed anchor unit. It must never be selected from
    /// one Event in isolation.
    pub fn validate_structural_in_context(&self, context: EventSubmitContext) -> Result<()> {
        self.event
            .validate_for_submit_structural_in_context(context)?;
        self.authorization_lease.validate_structural()?;
        validate_lease_binds_event(&self.event, &self.authorization_lease)?;
        validate_control_proposal_receipt(
            &self.event,
            self.control_proposal_receipt.as_ref(),
            context,
        )?;
        if self.cba_proof_bundles.len() > MAX_SUBMISSION_CBA_BUNDLES {
            return Err(Error::Protocol(format!(
                "submission exceeds {MAX_SUBMISSION_CBA_BUNDLES} CBA proof bundles"
            )));
        }
        for bundle in &self.cba_proof_bundles {
            bundle.validate_structural()?;
        }
        Ok(())
    }
}

impl EventFederationSubmission {
    /// Structural gate a receiving peer runs before revalidating dependencies.
    ///
    /// At least one receipt must bind this exact Event digest to this exact
    /// lease and fall inside the lease window. Whether the receipt issuers,
    /// threshold and transparency evidence satisfy the *target* Realm policy
    /// is a separate decision the caller makes.
    pub fn validate_structural(&self) -> Result<()> {
        self.validate_structural_in_context(EventSubmitContext::Standard)
    }

    /// Federation structural validation under a caller-proven anchor context.
    pub fn validate_structural_in_context(&self, context: EventSubmitContext) -> Result<()> {
        self.event
            .validate_for_submit_structural_in_context(context)?;
        self.authorization_lease.validate_structural()?;
        validate_lease_binds_event(&self.event, &self.authorization_lease)?;
        validate_control_proposal_receipt(
            &self.event,
            self.control_proposal_receipt.as_ref(),
            context,
        )?;
        if self.ingress_receipts.is_empty()
            || self.ingress_receipts.len() > MAX_FEDERATION_INGRESS_RECEIPTS
        {
            return Err(Error::Protocol(format!(
                "federation submission requires 1..={MAX_FEDERATION_INGRESS_RECEIPTS} ingress receipts"
            )));
        }
        let event_digest = crate::Hash::new(self.event.event_digest()?)?;
        for receipt in &self.ingress_receipts {
            receipt.validate_structural()?;
            receipt.validate_against_lease(&self.authorization_lease, &event_digest)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::offline_publication::{
        AUTHORITY_SET_POLICY_SCHEMA, AuthoritySetAuthorizationRule, AuthoritySetIssuer,
        AuthoritySetIssuerRole, AuthoritySetPolicy, AuthoritySetPolicyKind,
        AuthoritySetPolicySource, AuthoritySetRef, AuthoritySetSourceKind,
    };
    use crate::{
        AuthorizationLeaseId, DeviceId, Did, DidUrl, Hash, PayloadProof, RealmId, SealId,
        proof_kind,
    };

    fn instant(hour: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 28, hour, 0, 0).unwrap()
    }

    fn scope() -> ScopeRef {
        ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
        }
    }

    fn intent() -> AuthorizationLeaseIssueIntent {
        AuthorizationLeaseIssueIntent {
            scope_ref: scope(),
            action: "ak.message.create".to_owned(),
            authorization_rule_id: "realm_admission".to_owned(),
            risk_tier: RiskTier::Low,
            basis_ref: LeaseBasisRef::Seal(
                SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ),
        }
    }

    fn lease_for(intent: &AuthorizationLeaseIssueIntent) -> AuthorizationLease {
        let authority_set_policy = AuthoritySetPolicy {
            schema: AUTHORITY_SET_POLICY_SCHEMA.to_owned(),
            authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
            policy_kind: AuthoritySetPolicyKind::RealmAdmission,
            scope_ref: intent.scope_ref.clone(),
            source: AuthoritySetPolicySource {
                source_kind: AuthoritySetSourceKind::RealmControl,
                source_ref: format!("ak:seal:sha256:{}", "a".repeat(64)),
                source_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
                generation_ref: "1".to_owned(),
            },
            authorization_rules: vec![AuthoritySetAuthorizationRule {
                rule_id: intent.authorization_rule_id.clone(),
                issuer_role: AuthoritySetIssuerRole::RealmAdmission,
                allowed_actions: vec![intent.action.clone()],
                issuers: vec![AuthoritySetIssuer {
                    verification_method: DidUrl::new(
                        "did:webvh:z6mkfixture:authority.example#key-1",
                    )
                    .unwrap(),
                }],
                threshold: 1,
            }],
        };
        let authority_set_ref = AuthoritySetRef {
            authority_set_id: authority_set_policy.authority_set_id.clone(),
            authority_set_digest: authority_set_policy.digest().unwrap(),
        };
        let mut lease = AuthorizationLease {
            authorization_lease_id: AuthorizationLeaseId::new(
                "ak:authorization_lease:01904100-0000-7000-8000-aaaaaaaaaaaa",
            )
            .unwrap(),
            basis_ref: intent.basis_ref.clone(),
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap(),
            scope_ref: intent.scope_ref.clone(),
            action: intent.action.clone(),
            authorization_rule_id: intent.authorization_rule_id.clone(),
            risk_tier: intent.risk_tier,
            issued_at: instant(0),
            expires_at: instant(8),
            authority_set_ref,
            authority_set_policy,
            proofs: Vec::new(),
        };
        let digest = lease.lease_digest().unwrap();
        lease.proofs = vec![PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:authority.example#key-1".to_owned(),
            payload_digest: digest,
            created_at: lease.issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }];
        lease
    }

    #[test]
    fn lease_issue_request_enforces_closed_target_shape() {
        let empty = AuthorizationLeaseIssueRequest {
            events: Vec::new(),
            intents: Vec::new(),
        };
        assert!(empty.validate_structural().is_err());

        let target = intent();
        let mut event = Event::new(
            "ak.message.create",
            scope(),
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            1,
            crate::Hlc::new("000000000000-0000-00000000").unwrap(),
            serde_json::json!({}),
        )
        .unwrap();
        event.seal_ref = Some(match &target.basis_ref {
            LeaseBasisRef::Seal(value) => value.clone(),
            _ => unreachable!(),
        });
        let mixed = AuthorizationLeaseIssueRequest {
            events: vec![event],
            intents: vec![target.clone()],
        };
        assert!(mixed.validate_structural().is_err());

        let too_many = AuthorizationLeaseIssueRequest {
            events: Vec::new(),
            intents: vec![target; 501],
        };
        assert!(too_many.validate_structural().is_err());
    }

    #[test]
    fn lease_issue_outcome_preserves_ordered_intent_binding() {
        let requested = intent();
        let request = AuthorizationLeaseIssueRequest {
            events: Vec::new(),
            intents: vec![requested.clone()],
        };
        let outcome = AuthorizationLeaseIssueOutcome {
            authorization_leases: vec![lease_for(&requested)],
        };
        outcome.validate_against_request(&request).unwrap();

        let mut changed = request;
        changed.intents[0].action = "ak.message.redact".to_owned();
        assert!(outcome.validate_against_request(&changed).is_err());
    }
}
