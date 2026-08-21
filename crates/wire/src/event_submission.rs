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
use crate::control_proposal::ControlProposalAck;
use crate::error::{Error, Result};
use crate::event_envelope::{Event, EventSubmitContext};
use crate::offline_publication::{
    AnchorUnitLeaseBasis, AuthorizationLease, IngressReceipt, LeaseBasisRef,
};
use crate::{DidCoreId, RiskTier, ScopeRef};

pub const MAX_SUBMISSION_CBA_BUNDLES: usize = 64;

/// Mutually exclusive publication authority lanes. This selector describes
/// where admission authority comes from; it is not serialized into an Event
/// or submission wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventPublicationLane {
    /// Sender-constrained verified session + typed request context.
    OnlineSelf,
    /// Pre-issued authorization lease, followed by an ingress receipt.
    OfflineDelayed,
    /// Origin Principal Server admission proof inside the Event envelope.
    PeerFederation,
}

/// Classify a complete ordered submission unit before any network request.
///
/// Basis-free Events are admitted only as one closed Realm-bootstrap or
/// device-reanchor unit. Ordinary Events never become anchors merely because
/// their authorization fields are missing.
pub fn classify_event_submit_context(events: &[Event]) -> Result<EventSubmitContext> {
    let context = classify_event_submit_context_shape(events)?;
    for event in events {
        event.validate_for_submit_structural_in_context(context)?;
    }
    Ok(context)
}

/// Classify and validate a complete ordered federation unit whose Events have
/// already received their origin Principal Server admission proof.
pub fn classify_federated_event_submit_context(
    events: &[Event],
    digest_suites: &[arkret_canonical::DigestSuite],
) -> Result<EventSubmitContext> {
    if events.len() != digest_suites.len() {
        return Err(Error::Protocol(
            "federated Event and digest-suite cardinality must match".to_owned(),
        ));
    }
    let context = classify_event_submit_context_shape(events)?;
    for (event, digest_suite) in events.iter().zip(digest_suites.iter().copied()) {
        event.validate_for_federation_structural_in_context(context, digest_suite)?;
    }
    Ok(context)
}

fn classify_event_submit_context_shape(events: &[Event]) -> Result<EventSubmitContext> {
    let basis_free = |event: &Event| {
        event.seal_ref.is_none() && event.auth_context.is_none() && event.seal_basis.is_none()
    };
    let has_basis_free = events.iter().any(basis_free);
    let all_basis_free = !events.is_empty() && events.iter().all(basis_free);
    if has_basis_free && !all_basis_free {
        return Err(Error::Protocol(
            "anchor Events must be authorized as one complete ordered unit".to_owned(),
        ));
    }
    let context = if all_basis_free {
        let first_kind = events
            .first()
            .map(|event| event.kind.as_str())
            .unwrap_or_default();
        if !matches!(
            first_kind,
            crate::event_kind_str::REALM_CREATE | crate::event_kind_str::DEVICE_REANCHOR
        ) {
            return Err(Error::Protocol(
                "basis-free publication unit must be a registered Realm bootstrap or device re-anchor unit"
                    .to_owned(),
            ));
        }
        EventSubmitContext::AnchorUnit
    } else {
        EventSubmitContext::Standard
    };
    Ok(context)
}

/// Batch `ak.self.events.command.submit` request used by account clients.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSubmitBatchRequestBody {
    pub events: Vec<EventInitialSubmission>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrGenesisUnit {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub events: [Event; 2],
}

impl PcrGenesisUnit {
    pub fn new(create: Event, founding_authorize: Event) -> Result<Self> {
        let unit = Self {
            events: [create, founding_authorize],
        };
        unit.validate_ordered_envelopes()?;
        Ok(unit)
    }

    pub fn create(&self) -> &Event {
        &self.events[0]
    }

    pub fn founding_authorize(&self) -> &Event {
        &self.events[1]
    }

    pub fn validate_ordered_envelopes(&self) -> Result<()> {
        let create = self.create();
        let authorize = self.founding_authorize();
        if create.kind.as_str() != crate::event_kind_str::REALM_CREATE
            || authorize.kind.as_str() != crate::event_kind_str::DEVICE_AUTHORIZE
            || create.actor_id != authorize.actor_id
            || create.realm_id != authorize.realm_id
            || create.realm_id != crate::RealmId::from_event_id(&create.event_id)
            || create.actor_seq != 0
            || authorize.prev_refs.as_slice() != [create.event_id.clone()]
            || authorize.actor_seq != 1
            || authorize.event_id == create.event_id
        {
            return Err(Error::Protocol(
                "PCR genesis unit must be the exact ordered create/authorize pair".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Signed Events presented to the actor's Principal Server for publication
/// lease issuance. Issuance validates but does not commit these Events.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLeaseIssueRequestBody {
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

impl AuthorizationLeaseIssueRequestBody {
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
    pub fn validate_against_request(
        &self,
        request: &AuthorizationLeaseIssueRequestBody,
        digest_suites: &[arkret_canonical::DigestSuite],
    ) -> Result<()> {
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
            self.validate_event_bindings(&request.events, digest_suites)
        } else {
            if !digest_suites.is_empty() {
                return Err(Error::Protocol(
                    "non-Event authorization lease intents forbid digest suites".to_owned(),
                ));
            }
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

    fn validate_event_bindings(
        &self,
        events: &[Event],
        digest_suites: &[arkret_canonical::DigestSuite],
    ) -> Result<()> {
        if events.len() != digest_suites.len() {
            return Err(Error::Protocol(
                "authorization lease Event and digest-suite cardinality must match".to_owned(),
            ));
        }
        let anchor_unit = events
            .iter()
            .all(|event| event.seal_ref.is_none() && event.seal_basis.is_none());
        if anchor_unit {
            validate_anchor_unit_lease_bindings(events, &self.authorization_leases, digest_suites)?;
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
    digest_suites: &[arkret_canonical::DigestSuite],
) -> Result<()> {
    if events.is_empty() || events.len() != leases.len() || events.len() != digest_suites.len() {
        return Err(Error::Protocol(
            "anchor-unit Event, lease, and digest-suite cardinality must match and be non-empty"
                .to_owned(),
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
        .zip(digest_suites.iter().copied())
        .map(|(event, digest_suite)| {
            let digest = event.event_digest_with_digest_suite(digest_suite)?;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_lease: Option<AuthorizationLease>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cba_proof_bundles: Vec<CbaProofBundle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_proposal_ack: Option<ControlProposalAck>,
    /// Present only for an `ak.member.state` compensation submission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_compensation_evidence: Option<crate::MembershipCompensationSubmissionEvidence>,
}

/// Previously receipted publication evidence transported between peers.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventFederationSubmission {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub event: Event,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_lease: Option<AuthorizationLease>,
    pub ingress_receipts: Vec<IngressReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_proposal_ack: Option<ControlProposalAck>,
    /// Byte-identical transport-only evidence forwarded from self admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_compensation_evidence: Option<crate::MembershipCompensationSubmissionEvidence>,
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

fn validate_control_proposal_ack(
    event: &Event,
    receipt: Option<&ControlProposalAck>,
    context: EventSubmitContext,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<()> {
    if let Some(receipt) = receipt {
        // A caller-proven closed anchor unit consists entirely of Control
        // Moves even though its Events intentionally carry no `seal_basis`.
        // Those Moves still participate in the bounded proposal protocol and
        // therefore may (and at durable ingress must) carry their receipts.
        // Outside that explicit context, absence of `seal_basis` continues to
        // identify a DataEvent and must fail closed.
        if context == EventSubmitContext::Standard && event.seal_basis.is_none() {
            return Err(Error::Protocol(
                "DataEvent submissions forbid a Control Proposal Ack".to_owned(),
            ));
        }
        let event_digest = crate::Hash::new(event.event_digest_with_digest_suite(digest_suite)?)?;
        if receipt.realm_id != event.realm_id || receipt.proposal_digest != event_digest {
            return Err(Error::Protocol(
                "Control Proposal Ack does not bind the submitted Event".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_membership_compensation_evidence(
    event: &Event,
    evidence: Option<&crate::MembershipCompensationSubmissionEvidence>,
) -> Result<()> {
    let Some(evidence) = evidence else {
        return Ok(());
    };
    evidence.validate_bindings()?;
    let core = &evidence.delegation.core;
    if event.kind.as_str() != crate::event_kind_str::MEMBER_STATE
        || event.executed_by.as_ref().map(DidCoreId::as_core_id)
            != Some(core.executor_service_id.as_core_id())
        || event.authorization_ref.as_ref().map(|value| value.as_str())
            != Some(evidence.delegation.delegation_id.as_str())
        || event.actor_id != core.join_actor_id
        || event.realm_id != core.resource
        || event
            .payload
            .get("actor_id")
            .and_then(serde_json::Value::as_str)
            != Some(core.subject_id.as_str())
    {
        return Err(Error::Protocol(
            "membership compensation evidence does not bind the submitted Event".to_owned(),
        ));
    }
    Ok(())
}

impl EventInitialSubmission {
    #[must_use]
    pub const fn publication_lane(&self) -> EventPublicationLane {
        if self.authorization_lease.is_some() {
            EventPublicationLane::OfflineDelayed
        } else {
            EventPublicationLane::OnlineSelf
        }
    }

    /// Build the default online submission path. Authorization is evaluated
    /// atomically against current accepted state by the receiver.
    pub fn online(event: Event) -> Self {
        Self {
            event,
            authorization_lease: None,
            cba_proof_bundles: Vec::new(),
            control_proposal_ack: None,
            membership_compensation_evidence: None,
        }
    }

    /// Build an explicitly delayed/offline submission using a pre-issued
    /// authorization window.
    pub fn delayed(event: Event, authorization_lease: AuthorizationLease) -> Self {
        Self {
            event,
            authorization_lease: Some(authorization_lease),
            cba_proof_bundles: Vec::new(),
            control_proposal_ack: None,
            membership_compensation_evidence: None,
        }
    }

    /// Structural gate an ingress runs before it will mint a receipt.
    ///
    /// Key material, accepted CBA basis and Realm issuer policy are checked by
    /// the caller; this covers only what the wrapper alone can decide.
    pub fn validate_structural(&self, digest_suite: arkret_canonical::DigestSuite) -> Result<()> {
        self.validate_structural_in_context(EventSubmitContext::Standard, digest_suite)
    }

    /// Structural validation under an explicit Event submit context.
    ///
    /// `AnchorUnit` is safe only after the caller has recognized and will
    /// validate a complete closed anchor unit. It must never be selected from
    /// one Event in isolation.
    pub fn validate_structural_in_context(
        &self,
        context: EventSubmitContext,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        self.event
            .validate_for_submit_structural_in_context(context)?;
        if let Some(lease) = &self.authorization_lease {
            lease.validate_structural()?;
            validate_lease_binds_event(&self.event, lease)?;
        }
        validate_control_proposal_ack(
            &self.event,
            self.control_proposal_ack.as_ref(),
            context,
            digest_suite,
        )?;
        validate_membership_compensation_evidence(
            &self.event,
            self.membership_compensation_evidence.as_ref(),
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
    #[must_use]
    pub const fn publication_lane(&self) -> EventPublicationLane {
        EventPublicationLane::PeerFederation
    }

    /// Structural gate a receiving peer runs before revalidating dependencies.
    ///
    /// Online federation carries neither a lease nor lease-bound receipts.
    /// Delayed federation carries a lease and at least one receipt that binds
    /// this exact Event digest inside that lease window. Whether the receipt
    /// issuers, threshold and transparency evidence satisfy the *target* Realm
    /// policy is a separate decision the caller makes.
    pub fn validate_structural(&self, digest_suite: arkret_canonical::DigestSuite) -> Result<()> {
        self.validate_structural_in_context(EventSubmitContext::Standard, digest_suite)
    }

    /// Federation structural validation under a caller-proven anchor context.
    pub fn validate_structural_in_context(
        &self,
        context: EventSubmitContext,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        self.event
            .validate_for_federation_structural_in_context(context, digest_suite)?;
        if let Some(lease) = &self.authorization_lease {
            lease.validate_structural()?;
            validate_lease_binds_event(&self.event, lease)?;
        }
        validate_control_proposal_ack(
            &self.event,
            self.control_proposal_ack.as_ref(),
            context,
            digest_suite,
        )?;
        validate_membership_compensation_evidence(
            &self.event,
            self.membership_compensation_evidence.as_ref(),
        )?;
        if self.ingress_receipts.len() > MAX_FEDERATION_INGRESS_RECEIPTS {
            return Err(Error::Protocol(format!(
                "federation submission permits at most {MAX_FEDERATION_INGRESS_RECEIPTS} ingress receipts"
            )));
        }
        match (
            self.authorization_lease.is_some(),
            self.ingress_receipts.is_empty(),
        ) {
            (true, true) => {
                return Err(Error::Protocol(
                    "delayed federation requires at least one lease-bound ingress receipt"
                        .to_owned(),
                ));
            }
            (false, false) => {
                return Err(Error::Protocol(
                    "online federation forbids lease-bound ingress receipts".to_owned(),
                ));
            }
            _ => {}
        }
        let event_digest =
            crate::Hash::new(self.event.event_digest_with_digest_suite(digest_suite)?)?;
        for receipt in &self.ingress_receipts {
            receipt.validate_structural()?;
            if receipt.event_digest != event_digest {
                return Err(Error::Protocol(
                    "ingress receipt event_digest does not match the submitted Event".to_owned(),
                ));
            }
            if let Some(lease) = &self.authorization_lease {
                receipt.validate_against_lease(lease, &event_digest)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::offline_publication::{
        AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole,
        AuthoritySetPolicy, AuthoritySetPolicySource, AuthoritySetRef,
    };
    use crate::{
        AuthContext, AuthoritySetPolicyKind, AuthoritySetSourceKind, AuthorizationLeaseId,
        DeviceId, DidKey, DidUrl, EventProof, Hash, PayloadProof, PrincipalServerAdmissionProof,
        PrincipalServerAdmissionProofKind, Proof, RealmId, SchemaId, SealId, proof_kind,
    };

    fn instant(hour: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 28, hour, 0, 0).unwrap()
    }

    fn scope() -> ScopeRef {
        ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI")
                .unwrap(),
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
            schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
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
            actor_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
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
            verification_method: DidUrl::new("did:webvh:z6mkfixture:authority.example#key-1")
                .unwrap(),
            payload_digest: digest,
            created_at: lease.issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }];
        lease
    }

    fn online_event() -> Event {
        let mut event = Event::new(
            "ak.message.create",
            scope(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
            1,
            crate::Hlc::new("000000000000-0000-00000000").unwrap(),
            serde_json::json!({}),
        )
        .unwrap();
        event.seal_ref = Some(match intent().basis_ref {
            LeaseBasisRef::Seal(value) => value,
            _ => unreachable!(),
        });
        event.auth_context = Some(AuthContext {
            actor_id: event.actor_id.clone(),
            key_id: crate::OpaqueLocalId::new("device-1").unwrap(),
            key_epoch: 1,
            credential_epoch: None,
        });
        let event_digest = Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.proofs = vec![
            Proof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#device-1")
                    .unwrap(),
                event_digest,
                signer_resolution_evidence_ref: Some(
                    crate::SignerEvidenceRef::new(format!(
                        "ak:signer_evidence:sha256:{}",
                        "22".repeat(32)
                    ))
                    .unwrap(),
                ),
                signer_resolution_evidence_digest: Some(
                    Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
                ),
                created_at: event.created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "a..b".to_owned(),
            }
            .into(),
        ];
        event
    }

    fn federated_event() -> Event {
        let mut event = online_event();
        let producer = event.proofs[0].as_producer().unwrap().clone();
        event.proofs.push(EventProof::PrincipalServerAdmission(
            PrincipalServerAdmissionProof {
                kind: PrincipalServerAdmissionProofKind::PrincipalServerAdmission,
                verification_method: DidUrl::new("did:webvh:z6mkfixtureps:principal.example#key-1")
                    .unwrap(),
                event_digest: producer.event_digest.clone(),
                producer_proof_digest: PrincipalServerAdmissionProof::producer_proof_digest(
                    &producer,
                )
                .unwrap(),
                producer_verification_method: producer.verification_method.clone(),
                producer_signing_key: DidKey::new("did:key:z6Mkhfixture").unwrap(),
                producer_signer_resolution_evidence_ref: None,
                producer_signer_resolution_evidence_digest: None,
                signer_resolution_evidence_ref: crate::SignerEvidenceRef::new(format!(
                    "ak:signer_evidence:sha256:{}",
                    "11".repeat(32)
                ))
                .unwrap(),
                signer_resolution_evidence_digest: Hash::new(format!("sha256:{}", "11".repeat(32)))
                    .unwrap(),
                accepted_at: event.created_at,
                jws: "admission..signature".to_owned(),
            },
        ));
        event
    }

    #[test]
    fn online_submission_validates_and_omits_authorization_lease() {
        let submission = EventInitialSubmission::online(online_event());
        assert_eq!(
            submission.publication_lane(),
            EventPublicationLane::OnlineSelf
        );
        submission
            .validate_structural(arkret_canonical::DigestSuite::Sha256)
            .unwrap();

        let value = serde_json::to_value(submission).unwrap();
        assert!(value.get("authorization_lease").is_none());
    }

    #[test]
    fn caller_proven_anchor_allows_its_control_proposal_ack_without_seal_basis() {
        let mut event = online_event();
        event.seal_ref = None;
        event.seal_basis = None;
        let proposal_digest = Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        let now = Utc::now();
        let receipt = ControlProposalAck {
            kind: crate::ControlProposalAckKind::SignedAck,
            realm_id: event.realm_id.clone(),
            proposal_digest,
            received_at: now,
            decision_due_at: now + chrono::Duration::hours(1),
            absolute_due_at: now + chrono::Duration::hours(2),
            defer_count: 0,
            authority_set_ref: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            authority_acks: Vec::new(),
        };

        assert!(
            validate_control_proposal_ack(
                &event,
                Some(&receipt),
                EventSubmitContext::Standard,
                arkret_canonical::DigestSuite::Sha256,
            )
            .is_err(),
            "basis-free standard Events remain DataEvents"
        );
        validate_control_proposal_ack(
            &event,
            Some(&receipt),
            EventSubmitContext::AnchorUnit,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("caller-proven closed anchors remain Control Moves");
    }

    #[test]
    fn delayed_submission_keeps_the_explicit_lease() {
        let event = online_event();
        let submission = EventInitialSubmission::delayed(event, lease_for(&intent()));
        assert_eq!(
            submission.publication_lane(),
            EventPublicationLane::OfflineDelayed
        );
        submission
            .validate_structural(arkret_canonical::DigestSuite::Sha256)
            .unwrap();

        let value = serde_json::to_value(submission).unwrap();
        assert!(value.get("authorization_lease").is_some());
    }

    #[test]
    fn online_federation_uses_no_offline_publication_evidence() {
        let submission = EventFederationSubmission {
            event: federated_event(),
            authorization_lease: None,
            ingress_receipts: Vec::new(),
            control_proposal_ack: None,
            membership_compensation_evidence: None,
        };
        assert_eq!(
            submission.publication_lane(),
            EventPublicationLane::PeerFederation
        );
        submission
            .validate_structural(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
    }

    #[test]
    fn delayed_federation_requires_a_lease_bound_receipt() {
        let submission = EventFederationSubmission {
            event: federated_event(),
            authorization_lease: Some(lease_for(&intent())),
            ingress_receipts: Vec::new(),
            control_proposal_ack: None,
            membership_compensation_evidence: None,
        };
        assert!(
            submission
                .validate_structural(arkret_canonical::DigestSuite::Sha256)
                .is_err()
        );
    }

    #[test]
    fn lease_issue_request_enforces_closed_target_shape() {
        let empty = AuthorizationLeaseIssueRequestBody {
            events: Vec::new(),
            intents: Vec::new(),
        };
        assert!(empty.validate_structural().is_err());

        let target = intent();
        let mut event = Event::new(
            "ak.message.create",
            scope(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
            1,
            crate::Hlc::new("000000000000-0000-00000000").unwrap(),
            serde_json::json!({}),
        )
        .unwrap();
        event.seal_ref = Some(match &target.basis_ref {
            LeaseBasisRef::Seal(value) => value.clone(),
            _ => unreachable!(),
        });
        let mixed = AuthorizationLeaseIssueRequestBody {
            events: vec![event],
            intents: vec![target.clone()],
        };
        assert!(mixed.validate_structural().is_err());

        let too_many = AuthorizationLeaseIssueRequestBody {
            events: Vec::new(),
            intents: vec![target; 501],
        };
        assert!(too_many.validate_structural().is_err());
    }

    #[test]
    fn lease_issue_outcome_preserves_ordered_intent_binding() {
        let requested = intent();
        let request = AuthorizationLeaseIssueRequestBody {
            events: Vec::new(),
            intents: vec![requested.clone()],
        };
        let outcome = AuthorizationLeaseIssueOutcome {
            authorization_leases: vec![lease_for(&requested)],
        };
        outcome.validate_against_request(&request, &[]).unwrap();

        let mut changed = request;
        changed.intents[0].action = "ak.message.redact".to_owned();
        assert!(outcome.validate_against_request(&changed, &[]).is_err());
    }
}
