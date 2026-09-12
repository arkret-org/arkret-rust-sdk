//! Event publication wrappers (`zh/authz/offline-publication.md` §2.1).
//!
//! The Event stays the only signed business fact. The lease, the ingress
//! receipts and the CBS bundles travel beside it as independently verified
//! publication evidence; none of them is an Event field and none of them
//! enters the Event digest. A service MUST NOT copy this transport evidence
//! into the Event, and MUST NOT rewrite `received_at` because it happened to
//! see the Event later.

use serde::{Deserialize, Serialize};

use crate::cbs_proof_bundle::CbsProofBundle;
use crate::control_proposal::ControlProposalAck;
use crate::error::{Result, WireError};
use crate::event_envelope::{Event, EventSubmitContext};
use crate::offline_publication::{
    AnchorUnitLeaseBasis, AuthorizationLease, IngressReceipt, LeaseBasisRef,
};
use crate::{DeviceId, EventId, Hash, RiskTier, ScopeRef};

pub const MAX_SUBMISSION_CBS_BUNDLES: usize = 64;

/// Mutually exclusive publication authority lanes. This selector describes
/// where admission authority comes from; it is not serialized into an Event
/// or submission wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventPublicationLane {
    /// Sender-constrained verified session + typed request context.
    OnlineSelf,
    /// Pre-issued authorization lease, followed by an ingress receipt.
    OfflineDelayed,
    /// Peer transport of the unchanged producer-authenticated Event.
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

/// Classify and validate a complete ordered federation unit.
pub fn classify_federated_event_submit_context(
    events: &[Event],
    digest_suites: &[arkret_canonical::DigestSuite],
) -> Result<EventSubmitContext> {
    if events.len() != digest_suites.len() {
        return Err(WireError::Protocol(
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
    let basis_free = |event: &Event| event.auth_context.is_none() && event.seal_basis.is_none();
    let has_basis_free = events.iter().any(basis_free);
    let all_basis_free = !events.is_empty() && events.iter().all(basis_free);
    if has_basis_free && !all_basis_free {
        return Err(WireError::Protocol(
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
            return Err(WireError::Protocol(
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

/// Batch `ak.self.events.command.submit.v1` request used by account clients.
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
            return Err(WireError::Protocol(
                "PCR genesis unit must be the exact ordered create/authorize pair".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Signed Events presented to the actor's Station for publication
/// lease issuance. Issuance validates but does not commit these Events.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLeaseIssueRequestBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub submissions: Vec<EventInitialSubmission>,
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

impl<'de> Deserialize<'de> for AuthorizationLeaseIssueRequestBody {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged, deny_unknown_fields)]
        enum Target {
            Submissions {
                submissions: Vec<EventInitialSubmission>,
            },
            Intents {
                intents: Vec<AuthorizationLeaseIssueIntent>,
            },
        }
        let request = match Target::deserialize(deserializer)? {
            Target::Submissions { submissions } => Self {
                submissions,
                intents: Vec::new(),
            },
            Target::Intents { intents } => Self {
                submissions: Vec::new(),
                intents,
            },
        };
        request
            .validate_structural()
            .map_err(serde::de::Error::custom)?;
        Ok(request)
    }
}

impl AuthorizationLeaseIssueRequestBody {
    pub fn validate_structural(&self) -> Result<()> {
        let target_count = self.submissions.len() + self.intents.len();
        if target_count == 0 || target_count > 500 {
            return Err(WireError::Protocol(
                "authorization lease issuance requires between 1 and 500 targets".to_owned(),
            ));
        }
        if !self.submissions.is_empty() && !self.intents.is_empty() {
            return Err(WireError::Protocol(
                "authorization lease issuance requires exactly one of submissions or intents"
                    .to_owned(),
            ));
        }
        for submission in &self.submissions {
            if submission.authorization_lease.is_some() {
                return Err(WireError::Protocol(
                    "lease preflight forbids an existing authorization_lease".to_owned(),
                ));
            }
            validate_mls_submission_leaves(
                &submission.event,
                submission.mls_frontier_leaves.as_deref(),
            )?;
            validate_membership_compensation_evidence(
                &submission.event,
                submission.membership_compensation_evidence.as_ref(),
            )?;
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
        if self.authorization_leases.len() != request.submissions.len() + request.intents.len() {
            return Err(WireError::Protocol(
                "authorization lease outcome cardinality changed".to_owned(),
            ));
        }
        for lease in &self.authorization_leases {
            lease.validate_structural()?;
        }
        if !request.submissions.is_empty() {
            self.validate_event_bindings(
                &request
                    .submissions
                    .iter()
                    .map(|submission| submission.event.clone())
                    .collect::<Vec<_>>(),
                digest_suites,
            )
        } else {
            if !digest_suites.is_empty() {
                return Err(WireError::Protocol(
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
                    return Err(WireError::Protocol(
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
            return Err(WireError::Protocol(
                "authorization lease Event and digest-suite cardinality must match".to_owned(),
            ));
        }
        let anchor_unit = events
            .iter()
            .all(|event| event.auth_context.is_none() && event.seal_basis.is_none());
        if anchor_unit {
            validate_anchor_unit_lease_bindings(events, &self.authorization_leases, digest_suites)?;
        }
        for (lease, event) in self.authorization_leases.iter().zip(events) {
            validate_lease_binds_event(event, lease)?;
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
        return Err(WireError::Protocol(
            "anchor-unit Event, lease, and digest-suite cardinality must match and be non-empty"
                .to_owned(),
        ));
    }
    let realm_id = events[0].realm_id.clone();
    if events.iter().any(|event| event.realm_id != realm_id) {
        return Err(WireError::Protocol(
            "anchor-unit Events must share one realm_id".to_owned(),
        ));
    }
    let event_digests = events
        .iter()
        .zip(digest_suites.iter().copied())
        .map(|(event, digest_suite)| {
            let digest = event.event_digest_with_digest_suite(digest_suite)?;
            Hash::new(digest).map_err(|error| {
                WireError::Protocol(format!("anchor Event digest is invalid: {error}"))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut expected = AnchorUnitLeaseBasis {
        realm_id,
        event_digests,
        unit_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
    };
    expected.unit_digest = expected.expected_unit_digest()?;
    for lease in leases {
        let LeaseBasisRef::AnchorUnit(reference) = &lease.basis_ref else {
            return Err(WireError::Protocol(
                "closed anchor-unit submission requires an anchor_unit lease basis".to_owned(),
            ));
        };
        if reference.anchor_unit != expected {
            return Err(WireError::Protocol(
                "authorization lease anchor_unit does not match the submitted Event unit"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

/// First durable publication of an Event.
///
/// Wire shape: `service-operation-dtos.schema.json#/$defs/EventInitialSubmission`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventInitialSubmission {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub event: Event,
    /// Exact final leaf intent for MLS Genesis/Commit; retained with admission.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_mls_frontier_leaves"
    )]
    pub mls_frontier_leaves: Option<Vec<crate::mls_transition::MlsSecurityFrontierLeaf>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_authorization_lease"
    )]
    pub authorization_lease: Option<AuthorizationLease>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cbs_proof_bundles: Vec<CbsProofBundle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_proposal_ack: Option<ControlProposalAck>,
    /// Present only for an `ak.member.state` compensation submission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_compensation_evidence: Option<crate::MembershipCompensationSubmissionEvidence>,
}

/// One ordinary producer-authenticated Event accepted without an account
/// session, origin callback, handoff, or authorization lease.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProofAuthenticatedPublication(pub EventInitialSubmission);

impl ProofAuthenticatedPublication {
    pub fn new(
        submission: EventInitialSubmission,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Self> {
        submission.validate_structural(digest_suite)?;
        if submission.event.auth_context.is_none()
            || submission.event.seal_basis.is_some()
            || submission.authorization_lease.is_some()
            || submission.control_proposal_ack.is_some()
            || submission.membership_compensation_evidence.is_some()
            || submission.mls_frontier_leaves.is_some()
        {
            return Err(WireError::Protocol(
                "proof-authenticated publication must contain one ordinary Event only".to_owned(),
            ));
        }
        Ok(Self(submission))
    }

    pub fn submission(&self) -> &EventInitialSubmission {
        &self.0
    }

    pub fn into_submission(self) -> EventInitialSubmission {
        self.0
    }
}

/// Stable first-admission references for the one Ack-less human
/// self-principal PCR Control authority class.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcklessSelfPrincipalAdmissionEvidence {
    pub device_id: DeviceId,
    pub device_authorize_event_id: EventId,
    pub device_generation_ref: u64,
    pub seal_basis_digest: Hash,
}

/// Previously receipted publication evidence transported between peers.
///
/// Wire shape: `service-operation-dtos.schema.json#/$defs/EventFederationSubmission`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventFederationSubmission {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub event: Event,
    /// Exact final leaf intent for MLS Genesis/Commit; retained with admission.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_mls_frontier_leaves"
    )]
    pub mls_frontier_leaves: Option<Vec<crate::mls_transition::MlsSecurityFrontierLeaf>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_authorization_lease"
    )]
    pub authorization_lease: Option<AuthorizationLease>,
    pub ingress_receipts: Vec<IngressReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_proposal_ack: Option<ControlProposalAck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ackless_self_principal_admission_evidence: Option<AcklessSelfPrincipalAdmissionEvidence>,
    /// Byte-identical transport-only evidence forwarded from self admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_compensation_evidence: Option<crate::MembershipCompensationSubmissionEvidence>,
}

fn deserialize_optional_authorization_lease<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<AuthorizationLease>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    AuthorizationLease::deserialize(deserializer).map(Some)
}

fn deserialize_mls_frontier_leaves<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<crate::mls_transition::MlsSecurityFrontierLeaf>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let leaves = Vec::<crate::mls_transition::MlsSecurityFrontierLeaf>::deserialize(deserializer)?;
    crate::mls_transition::validate_mls_frontier_leaves(&leaves)
        .map_err(serde::de::Error::custom)?;
    Ok(Some(leaves))
}

pub fn validate_mls_submission_leaves(
    event: &Event,
    leaves: Option<&[crate::mls_transition::MlsSecurityFrontierLeaf]>,
) -> Result<()> {
    let required = matches!(
        event.kind,
        crate::EventKind::MlsGenesis | crate::EventKind::MlsCommit
    );
    if required != leaves.is_some() {
        return Err(WireError::Protocol(
            "mls_frontier_leaves are required exactly for MLS Genesis/Commit (schema_violation)"
                .to_owned(),
        ));
    }
    if let Some(leaves) = leaves {
        crate::mls_transition::validate_mls_frontier_leaves(leaves)?;
    }
    Ok(())
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
        return Err(WireError::Protocol(
            "authorization lease actor_id does not match the Event actor".to_owned(),
        ));
    }
    if lease.scope_ref != event.scope_ref {
        return Err(WireError::Protocol(
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
        // identify an ordinary Event and must fail closed.
        if context == EventSubmitContext::Standard && event.seal_basis.is_none() {
            return Err(WireError::Protocol(
                "ordinary Event submissions forbid a Control Proposal Ack".to_owned(),
            ));
        }
        let event_digest = Hash::new(event.event_digest_with_digest_suite(digest_suite)?)?;
        if receipt.realm_id != event.realm_id || receipt.proposal_digest != event_digest {
            return Err(WireError::Protocol(
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
    let selects_compensation = event.authorization_ref.as_ref().is_some_and(|value| {
        crate::MembershipCompensationDelegationRef::new(value.as_str()).is_ok()
    });
    match (selects_compensation, evidence) {
        (false, None) => Ok(()),
        (true, None) => {
            Err(WireError::Protocol(
                "membership compensation authorization requires membership_compensation_evidence"
                    .to_owned(),
            ))
        }
        (false, Some(_)) => {
            Err(WireError::Protocol(
                "membership_compensation_evidence requires a matching membership compensation authorization_ref"
                    .to_owned(),
            ))
        }
        (true, Some(_)) => Ok(()),
    }
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
            mls_frontier_leaves: None,
            authorization_lease: None,
            cbs_proof_bundles: Vec::new(),
            control_proposal_ack: None,
            membership_compensation_evidence: None,
        }
    }

    /// Build an explicitly delayed/offline submission using a pre-issued
    /// authorization window.
    pub fn delayed(event: Event, authorization_lease: AuthorizationLease) -> Self {
        Self {
            event,
            mls_frontier_leaves: None,
            authorization_lease: Some(authorization_lease),
            cbs_proof_bundles: Vec::new(),
            control_proposal_ack: None,
            membership_compensation_evidence: None,
        }
    }

    /// Structural gate an ingress runs before it will mint a receipt.
    ///
    /// Key material, accepted CBS basis and Realm issuer policy are checked by
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
        validate_mls_submission_leaves(&self.event, self.mls_frontier_leaves.as_deref())?;
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
        if self.cbs_proof_bundles.len() > MAX_SUBMISSION_CBS_BUNDLES {
            return Err(WireError::Protocol(format!(
                "submission exceeds {MAX_SUBMISSION_CBS_BUNDLES} CBS proof bundles"
            )));
        }
        for bundle in &self.cbs_proof_bundles {
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
        validate_mls_submission_leaves(&self.event, self.mls_frontier_leaves.as_deref())?;
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
        if self.control_proposal_ack.is_some()
            && self.ackless_self_principal_admission_evidence.is_some()
        {
            return Err(WireError::Protocol(
                "federation Control admission cannot carry both an Ack and Ack-less evidence"
                    .to_owned(),
            ));
        }
        if let Some(evidence) = &self.ackless_self_principal_admission_evidence {
            if !self.event.kind.is_control_plane() || self.event.seal_basis.is_none() {
                return Err(WireError::Protocol(
                    "Ack-less self-principal admission evidence requires a based Control Move"
                        .to_owned(),
                ));
            }
            let basis_digest = crate::canonical::canonical_sha256(
                self.event.seal_basis.as_ref().expect("checked above"),
            )?;
            if evidence.seal_basis_digest.as_str() != basis_digest {
                return Err(WireError::Protocol(
                    "Ack-less self-principal admission evidence does not bind the signed Seal basis"
                        .to_owned(),
                ));
            }
        }
        validate_membership_compensation_evidence(
            &self.event,
            self.membership_compensation_evidence.as_ref(),
        )?;
        if self.ingress_receipts.len() > MAX_FEDERATION_INGRESS_RECEIPTS {
            return Err(WireError::Protocol(format!(
                "federation submission permits at most {MAX_FEDERATION_INGRESS_RECEIPTS} ingress receipts"
            )));
        }
        match (
            self.authorization_lease.is_some(),
            self.ingress_receipts.is_empty(),
        ) {
            (true, true) => {
                return Err(WireError::Protocol(
                    "delayed federation requires at least one lease-bound ingress receipt"
                        .to_owned(),
                ));
            }
            (false, false) => {
                return Err(WireError::Protocol(
                    "online federation forbids lease-bound ingress receipts".to_owned(),
                ));
            }
            _ => {}
        }
        let event_digest = Hash::new(self.event.event_digest_with_digest_suite(digest_suite)?)?;
        for receipt in &self.ingress_receipts {
            receipt.validate_structural()?;
            if receipt.event_digest != event_digest {
                return Err(WireError::Protocol(
                    "ingress receipt event_digest does not match the submitted Event".to_owned(),
                ));
            }
            if let Some(lease) = &self.authorization_lease {
                receipt.validate_against_lease(lease, &event_digest, &self.event.event_id)?;
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
        AccountId, ActorId, AuthContext, AuthoritySetPolicyKind, AuthoritySetSourceKind,
        AuthorizationLeaseId, Base64UrlString, DeviceId, DidCoreId, DidUrl, Hash, PayloadProof,
        ProducerEventProof, RealmId, SchemaId, SealId, proof_kind,
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

    fn account_actor(principal: &str) -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixturestation").unwrap(),
        ))
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
            actor_id: account_actor("ak:did_core:webvh:z6mkfixture"),
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
            account_actor("ak:did_core:webvh:z6mkfixture"),
            1,
            crate::Hlc::new("000000000000-0000-00000000").unwrap(),
            serde_json::json!({}),
        )
        .unwrap();
        let authority_ref = match intent().basis_ref {
            LeaseBasisRef::Seal(value) => value,
            _ => unreachable!(),
        };
        event.auth_context = Some(AuthContext {
            key_id: crate::OpaqueLocalId::new("device-1").unwrap(),
            key_epoch: 1,
            credential_epoch: None,
            authority_refs: vec![authority_ref],
        });
        let event_digest = Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.proofs = vec![ProducerEventProof {
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
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }];
        event
    }

    fn federated_event() -> Event {
        online_event()
    }

    fn membership_compensation_submission()
    -> (Event, crate::MembershipCompensationSubmissionEvidence) {
        let join_actor_id = account_actor("ak:did_core:webvh:z6mkfixture");
        let subject_id = account_actor("ak:did_core:webvh:z6mkfixturesubject");
        let executor_id = account_actor("ak:did_core:webvh:z6mkfixtureexecutor");
        let ScopeRef::Realm { realm_id: resource } = scope() else {
            unreachable!()
        };
        let join_event = online_event();
        let admission_id = crate::ProtocolOpaqueId::new("membership-admission-1").unwrap();
        let core = crate::MembershipCompensationDelegationCore {
            authority: crate::MembershipCompensationAuthority::V1,
            admission_id: admission_id.clone(),
            join_event_id: join_event.event_id.clone(),
            membership_cell_id: crate::ProtocolOpaqueId::new("membership-cell-1").unwrap(),
            member_id: subject_id.clone(),
            join_actor_id: join_actor_id.clone(),
            executed_by: None,
            authorization_ref: None,
            verification_method: DidUrl::new("did:webvh:z6mkfixture:authority.example#key-1")
                .unwrap(),
            executor_id: executor_id.clone(),
            executor_proof_key_kid: DidUrl::new(
                "did:webvh:z6mkfixtureexecutor:executor.example#key-1",
            )
            .unwrap(),
            resource_id: resource.clone(),
            action: crate::MembershipCompensationAction::Remove,
            deadline: instant(8),
        };
        let delegation_digest = Hash::new(crate::canonical::sha256_digest(
            crate::canonical::canonical_json_bytes(&core).unwrap(),
        ))
        .unwrap();
        let delegation_id = crate::MembershipCompensationDelegationRef::new(format!(
            "ak:membership_compensation_delegation:sha256:{}",
            delegation_digest.as_str().strip_prefix("sha256:").unwrap()
        ))
        .unwrap();
        let signature = || crate::ProtocolSignature {
            verification_method: DidUrl::new("did:webvh:z6mkfixture:authority.example#key-1")
                .unwrap(),
            created_at: instant(1),
            jws: Base64UrlString::new("AA").unwrap(),
        };
        let evidence = crate::MembershipCompensationSubmissionEvidence {
            delegation: crate::MembershipCompensationExecutorDelegation {
                delegation_id: delegation_id.clone(),
                core,
                signature: signature(),
            },
            join_accepted_proof: crate::MembershipJoinAcceptedProof {
                admission_id: admission_id.clone(),
                join_event_id: join_event.event_id,
                accepted_at: instant(1),
                issuer_id: DidCoreId::new("ak:did_core:webvh:z6mkfixtureissuer").unwrap(),
                signature: signature(),
            },
            terminal_certificate: crate::MembershipCompensationTerminalCertificate {
                domain: crate::MembershipCompensationTerminalDomain::V1,
                admission_id: admission_id.clone(),
                delegation_id: delegation_id.clone(),
                operation_id: crate::ProtocolOperationId::new(
                    "ak:operation:019a6aa0-1000-7000-8000-000000000000",
                )
                .unwrap(),
                terminal_state:
                    crate::MembershipCompensationTerminalState::FailedAfterMembershipAcceptance,
                certified_at: instant(2),
                issuer_id: DidCoreId::new("ak:did_core:webvh:z6mkfixtureissuer").unwrap(),
                signature: signature(),
            },
            single_use_cas_token: crate::MembershipCompensationCasToken {
                domain: crate::MembershipCompensationCasDomain::V1,
                admission_id,
                delegation_id: delegation_id.clone(),
                expected_state: crate::MembershipCompensationExpectedState::Unused,
                destination_id: executor_id.route_service_id().clone(),
                issued_at: instant(2),
                expires_at: instant(7),
                issuer_id: DidCoreId::new("ak:did_core:webvh:z6mkfixtureissuer").unwrap(),
                signature: signature(),
            },
        };
        let mut event = Event::new(
            "ak.member.state",
            ScopeRef::Realm { realm_id: resource },
            join_actor_id,
            2,
            crate::Hlc::new("000000000001-0000-00000000").unwrap(),
            serde_json::json!({
                "member_id": subject_id,
                "membership": "leave",
                "reason": "compensate failed admission"
            }),
        )
        .unwrap();
        event.executed_by = Some(executor_id);
        event.authorization_ref =
            Some(crate::AuthorizationRef::new(delegation_id.as_str()).unwrap());
        (event, evidence)
    }

    #[test]
    fn mls_submission_requires_exact_kind_presence_and_rejects_null() {
        let mut event = online_event();
        let leaf = crate::mls_transition::MlsSecurityFrontierLeaf {
            leaf_index: 0,
            actor_id: event.actor_id.clone(),
            credential_ref: crate::NonEmptyString::new("device-a").unwrap(),
        };
        validate_mls_submission_leaves(&event, None).unwrap();
        assert!(validate_mls_submission_leaves(&event, Some(&[leaf.clone()])).is_err());
        for kind in [crate::EventKind::MlsGenesis, crate::EventKind::MlsCommit] {
            event.kind = kind;
            assert!(validate_mls_submission_leaves(&event, None).is_err());
            assert!(validate_mls_submission_leaves(&event, Some(&[])).is_err());
            validate_mls_submission_leaves(&event, Some(&[leaf.clone()])).unwrap();
        }
        let mut value =
            serde_json::to_value(EventInitialSubmission::online(online_event())).unwrap();
        value["mls_frontier_leaves"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<EventInitialSubmission>(value).is_err());
        let mut value =
            serde_json::to_value(EventInitialSubmission::online(online_event())).unwrap();
        value["mls_frontier_leaves"] = serde_json::json!([leaf]);
        value["mls_frontier_leaves"][0]["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EventInitialSubmission>(value).is_err());
    }

    #[test]
    fn mls_submission_rejects_duplicate_indices_credentials_and_bounds() {
        use crate::mls_transition::{MlsSecurityFrontierLeaf, validate_mls_frontier_leaves};
        let leaf = MlsSecurityFrontierLeaf {
            leaf_index: 0,
            actor_id: online_event().actor_id,
            credential_ref: crate::NonEmptyString::new("a".repeat(2048)).unwrap(),
        };
        validate_mls_frontier_leaves(std::slice::from_ref(&leaf)).unwrap();
        let mut other = leaf.clone();
        other.leaf_index = 1;
        assert!(validate_mls_frontier_leaves(&[leaf.clone(), other.clone()]).is_err());
        other.credential_ref = crate::NonEmptyString::new("another-device").unwrap();
        validate_mls_frontier_leaves(&[leaf.clone(), other.clone()]).unwrap();
        assert!(validate_mls_frontier_leaves(&[other.clone(), leaf.clone()]).is_err());
        other.leaf_index = 0;
        assert!(validate_mls_frontier_leaves(&[leaf, other.clone()]).is_err());
        other.credential_ref = crate::NonEmptyString::new("a".repeat(2049)).unwrap();
        assert!(validate_mls_frontier_leaves(&[other]).is_err());
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
    fn membership_compensation_carrier_is_closed_and_exactly_bound() {
        let (event, evidence) = membership_compensation_submission();
        validate_membership_compensation_evidence(&event, Some(&evidence)).unwrap();
        evidence.validate_for_event(&event).unwrap();
        let encoded = serde_json::to_value(&evidence).unwrap();
        assert_eq!(
            encoded["terminal_certificate"]["delegation_id"],
            encoded["delegation"]["delegation_id"]
        );
        assert!(encoded["delegation"].get("delegation_digest").is_none());
        assert!(
            encoded["terminal_certificate"]
                .get("delegation_digest")
                .is_none()
        );
        assert_eq!(
            encoded["single_use_cas_token"]["delegation_id"],
            encoded["delegation"]["delegation_id"]
        );
        assert!(
            encoded["single_use_cas_token"]
                .get("delegation_digest")
                .is_none()
        );

        let mut wrong_delegation = evidence.clone();
        wrong_delegation.single_use_cas_token.delegation_id =
            crate::MembershipCompensationDelegationRef::new(format!(
                "ak:membership_compensation_delegation:sha256:{}",
                "00".repeat(32)
            ))
            .unwrap();
        assert!(wrong_delegation.validate_for_event(&event).is_err());
        assert!(validate_membership_compensation_evidence(&event, None).is_err());

        let ordinary = online_event();
        assert!(validate_membership_compensation_evidence(&ordinary, Some(&evidence)).is_err());

        let mut wrong_subject = event;
        wrong_subject.payload.insert(
            "member_id".to_owned(),
            serde_json::json!({
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixturewrongsubject",
                    "station_id": "ak:did_core:webvh:z6mkfixturestation"
                }
            }),
        );
        assert!(evidence.validate_for_event(&wrong_subject).is_err());
    }

    #[test]
    fn signed_event_and_write_submission_reject_unknown_critical_members() {
        let submission = EventInitialSubmission::online(online_event());

        let mut unknown_request_member = serde_json::to_value(&submission).unwrap();
        unknown_request_member["x_future_write_control"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<EventInitialSubmission>(unknown_request_member).is_err(),
            "the current write request is closed"
        );

        let mut unknown_signed_member = serde_json::to_value(&submission).unwrap();
        unknown_signed_member["event"]["x_future_signed_control"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<EventInitialSubmission>(unknown_signed_member).is_err(),
            "the signed Event envelope is closed"
        );
    }

    #[test]
    fn caller_proven_anchor_allows_its_control_proposal_ack_without_seal_basis() {
        let mut event = online_event();
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
            "basis-free standard Events remain ordinary Events"
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
            mls_frontier_leaves: None,
            event: federated_event(),
            authorization_lease: None,
            ingress_receipts: Vec::new(),
            control_proposal_ack: None,
            ackless_self_principal_admission_evidence: None,
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
            mls_frontier_leaves: None,
            event: federated_event(),
            authorization_lease: Some(lease_for(&intent())),
            ingress_receipts: Vec::new(),
            control_proposal_ack: None,
            ackless_self_principal_admission_evidence: None,
            membership_compensation_evidence: None,
        };
        assert!(
            submission
                .validate_structural(arkret_canonical::DigestSuite::Sha256)
                .is_err()
        );
    }

    #[test]
    fn lease_preflight_rejects_bare_events_existing_lease_and_mls_input_omission() {
        let mut submission = EventInitialSubmission::online(online_event());
        let mut request = AuthorizationLeaseIssueRequestBody {
            submissions: vec![submission.clone()],
            intents: Vec::new(),
        };
        request.validate_structural().unwrap();
        let encoded = serde_json::to_value(&request).unwrap();
        serde_json::from_value::<AuthorizationLeaseIssueRequestBody>(encoded.clone()).unwrap();
        assert!(
            serde_json::from_value::<AuthorizationLeaseIssueRequestBody>(
                serde_json::json!({"events":[online_event()]})
            )
            .is_err()
        );
        for invalid in [serde_json::Value::Null, serde_json::json!([])] {
            let mut value = encoded.clone();
            value["intents"] = invalid;
            assert!(serde_json::from_value::<AuthorizationLeaseIssueRequestBody>(value).is_err());
        }
        let mut value = encoded.clone();
        value["submissions"][0]["authorization_lease"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<AuthorizationLeaseIssueRequestBody>(value).is_err());
        request.submissions[0].authorization_lease = Some(lease_for(&intent()));
        assert!(request.validate_structural().is_err());
        submission.event.kind = crate::EventKind::MlsGenesis;
        request.submissions = vec![submission];
        assert!(request.validate_structural().is_err());
        request.submissions[0].mls_frontier_leaves =
            Some(vec![crate::mls_transition::MlsSecurityFrontierLeaf {
                leaf_index: 0,
                actor_id: request.submissions[0].event.actor_id.clone(),
                credential_ref: crate::NonEmptyString::new("device-a").unwrap(),
            }]);
        request.validate_structural().unwrap();
    }

    #[test]
    fn lease_issue_request_enforces_closed_target_shape() {
        let empty = AuthorizationLeaseIssueRequestBody {
            submissions: Vec::new(),
            intents: Vec::new(),
        };
        assert!(empty.validate_structural().is_err());

        let target = intent();
        let mut event = Event::new(
            "ak.message.create",
            scope(),
            account_actor("ak:did_core:webvh:z6mkfixture"),
            1,
            crate::Hlc::new("000000000000-0000-00000000").unwrap(),
            serde_json::json!({}),
        )
        .unwrap();
        event.auth_context = Some(AuthContext {
            key_id: crate::OpaqueLocalId::new("device-1").unwrap(),
            key_epoch: 1,
            credential_epoch: None,
            authority_refs: vec![match &target.basis_ref {
                LeaseBasisRef::Seal(value) => value.clone(),
                _ => unreachable!(),
            }],
        });
        let mixed = AuthorizationLeaseIssueRequestBody {
            submissions: vec![EventInitialSubmission::online(event)],
            intents: vec![target.clone()],
        };
        assert!(mixed.validate_structural().is_err());

        let too_many = AuthorizationLeaseIssueRequestBody {
            submissions: Vec::new(),
            intents: vec![target; 501],
        };
        assert!(too_many.validate_structural().is_err());
    }

    #[test]
    fn lease_issue_outcome_preserves_ordered_intent_binding() {
        let requested = intent();
        let request = AuthorizationLeaseIssueRequestBody {
            submissions: Vec::new(),
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
