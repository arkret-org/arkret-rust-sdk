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
use crate::error::{Error, Result};
use crate::event_envelope::{Event, EventSubmitContext};
use crate::offline_publication::{
    AnchorUnitLeaseBasis, AuthorizationLease, IngressReceipt, LeaseBasisRef,
};

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
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub events: Vec<Event>,
}

/// One authority-issued lease per requested Event, preserving request order.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLeaseIssueOutcome {
    pub authorization_leases: Vec<AuthorizationLease>,
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
