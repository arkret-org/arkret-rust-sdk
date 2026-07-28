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
use crate::event_envelope::Event;
use crate::offline_publication::{AuthorizationLease, IngressReceipt};

pub const MAX_SUBMISSION_CBA_BUNDLES: usize = 64;
pub const MAX_FEDERATION_INGRESS_RECEIPTS: usize = 32;

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
        self.event.validate_for_submit_structural()?;
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
        self.event.validate_for_submit_structural()?;
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
