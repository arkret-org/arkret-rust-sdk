//! Consumer-side checks for `ak.self.actor_profile.read.resolve.v1` rows and
//! the Contact identity-confirmation decisions that read them.
//!
//! The operation is the only outward carrier for a PCR-resident global Actor
//! Profile, and the row it returns is an own-Station display projection plus
//! the exact signed Event that sources it. Ordinary profile state has no
//! independent governance proof, so a consumer must check
//! that the Event, the projection and the requested actor are the same subject
//! before any of it reaches a display surface
//! (`zh/discovery/profiles-presence.md` section 2.3,
//! `zh/sync/service-http-binding.md` section 5.1).
//!
//! A single patch Event does not prove the full retained evidence set, patch
//! ancestry or global freshness. Nothing here claims otherwise: these checks
//! reject a row whose parts disagree, they do not turn the row into an
//! independent proof of the projection.

use arkret_models_identity::actor_profile::ActorProfile;
use arkret_models_identity::actor_profile_operations::{
    ActorProfileResolveOutcome, ResolvedActorProfile,
};
use arkret_wire::{ActorId, ActorProfileId, EventKind, Result, WireError};

use crate::objects::productivity::ContactRemark;

/// Reject a resolved row whose Event, projection and actor disagree.
///
/// Returns the create-derived profile id the row is bound to, so a caller that
/// keeps a per-actor cache keys it on the identity the evidence actually
/// carries rather than on the optional field the projection happened to ship.
pub fn validate_resolved_actor_profile(row: &ResolvedActorProfile) -> Result<ActorProfileId> {
    let event = &row.profile_event;
    if event.actor_id != row.actor_id {
        return Err(WireError::Protocol(
            "resolved profile Event actor does not match the resolved actor".to_owned(),
        ));
    }
    if row.actor_profile.schema != ActorProfile::SCHEMA {
        return Err(WireError::Protocol(
            "resolved profile projection carries a foreign schema".to_owned(),
        ));
    }
    if row.actor_profile.principal_id != *row.actor_id.signing_principal_id() {
        return Err(WireError::Protocol(
            "resolved profile projection belongs to another principal".to_owned(),
        ));
    }
    // The global profile lives in its owner's Principal Control Realm, so the
    // projection Realm and the carrier Event Realm are the same Realm. A row
    // that disagrees is either a Realm override wearing a global shape or a
    // projection stitched to the wrong Event.
    if row.actor_profile.realm_id.as_ref() != Some(&event.realm_id) {
        return Err(WireError::Protocol(
            "resolved profile projection and its Event do not share one Principal Control Realm"
                .to_owned(),
        ));
    }
    let profile_id = match &event.kind {
        EventKind::ProfileCreate => {
            let payload: crate::events_payloads::ActorProfileCreatePayload =
                crate::events_payloads::event_wire::decode_payload_after_kind_validation(event)?;
            if payload.object.principal_id != row.actor_profile.principal_id {
                return Err(WireError::Protocol(
                    "resolved ak.profile.create payload belongs to another principal".to_owned(),
                ));
            }
            ActorProfileId::from_event_id(&event.event_id)
        }
        EventKind::ProfileUpdate => {
            let payload: crate::events_payloads::ActorProfileUpdatePayload =
                crate::events_payloads::event_wire::decode_payload_after_kind_validation(event)?;
            payload.target_ref
        }
        _ => {
            return Err(WireError::Protocol(
                "resolved profile evidence is not ak.profile.create or ak.profile.update"
                    .to_owned(),
            ));
        }
    };
    if row.actor_profile.id.as_ref() != Some(&profile_id) {
        return Err(WireError::Protocol(
            "resolved profile projection id does not match its create-derived Event basis"
                .to_owned(),
        ));
    }
    Ok(profile_id)
}

/// The strict whole-outcome check: every requested actor accounted for exactly
/// once, and every returned row internally consistent.
///
/// This is for a caller that wants one verdict over the batch and has no way to
/// degrade a single actor — a conformance assertion about a service, say. A
/// display surface wants the opposite: keep the rows that hold and mark the one
/// that does not as unavailable, so it calls
/// [`ActorProfileResolveOutcome::validate_covers`] plus
/// [`validate_resolved_actor_profile`] per row instead.
pub fn validate_actor_profile_resolve_outcome(
    outcome: &ActorProfileResolveOutcome,
    requested: &[ActorId],
) -> Result<()> {
    outcome.validate_covers(requested)?;
    for row in &outcome.profiles {
        validate_resolved_actor_profile(row)?;
    }
    Ok(())
}

/// How the holder's confirmed display-name baseline compares with the current
/// verified profile evidence.
///
/// `Unknown` is deliberately distinct from `Unchanged`: an unreachable profile,
/// a row that failed validation and a Realm-override-only view all leave the
/// comparison undecided, and a client must not report `Changed` from any of
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfirmedDisplayNameState {
    /// The holder has never confirmed this Contact identity.
    Unconfirmed,
    /// Current verified profile display equals the confirmed baseline.
    Unchanged { confirmed: String },
    /// Current verified profile display differs from the confirmed baseline.
    Changed { confirmed: String, current: String },
    /// No usable evidence, so nothing may be claimed about the baseline.
    Unknown { confirmed: Option<String> },
}

impl ConfirmedDisplayNameState {
    /// Whether a holder-facing surface must show the changed-display-name
    /// notice together with the old confirmed value.
    pub fn is_changed(&self) -> bool {
        matches!(self, Self::Changed { .. })
    }

    /// The last explicitly confirmed value, when one exists.
    pub fn confirmed(&self) -> Option<&str> {
        match self {
            Self::Unconfirmed => None,
            Self::Unchanged { confirmed } | Self::Changed { confirmed, .. } => Some(confirmed),
            Self::Unknown { confirmed } => confirmed.as_deref(),
        }
    }
}

/// Compare a Contact confirmation baseline with validated profile evidence.
///
/// `evidence` must already have passed [`validate_resolved_actor_profile`];
/// pass `None` whenever the profile is unavailable, the row failed validation
/// or only a Realm override is on hand.
pub fn classify_confirmed_display_name(
    remark: Option<&ContactRemark>,
    evidence: Option<&ResolvedActorProfile>,
) -> ConfirmedDisplayNameState {
    let confirmed = remark
        .and_then(|remark| remark.confirmed_display_name.clone())
        .filter(|value| !value.is_empty());
    match (confirmed, evidence) {
        (None, _) => ConfirmedDisplayNameState::Unconfirmed,
        (Some(confirmed), None) => ConfirmedDisplayNameState::Unknown {
            confirmed: Some(confirmed),
        },
        (Some(confirmed), Some(evidence)) => {
            let current = evidence.actor_profile.display_name.clone();
            if current == confirmed {
                ConfirmedDisplayNameState::Unchanged { confirmed }
            } else {
                ConfirmedDisplayNameState::Changed { confirmed, current }
            }
        }
    }
}

/// Whether Contact accept may treat itself as the holder's first identity
/// confirmation for this peer.
///
/// True only when the accept surface actually holds validated profile evidence
/// and no record for this Contact exists yet. An existing record is left to an
/// explicit confirmation, so a silent background read can never be dressed up
/// as a user decision.
pub fn contact_accept_may_initialize_confirmation(
    existing: Option<&ContactRemark>,
    evidence: Option<&ResolvedActorProfile>,
) -> bool {
    existing.is_none() && evidence.is_some()
}
