//! Consumer-side checks for `ak.self.actor_profile.read.resolve.v1` rows and
//! the Contact identity-confirmation decisions that read them.
//!
//! The operation is the only outward carrier for a PCR-resident global Actor
//! Profile, and the row it returns is an own-Station display projection plus
//! the exact signed Event that sources it. Ordinary profile state has no
//! covering Seal, so a consumer cannot be handed one and must instead check
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

#[cfg(test)]
mod tests {
    use arkret_models_identity::actor_profile_operations::{
        ActorProfileResolveFailure, ActorProfileResolveFailureReason,
    };
    use arkret_wire::{DidCoreId, Event, Hlc, RealmId, ScopeRef};
    use chrono::{DateTime, Utc};
    use serde_json::json;

    use super::*;

    const HOLDER: &str = "ak:did_core:webvh:z6mkfixture";
    const STATION: &str = "ak:did_core:webvh:z6mkfixturestation";
    const OTHER_HOLDER: &str = "ak:did_core:webvh:z6mkother";
    const PCR: &str = "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm";
    const OTHER_PCR: &str = "ak:realm:ARmJMvTcKFyiF-V_8oL4mIoHfnlqERCrcgNBONtY4HQD";

    fn created_at() -> DateTime<Utc> {
        "2026-08-11T00:00:00.000Z".parse().unwrap()
    }

    fn profile_event(kind: &str, holder: &str, realm: &str, payload: serde_json::Value) -> Event {
        let mut event = arkret_wire::test_support::raw_event_at(
            kind,
            ScopeRef::Realm {
                realm_id: RealmId::new(realm).unwrap(),
            },
            DidCoreId::new(holder).unwrap(),
            DidCoreId::new(STATION).unwrap(),
            7,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
            created_at(),
        )
        .unwrap();
        event
            .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        event
    }

    fn projection(
        id: Option<&ActorProfileId>,
        holder: &str,
        realm: &str,
        display_name: &str,
    ) -> ActorProfile {
        let mut value = json!({
            "schema": "ak.schema.actor_profile.v1",
            "realm_id": realm,
            "principal_id": holder,
            "actor_kind": "user",
            "display_name": display_name,
            "created_at": "2026-08-11T00:00:00.000Z"
        });
        if let Some(id) = id {
            value["id"] = json!(id);
        }
        serde_json::from_value(value).unwrap()
    }

    fn create_row(display_name: &str) -> ResolvedActorProfile {
        let event = profile_event(
            "ak.profile.create",
            HOLDER,
            PCR,
            json!({"object": projection(None, HOLDER, PCR, display_name)}),
        );
        let profile_id = ActorProfileId::from_event_id(&event.event_id);
        ResolvedActorProfile {
            actor_id: event.actor_id.clone(),
            actor_profile: projection(Some(&profile_id), HOLDER, PCR, display_name),
            profile_event: event,
        }
    }

    fn update_row(profile_id: &ActorProfileId, display_name: &str) -> ResolvedActorProfile {
        let event = profile_event(
            "ak.profile.update",
            HOLDER,
            PCR,
            json!({
                "target_ref": profile_id,
                "patch": {"display_name": {"$op": "set", "value": display_name}}
            }),
        );
        ResolvedActorProfile {
            actor_id: event.actor_id.clone(),
            actor_profile: projection(Some(profile_id), HOLDER, PCR, display_name),
            profile_event: event,
        }
    }

    fn other_actor() -> ActorId {
        profile_event("ak.profile.create", OTHER_HOLDER, OTHER_PCR, json!({})).actor_id
    }

    #[test]
    fn create_and_update_rows_bind_to_the_same_create_derived_profile_id() {
        let create = create_row("Alice Zhang");
        let profile_id = validate_resolved_actor_profile(&create).unwrap();
        assert_eq!(
            profile_id,
            ActorProfileId::from_event_id(&create.profile_event.event_id)
        );

        let update = update_row(&profile_id, "Alice C.");
        assert_eq!(
            validate_resolved_actor_profile(&update).unwrap(),
            profile_id,
            "an update row keeps the create-derived identity instead of minting a second one"
        );
    }

    #[test]
    fn row_is_rejected_when_its_parts_describe_different_subjects() {
        let profile_id = validate_resolved_actor_profile(&create_row("Alice Zhang")).unwrap();

        let mut foreign_principal = update_row(&profile_id, "Alice C.");
        foreign_principal.actor_profile.principal_id = DidCoreId::new(OTHER_HOLDER).unwrap();
        assert!(validate_resolved_actor_profile(&foreign_principal).is_err());

        let mut foreign_actor = update_row(&profile_id, "Alice C.");
        foreign_actor.actor_id = other_actor();
        assert!(validate_resolved_actor_profile(&foreign_actor).is_err());

        let mut foreign_realm = update_row(&profile_id, "Alice C.");
        foreign_realm.actor_profile.realm_id = Some(RealmId::new(OTHER_PCR).unwrap());
        assert!(
            validate_resolved_actor_profile(&foreign_realm).is_err(),
            "a projection Realm that is not the carrier Event Realm is a Realm override wearing a global shape"
        );

        let mut absent_id = update_row(&profile_id, "Alice C.");
        absent_id.actor_profile.id = None;
        assert!(validate_resolved_actor_profile(&absent_id).is_err());

        let mut wrong_target = update_row(&profile_id, "Alice C.");
        wrong_target.profile_event.payload.insert(
            "target_ref".to_owned(),
            json!("ak:actor_profile:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0"),
        );
        assert!(validate_resolved_actor_profile(&wrong_target).is_err());
    }

    #[test]
    fn a_foreign_event_kind_cannot_carry_a_resolved_profile() {
        let row = create_row("Alice Zhang");
        let mut override_row = row.clone();
        override_row.profile_event = profile_event(
            "ak.profile.realm_override",
            HOLDER,
            PCR,
            json!({
                "target_ref": row.actor_profile.id.as_ref().unwrap(),
                "target_realm_id": OTHER_PCR,
                "patch": {"display_name": {"$op": "set", "value": "alice-oss"}}
            }),
        );
        assert!(
            validate_resolved_actor_profile(&override_row).is_err(),
            "a Realm override is not the global profile carrier"
        );
    }

    #[test]
    fn outcome_must_account_for_every_requested_actor_and_validate_each_row() {
        let row = create_row("Alice Zhang");
        let other = other_actor();
        let requested = vec![row.actor_id.clone(), other.clone()];

        let outcome = ActorProfileResolveOutcome {
            profiles: vec![row.clone()],
            failures: Some(vec![ActorProfileResolveFailure {
                actor_id: other.clone(),
                reason: ActorProfileResolveFailureReason::ProfileUnavailable,
            }]),
        };
        validate_actor_profile_resolve_outcome(&outcome, &requested).unwrap();

        let silently_omitted = ActorProfileResolveOutcome {
            profiles: vec![row.clone()],
            failures: None,
        };
        assert!(
            validate_actor_profile_resolve_outcome(&silently_omitted, &requested).is_err(),
            "an omitted actor must not be distinguishable from a withheld one"
        );

        let mut broken = row;
        broken.actor_profile.id = None;
        let broken_outcome = ActorProfileResolveOutcome {
            profiles: vec![broken],
            failures: Some(vec![ActorProfileResolveFailure {
                actor_id: other,
                reason: ActorProfileResolveFailureReason::ProfileUnavailable,
            }]),
        };
        assert!(validate_actor_profile_resolve_outcome(&broken_outcome, &requested).is_err());
    }

    fn remark(confirmed: Option<&str>, petname: &str) -> ContactRemark {
        let mut remark = ContactRemark::new(DidCoreId::new(HOLDER).unwrap(), petname, created_at());
        remark.confirmed_display_name = confirmed.map(str::to_owned);
        remark
    }

    #[test]
    fn a_missing_profile_is_unknown_rather_than_changed() {
        let confirmed = remark(Some("Alice Zhang"), "");
        assert_eq!(
            classify_confirmed_display_name(Some(&confirmed), None),
            ConfirmedDisplayNameState::Unknown {
                confirmed: Some("Alice Zhang".to_owned())
            }
        );
        assert!(!classify_confirmed_display_name(Some(&confirmed), None).is_changed());
    }

    #[test]
    fn a_renamed_peer_is_changed_and_keeps_the_old_confirmed_value() {
        let confirmed = remark(Some("Alice Zhang"), "Alice from Ops");
        let renamed = create_row("Alice C.");
        let state = classify_confirmed_display_name(Some(&confirmed), Some(&renamed));
        assert_eq!(
            state,
            ConfirmedDisplayNameState::Changed {
                confirmed: "Alice Zhang".to_owned(),
                current: "Alice C.".to_owned()
            }
        );
        assert_eq!(state.confirmed(), Some("Alice Zhang"));

        let same = create_row("Alice Zhang");
        assert_eq!(
            classify_confirmed_display_name(Some(&confirmed), Some(&same)),
            ConfirmedDisplayNameState::Unchanged {
                confirmed: "Alice Zhang".to_owned()
            }
        );
    }

    #[test]
    fn a_contact_without_a_baseline_is_unconfirmed_even_with_live_evidence() {
        let petname_only = remark(None, "Alice from Ops");
        let evidence = create_row("Alice C.");
        assert_eq!(
            classify_confirmed_display_name(Some(&petname_only), Some(&evidence)),
            ConfirmedDisplayNameState::Unconfirmed
        );
        assert_eq!(
            classify_confirmed_display_name(None, Some(&evidence)),
            ConfirmedDisplayNameState::Unconfirmed
        );
    }

    #[test]
    fn accept_initializes_confirmation_only_from_evidence_on_a_first_record() {
        let evidence = create_row("Alice Zhang");
        assert!(contact_accept_may_initialize_confirmation(
            None,
            Some(&evidence)
        ));
        assert!(
            !contact_accept_may_initialize_confirmation(None, None),
            "accept without verifiable Profile leaves both fields absent"
        );
        let existing = remark(None, "Alice from Ops");
        assert!(
            !contact_accept_may_initialize_confirmation(Some(&existing), Some(&evidence)),
            "an existing record is refreshed only by an explicit confirmation"
        );
    }
}
