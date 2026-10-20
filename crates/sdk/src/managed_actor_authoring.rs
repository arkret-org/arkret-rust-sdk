//! Applet Service authoring for one Realm-owned Bot/Ghost creation Event.
use arkret_canonical::DigestSuite;
use arkret_event_draft::TypedEventDraft;
use arkret_models_integration::RealmActorCreatePayload;
use arkret_signatures::{EventSigner, SignEventOptions, sign_event};
use arkret_wire::{ActorId, AuthorizationRef, Event, ScopeRef, event_spec};
use chrono::{DateTime, Utc};

/// The candidate carries its independent control proof. The Service signs only
/// the outer creation Event; admission still verifies the locked installation,
/// grant, review, quota and dedup state in the owning Realm's transaction.
pub fn author_realm_actor_create<S: EventSigner + ?Sized>(
    candidate: RealmActorCreatePayload,
    digest_suite: DigestSuite,
    created_at: DateTime<Utc>,
    service_signer: &S,
) -> crate::Result<Event> {
    candidate.validate()?;
    arkret_identity::verify_realm_actor_initial_resolution(&candidate, created_at)?;
    let realm_id = candidate
        .actor_id
        .as_realm_actor_id()
        .ok_or_else(|| {
            crate::sdk_error::Error::Protocol("Realm actor candidate is required".into())
        })?
        .realm_id
        .clone();
    let intent = TypedEventDraft::<event_spec::RealmActorCreate>::new(
        ScopeRef::RealmControl { realm_id },
        ActorId::service(candidate.service_id.clone()),
        candidate.clone(),
    )?
    .with_authorization_ref(AuthorizationRef::from(candidate.creation_authorization_ref))
    .with_applet_id(candidate.applet_id)
    .into_intent(created_at)?;
    let mut event = intent.author_with_digest_suite(digest_suite)?;
    sign_event(
        &mut event,
        service_signer,
        SignEventOptions::new().with_created_at(created_at),
    )?;
    Ok(event.into_event())
}
