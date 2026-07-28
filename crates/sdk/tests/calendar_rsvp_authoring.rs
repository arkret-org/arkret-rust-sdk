//! The authoring helper is the only supported RSVP producer path, so these
//! tests pin the two failures the closure review called out: an effect-less
//! RSVP that never reaches its CBA cell, and a basis the envelope does not
//! causally carry.

use arkret::calendar::build_rsvp_set_event;
use arkret::{
    CalendarEventFields, CalendarStatus, RsvpAuthoring, RsvpResponse, RsvpResponseBranch,
    RsvpStatus,
};
use arkret_wire::{Did, EventId, Hash, Hlc, RealmId, StrandId};

const BASIS_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BASIS_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn calendar() -> CalendarEventFields {
    CalendarEventFields {
        start: "2026-06-22T09:00:00".to_owned(),
        end: "2026-06-22T10:00:00".to_owned(),
        timezone: "America/Los_Angeles".to_owned(),
        tzdb_version: "2025a".to_owned(),
        all_day: false,
        status: CalendarStatus::Confirmed,
        recurrence: None,
        location: None,
        call_id: None,
        attendees: Vec::new(),
    }
}

fn authoring(basis: Vec<Hash>) -> RsvpAuthoring {
    RsvpAuthoring {
        event_ref: StrandId::new("ak:strand:0196419b-0000-7000-8000-000000000201").unwrap(),
        occurrence: None,
        schedule_basis_refs: basis,
        response: RsvpResponseBranch::Plaintext(RsvpResponse {
            status: RsvpStatus::Accepted,
            comment: None,
        }),
    }
}

fn schedule(basis: Vec<Hash>) -> arkret::CalendarScheduleProjection {
    arkret::CalendarScheduleProjection::from_heads(
        &basis
            .into_iter()
            .map(|digest| (digest, Some(b"schedule".to_vec())))
            .collect::<Vec<_>>(),
    )
}

fn build(basis: Vec<Hash>, causal_refs: Vec<Hash>) -> arkret_wire::Result<arkret_wire::Event> {
    let projection = schedule(basis.clone());
    build_rsvp_set_event(
        authoring(basis),
        &calendar(),
        &projection,
        EventId::new("ak:event:0196419b-0000-7000-8000-000000000301").unwrap(),
        arkret::ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000101").unwrap(),
        },
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        1,
        Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
        causal_refs,
    )
}

#[test]
fn authored_rsvp_projects_onto_the_registered_cell() {
    let basis = Hash::new(BASIS_A).unwrap();
    let event = build(vec![basis.clone()], vec![basis]).unwrap();

    // The Event states no writes; they are derived from kind + payload through
    // the registry, so this asserts the projection a receiver computes rather
    // than an array the producer stamped.
    let writes = arkret_schema::project_registered_cell_writes(
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    assert_eq!(writes.len(), 1);
    assert!(
        writes[0]
            .cell
            .as_str()
            .starts_with("ak:cell:ak.component.calendar.rsvp.v1:")
    );

    // effect_projection = set(payload.entry): the op value is the whole entry,
    // not just the status.
    let effect = writes[0].as_direct().expect("rsvp projects a direct set");
    let value = effect.op.value.as_ref().expect("a set carries its value");
    assert_eq!(value, &event.payload["entry"]);
    assert!(value.get("schedule_basis_refs").is_some());
    assert_eq!(value["response"]["status"], "accepted");
}

#[test]
fn basis_is_canonicalized_and_must_be_carried_by_causal_refs() {
    let a = Hash::new(BASIS_A).unwrap();
    let b = Hash::new(BASIS_B).unwrap();

    // Descending input is sorted into canonical ascending byte order rather
    // than signed as given.
    let event = build(vec![b.clone(), a.clone()], vec![a.clone(), b.clone()]).unwrap();
    let refs = event.payload["entry"]["schedule_basis_refs"]
        .as_array()
        .unwrap();
    assert_eq!(refs[0], BASIS_A);
    assert_eq!(refs[1], BASIS_B);

    // A basis the envelope does not causally carry is refused at authoring
    // time, matching the receiver's rsvp_basis_not_causal shape admission.
    assert!(build(vec![b], vec![a]).is_err());
}

#[test]
fn non_recurring_event_only_accepts_a_series_rsvp() {
    let basis = Hash::new(BASIS_A).unwrap();
    let mut authoring = authoring(vec![basis]);
    authoring.occurrence = Some("2026-06-22T09:00:00[America/Los_Angeles]".to_owned());
    let projection = schedule(vec![Hash::new(BASIS_A).unwrap()]);
    assert!(authoring.into_payload(&calendar(), &projection).is_err());
}

#[test]
fn cancelled_or_unsettled_schedule_cannot_author_an_rsvp() {
    let basis = Hash::new(BASIS_A).unwrap();
    let projection = schedule(vec![basis.clone()]);
    let mut cancelled = calendar();
    cancelled.status = CalendarStatus::Cancelled;
    assert!(
        authoring(vec![basis.clone()])
            .into_payload(&cancelled, &projection)
            .is_err()
    );

    let conflicted = arkret::CalendarScheduleProjection::from_heads(&[
        (basis.clone(), Some(b"one".to_vec())),
        (Hash::new(BASIS_B).unwrap(), Some(b"two".to_vec())),
    ]);
    assert!(
        authoring(vec![basis])
            .into_payload(&calendar(), &conflicted)
            .is_err()
    );
}
