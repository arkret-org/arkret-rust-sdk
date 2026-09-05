//! Registered cell-contract projection for the Invite family.
//!
//! The live-target slot (`governance-objects.md` section 5.3) makes every
//! Invite Control Move write two cells at once, and the `stored_field_matches_payload`
//! pre-state requirement is what keeps a third-party invite from releasing a
//! direct invite's slot. These live here rather than in the module's in-source
//! tests because the projection surface is public and the module is a frozen
//! hotspot in `tools/test_layout_gate.py`.

use arkret_canonical::DigestSuite;
use arkret_identifiers::CellRef;
use arkret_schema::{
    EventCellContractError, FrozenPreState, project_registered_cell_writes,
    project_registered_cell_writes_with_pre_state,
};
use arkret_wire::cba::{LatticeOp, LatticeOpType, ProjectedCellWrite, ProjectedOp};
use arkret_wire::{Event, EventKind};
use serde_json::{Value, json};

fn project(event: &Event) -> Vec<ProjectedCellWrite> {
    project_registered_cell_writes(event, DigestSuite::Sha256)
        .expect("the registered contract must be evaluable")
}

fn write(cell: &str, op: ProjectedOp) -> ProjectedCellWrite {
    ProjectedCellWrite {
        cell_id: CellRef::new(cell).unwrap(),
        op,
    }
}

fn set_op(value: Value) -> ProjectedOp {
    let mut op = LatticeOp::empty();
    op.value = Some(value);
    ProjectedOp::Direct(op)
}

fn transition_op(from: Value, to: Value) -> ProjectedOp {
    let mut op = LatticeOp::empty();
    op.op_type = LatticeOpType::Transition;
    op.from = Some(from);
    op.to = Some(to);
    ProjectedOp::Direct(op)
}

fn invite_create_event(invitee: bool) -> Event {
    let mut payload = json!({});
    if invitee {
        payload["invitee_account_id"] = json!({
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "station_id": "ak:did_core:web:principal.example"
        });
    }
    serde_json::from_value(json!({
        "event_id": "ak:event:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA",
        "kind": EventKind::InviteCreate,
        "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy",
        "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy"},
        "actor_id": {"kind": "account", "account_id": {
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "station_id": "ak:did_core:web:principal.example"
        }},
        "actor_seq": 4,
        "created_at": "2026-07-26T00:00:00.000Z",
        "hlc": "019f90000000-0000-aabbccdd",
        "prev_refs": [],
        "payload": payload,
        "proofs": []
    }))
    .unwrap()
}

const INVITE_LIFECYCLE_CELL: &str = "ak:cell:ak.component.invite.lifecycle.v1:ak:invite:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA";
const BOB_MEMBER_CELL: &str =
    "ak:cell:ak.component.member.state.v1:-R4dRtD6CAwTRae2S7Pu2Y-yX68SpjNQkAPrG7HLvk4";
/// `ak.component.invite.live_target.v1` keyed by the fixture invitee: a
/// single-component composite over `canonical_json(payload.invitee_account_id)`
/// (`governance-objects.md` §5.3).
const FIXTURE_LIVE_TARGET_CELL: &str =
    "ak:cell:ak.component.invite.live_target.v1:RMIat7Rg9OslR6WIHOjxCmCFnUVUGyoovN1ldcxev88";

#[test]
fn invite_create_claims_the_live_target_slot() {
    // The producer picks neither the Invite ID, the slot cell nor the
    // transition, so the assertion is the exact projected set rather than a
    // rejected mutation. The lifecycle subject is retyped from event_id and
    // enters from null; the slot is claimed in the same Control Move and
    // carries only the create event id.
    let directed = invite_create_event(true);
    assert_eq!(
        project(&directed),
        vec![
            write(
                INVITE_LIFECYCLE_CELL,
                transition_op(json!(null), json!("pending")),
            ),
            write(
                FIXTURE_LIVE_TARGET_CELL,
                set_op(json!(
                    "ak:event:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA"
                )),
            ),
        ]
    );

    // `invitee_account_id` is required by invite_create_payload and is the
    // sole source of the slot subject, so a create without it has no
    // derivable slot address. The contract must fail closed rather than
    // project the lifecycle write alone and leave the slot unclaimed.
    let without_invitee = invite_create_event(false);
    project_registered_cell_writes(&without_invitee, DigestSuite::Sha256)
        .expect_err("a create without an invitee has no derivable slot subject");
}

#[test]
fn invite_accept_member_target_uses_explicit_envelope_actor() {
    let event: Event = serde_json::from_value(json!({
        "event_id": "ak:event:AVoVBx7js38H0fUT57Q-OzdWFD9lkqs6-SHqacF1Z0kE",
        "kind": EventKind::InviteAccept,
        "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy",
        "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy"},
        "actor_id": {"kind": "account", "account_id": {
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "station_id": "ak:did_core:web:principal.example"
        }},
        "actor_seq": 1,
        "created_at": "2026-07-26T00:00:00.000Z",
        "hlc": "019f90000000-0000-aabbccdd",
        "prev_refs": [],
        "payload": {
            "invite_id": "ak:invite:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA"
        },
        "proofs": []
    }))
    .unwrap();

    // The payload names no member at all: the joined member cell is the
    // envelope `actor_id`, the invitee who signed the acceptance.
    assert_eq!(
        project(&event),
        vec![
            write(
                INVITE_LIFECYCLE_CELL,
                ProjectedOp::TransitionTo {
                    to: json!("accepted"),
                },
            ),
            write(
                BOB_MEMBER_CELL,
                ProjectedOp::TransitionTo { to: json!("join") }
            ),
        ]
    );
}

fn invite_terminal_event(kind: EventKind) -> Event {
    serde_json::from_value(json!({
        "event_id": "ak:event:Ae88ZtS-5TAd47HF5YoHYlf7n9J0LovDSKxh6tVLAhQK",
        "kind": kind,
        "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy",
        "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy"},
        "actor_id": {"kind": "account", "account_id": {
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "station_id": "ak:did_core:web:principal.example"
        }},
        "actor_seq": 5,
        "created_at": "2026-07-26T00:00:00.000Z",
        "hlc": "019f90000000-0000-aabbccdd",
        "prev_refs": [],
        "payload": {
            "invite_id": "ak:invite:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA",
            "invitee_account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            },
            "target_state": "revoked"
        },
        "proofs": []
    }))
    .unwrap()
}

fn stored_invitee(principal: &str) -> Value {
    json!({"invitee_account_id": {
        "principal_id": principal,
        "station_id": "ak:did_core:web:principal.example"
    }})
}

fn pre_state_with(stored: Option<Value>) -> FrozenPreState {
    let mut pre_state = FrozenPreState::new();
    if let Some(stored) = stored {
        pre_state.insert(
            CellRef::new(INVITE_LIFECYCLE_CELL.to_owned()).unwrap(),
            stored,
        );
    }
    pre_state
}

fn project_with(
    event: &Event,
    stored: Option<Value>,
) -> Result<Vec<ProjectedCellWrite>, EventCellContractError> {
    project_registered_cell_writes_with_pre_state(
        event,
        DigestSuite::Sha256,
        &pre_state_with(stored),
    )
}

#[test]
fn invite_terminal_member_transition_is_exact() {
    // A terminal move on a direct invite releases the slot in the same
    // Control Move as the lifecycle transition, so the exact projected set
    // is two writes; the slot value returns to the sentinel the next
    // create's `head_eq` tests.
    let expected = vec![
        write(
            INVITE_LIFECYCLE_CELL,
            ProjectedOp::TransitionTo {
                to: json!("revoked"),
            },
        ),
        write(FIXTURE_LIVE_TARGET_CELL, set_op(json!("__unset__"))),
    ];
    let revoke = invite_terminal_event(EventKind::InviteRevoke);
    let matching = Some(stored_invitee("ak:did_core:webvh:z6mkfixture"));
    assert_eq!(project_with(&revoke, matching.clone()).unwrap(), expected);

    let cancel = invite_terminal_event(EventKind::InviteCancel);
    assert_eq!(project_with(&cancel, matching).unwrap(), expected);

    // Cancel is the direct-invite-only path: no stored invitee at all means
    // the target is a third-party invite and the caller must use revoke.
    assert_eq!(
        project_with(&cancel, None).unwrap_err().reason_code(),
        "invite_kind_requires_revoke"
    );
    assert_eq!(
        project_with(
            &cancel,
            Some(stored_invitee("ak:did_core:webvh:z6mkmallory"))
        )
        .unwrap_err()
        .reason_code(),
        "reducer_projection_failed"
    );
}

/// `stored_field_matches_payload` closes both replay directions on the slot
/// (`governance-objects.md` §5.3): a third-party invite cannot forge a
/// payload invitee to release someone else's slot, and a direct invite
/// cannot omit the field to leak its own slot forever.
#[test]
fn invite_revoke_pins_the_released_slot_to_the_stored_invitee() {
    let revoke = invite_terminal_event(EventKind::InviteRevoke);

    // Stored absent, payload present: a third-party invite reaching for a
    // direct slot that was never its own.
    assert_eq!(
        project_with(&revoke, None).unwrap_err().reason_code(),
        "reducer_projection_failed"
    );

    // Stored present, payload names a different account.
    assert_eq!(
        project_with(
            &revoke,
            Some(stored_invitee("ak:did_core:webvh:z6mkmallory"))
        )
        .unwrap_err()
        .reason_code(),
        "reducer_projection_failed"
    );

    // Stored present, payload omits the field: the direct invite would
    // reach its terminal state while its slot stayed occupied forever.
    let mut without_invitee: Value = serde_json::to_value(&revoke).unwrap();
    without_invitee["payload"]
        .as_object_mut()
        .unwrap()
        .remove("invitee_account_id");
    let without_invitee: Event = serde_json::from_value(without_invitee).unwrap();
    assert_eq!(
        project_with(
            &without_invitee,
            Some(stored_invitee("ak:did_core:webvh:z6mkfixture"))
        )
        .unwrap_err()
        .reason_code(),
        "reducer_projection_failed"
    );

    // Both absent is the third-party invite's own terminal move: it matches,
    // and no slot write is derived because the release write is conditional.
    assert_eq!(
        project_with(&without_invitee, None).unwrap(),
        vec![write(
            INVITE_LIFECYCLE_CELL,
            ProjectedOp::TransitionTo {
                to: json!("revoked"),
            },
        )]
    );

    // `send_failed` carries no invitee by schema, so it is the one target
    // state with no requirement and no release write.
    let mut send_failed: Value = serde_json::to_value(&revoke).unwrap();
    let payload = send_failed["payload"].as_object_mut().unwrap();
    payload.remove("invitee_account_id");
    payload.insert("target_state".to_owned(), json!("send_failed"));
    let send_failed: Event = serde_json::from_value(send_failed).unwrap();
    assert_eq!(
        project_with(
            &send_failed,
            Some(stored_invitee("ak:did_core:webvh:z6mkfixture"))
        )
        .unwrap(),
        vec![write(
            INVITE_LIFECYCLE_CELL,
            ProjectedOp::TransitionTo {
                to: json!("send_failed"),
            },
        )]
    );
}
#[test]
fn fails_closed_when_a_projection_source_is_missing() {
    // `ak.invite.cancel` projects its lifecycle target state from
    // `payload.target_state`. A payload without it leaves the reducer with
    // no derivable write, which fails the whole Event closed rather than
    // falling back to an implementation-private default.
    let mut event = invite_terminal_event(EventKind::InviteCancel);
    event.payload.remove("target_state");
    let mut pre_state = FrozenPreState::new();
    pre_state.insert(
        CellRef::new(INVITE_LIFECYCLE_CELL.to_owned()).unwrap(),
        json!({"invitee_account_id": {
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "station_id": "ak:did_core:web:principal.example"
        }}),
    );
    let error =
        project_registered_cell_writes_with_pre_state(&event, DigestSuite::Sha256, &pre_state)
            .unwrap_err();
    assert!(
        matches!(error, EventCellContractError::EffectSetMismatch { .. }),
        "got {error}"
    );
    assert_eq!(error.reason_code(), "effects_payload_mismatch");
}
