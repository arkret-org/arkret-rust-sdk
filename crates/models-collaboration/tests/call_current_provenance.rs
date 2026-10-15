use arkret_canonical::{DigestSuite, canonical_json_bytes, sha256_bytes};
use arkret_models_collaboration::events_payloads::call::*;
use arkret_models_collaboration::exact_current_results::CanonicalEventDot;
use arkret_wire::{CurrentRevision, EventId, RealmCommit, RealmCommitId};
use serde_json::json;

fn commit(byte: u8, position: u64) -> RealmCommit {
    let event = EventId::from_digest(DigestSuite::Sha256, [byte; 32]);
    let mut value = json!({
        "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "stream_ref": {"kind":"realm","realm_id":"ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
        "stream_position": position,
        "previous_commit_ref": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
        "event_ref": event, "governance_generation":0,
        "authority_ref": event,
        "committed_at":"2026-10-15T00:00:00.000Z"
    });
    let id = RealmCommitId::from_digest(sha256_bytes(&canonical_json_bytes(&value).unwrap()));
    value["commit_id"] = json!(id);
    value["signature"] = json!({
        "context":"ak.realm_commit_signature.v1", "signature_algorithm":"Ed25519",
        "verification_method":"did:web:station.example#authority",
        "signed_digest":format!("sha256:{}", "0".repeat(64)),
        "created_at":"2026-10-15T00:00:00.000Z", "sig":"A".repeat(86)
    });
    serde_json::from_value(value).unwrap()
}

fn revision(commit: &RealmCommit) -> CurrentRevision {
    CurrentRevision {
        commit_id: commit.commit_id.clone(),
        stream_position: commit.stream_position,
    }
}

fn join(commit: RealmCommit, device: &str) -> CallRosterAssertion {
    CallRosterAssertion {
        tag_id: CanonicalEventDot::new(commit.event_ref.clone(), 7).unwrap(),
        source_commit: commit,
        value: serde_json::from_value(json!({"op":"join", "participant":{
            "actor_id":"ak:did_core:web:anonymous.example", "device_id":device
        }}))
        .unwrap(),
    }
}

#[test]
fn complete_roster_folds_by_commit_order_and_leave_guards_whole_axis() {
    let first = commit(0x77, 3);
    let second = commit(0x11, 5);
    let leave = commit(0x33, 8);
    let roster = CallRosterCurrentValue { assertions: vec![] }
        .with_assertion(join(first.clone(), "first"))
        .unwrap()
        .with_assertion(join(second.clone(), "second"))
        .unwrap();
    roster
        .validate_for_axis(&first.stream_ref, &revision(&second))
        .unwrap();
    assert_eq!(roster.effective_participants().unwrap().len(), 2);
    let delta = |expected| CallRosterAssertion {
        tag_id: CanonicalEventDot::new(leave.event_ref.clone(), 7).unwrap(),
        source_commit: leave.clone(),
        value: CallRosterDelta::Leave {
            actor_id: "ak:did_core:web:anonymous.example".parse().unwrap(),
            device_id: "first".into(),
            expected_revision: expected,
        },
    };
    assert!(
        roster
            .clone()
            .with_assertion(delta(revision(&first)))
            .unwrap()
            .validate_for_axis(&first.stream_ref, &revision(&leave))
            .is_err()
    );
    let complete = roster.with_assertion(delta(revision(&second))).unwrap();
    complete
        .validate_for_axis(&first.stream_ref, &revision(&leave))
        .unwrap();
    assert_eq!(complete.assertions.len(), 3);
    assert_eq!(
        complete.effective_participants().unwrap()[0].device_id,
        "second"
    );
}

#[test]
fn immutable_provenance_rejects_conflicting_dots_streams_and_duplicate_positions() {
    let first = commit(0x11, 3);
    let entry = join(first.clone(), "first");
    let roster = CallRosterCurrentValue { assertions: vec![] }
        .with_assertion(entry.clone())
        .unwrap();
    assert_eq!(
        roster
            .clone()
            .with_assertion(entry)
            .unwrap()
            .assertions
            .len(),
        1
    );
    assert!(
        roster
            .clone()
            .with_assertion(join(first.clone(), "substituted"))
            .is_err()
    );
    let duplicate = roster
        .clone()
        .with_assertion(join(commit(0x33, 3), "second"))
        .unwrap();
    assert!(
        duplicate
            .validate_for_axis(&first.stream_ref, &revision(&first))
            .is_err()
    );
    let mut wrong = roster;
    wrong.assertions[0].tag_id = CanonicalEventDot::new(first.event_ref.clone(), 6).unwrap();
    assert!(
        wrong
            .validate_for_axis(&first.stream_ref, &revision(&first))
            .is_err()
    );
}

#[test]
fn moderation_restore_keeps_the_full_account_and_compares_the_axis_revision() {
    let first = commit(0x77, 3);
    let second = commit(0x11, 5);
    let restored = commit(0x33, 8);
    let actor = |station: &str| {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:participant.example".parse().unwrap(),
            station.parse().unwrap(),
        ))
    };
    let assertion = |source: &RealmCommit, value| CallModerationAssertion {
        tag_id: CanonicalEventDot::new(source.event_ref.clone(), 6).unwrap(),
        source_commit: source.clone(),
        value: serde_json::from_value(value).unwrap(),
    };
    let ban = |target| {
        json!({"op":"remove_participant","removal":{
            "actor_id":target,"action":"ban","removed_by":"ak:did_core:web:moderator.example",
            "removed_at":"2026-10-15T00:00:00.000Z"
        }})
    };
    let current = CallModerationCurrentValue { assertions: vec![] }
        .with_assertion(assertion(&first, ban(actor("ak:did_core:web:one.example"))))
        .unwrap()
        .with_assertion(assertion(
            &second,
            ban(actor("ak:did_core:web:two.example")),
        ))
        .unwrap();
    let restore = |revision| {
        assertion(
            &restored,
            json!({
                "op":"restore_participant","actor_id":actor("ak:did_core:web:one.example"),
                "restored_by":"ak:did_core:web:moderator.example","restored_at":"2026-10-15T00:00:00.000Z",
                "expected_revision":revision
            }),
        )
    };
    assert!(
        current
            .clone()
            .with_assertion(restore(revision(&first)))
            .unwrap()
            .validate_for_axis(&first.stream_ref, &revision(&restored))
            .is_err()
    );
    let current = current.with_assertion(restore(revision(&second))).unwrap();
    current
        .validate_for_axis(&first.stream_ref, &revision(&restored))
        .unwrap();
    assert_eq!(current.assertions.len(), 3);
    let effective = current.effective_removals().unwrap();
    assert_eq!(effective.len(), 1);
    assert_eq!(effective[0].actor_id, actor("ak:did_core:web:two.example"));
    assert!(serde_json::from_value::<CallModerationDelta>(json!({
        "op":"restore_participant","actor_id":"ak:did_core:web:participant.example",
        "restored_by":"ak:did_core:web:moderator.example","restored_at":"2026-10-15T00:00:00.000Z",
        "expected_revision":revision(&second)
    })).is_err());
}
