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
    let id = RealmCommitId::from_digest(sha256_bytes(canonical_json_bytes(&value).unwrap()));
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

fn participant_actor(station: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        "ak:did_core:web:participant.example".parse().unwrap(),
        station.parse().unwrap(),
    ))
}

fn join(commit: RealmCommit, device: &str) -> CallRosterSource {
    CallRosterSource {
        tag_id: CanonicalEventDot::new(commit.event_ref.clone(), 7)
            .unwrap()
            .to_string(),
        source_commit: commit,
        value: serde_json::from_value(json!({"op":"join", "participant":{
            "actor_id":participant_actor("ak:did_core:web:station.example"), "device_id":device
        }}))
        .unwrap(),
    }
}

#[test]
fn complete_roster_replaces_join_and_retains_empty_last_source() {
    let first = commit(0x77, 3);
    let second = commit(0x11, 5);
    let left = commit(0x33, 8);
    let roster = CallRosterCurrentValue::apply_delta(
        None,
        join(
            first.clone(),
            "ak:device:01964137-0000-7000-8000-000000000001",
        ),
        None,
    )
    .unwrap();
    let roster = CallRosterCurrentValue::apply_delta(
        Some(&roster),
        join(
            second.clone(),
            "ak:device:01964137-0000-7000-8000-000000000001",
        ),
        None,
    )
    .unwrap();
    assert_eq!(roster.entries.len(), 1);
    assert_eq!(roster.entries[0].source_commit, second);
    let leave = |expected| CallRosterSource {
        tag_id: CanonicalEventDot::new(left.event_ref.clone(), 7)
            .unwrap()
            .to_string(),
        source_commit: left.clone(),
        value: CallRosterDelta::Leave {
            actor_id: participant_actor("ak:did_core:web:station.example"),
            device_id: "ak:device:01964137-0000-7000-8000-000000000001".into(),
            expected_revision: expected,
        },
    };
    assert!(
        CallRosterCurrentValue::apply_delta(Some(&roster), leave(revision(&first)), None).is_err()
    );
    let roster =
        CallRosterCurrentValue::apply_delta(Some(&roster), leave(revision(&second)), None).unwrap();
    assert!(roster.entries.is_empty());
    assert_eq!(roster.last_source.source_commit, left);
    roster
        .validate_for_axis(&left.stream_ref, &revision(&left))
        .unwrap();
    let wire = serde_json::to_value(&roster).unwrap();
    assert_eq!(wire.as_object().unwrap().len(), 2);
    assert!(serde_json::from_value::<CallRosterCurrentValue>(json!({"assertions":[]})).is_err());
    assert!(serde_json::from_value::<CallRosterCurrentValue>(json!({"entries":[]})).is_err());
}

#[test]
fn immutable_provenance_rejects_wrong_dots_duplicate_targets_and_forked_positions() {
    let first = commit(0x11, 3);
    let roster = CallRosterCurrentValue::apply_delta(
        None,
        join(
            first.clone(),
            "ak:device:01964137-0000-7000-8000-000000000001",
        ),
        None,
    )
    .unwrap();
    assert!(
        CallRosterCurrentValue::apply_delta(
            Some(&roster),
            join(
                commit(0x33, 3),
                "ak:device:01964137-0000-7000-8000-000000000002"
            ),
            None
        )
        .is_err()
    );
    let mut wrong = roster.clone();
    wrong.entries[0].tag_id = CanonicalEventDot::new(first.event_ref.clone(), 6)
        .unwrap()
        .to_string();
    assert!(
        wrong
            .validate_for_axis(&first.stream_ref, &revision(&first))
            .is_err()
    );
    let mut duplicate = roster.clone();
    duplicate.entries.push(duplicate.entries[0].clone());
    assert!(
        duplicate
            .validate_for_axis(&first.stream_ref, &revision(&first))
            .is_err()
    );
    let mut wrong = roster;
    wrong.last_source.source_commit = commit(0x44, 3);
    assert!(
        wrong
            .validate_for_axis(&first.stream_ref, &revision(&first))
            .is_err()
    );
}

#[test]
fn roster_keeps_same_principal_at_different_stations_separate() {
    let first = commit(0x11, 3);
    let second = commit(0x22, 5);
    let roster = CallRosterCurrentValue::apply_delta(
        None,
        join(first, "ak:device:01964137-0000-7000-8000-000000000001"),
        None,
    )
    .unwrap();
    let mut other = join(
        second.clone(),
        "ak:device:01964137-0000-7000-8000-000000000001",
    );
    let CallRosterDelta::Join { participant } = &mut other.value else {
        unreachable!()
    };
    participant.actor_id = participant_actor("ak:did_core:web:other-station.example");
    let roster = CallRosterCurrentValue::apply_delta(Some(&roster), other, None).unwrap();
    assert_eq!(roster.effective_participants().unwrap().len(), 2);
    let left = commit(0x33, 8);
    let roster = CallRosterCurrentValue::apply_delta(
        Some(&roster),
        CallRosterSource {
            tag_id: CanonicalEventDot::new(left.event_ref.clone(), 7)
                .unwrap()
                .to_string(),
            source_commit: left.clone(),
            value: CallRosterDelta::Leave {
                actor_id: participant_actor("ak:did_core:web:station.example"),
                device_id: "ak:device:01964137-0000-7000-8000-000000000001".into(),
                expected_revision: revision(&second),
            },
        },
        None,
    )
    .unwrap();
    assert_eq!(
        roster.effective_participants().unwrap()[0].actor_id,
        participant_actor("ak:did_core:web:other-station.example")
    );
}

#[test]
fn moderation_restore_removes_only_the_exact_full_actor_ban_and_keeps_kick() {
    let first = commit(0x77, 3);
    let second = commit(0x11, 5);
    let restored = commit(0x33, 8);
    let target = participant_actor("ak:did_core:web:station.example");
    let source = |commit: &RealmCommit, value| CallModerationSource {
        tag_id: CanonicalEventDot::new(commit.event_ref.clone(), 6)
            .unwrap()
            .to_string(),
        source_commit: commit.clone(),
        value: serde_json::from_value(value).unwrap(),
    };
    let removal = |action, device: Option<&str>| {
        let mut value = json!({"op":"remove_participant","removal":{"actor_id":target,"action":action,"removed_by":"ak:did_core:web:moderator.example","removed_at":"2026-10-15T00:00:00.000Z"}});
        if let Some(device) = device {
            value["removal"]["device_id"] = json!(device)
        };
        value
    };
    let current =
        CallModerationCurrentValue::apply_delta(None, source(&first, removal("ban", None)))
            .unwrap();
    let current = CallModerationCurrentValue::apply_delta(
        Some(&current),
        source(
            &second,
            removal(
                "kick",
                Some("ak:device:01964137-0000-7000-8000-000000000003"),
            ),
        ),
    )
    .unwrap();
    let restore = |expected| {
        source(
            &restored,
            json!({"op":"restore_participant","actor_id":target,"restored_by":"ak:did_core:web:moderator.example","restored_at":"2026-10-15T00:00:00.000Z","expected_revision":expected}),
        )
    };
    assert!(
        CallModerationCurrentValue::apply_delta(Some(&current), restore(revision(&first))).is_err()
    );
    let current =
        CallModerationCurrentValue::apply_delta(Some(&current), restore(revision(&second)))
            .unwrap();
    assert_eq!(current.entries.len(), 1);
    assert_eq!(current.entries[0].source_commit, second);
    assert_eq!(current.last_source.source_commit, restored);
    assert_eq!(
        current.effective_removals().unwrap()[0].action,
        CallParticipantRemovalAction::Kick
    );
}

#[test]
fn normative_checkpoints_match_the_actual_incremental_projector() {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/call-current-fixture.json")
            .expect("pinned Call fixture must be available");
    let rows = fixture["original_rows"].as_array().unwrap();
    let checkpoints = fixture["checkpoints"].as_array().unwrap();
    assert_eq!(rows.len(), 11);
    assert_eq!(checkpoints.len(), 11);
    let mut roster = None;
    let mut moderation = None;
    for (row, checkpoint) in rows.iter().zip(checkpoints) {
        let commit: RealmCommit = serde_json::from_value(row["commit"].clone()).unwrap();
        let payload = &row["event"]["payload"];
        if let Some(delta) = payload.get("roster_delta") {
            let value: CallRosterDelta = serde_json::from_value(delta.clone()).unwrap();
            let key=matches!(&value,CallRosterDelta::Join {participant} if participant.participant_binding.is_some()).then(||CallParticipantSigningKey {public_key_b64u:fixture["test_keys"]["issuer_public_key_b64u"].as_str().unwrap().into()});
            roster = Some(
                CallRosterCurrentValue::apply_delta(
                    roster.as_ref(),
                    CallRosterSource {
                        tag_id: format!("{}:{CALL_ROSTER_WRITE_INDEX}", commit.event_ref),
                        source_commit: commit.clone(),
                        value,
                    },
                    key,
                )
                .unwrap(),
            );
        }
        if let Some(delta) = payload.get("moderation_delta") {
            moderation = Some(
                CallModerationCurrentValue::apply_delta(
                    moderation.as_ref(),
                    CallModerationSource {
                        tag_id: format!("{}:{CALL_MODERATION_WRITE_INDEX}", commit.event_ref),
                        source_commit: commit.clone(),
                        value: serde_json::from_value(delta.clone()).unwrap(),
                    },
                )
                .unwrap(),
            );
        }
        for (axis, actual) in [
            (
                "call_roster",
                roster.as_ref().map(|v| serde_json::to_value(v).unwrap()),
            ),
            (
                "call_moderation",
                moderation
                    .as_ref()
                    .map(|v| serde_json::to_value(v).unwrap()),
            ),
        ] {
            let expected = checkpoint["current_state_entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["selector"]["kind"] == axis)
                .map(|row| row["value"].clone());
            assert_eq!(actual, expected, "{} at {}", axis, commit.stream_position);
        }
    }
}

#[test]
fn a_binding_expired_at_its_accepting_commit_cannot_form_an_effective_entry() {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/call-current-fixture.json")
            .expect("the pinned Call fixture must be available");
    let row = fixture["checkpoints"][10]["current_state_entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["selector"]["kind"] == "call_roster")
        .unwrap();
    let mut value = row["value"].clone();
    value["entries"][0]["value"]["participant"]["participant_binding"]["expires_at"] =
        value["entries"][0]["source_commit"]["committed_at"].clone();
    value["last_source"]["value"] = value["entries"][0]["value"].clone();
    let roster: CallRosterCurrentValue = serde_json::from_value(value).unwrap();
    assert!(
        roster
            .validate_for_axis(
                &serde_json::from_value(row["source_stream_ref"].clone()).unwrap(),
                &serde_json::from_value(row["revision"].clone()).unwrap()
            )
            .is_err()
    );
}
