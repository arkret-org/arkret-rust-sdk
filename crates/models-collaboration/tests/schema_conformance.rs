use arkret_schema::*;
use serde_json::json;

mod models {
    pub use arkret_models_collaboration::events_payloads::preview_realm_reaction::RealmFreezePayload;
    pub use arkret_models_collaboration::events_payloads::strand_history_join::{
        HistorySharingPolicyPayload, HistorySharingPolicyPayloadValue,
        HistorySharingPolicyPayloadValueAudit,
    };
    pub use arkret_models_collaboration::events_payloads::strand_ops::{
        StrandMoveExpectedPosition, StrandMovePayload, StrandReorderExpectedPosition,
        StrandReorderPayload, StrandWatchExpectedValue, StrandWatchLevel, StrandWatchSetPayload,
    };
    pub use arkret_models_collaboration::governance::delivery_binding::DeliveryStatus;
    pub use arkret_models_collaboration::governance::history_visibility::{
        HistoryKeyShareDefault, HistoryKeySource,
    };
    pub use arkret_models_collaboration::governance::invite_addressing::InviteDeliveryTarget;
    pub use arkret_models_collaboration::governance::membership_invite::{
        InviteCreatePayload, InviteRefPayload, MembershipInviteRef, MembershipPayload,
        MembershipPayloadState, RelationCreatePayload, validate_invite_create_wire_keys,
    };
    pub use arkret_models_collaboration::governance::plaintext_visibility::{
        PlaintextServiceVisibility, PlaintextVisibleService, PlaintextVisibleServicesPayload,
    };
    pub use arkret_models_collaboration::governance::realm_lifecycle::{
        HistoryVisibilityPayload, ObjectLifecyclePayload, RealmArchivePayload, RealmDestroyPayload,
        RealmTombstonePayload,
    };
    pub use arkret_wire::{
        Did, EventId, Hash, HistoryVisibility, InviteId, PlaintextDataClassKind, RealmId, SpaceId,
        StrandId,
    };
}

mod events {
    pub use arkret_wire::events::*;
}

use models::*;

fn assert_warns_additional_field(warnings: &[String], field: &str) {
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("additional field") && warning.contains(field)),
        "expected warning for additional field {field:?}, got {warnings:?}"
    );
}

#[test]
fn relation_create_payload_strong_type_passes_spec_validator() {
    let catalog = event_payload_validator_catalog().unwrap();
    let payload = RelationCreatePayload::new(
        "ak.relation.parent_of",
        "ak:strand:01904100-0000-7000-8000-111111111111",
        "ak:strand:01904100-0000-7000-8000-222222222222",
    )
    .with_rank("U");
    catalog
        .validate_payload("ak.relation.create", &payload.to_value().unwrap())
        .unwrap();

    // Closed payload schemas reject unknown additive keys.
    let mut leaky = payload.to_value().unwrap();
    leaky["fields"] = json!({"role": "x"});
    assert!(
        catalog
            .validate_payload("ak.relation.create", &leaky)
            .is_err()
    );
}

#[test]
fn membership_payload_strong_type_passes_spec_validator() {
    use crate::models::{DeliveryStatus, MembershipPayload, MembershipPayloadState};
    let catalog = event_payload_validator_catalog().unwrap();

    // invite transition (non-join): only `membership` is structurally required.
    let invite = MembershipPayload::transition(
        MembershipPayloadState::Invite,
        Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
        "space_create",
    );
    catalog
        .validate_payload("ak.member.state", &invite.to_value().unwrap())
        .unwrap();

    // join transition (unroutable): realm_id + actor_id + delivery_status
    // required, but delivery_binding only when routable.
    let join = MembershipPayload::join(
        RealmId::new("ak:realm:01904100-0000-7000-8000-111111111111").unwrap(),
        Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
        DeliveryStatus::Unroutable,
        "invite_accept",
    )
    .with_invite_ref(MembershipInviteRef::Event(
        EventId::new("ak:event:01904100-0000-7000-8000-222222222222").unwrap(),
    ));
    catalog
        .validate_payload("ak.member.state", &join.to_value().unwrap())
        .unwrap();

    // join missing delivery_status is rejected by to_value (conditional req).
    let mut bad = join;
    bad.delivery_status = None;
    assert!(matches!(
        bad.to_value(),
        Err(arkret_wire::Error::Protocol(_))
    ));

    // Closed payload schemas reject unknown additive keys.
    let mut leaky = invite.to_value().unwrap();
    leaky["handle"] = json!("bob:example.com");
    assert!(catalog.validate_payload("ak.member.state", &leaky).is_err());
}

#[test]
fn invite_payload_strong_types_pass_spec_validator() {
    use crate::models::{
        Did, Hash, InviteCreatePayload, InviteDeliveryTarget, InviteId, InviteRefPayload,
    };
    let catalog = event_payload_validator_catalog().unwrap();

    // Directed-create (anyOf branch: invitee + invite_delivery_target +
    // introduction_evidence_digest + expires_at), with an `x_role` extension.
    let create = InviteCreatePayload::new(
        InviteId::new("ak:invite:01904100-0000-7000-8000-111111111111").unwrap(),
        Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
        InviteDeliveryTarget::principal_server(
            Did::new("did:webvh:z6mkfixture:ps.example").unwrap(),
        ),
        Hash::new("sha256:".to_owned() + &"a".repeat(64)).unwrap(),
        chrono::Utc::now() + chrono::Duration::days(7),
    )
    .with_extension("role", json!("member"))
    .unwrap();
    let create_value = create.to_value().unwrap();
    assert_eq!(create_value["x_role"], "member");
    catalog
        .validate_payload("ak.invite.create", &create_value)
        .unwrap();
    validate_invite_create_wire_keys(&create_value).unwrap();
    let decoded: InviteCreatePayload = serde_json::from_value(create_value.clone()).unwrap();
    decoded.invite_delivery_target.validate().unwrap();
    let mut leaky_create = create_value;
    leaky_create["hlc"] = json!("2026-06-14T10:00:00.000Z/node/1");
    assert!(validate_invite_create_wire_keys(&leaky_create).is_err());

    // invite_id ref form (accept / cancel / revoke).
    let cancel = InviteRefPayload::new(
        InviteId::new("ak:invite:01904100-0000-7000-8000-222222222222").unwrap(),
    )
    .with_reason("withdrawn");
    let cancel_value = cancel.to_value().unwrap();
    catalog
        .validate_payload("ak.invite.cancel", &cancel_value)
        .unwrap();
    catalog
        .validate_payload("ak.invite.revoke", &cancel_value)
        .unwrap();
}

#[test]
fn realm_lifecycle_payloads_strong_types_pass_spec_validator() {
    use crate::models::{
        RealmArchivePayload, RealmDestroyPayload, RealmFreezePayload, RealmId,
        RealmTombstonePayload,
    };
    let catalog = event_payload_validator_catalog().unwrap();

    // ak.realm.archive: reversible boolean register; `archived:false` un-archives.
    let archive = RealmArchivePayload::new(true).with_reason("retiring inactive realm");
    catalog
        .validate_payload("ak.realm.archive", &archive.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            "ak.realm.archive",
            &RealmArchivePayload::new(false).to_value().unwrap(),
        )
        .unwrap();

    // ak.realm.freeze: reversible boolean register; `frozen:false` unfreezes.
    let freeze = RealmFreezePayload::new(true).with_reason("incident response hold");
    catalog
        .validate_payload("ak.realm.freeze", &freeze.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            "ak.realm.freeze",
            &RealmFreezePayload::new(false).to_value().unwrap(),
        )
        .unwrap();

    // ak.realm.tombstone: reason + successor_realm_id both required by spec.
    let tombstone = RealmTombstonePayload::new(
        RealmId::new("ak:realm:01904100-0000-7000-8000-333333333333").unwrap(),
        "migrated to successor",
    );
    catalog
        .validate_payload("ak.realm.tombstone", &tombstone.to_value().unwrap())
        .unwrap();

    // ak.realm.destroy: reason required; verification_stub_required omitted so
    // the reducer applies its default (true).
    let destroy = RealmDestroyPayload::new("permanent retirement");
    catalog
        .validate_payload("ak.realm.destroy", &destroy.to_value().unwrap())
        .unwrap();

    // Closed payload schemas reject unknown additive keys.
    let mut leaky = archive.to_value().unwrap();
    leaky["successor_realm_id"] = json!("ak:realm:01904100-0000-7000-8000-444444444444");
    assert!(
        catalog
            .validate_payload("ak.realm.archive", &leaky)
            .is_err()
    );
}

#[test]
fn strand_lifecycle_payloads_strong_types_pass_spec_validator() {
    use crate::models::{
        Did, ObjectLifecyclePayload, SpaceId, StrandId, StrandMovePayload,
        StrandReorderExpectedPosition, StrandReorderPayload, StrandWatchExpectedValue,
        StrandWatchLevel, StrandWatchSetPayload,
    };
    let catalog = event_payload_validator_catalog().unwrap();
    let board = || SpaceId::new("ak:space:01904100-0000-7000-8000-111111111111").unwrap();
    let target = || SpaceId::new("ak:space:01904100-0000-7000-8000-222222222222").unwrap();
    let strand = || StrandId::new("ak:strand:01904100-0000-7000-8000-6c663fa0205f").unwrap();
    let actor = || Did::new("did:webvh:z6mkfixture:alice.example").unwrap();

    // ak.strand.move — board/target Space ids + rank; from_space_id +
    // expected_position optional. Destination is single-sourced by
    // target_space_id (a stray `list_space_id` is reported as additive).
    let mv = StrandMovePayload::new(board(), strand(), target(), "U")
        .with_from_space_id(board())
        .with_expected_position(StrandMoveExpectedPosition {
            space_id: Some(board()),
            rank: Some("T".to_owned()),
            relation_id: None,
        });
    catalog
        .validate_payload("ak.strand.move", &mv.to_value().unwrap())
        .unwrap();

    // ak.strand.reorder — single List Space (`space_id`); no destination field.
    let reorder = StrandReorderPayload::new(board(), strand(), target(), "V")
        .with_expected_position(StrandReorderExpectedPosition {
            rank: Some("U".to_owned()),
            relation_id: None,
        });
    catalog
        .validate_payload("ak.strand.reorder", &reorder.to_value().unwrap())
        .unwrap();

    // ak.strand.watch.set — concrete level + clear (level:null) + CAS guard.
    let set = StrandWatchSetPayload::set(strand(), actor(), StrandWatchLevel::All, Some(true));
    catalog
        .validate_payload("ak.strand.watch.set", &set.to_value().unwrap())
        .unwrap();
    let cleared = StrandWatchSetPayload::clear(strand(), actor());
    let cleared_value = cleared.to_value().unwrap();
    assert!(cleared_value["level"].is_null());
    // allOf: level_public MUST be omitted when level is null.
    assert!(cleared_value.get("level_public").is_none());
    catalog
        .validate_payload("ak.strand.watch.set", &cleared_value)
        .unwrap();
    let guarded =
        StrandWatchSetPayload::set(strand(), actor(), StrandWatchLevel::Participating, None)
            .with_expected_value(Some(StrandWatchExpectedValue {
                level: StrandWatchLevel::Muted,
                level_public: None,
            }));
    catalog
        .validate_payload("ak.strand.watch.set", &guarded.to_value().unwrap())
        .unwrap();
    // expected_value may also assert "no prior cell" via null.
    let guarded_null = StrandWatchSetPayload::set(strand(), actor(), StrandWatchLevel::All, None)
        .with_expected_value(None);
    let guarded_null_value = guarded_null.to_value().unwrap();
    assert!(guarded_null_value["expected_value"].is_null());
    catalog
        .validate_payload("ak.strand.watch.set", &guarded_null_value)
        .unwrap();

    // ak.strand.archive / ak.strand.restore — object_lifecycle_payload, single
    // truth source `target_ref`.
    let archive = ObjectLifecyclePayload::new("ak:strand:01904100-0000-7000-8000-6c663fa0205f")
        .with_target_state("archived")
        .with_reason("season closed");
    catalog
        .validate_payload("ak.strand.archive", &archive.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            "ak.strand.restore",
            &ObjectLifecyclePayload::new("ak:strand:01904100-0000-7000-8000-6c663fa0205f")
                .to_value()
                .unwrap(),
        )
        .unwrap();

    // Closed payload schemas reject unknown additive keys.
    let mut leaky = mv.to_value().unwrap();
    leaky["list_space_id"] = json!("ak:space:01904100-0000-7000-8000-222222222222");
    assert!(catalog.validate_payload("ak.strand.move", &leaky).is_err());
}

#[test]
fn realm_state_payloads_strong_types_match_named_spec_defs() {
    // Validate the strong types directly against the named `$defs/*_payload`
    // schema_ref so this test stays pinned to the exact artifact shape.
    use crate::models::{
        Did, HistoryKeyShareDefault, HistoryKeySource, HistorySharingPolicyPayload,
        HistorySharingPolicyPayloadValue, HistorySharingPolicyPayloadValueAudit, HistoryVisibility,
        HistoryVisibilityPayload, PlaintextDataClassKind, PlaintextServiceVisibility,
        PlaintextVisibleService, PlaintextVisibleServicesPayload,
    };
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let registry = schema_registry_from_spec_artifacts(&artifacts_dir).unwrap();
    let catalog = event_payload_validator_catalog_from_spec_artifacts(&artifacts_dir).unwrap();
    let history_ref = format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/history_visibility_payload");
    let history_policy_ref =
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/history_sharing_policy_payload");
    let services_ref = format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/plaintext_visible_services_payload");

    // history_visibility: non-restricted value carries just `{value}`.
    let shared = HistoryVisibilityPayload::new(HistoryVisibility::Shared);
    registry
        .validate_value(&history_ref, &shared.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            events::EventKind::REALM_HISTORY_VISIBILITY,
            &shared.to_value().unwrap(),
        )
        .unwrap();
    // restricted requires restricted_policy_digest (schema allOf); to_value
    // refuses to emit a non-conformant restricted payload.
    assert!(
        HistoryVisibilityPayload::new(HistoryVisibility::Restricted)
            .to_value()
            .is_err()
    );
    let restricted = HistoryVisibilityPayload::restricted("sha256:".to_owned() + &"a".repeat(64));
    registry
        .validate_value(&history_ref, &restricted.to_value().unwrap())
        .unwrap();
    // Unknown additive keys are reported but do not fail schema validation.
    let mut leaky = shared.to_value().unwrap();
    leaky["unexpected"] = json!(true);
    let warnings = registry
        .validate_value_with_warnings(&history_ref, &leaky)
        .unwrap();
    assert_warns_additional_field(&warnings, "unexpected");

    let history_policy = HistorySharingPolicyPayload {
        value: HistorySharingPolicyPayloadValue {
            version: 1,
            default_key_share: HistoryKeyShareDefault::EventTimeVisibility,
            pre_join_history: None,
            post_removal_recovery: None,
            allowed_key_sources: vec![HistoryKeySource::VerifiedMemberDevice],
            allowed_receiver_states: None,
            audit: HistorySharingPolicyPayloadValueAudit {
                share_audit_event_required: false,
                access_audit_required: false,
            },
            restricted_rules: None,
        },
        reason: None,
    };
    let history_policy_value = serde_json::to_value(&history_policy).unwrap();
    registry
        .validate_value(&history_policy_ref, &history_policy_value)
        .unwrap();
    catalog
        .validate_payload(
            events::EventKind::REALM_HISTORY_SHARING_POLICY,
            &history_policy_value,
        )
        .unwrap();

    // plaintext_visible_services: required item fields strongly typed.
    let services = PlaintextVisibleServicesPayload::new(vec![PlaintextVisibleService::new(
        Did::new("did:webvh:z6mkfixture:index.example").unwrap(),
        "principal_server",
        vec![
            PlaintextDataClassKind::MessageContent,
            PlaintextDataClassKind::FullTextIndex,
            PlaintextDataClassKind::NotificationSummary,
            PlaintextDataClassKind::InboxPreview,
        ],
        vec!["message_index".to_owned(), "notification_fanout".to_owned()],
        PlaintextServiceVisibility::PrivatePlaintext,
    )]);
    registry
        .validate_value(&services_ref, &services.to_value().unwrap())
        .unwrap();
    // Top-level additive keys are warnings, not schema violations.
    let mut leaky_services = services.to_value().unwrap();
    leaky_services["unexpected"] = json!(true);
    let warnings = registry
        .validate_value_with_warnings(&services_ref, &leaky_services)
        .unwrap();
    assert_warns_additional_field(&warnings, "unexpected");
}

#[test]
fn auth_session_fixture_enforces_device_identity_key_separation() {
    let fixture = embedded_json_artifact("fixtures/auth-session-proof-fixture.json").unwrap();
    let vector = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "session_and_device_identity_key_separation")
        .expect("session/device key-separation vector missing");
    for case in vector["cases"].as_array().unwrap() {
        let result = arkret_models_collaboration::session_grant_bodies::validate_session_device_key_separation(
            case["session_public_key_fingerprint"].as_str().unwrap(),
            case["device_public_key_fingerprint"].as_str().unwrap(),
        );
        match case["expected"].as_str().unwrap() {
            "accepted" => result.unwrap(),
            "unauthenticated" => assert!(result.is_err()),
            unexpected => panic!("unknown key-separation outcome {unexpected}"),
        }
    }
}
