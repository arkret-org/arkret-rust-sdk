use arkret_schema::*;
use arkret_wire::EventKind;
use serde_json::json;

mod models {
    pub use arkret_models_collaboration::events_payloads::{
        HistorySharingPolicyPayload, HistorySharingPolicyPayloadValue,
        HistorySharingPolicyPayloadValueAudit, RealmFreezePayload, StrandMoveExpectedPosition,
        StrandMovePayload, StrandReorderExpectedPosition, StrandReorderPayload,
        StrandWatchExpectedValue, StrandWatchLevel, StrandWatchSetPayload,
    };
    pub use arkret_models_collaboration::governance::delivery_binding::DeliveryStatus;
    pub use arkret_models_collaboration::governance::history_visibility::{
        HistoryKeyShareDefault, HistoryKeySource,
    };
    pub use arkret_models_collaboration::governance::invite_addressing::InviteDeliveryTarget;
    pub use arkret_models_collaboration::governance::membership_invite::{
        InviteCancelPayload, InviteCancelTargetState, InviteCreatePayload, InviteRevokePayload,
        InviteRevokeTargetState, MembershipInviteRef, MembershipPayload, MembershipPayloadState,
        RelationCreatePayload, validate_invite_create_wire_keys,
    };
    pub use arkret_models_collaboration::governance::plaintext_visibility::{
        PlaintextServiceVisibility, PlaintextVisibleService, PlaintextVisibleServicesPayload,
    };
    pub use arkret_models_collaboration::governance::realm_lifecycle::{
        HistoryVisibilityPayload, ObjectLifecyclePayload, RealmArchivePayload, RealmDestroyPayload,
        RealmTombstonePayload,
    };
    pub use arkret_models_collaboration::object_patch::ObjectPatchPayload;
    pub use arkret_models_identity::ServiceResolutionCarrier;
    pub use arkret_wire::patch::{Patch, PatchOp};
    pub use arkret_wire::{
        DidCoreId, DidFullId, EventId, Hash, HistoryVisibility, InviteId, PlaintextDataClassKind,
        RealmId, SpaceId, StrandId, project_full_id_to_core_id,
    };
}

use arkret_wire::SchemaId;
use models::*;

#[test]
fn relation_create_payload_strong_type_passes_spec_validator() {
    let catalog = event_payload_validator_catalog().unwrap();
    // No relation id: it is derived from the create Event's event_id.
    let payload = RelationCreatePayload::new(relation_create_object()).with_rank("U");
    catalog
        .validate_payload("ak.relation.create", &payload.to_value().unwrap())
        .unwrap();

    // `fields` is the one open extension container the create shape keeps
    // (`relation.schema.json` declares it), so free edge metadata is accepted.
    let mut with_fields = payload.to_value().unwrap();
    with_fields["relation"]["fields"] = json!({"role": "x"});
    catalog
        .validate_payload("ak.relation.create", &with_fields)
        .unwrap();

    // `effective_scope` is reducer-managed and the create shape bans it.
    let mut reducer_managed = payload.to_value().unwrap();
    reducer_managed["relation"]["effective_scope"] =
        json!({"kind": "realm", "realm_id": FIXTURE_REALM_ID});
    assert!(
        catalog
            .validate_payload("ak.relation.create", &reducer_managed)
            .is_err()
    );

    // The id is derived from the create Event; carrying it is a violation.
    let mut carries_id = payload.to_value().unwrap();
    carries_id["relation"]["id"] =
        json!("ak:relation:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD");
    assert!(
        catalog
            .validate_payload("ak.relation.create", &carries_id)
            .is_err()
    );
}

const FIXTURE_REALM_ID: &str = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";

fn relation_create_object() -> arkret_models_collaboration::objects::relation::Relation {
    arkret_models_collaboration::objects::relation::Relation {
        schema: SchemaId::RELATION_V1.to_owned(),
        id: None,
        realm_id: arkret_wire::RealmId::new(FIXTURE_REALM_ID.to_owned()).unwrap(),
        scope_circle_id: None,
        effective_scope: None,
        relation_kind: arkret_wire::RelationKind::Contains,
        from_ref: "ak:strand:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD".to_owned(),
        to_ref: "ak:strand:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G".to_owned(),
        rank: None,
        fields: Default::default(),
        state: None,
        state_changed_at: None,
        created_by: arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkfixture".to_owned())
            .unwrap(),
        created_at: "2026-08-18T00:00:00.000Z".parse().unwrap(),
        updated_by: None,
        updated_at: None,
    }
}

#[test]
fn membership_payload_strong_type_passes_spec_validator() {
    use crate::models::{DeliveryStatus, MembershipPayload, MembershipPayloadState};
    let catalog = event_payload_validator_catalog().unwrap();

    // invite transition (non-join): only `membership` is structurally required.
    let invite = MembershipPayload::transition(
        MembershipPayloadState::Invite,
        project_full_id_to_core_id(
            &DidFullId::new("did:webvh:z6mkfixturebob:bob.example").unwrap(),
        )
        .unwrap(),
        "space_create",
    );
    catalog
        .validate_payload("ak.member.state", &invite.to_value().unwrap())
        .unwrap();

    // join transition (unroutable): realm_id + actor_id + delivery_status
    // required, but delivery_binding only when routable.
    let join = MembershipPayload::join(
        RealmId::new("ak:realm:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD").unwrap(),
        project_full_id_to_core_id(
            &DidFullId::new("did:webvh:z6mkfixturebob:bob.example").unwrap(),
        )
        .unwrap(),
        DeliveryStatus::Unroutable,
        "invite_accept",
    )
    .with_invite_ref(MembershipInviteRef::Event(
        EventId::new("ak:event:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G").unwrap(),
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
fn split_invite_payload_strong_types_pass_spec_validator() {
    use crate::models::{
        DidCoreId, Hash, InviteCancelPayload, InviteCancelTargetState, InviteCreatePayload,
        InviteDeliveryTarget, InviteId, InviteRevokePayload, InviteRevokeTargetState,
        ServiceResolutionCarrier,
    };
    let catalog = event_payload_validator_catalog().unwrap();

    // Directed-create (anyOf branch: invitee + invite_delivery_target +
    // introduction_evidence_digest + expires_at), with an `x_role` extension.
    let create = InviteCreatePayload::new(
        DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
        InviteDeliveryTarget::principal_server(
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
            ServiceResolutionCarrier::CurrentRecordUrl {
                current_record_url: "https://ps.example/_arkret/open/service-resolution/current"
                    .to_owned(),
                pinned_record_digest: None,
            },
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

    let invite_id =
        InviteId::new("ak:invite:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G").unwrap();
    let invitee = DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap();
    let cancel = InviteCancelPayload::new(
        invite_id.clone(),
        invitee.clone(),
        InviteCancelTargetState::Revoked,
    )
    .with_reason("withdrawn");
    let cancel_value = cancel.to_value().unwrap();
    catalog
        .validate_payload("ak.invite.cancel", &cancel_value)
        .unwrap();
    let revoke = InviteRevokePayload {
        invite_id,
        invitee: Some(invitee),
        target_state: InviteRevokeTargetState::RevokedByInviterLeft,
        reason: Some("inviter_left".to_owned()),
    };
    catalog
        .validate_payload("ak.invite.revoke", &serde_json::to_value(revoke).unwrap())
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
        RealmId::new("ak:realm:ARkAfriCBkEJNgK9UxfUciMBt-L3mtRcFLO8ICOBW_9K").unwrap(),
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
    leaky["successor_realm_id"] = json!("ak:realm:AVhs1OILt1ULQUp4a0L9nz73K8MGcMB1ZFIHsJoNmNYW");
    assert!(
        catalog
            .validate_payload("ak.realm.archive", &leaky)
            .is_err()
    );
}

#[test]
fn strand_lifecycle_payloads_strong_types_pass_spec_validator() {
    use crate::models::{
        DidFullId, ObjectLifecyclePayload, SpaceId, StrandId, StrandMovePayload,
        StrandReorderExpectedPosition, StrandReorderPayload, StrandWatchExpectedValue,
        StrandWatchLevel, StrandWatchSetPayload, project_full_id_to_core_id,
    };
    let catalog = event_payload_validator_catalog().unwrap();
    let board = || SpaceId::new("ak:space:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD").unwrap();
    let target = || SpaceId::new("ak:space:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G").unwrap();
    let strand =
        || StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap();
    let actor = || {
        project_full_id_to_core_id(
            &DidFullId::new("did:webvh:z6mkfixturealice:alice.example").unwrap(),
        )
        .unwrap()
    };

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
    let archive =
        ObjectLifecyclePayload::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9")
            .with_target_state("archived")
            .with_reason("season closed");
    catalog
        .validate_payload("ak.strand.archive", &archive.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            "ak.strand.restore",
            &ObjectLifecyclePayload::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9")
                .to_value()
                .unwrap(),
        )
        .unwrap();

    // Closed payload schemas reject unknown additive keys.
    let mut leaky = mv.to_value().unwrap();
    leaky["list_space_id"] = json!("ak:space:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G");
    assert!(catalog.validate_payload("ak.strand.move", &leaky).is_err());
}

#[test]
fn realm_state_payloads_strong_types_match_named_spec_defs() {
    // Validate the strong types directly against the named `$defs/*_payload`
    // schema_ref so this test stays pinned to the exact artifact shape.
    use crate::models::{
        HistoryKeyShareDefault, HistoryKeySource, HistorySharingPolicyPayload,
        HistorySharingPolicyPayloadValue, HistorySharingPolicyPayloadValueAudit, HistoryVisibility,
        HistoryVisibilityPayload, PlaintextDataClassKind, PlaintextServiceVisibility,
        PlaintextVisibleService, PlaintextVisibleServicesPayload,
    };
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let registry = schema_registry_from_spec_artifacts(&artifacts_dir).unwrap();
    let catalog = event_payload_validator_catalog_from_spec_artifacts(&artifacts_dir).unwrap();
    let history_ref = format!(
        "{schemaid_event_payload_v1}#/$defs/history_visibility_payload",
        schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
    );
    let history_policy_ref = format!(
        "{schemaid_event_payload_v1}#/$defs/history_sharing_policy_payload",
        schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
    );
    let services_ref = format!(
        "{schemaid_event_payload_v1}#/$defs/plaintext_visible_services_payload",
        schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
    );

    // history_visibility: non-restricted value carries just `{value}`.
    let shared = HistoryVisibilityPayload::new(HistoryVisibility::Shared);
    registry
        .validate_value(&history_ref, &shared.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            EventKind::RealmHistoryVisibility.as_str(),
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
    // The named payload definition is closed at the top level.
    let mut leaky = shared.to_value().unwrap();
    leaky["unexpected"] = json!(true);
    assert!(registry.validate_value(&history_ref, &leaky).is_err());

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
            EventKind::RealmHistorySharingPolicy.as_str(),
            &history_policy_value,
        )
        .unwrap();

    // plaintext_visible_services: required item fields strongly typed.
    let services = PlaintextVisibleServicesPayload::new(vec![PlaintextVisibleService::new(
        DidCoreId::new("ak:did_core:webvh:z6mkfixtureindex").unwrap(),
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
    // The payload is closed at the top level even though service entries
    // remain forward-compatible.
    let mut leaky_services = services.to_value().unwrap();
    leaky_services["unexpected"] = json!(true);
    assert!(
        registry
            .validate_value(&services_ref, &leaky_services)
            .is_err()
    );
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

#[test]
fn object_patch_payload_matches_registered_event_payload_schema() {
    use models::{ObjectPatchPayload, Patch, PatchOp};

    let mut patch = Patch::new();
    patch.insert_op("title", PatchOp::set("Roadmap")).unwrap();
    let payload = ObjectPatchPayload::for_target(
        "ak:morph:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL",
        patch,
    )
    .unwrap()
    .to_value()
    .unwrap();

    event_payload_validator_catalog()
        .unwrap()
        .validate_payload("ak.morph.update", &payload)
        .unwrap();
}
