use arkret_schema::*;
use arkret_wire::EventKind;
use serde_json::json;

mod models {
    pub use arkret_models_collaboration::events_payloads::{
        RealmFreezePayload, StrandMoveExpectedPosition, StrandMovePayload,
        StrandReorderExpectedPosition, StrandReorderPayload, StrandWatchExpectedValue,
        StrandWatchLevel, StrandWatchSetPayload,
    };
    pub use arkret_models_collaboration::governance::membership_invite::{
        InviteCancelPayload, InviteCancelTargetState, InviteCreatePayload, InviteRevokePayload,
        InviteRevokeTargetState, MembershipInviteRef, MembershipPayload, MembershipPayloadState,
        RelationCreatePayload, validate_invite_create_wire_keys,
    };
    pub use arkret_models_collaboration::governance::plaintext_visibility::{
        PlaintextServiceVisibility, PlaintextVisibleService, PlaintextVisibleServicesPayload,
    };
    pub use arkret_models_collaboration::governance::realm_lifecycle::{
        HistoryAccessPayload, ObjectLifecyclePayload, RealmArchivePayload, RealmDestroyPayload,
        RealmTombstonePayload,
    };
    pub use arkret_wire::patch::{Patch, PatchOp};
    pub use arkret_wire::{
        AccountId, ActorId, Did, DidCoreId, EventId, Hash, HistoryAccess, InviteId,
        PlaintextDataClassKind, RealmId, SpaceId, StrandId, project_did_to_core_id,
    };
}

use arkret_wire::SchemaId;
use models::*;

#[test]
fn moderation_decision_rejects_retired_policy_server_field() {
    use arkret_models_collaboration::events_payloads::moderation::ModerationDecisionPayload;

    let catalog = event_payload_validator_catalog().unwrap();
    let value = json!({
        "target_ref": "ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "decision": "quarantine",
        "issuer_id": "ak:did_core:web:moderator.example",
        "request_canonical_digest": format!("sha256:{}", "11".repeat(32))
    });
    catalog
        .validate_payload("ak.moderation.decision", &value)
        .unwrap();
    let payload: ModerationDecisionPayload = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(payload).unwrap(), value);

    for retired_ref in [
        json!(null),
        json!("ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"),
        json!({"request_canonical_digest": value["request_canonical_digest"]}),
    ] {
        let mut retired = value.clone();
        retired["policy_decision_ref"] = retired_ref;
        assert!(
            catalog
                .validate_payload("ak.moderation.decision", &retired)
                .is_err()
        );
        assert!(serde_json::from_value::<ModerationDecisionPayload>(retired).is_err());
    }
}

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
        realm_id: RealmId::new(FIXTURE_REALM_ID.to_owned()).unwrap(),
        scope_circle_id: None,
        effective_scope: None,
        relation_kind: arkret_wire::RelationKind::Contains,
        from_ref: "ak:strand:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD".into(),
        to_ref: "ak:strand:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G".into(),
        rank: None,
        fields: Default::default(),
        state: None,
        state_changed_at: None,
        created_by: ActorId::service(
            DidCoreId::new("ak:did_core:webvh:z6mkfixture".to_owned()).unwrap(),
        ),
        created_at: "2026-08-18T00:00:00.000Z".parse().unwrap(),
        updated_by: None,
        updated_at: None,
    }
}

#[test]
fn membership_payload_strong_type_passes_spec_validator() {
    use crate::models::{AccountId, ActorId, DidCoreId, MembershipPayload, MembershipPayloadState};
    let catalog = event_payload_validator_catalog().unwrap();

    // knock transition (non-join): only `membership` is structurally required.
    let invite = MembershipPayload::transition(
        MembershipPayloadState::Knock,
        ActorId::service(
            project_did_to_core_id(&Did::new("did:webvh:z6mkfixturebob:bob.example").unwrap())
                .unwrap(),
        ),
        "space_create",
    );
    catalog
        .validate_payload("ak.member.state", &invite.to_value().unwrap())
        .unwrap();

    // join transition: realm_id + closed account identity are required.
    let mut join = MembershipPayload::join(
        RealmId::new("ak:realm:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD").unwrap(),
        ActorId::account(AccountId::new(
            project_did_to_core_id(&Did::new("did:webvh:z6mkfixturebob:bob.example").unwrap())
                .unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixturestation".to_owned()).unwrap(),
        )),
        "invite_accept",
    );
    join.invite_ref = Some(MembershipInviteRef::Event(
        EventId::new("ak:event:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G").unwrap(),
    ));
    catalog
        .validate_payload("ak.member.state", &join.to_value().unwrap())
        .unwrap();

    // Closed payload schemas reject unknown additive keys.
    let mut leaky = invite.to_value().unwrap();
    leaky["handle"] = json!("bob:example.com");
    assert!(catalog.validate_payload("ak.member.state", &leaky).is_err());
}

#[test]
fn split_invite_payload_strong_types_pass_spec_validator() {
    use crate::models::{
        AccountId, DidCoreId, Hash, InviteCancelPayload, InviteCancelTargetState,
        InviteCreatePayload, InviteId, InviteRevokePayload, InviteRevokeTargetState,
    };
    let catalog = event_payload_validator_catalog().unwrap();

    // Directed-create with a closed invitee account identity and an `x_role` extension.
    let invitee = AccountId::new(
        DidCoreId::new("ak:did_core:webvh:z6mkfixturebob".to_owned()).unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixturestation".to_owned()).unwrap(),
    );
    let create = InviteCreatePayload::new(
        invitee.clone(),
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
    decoded.invitee_account_id.validate().unwrap();
    let mut leaky_create = create_value;
    leaky_create["hlc"] = json!("2026-06-14T10:00:00.000Z/node/1");
    assert!(validate_invite_create_wire_keys(&leaky_create).is_err());

    let invite_id =
        InviteId::new("ak:invite:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G").unwrap();
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
        invitee_account_id: Some(invitee),
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

/// The 2026-08-20 ruling (0550) registered the optional lifecycle timestamps
/// the strong types already carried: `effective_at` on the four lifecycle
/// payload defs, `freeze_expires_at` on `realm_freeze_payload` and on
/// `realm_lifecycle_view`. Pin both directions per def: an instance carrying
/// the new field validates, and one without it still validates (optional
/// semantics — absence is never serialized).
#[test]
fn lifecycle_optional_timestamps_pass_spec_schemas() {
    use chrono::{DateTime, Utc};

    let catalog = event_payload_validator_catalog().unwrap();
    let at = || {
        DateTime::parse_from_rfc3339("2026-08-20T01:02:03Z")
            .unwrap()
            .with_timezone(&Utc)
    };
    let strand_ref = "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";

    // object_lifecycle_payload (carried by e.g. ak.strand.archive).
    let mut lifecycle = ObjectLifecyclePayload::new(strand_ref);
    catalog
        .validate_payload("ak.strand.archive", &lifecycle.to_value().unwrap())
        .unwrap();
    lifecycle.effective_at = Some(at());
    let value = lifecycle.to_value().unwrap();
    assert_eq!(value["effective_at"], json!("2026-08-20T01:02:03.000Z"));
    catalog
        .validate_payload("ak.strand.archive", &value)
        .unwrap();

    // realm_archive_payload.
    let mut archive = RealmArchivePayload::new(true);
    catalog
        .validate_payload("ak.realm.archive", &archive.to_value().unwrap())
        .unwrap();
    archive.effective_at = Some(at());
    catalog
        .validate_payload("ak.realm.archive", &archive.to_value().unwrap())
        .unwrap();

    // realm_destroy_payload.
    let mut destroy = RealmDestroyPayload::new("permanent retirement");
    catalog
        .validate_payload("ak.realm.destroy", &destroy.to_value().unwrap())
        .unwrap();
    destroy.effective_at = Some(at());
    catalog
        .validate_payload("ak.realm.destroy", &destroy.to_value().unwrap())
        .unwrap();

    // realm_tombstone_payload.
    let mut tombstone = RealmTombstonePayload::new(
        RealmId::new("ak:realm:ARkAfriCBkEJNgK9UxfUciMBt-L3mtRcFLO8ICOBW_9K").unwrap(),
        "migrated to successor",
    );
    catalog
        .validate_payload("ak.realm.tombstone", &tombstone.to_value().unwrap())
        .unwrap();
    tombstone.effective_at = Some(at());
    catalog
        .validate_payload("ak.realm.tombstone", &tombstone.to_value().unwrap())
        .unwrap();

    // realm_freeze_payload: effective_at + freeze_expires_at.
    let freeze = RealmFreezePayload::new(true);
    let bare = freeze.to_value().unwrap();
    assert!(bare.get("effective_at").is_none());
    assert!(bare.get("freeze_expires_at").is_none());
    catalog.validate_payload("ak.realm.freeze", &bare).unwrap();
    let mut freeze = freeze;
    freeze.freeze_expires_at = Some(at());
    freeze.effective_at = Some(at());
    let value = freeze.to_value().unwrap();
    assert_eq!(
        value["freeze_expires_at"],
        json!("2026-08-20T01:02:03.000Z")
    );
    catalog.validate_payload("ak.realm.freeze", &value).unwrap();

    // realm_lifecycle_view: freeze_expires_at on the read-side DTO.
    let registry = schema_registry_from_default_spec_artifacts()
        .unwrap()
        .expect("spec artifact registry available (live co-checkout or embedded)");
    let view_ref = format!(
        "{}#/$defs/realm_lifecycle_view",
        SchemaId::REALM_READ_OPERATIONS_V1
    );
    let mut view = arkret_models_collaboration::governance::realm_governance::RealmLifecycleView {
        realm_id: RealmId::new("ak:realm:ARkAfriCBkEJNgK9UxfUciMBt-L3mtRcFLO8ICOBW_9K").unwrap(),
        owner_id: DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
        member_ids: vec![ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixturestation").unwrap(),
        ))],
        deleted: false,
        archived: false,
        frozen: true,
        terminal_state: None,
        successor_realm_id: None,
        freeze_expires_at: None,
    };
    registry
        .validate_value(&view_ref, &serde_json::to_value(&view).unwrap())
        .unwrap();
    view.freeze_expires_at = Some(at());
    let value = serde_json::to_value(&view).unwrap();
    assert_eq!(
        value["freeze_expires_at"],
        json!("2026-08-20T01:02:03.000Z")
    );
    registry.validate_value(&view_ref, &value).unwrap();
}

#[test]
fn strand_lifecycle_payloads_strong_types_pass_spec_validator() {
    use crate::models::{
        Did, ObjectLifecyclePayload, SpaceId, StrandId, StrandMovePayload,
        StrandReorderExpectedPosition, StrandReorderPayload, StrandWatchExpectedValue,
        StrandWatchLevel, StrandWatchSetPayload, project_did_to_core_id,
    };
    let catalog = event_payload_validator_catalog().unwrap();
    let board = || SpaceId::new("ak:space:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD").unwrap();
    let target = || SpaceId::new("ak:space:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G").unwrap();
    let strand =
        || StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap();
    let actor = || {
        ActorId::account(AccountId::new(
            project_did_to_core_id(&Did::new("did:webvh:z6mkfixturealice:alice.example").unwrap())
                .unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixturestation").unwrap(),
        ))
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
    let mut guarded =
        StrandWatchSetPayload::set(strand(), actor(), StrandWatchLevel::Participating, None);
    guarded.expected_value = Some(StrandWatchExpectedValue {
        level: StrandWatchLevel::Muted,
        level_public: None,
    });
    catalog
        .validate_payload("ak.strand.watch.set", &guarded.to_value().unwrap())
        .unwrap();
    // expected_value may also assert "no prior cell" via null.
    let guarded_null = StrandWatchSetPayload::set(strand(), actor(), StrandWatchLevel::All, None);
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
        HistoryAccess, HistoryAccessPayload, PlaintextDataClassKind, PlaintextServiceVisibility,
        PlaintextVisibleService, PlaintextVisibleServicesPayload,
    };
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let registry = schema_registry_from_spec_artifacts(&artifacts_dir).unwrap();
    let catalog = event_payload_validator_catalog_from_spec_artifacts(&artifacts_dir).unwrap();
    let history_ref = format!(
        "{schemaid_event_payload_v1}#/$defs/history_access_payload",
        schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
    );
    let services_ref = format!(
        "{schemaid_event_payload_v1}#/$defs/plaintext_visible_services_payload",
        schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
    );

    let initial = HistoryAccessPayload::initialize(HistoryAccess::AllHistoryForCurrentMembers);
    registry
        .validate_value(&history_ref, &initial.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            EventKind::RealmHistoryAccess.as_str(),
            &initial.to_value().unwrap(),
        )
        .unwrap();
    let tightened = HistoryAccessPayload::tighten();
    registry
        .validate_value(&history_ref, &tightened.to_value().unwrap())
        .unwrap();
    let mut leaky = initial.to_value().unwrap();
    leaky["unexpected"] = json!(true);
    assert!(registry.validate_value(&history_ref, &leaky).is_err());

    // plaintext_visible_services: required item fields strongly typed.
    let services = PlaintextVisibleServicesPayload::new(vec![PlaintextVisibleService::new(
        DidCoreId::new("ak:did_core:webvh:z6mkfixtureindex").unwrap(),
        "station",
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
fn typed_patch_payloads_match_registered_event_payload_schemas() {
    use arkret_models_collaboration::events_payloads::{
        MorphUpdatePayload, SpacePatchPayload, StrandPatchPayload,
    };

    let mut patch = Patch::new();
    patch
        .insert_op("metadata.title", PatchOp::set("Roadmap"))
        .unwrap();
    let strand = StrandPatchPayload::for_strand(
        StrandId::new("ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL").unwrap(),
        patch.clone(),
    )
    .unwrap();
    let mut space_patch = Patch::new();
    space_patch
        .insert_op("title", PatchOp::set("Roadmap"))
        .unwrap();
    let space = SpacePatchPayload {
        space_id: SpaceId::new("ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL").unwrap(),
        patch: space_patch,
        expected_state_digest: None,
    };
    let morph = MorphUpdatePayload::for_morph(
        arkret_wire::MorphId::new("ak:morph:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL").unwrap(),
        patch.clone(),
    )
    .unwrap();

    let catalog = event_payload_validator_catalog().unwrap();
    for (kind, target_field, payload) in [
        ("ak.strand.update", "target_ref", strand.to_value().unwrap()),
        (
            "ak.space.update",
            "space_id",
            serde_json::to_value(space).unwrap(),
        ),
        ("ak.morph.update", "target_ref", morph.to_value().unwrap()),
    ] {
        catalog.validate_payload(kind, &payload).unwrap();
        let path = if kind == "ak.space.update" {
            "title"
        } else {
            "metadata.title"
        };
        assert_eq!(
            payload["patch"][path],
            json!({"$op": "set", "value": "Roadmap"})
        );
        assert_eq!(payload["patch"].as_object().unwrap().len(), 1);
        assert_eq!(payload.as_object().unwrap().len(), 2);

        let mut alias = payload.clone();
        alias["object_ref"] = payload[target_field].clone();
        assert!(catalog.validate_payload(kind, &alias).is_err());

        let mut untargeted = payload.clone();
        untargeted.as_object_mut().unwrap().remove(target_field);
        assert!(catalog.validate_payload(kind, &untargeted).is_err());

        let mut wrong_target = payload.clone();
        wrong_target[target_field] =
            json!("ak:message:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL");
        assert!(catalog.validate_payload(kind, &wrong_target).is_err());

        let mut malformed_target = payload.clone();
        let prefix = payload[target_field]
            .as_str()
            .unwrap()
            .rsplit_once(':')
            .unwrap()
            .0;
        malformed_target[target_field] = json!(format!("{prefix}:not-a-typed-id"));
        assert!(catalog.validate_payload(kind, &malformed_target).is_err());

        let mut empty_patch = payload;
        empty_patch["patch"] = json!({});
        assert!(catalog.validate_payload(kind, &empty_patch).is_err());
    }
}
