use super::artifacts::registry_entry;
use super::*;

#[test]
fn schema_catalog_reports_all_registered_schemas() {
    let catalog = schema_catalog();
    catalog.validate().unwrap();
    assert!(catalog.entries.iter().any(|entry| entry.schema_id == EVENT_SCHEMA));
}

#[test]
fn schema_vectors_include_negative_security_extension_case() {
    validate_schema_vectors(&built_in_schema_vectors()).unwrap();
}

#[test]
fn event_payload_catalog_validates_known_payload_fields() {
    let catalog = event_payload_validator_catalog();
    // `ck.flow.move` payload requires Space container ids:
    // `board_space_id` (ck:space prefix) + `target_space_id`.
    catalog
        .validate_payload(
            "ck.flow.move",
            &json!({
                "board_space_id": "ck:space:01904100-0000-7000-8000-111111111111",
                "flow_id": "ck:flow:01904100-0000-7000-8000-6c663fa0205f",
                "target_space_id": "ck:space:01904100-0000-7000-8000-222222222222",
                "rank": "U"
            }),
        )
        .unwrap();
    assert!(matches!(
        catalog.validate_payload(
            "ck.flow.move",
            &json!({
                "flow_id": "ck:flow:01904100-0000-7000-8000-6c663fa0205f",
                "target_space_id": "ck:space:01904100-0000-7000-8000-222222222222",
                "rank": "U"
            })
        ),
        Err(Error::Protocol(_))
    ));
}

#[test]
fn relation_create_payload_strong_type_passes_spec_validator() {
    let catalog = event_payload_validator_catalog();
    let payload = crate::model::RelationCreatePayload::new(
        "ck.relation.parent_of",
        "ck:flow:01904100-0000-7000-8000-111111111111",
        "ck:flow:01904100-0000-7000-8000-222222222222",
    )
    .with_rank("U");
    catalog.validate_payload("ck.relation.create", &payload.to_value().unwrap()).unwrap();

    // deny_unknown_fields: the legacy illegal keys (relation_id / fields /
    // scope_circle_id) are not representable and would be rejected by the
    // spec validator if injected.
    let mut leaky = payload.to_value().unwrap();
    leaky["fields"] = json!({"role": "x"});
    assert!(matches!(
        catalog.validate_payload("ck.relation.create", &leaky),
        Err(Error::Protocol(_))
    ));
}

#[test]
fn membership_payload_strong_type_passes_spec_validator() {
    use crate::model::{DeliveryStatus, MembershipPayload, MembershipPayloadState};
    let catalog = event_payload_validator_catalog();

    // invite transition (non-join): only `membership` is structurally required.
    let invite = MembershipPayload::transition(
        MembershipPayloadState::Invite,
        crate::model::Did::new("did:web:bob.example").unwrap(),
        "space_create",
    );
    catalog.validate_payload("ck.member.state", &invite.to_value().unwrap()).unwrap();

    // join transition (unroutable): realm_id + actor_id + delivery_status
    // required, but delivery_binding only when routable.
    let join = MembershipPayload::join(
        crate::model::RealmId::new("ck:realm:01904100-0000-7000-8000-111111111111").unwrap(),
        crate::model::Did::new("did:web:bob.example").unwrap(),
        DeliveryStatus::Unroutable,
        "invite_accept",
    )
    .with_invite_ref("ck:event:01904100-0000-7000-8000-222222222222");
    catalog.validate_payload("ck.member.state", &join.to_value().unwrap()).unwrap();

    // join missing delivery_status is rejected by to_value (conditional req).
    let mut bad = join.clone();
    bad.delivery_status = None;
    assert!(matches!(bad.to_value(), Err(Error::Protocol(_))));

    // deny_unknown_fields: the legacy illegal `handle` key would be rejected
    // by the spec validator (membership_payload is additionalProperties:false).
    let mut leaky = invite.to_value().unwrap();
    leaky["handle"] = json!("bob:example.com");
    assert!(matches!(catalog.validate_payload("ck.member.state", &leaky), Err(Error::Protocol(_))));
}

#[test]
fn invite_payload_strong_types_pass_spec_validator() {
    use crate::model::{
        Did, Hash, InviteCreatePayload, InviteDeliveryTarget, InviteId, InviteRefPayload,
    };
    let catalog = event_payload_validator_catalog();

    // Directed-create (anyOf branch: invitee + invite_delivery_target +
    // introduction_evidence_digest + expires_at), with an `x_role` extension.
    let create = InviteCreatePayload::new(
        InviteId::new("ck:invite:01904100-0000-7000-8000-111111111111").unwrap(),
        Did::new("did:web:bob.example").unwrap(),
        InviteDeliveryTarget::principal_server(Did::new("did:web:ps.example").unwrap()),
        Hash::new("sha256:".to_owned() + &"a".repeat(64)).unwrap(),
        chrono::Utc::now() + chrono::Duration::days(7),
    )
    .with_extension("role", json!("member"));
    let create_value = create.to_value().unwrap();
    assert_eq!(create_value["x_role"], "member");
    catalog.validate_payload("ck.invite.create", &create_value).unwrap();

    // invite_id ref form (accept / cancel).
    let cancel = InviteRefPayload::new(
        InviteId::new("ck:invite:01904100-0000-7000-8000-222222222222").unwrap(),
    )
    .with_reason("withdrawn");
    catalog.validate_payload("ck.invite.cancel", &cancel.to_value().unwrap()).unwrap();
}

#[test]
fn realm_lifecycle_payloads_strong_types_pass_spec_validator() {
    use crate::model::{RealmArchivePayload, RealmDestroyPayload, RealmId, RealmTombstonePayload};
    let catalog = event_payload_validator_catalog();

    // ck.realm.archive: reversible boolean register; `archived:false` un-archives.
    let archive = RealmArchivePayload::new(true).with_reason("retiring legacy realm");
    catalog.validate_payload("ck.realm.archive", &archive.to_value().unwrap()).unwrap();
    catalog
        .validate_payload("ck.realm.archive", &RealmArchivePayload::new(false).to_value().unwrap())
        .unwrap();

    // ck.realm.tombstone: reason + successor_realm_id both required by spec.
    let tombstone = RealmTombstonePayload::new(
        RealmId::new("ck:realm:01904100-0000-7000-8000-333333333333").unwrap(),
        "migrated to successor",
    );
    catalog.validate_payload("ck.realm.tombstone", &tombstone.to_value().unwrap()).unwrap();

    // ck.realm.destroy: reason required; verification_stub_required omitted so
    // the reducer applies its default (true).
    let destroy = RealmDestroyPayload::new("permanent retirement");
    catalog.validate_payload("ck.realm.destroy", &destroy.to_value().unwrap()).unwrap();

    // deny_unknown_fields: an illegal key on any of these is rejected by the
    // spec validator (all three defs are additionalProperties:false).
    let mut leaky = archive.to_value().unwrap();
    leaky["successor_realm_id"] = json!("ck:realm:01904100-0000-7000-8000-444444444444");
    assert!(matches!(
        catalog.validate_payload("ck.realm.archive", &leaky),
        Err(Error::Protocol(_))
    ));
}

#[test]
fn flow_lifecycle_payloads_strong_types_pass_spec_validator() {
    use crate::model::{
        Did, FlowId, FlowMovePayload, FlowReorderExpectedPosition, FlowReorderPayload,
        FlowWatchExpectedValue, FlowWatchLevel, FlowWatchSetPayload, ObjectLifecyclePayload,
        SpaceId,
    };
    let catalog = event_payload_validator_catalog();
    let board = || SpaceId::new("ck:space:01904100-0000-7000-8000-111111111111").unwrap();
    let target = || SpaceId::new("ck:space:01904100-0000-7000-8000-222222222222").unwrap();
    let flow = || FlowId::new("ck:flow:01904100-0000-7000-8000-6c663fa0205f").unwrap();
    let actor = || Did::new("did:web:alice.example").unwrap();

    // ck.flow.move — board/target Space ids + rank; from_space_id +
    // expected_position optional. Destination is single-sourced by
    // target_space_id (a stray `list_space_id` would be rejected).
    let mv = FlowMovePayload::new(board(), flow(), target(), "U")
        .with_from_space_id(board())
        .with_expected_position(crate::model::FlowMoveExpectedPosition {
            space_id: Some(board()),
            rank: Some("T".to_owned()),
            relation_id: None,
        });
    catalog.validate_payload("ck.flow.move", &mv.to_value().unwrap()).unwrap();

    // ck.flow.reorder — single List Space (`space_id`); no destination field.
    let reorder = FlowReorderPayload::new(board(), flow(), target(), "V").with_expected_position(
        FlowReorderExpectedPosition { rank: Some("U".to_owned()), relation_id: None },
    );
    catalog.validate_payload("ck.flow.reorder", &reorder.to_value().unwrap()).unwrap();

    // ck.flow.watch.set — concrete level + clear (level:null) + CAS guard.
    let set = FlowWatchSetPayload::set(flow(), actor(), FlowWatchLevel::All, Some(true));
    catalog.validate_payload("ck.flow.watch.set", &set.to_value().unwrap()).unwrap();
    let cleared = FlowWatchSetPayload::clear(flow(), actor());
    let cleared_value = cleared.to_value().unwrap();
    assert!(cleared_value["level"].is_null());
    // allOf: level_public MUST be omitted when level is null.
    assert!(cleared_value.get("level_public").is_none());
    catalog.validate_payload("ck.flow.watch.set", &cleared_value).unwrap();
    let guarded = FlowWatchSetPayload::set(flow(), actor(), FlowWatchLevel::Participating, None)
        .with_expected_value(Some(FlowWatchExpectedValue {
            level: FlowWatchLevel::Muted,
            level_public: None,
        }));
    catalog.validate_payload("ck.flow.watch.set", &guarded.to_value().unwrap()).unwrap();
    // expected_value may also assert "no prior cell" via null.
    let guarded_null = FlowWatchSetPayload::set(flow(), actor(), FlowWatchLevel::All, None)
        .with_expected_value(None);
    let guarded_null_value = guarded_null.to_value().unwrap();
    assert!(guarded_null_value["expected_value"].is_null());
    catalog.validate_payload("ck.flow.watch.set", &guarded_null_value).unwrap();

    // ck.flow.archive / ck.flow.restore — object_lifecycle_payload, single
    // truth source `target_ref`.
    let archive = ObjectLifecyclePayload::new("ck:flow:01904100-0000-7000-8000-6c663fa0205f")
        .with_target_state("archived")
        .with_reason("season closed");
    catalog.validate_payload("ck.flow.archive", &archive.to_value().unwrap()).unwrap();
    catalog
        .validate_payload(
            "ck.flow.restore",
            &ObjectLifecyclePayload::new("ck:flow:01904100-0000-7000-8000-6c663fa0205f")
                .to_value()
                .unwrap(),
        )
        .unwrap();

    // deny_unknown_fields: a stray destination key on ck.flow.move is rejected
    // (additionalProperties:false on flow_move_payload).
    let mut leaky = mv.to_value().unwrap();
    leaky["list_space_id"] = json!("ck:space:01904100-0000-7000-8000-222222222222");
    assert!(matches!(catalog.validate_payload("ck.flow.move", &leaky), Err(Error::Protocol(_))));
}

#[test]
fn realm_state_payloads_strong_types_match_named_spec_defs() {
    // The kind→def resolver routes these realm-state kinds to the lenient
    // `generic_standard_payload`, so we validate the strong types DIRECTLY
    // against their named `$defs/*_payload` schema_ref (the shape these defs
    // describe) rather than via `validate_payload(kind, …)`.
    use crate::model::{
        Did, HistoryVisibility, HistoryVisibilityPayload, PlaintextDataClassKind,
        PlaintextServiceVisibility, PlaintextVisibleService, PlaintextVisibleServicesPayload,
    };
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let registry = schema_registry_from_spec_artifacts(artifacts_dir).unwrap();
    let history_ref = format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/history_visibility_payload");
    let services_ref = format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/plaintext_visible_services_payload");

    // history_visibility: non-restricted value carries just `{value}`.
    let shared = HistoryVisibilityPayload::new(HistoryVisibility::Shared);
    registry.validate_value(&history_ref, &shared.to_value().unwrap()).unwrap();
    // restricted requires restricted_policy_digest (schema allOf); to_value
    // refuses to emit a non-conformant restricted payload.
    assert!(HistoryVisibilityPayload::new(HistoryVisibility::Restricted).to_value().is_err());
    let restricted = HistoryVisibilityPayload::restricted("sha256:".to_owned() + &"a".repeat(64));
    registry.validate_value(&history_ref, &restricted.to_value().unwrap()).unwrap();
    // deny_unknown_fields: an unknown key is rejected by the named def
    // (additionalProperties:false).
    let mut leaky = shared.to_value().unwrap();
    leaky["unexpected"] = json!(true);
    assert!(registry.validate_value(&history_ref, &leaky).is_err());

    // plaintext_visible_services: required item fields strongly typed.
    let services = PlaintextVisibleServicesPayload::new(vec![PlaintextVisibleService::new(
        Did::new("did:web:index.example").unwrap(),
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
    registry.validate_value(&services_ref, &services.to_value().unwrap()).unwrap();
    // top-level additionalProperties:false on the payload.
    let mut leaky_services = services.to_value().unwrap();
    leaky_services["unexpected"] = json!(true);
    assert!(registry.validate_value(&services_ref, &leaky_services).is_err());
}

#[test]
fn artifact_payload_catalog_covers_active_durable_event_kinds() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let bundle = SpecArtifactBundle::load(&artifacts_dir).unwrap();
    let catalog = event_payload_validator_catalog_from_spec_artifacts(&artifacts_dir).unwrap();
    let durable_event_kinds = bundle.event_kind_registry["event_kinds"]
        .as_array()
        .expect("event_kinds array")
        .iter()
        .filter(|entry| entry["status"].as_str() == Some("active"))
        .filter(|entry| entry["wire_scope"].as_str() == Some("durable_event"))
        .filter_map(|entry| entry["event_kind"].as_str())
        .filter(|event_kind| crate::events::is_standard_event_kind(event_kind))
        .collect::<Vec<_>>();
    let missing = catalog.missing_payload_validators_for(durable_event_kinds.iter().copied());
    assert!(missing.is_empty(), "missing payload validators: {missing:?}");
    assert!(
        catalog.rules.len() > 7,
        "artifact-derived payload catalog should not collapse to old hand-written rules"
    );
}

#[test]
fn artifact_payload_catalog_enforces_deep_schema_rules() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    // `ck.flow.move` requires current Space container ids:
    // `board_space_id` and `target_space_id`.
    catalog
        .validate_payload(
            crate::events::FLOW_MOVE,
            &json!({
                "board_space_id": "ck:space:01904100-0000-7000-8000-111111111111",
                "flow_id": "ck:flow:01904100-0000-7000-8000-6c663fa0205f",
                "target_space_id": "ck:space:01904100-0000-7000-8000-222222222222",
                "rank": "U"
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                crate::events::FLOW_MOVE,
                &json!({
                    "board_space_id": "not-a-space-id",
                    "flow_id": "ck:flow:01904100-0000-7000-8000-6c663fa0205f",
                    "target_space_id": "ck:space:01904100-0000-7000-8000-222222222222",
                    "rank": "U"
                }),
            )
            .is_err()
    );
    assert!(
        catalog
            .validate_payload(
                crate::events::FLOW_MOVE,
                &json!({
                    "board_space_id": "ck:space:01904100-0000-7000-8000-111111111111",
                    "flow_id": "ck:flow:01904100-0000-7000-8000-6c663fa0205f",
                    "target_space_id": "ck:space:01904100-0000-7000-8000-222222222222",
                    "rank": "U",
                    "unexpected": true
                }),
            )
            .is_err()
    );
}

#[test]
fn artifact_payload_catalog_prefers_registered_specialized_defs_over_name_matches() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();

    assert_eq!(
        catalog.rules["ck.space.archive"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/space_state_transition_payload")
    );
    assert_eq!(
        catalog.rules["ck.space.restore"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/space_state_transition_payload")
    );
    assert_eq!(
        catalog.rules["ck.space.tombstone"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/space_object_tombstone_payload")
    );

    catalog
        .validate_payload(
            "ck.space.archive",
            &json!({
                "space_id": "ck:space:01904100-0000-7000-8000-111111111111",
                "reason": "done"
            }),
        )
        .unwrap();
    assert!(catalog.validate_payload("ck.space.archive", &json!({ "archived": true })).is_err());
}

#[test]
fn artifact_payload_catalog_maps_object_patch_event_family_to_object_patch_payload() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    let object_patch_kinds = [
        "ck.realm.update",
        "ck.flow.update",
        "ck.morph.update",
        "ck.space.update",
        "ck.profile.update",
    ];
    for event_kind in object_patch_kinds {
        let patch = if matches!(event_kind, "ck.flow.update" | "ck.morph.update") {
            json!({ "metadata.title": { "$op": "set", "value": "Roadmap" } })
        } else {
            json!({ "title": { "$op": "set", "value": "Roadmap" } })
        };
        assert_eq!(
            catalog.rules[event_kind].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/object_patch_payload"),
            "{event_kind} must use the shared object_patch_payload schema"
        );
        catalog
            .validate_payload(
                event_kind,
                &json!({
                    "target_ref": "ck:realm:0196419b-0000-7000-8000-000000000001",
                "patch": patch
                }),
            )
            .unwrap_or_else(|err| panic!("{event_kind} should accept object_patch_payload: {err}"));
    }
    // ck.profile.realm_override carries a Realm-scoped override and needs
    // target_realm_id in addition to target_ref+patch, so the spec gives it a
    // dedicated profile_realm_override_payload def rather than folding it into
    // the generic object_patch_payload.
    assert_eq!(
        catalog.rules["ck.profile.realm_override"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/profile_realm_override_payload"),
        "ck.profile.realm_override must use the dedicated profile_realm_override_payload schema"
    );
    catalog
        .validate_payload(
            "ck.profile.realm_override",
            &json!({
                "target_ref": "ck:actor_profile:0196419b-0000-7000-8000-000000000001",
                "target_realm_id": "ck:realm:0196419b-0000-7000-8000-000000000002",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ck.profile.realm_override should accept profile_realm_override_payload: {err}")
        });
    assert_eq!(
        catalog.rules["ck.flow.tracks.update"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/generic_standard_payload"),
        "ck.flow.tracks.update has dedicated track-table semantics and must not be folded into object_patch_payload"
    );
    catalog
        .validate_payload(
            "ck.flow.tracks.update",
            &json!({
                "flow_id": "ck:flow:0196419b-0000-7000-8000-000000000001",
                "tracks": {
                    "main": { "title": "Main", "rank": "a0" }
                }
            }),
        )
        .unwrap_or_else(|err| panic!("ck.flow.tracks.update should accept track payloads: {err}"));
    assert!(
        catalog
            .validate_payload(
                "ck.flow.tracks.update",
                &json!({
                    "type": "ck.flow.tracks.update",
                    "flow_id": "ck:flow:0196419b-0000-7000-8000-000000000001"
                }),
            )
            .is_err(),
        "ck.flow.tracks.update must still reject the retired type discriminator"
    );
}

#[test]
fn artifact_payload_catalog_enforces_invite_create_payload_shape() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    let payload = json!({
        "invite_id": "ck:invite:01904100-0000-7000-8000-000000000001",
        "invitee": "did:web:bob.example",
        "invite_delivery_target": {
            "recipient_service_did": "did:web:server.example",
            "recipient_service_type": "principal_server"
        },
        "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "expires_at": "2026-06-14T10:00:00Z",
        "x_role": "member"
    });

    assert_eq!(
        catalog.rules[crate::events::INVITE_CREATE].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/invite_payload")
    );
    assert!(
        catalog.rules[crate::events::INVITE_CREATE]
            .required_fields
            .iter()
            .any(|field| field == "invite_id"),
        "ck.invite.create must require invite_id"
    );
    catalog
        .validate_payload(crate::events::INVITE_CREATE, &payload)
        .unwrap_or_else(|err| panic!("ck.invite.create should accept directed invite: {err}"));

    let mut missing_invite_id = payload.clone();
    missing_invite_id.as_object_mut().unwrap().remove("invite_id");
    assert!(
        catalog.validate_payload(crate::events::INVITE_CREATE, &missing_invite_id).is_err(),
        "ck.invite.create must reject directed invite payloads without invite_id"
    );

    let mut missing_expires_at = payload;
    missing_expires_at.as_object_mut().unwrap().remove("expires_at");
    assert!(
        catalog.validate_payload(crate::events::INVITE_CREATE, &missing_expires_at).is_err(),
        "ck.invite.create must reject directed invite payloads without expires_at"
    );
}

#[test]
fn artifact_payload_catalog_enforces_external_schema_refs_and_enums() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    let key = json!({
        "kid": "did:web:alice.example#psk-1",
        "alg": "EdDSA",
        "public_key": "z6MkiExample",
        "key_format": "multibase"
    });
    let subordinate_key = json!({
        "kid": "did:web:alice.example#ssk-1",
        "alg": "EdDSA",
        "public_key": "z6MkiExampleSub",
        "key_format": "multibase",
        "binding": {
            "verification_method": "did:web:alice.example#psk-1",
            "alg": "EdDSA",
            "signature": "sig"
        }
    });
    catalog
        .validate_payload(
            crate::events::CROSS_SIGNING_PUBLISH,
            &json!({
                "principal_id": "did:web:alice.example",
                "trust_domain": "ck:trust_domain:example.net",
                "principal_signing_key": key,
                "self_signing_key": subordinate_key,
                "user_signing_key": subordinate_key,
                "expected_previous_generation": 0,
                "generation": 1,
                "issued_at": "2026-05-02T00:00:00Z"
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                crate::events::CROSS_SIGNING_PUBLISH,
                &json!({
                    "principal_id": "did:web:alice.example",
                    "principal_signing_key": key,
                    "self_signing_key": subordinate_key,
                    "user_signing_key": subordinate_key,
                    "generation": 0,
                    "issued_at": "2026-05-02T00:00:00Z"
                }),
            )
            .is_err()
    );
}

fn registry_with_keys(array_field: &str, key_field: &str, values: &[&str]) -> Value {
    let entries = values
        .iter()
        .map(|value| json!({ key_field: *value, "status": "active" }))
        .collect::<Vec<_>>();
    json!({ array_field: entries })
}

#[test]
fn profile_requirement_drift_reports_missing_sdk_constants() {
    let mut profile_requirements = serde_json::Map::new();
    profile_requirements.insert(
        crate::PROFILE_DIRECTORY_SERVICE.to_owned(),
        json!({
            "required_endpoints": ["ck.find.directory.search_realms", "ck.missing.operation"],
            "required_event_kinds": ["ck.realm.discovery"],
            "required_schemas": ["ck.schema.actor_profile.v1"]
        }),
    );
    let bundle = SpecArtifactBundle {
        schema_registry: registry_with_keys("schemas", "schema_id", ARTIFACT_BACKED_SCHEMA_IDS),
        event_kind_registry: registry_with_keys(
            "event_kinds",
            "event_kind",
            ARTIFACT_BACKED_EVENT_KINDS,
        ),
        operation_registry: registry_with_keys(
            "operations",
            "operation_id",
            ARTIFACT_BACKED_SERVICE_OPERATIONS,
        ),
        id_kind_registry: registry_with_keys("id_kinds", "kind", ARTIFACT_BACKED_ID_KINDS),
        conformance_profiles: json!({ "profile_requirements": profile_requirements }),
        artifacts_dir: None,
    };

    let report = bundle.drift_report();
    assert!(
        report
            .profile_requirement_issues
            .iter()
            .any(|issue| issue.contains("ck.missing.operation")),
        "{:?}",
        report.profile_requirement_issues
    );
    assert!(report.validate().is_err());
}

#[test]
fn generated_validators_cover_core_schema_ids() {
    let validators = generated_validators().unwrap();
    for schema_id in CORE_SCHEMA_IDS {
        assert!(validators.contains_key(*schema_id), "{schema_id}");
    }
}

#[test]
fn generated_validators_cover_all_artifact_schema_ids() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let bundle = SpecArtifactBundle::load(artifacts_dir).unwrap();
    let validators = generated_validators().unwrap();
    let schema_ids = bundle.schema_registry["schemas"]
        .as_array()
        .expect("schemas array")
        .iter()
        .filter_map(|schema| schema["schema_id"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(validators.len(), schema_ids.len());
    for schema_id in schema_ids {
        assert!(validators.contains_key(schema_id), "{schema_id}");
    }
}

#[test]
fn generated_profile_constants_match_artifact_profile_ids() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let bundle = SpecArtifactBundle::load(artifacts_dir).unwrap();
    let artifact_ids = bundle.profile_ids();
    let generated_ids =
        crate::generated::profiles::PROFILE_IDS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        generated_ids.len(),
        crate::generated::profiles::PROFILE_IDS.len(),
        "generated profile constants contain duplicates"
    );
    assert_eq!(
        artifact_ids.len(),
        generated_ids.len(),
        "generated profile constants drifted from conformance profile artifacts"
    );
    for profile_id in artifact_ids {
        assert!(
            crate::generated::profiles::is_profile_id(&profile_id),
            "generated profile constants missing {profile_id}"
        );
    }
}

#[test]
fn schema_registry_enforces_json_schema_composition_and_value_rules() {
    let mut registry = ProtocolSchemaRegistry::new();
    registry.register(
        "ck.schema.deep_test.v1",
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "ck.schema.deep_test.v1",
            "type": "object",
            "required": ["kind", "items", "target"],
            "properties": {
                "kind": {"const": "demo"},
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string", "pattern": "^[a-z]+$"}
                },
                "target": {
                    "oneOf": [
                        {"type": "string", "enum": ["user", "space"]},
                        {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}
                    ]
                }
            },
            "allOf": [{"properties": {"kind": {"type": "string"}}}],
            "patternProperties": {
                "^x_[a-z][a-z0-9_]{0,63}$": {"type": "string"}
            },
            "additionalProperties": false
        }),
    );
    registry
        .validate_value(
            "ck.schema.deep_test.v1",
            &json!({"kind": "demo", "items": ["alpha"], "target": "user", "x_role": "member"}),
        )
        .unwrap();
    assert!(
        registry
            .validate_value(
                "ck.schema.deep_test.v1",
                &json!({"kind": "demo", "items": [], "target": "user"}),
            )
            .is_err()
    );
    assert!(
        registry
            .validate_value(
                "ck.schema.deep_test.v1",
                &json!({"kind": "demo", "items": ["alpha"], "target": "other"}),
            )
            .is_err()
    );
    assert!(
        registry
            .validate_value(
                "ck.schema.deep_test.v1",
                &json!({"kind": "other", "items": ["alpha"], "target": "user"}),
            )
            .is_err()
    );
    assert!(
        registry
            .validate_value(
                "ck.schema.deep_test.v1",
                &json!({"kind": "demo", "items": ["alpha"], "target": "user", "extra": true}),
            )
            .is_err()
    );
    assert!(
        registry
            .validate_value(
                "ck.schema.deep_test.v1",
                &json!({"kind": "demo", "items": ["alpha"], "target": "user", "x_role": false}),
            )
            .is_err()
    );
}

#[test]
fn spec_artifact_registry_covers_key_local_schema_and_event_contracts() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let bundle = SpecArtifactBundle::load(artifacts_dir).unwrap();
    bundle.drift_report().validate().unwrap();

    let spec_active_event_kinds = bundle.event_kind_registry["event_kinds"]
        .as_array()
        .expect("event_kinds array")
        .iter()
        .filter(|entry| entry["status"].as_str() == Some("active"))
        .filter_map(|entry| entry["event_kind"].as_str())
        .collect::<BTreeSet<_>>();
    let sdk_event_kinds = ARTIFACT_BACKED_EVENT_KINDS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        sdk_event_kinds.len(),
        ARTIFACT_BACKED_EVENT_KINDS.len(),
        "SDK event constants contain duplicates"
    );
    let missing_event_kinds =
        spec_active_event_kinds.difference(&sdk_event_kinds).copied().collect::<Vec<_>>();
    let extra_event_kinds =
        sdk_event_kinds.difference(&spec_active_event_kinds).copied().collect::<Vec<_>>();
    assert!(
        missing_event_kinds.is_empty(),
        "SDK event constants missing active spec event kinds {missing_event_kinds:?}"
    );
    assert!(
        extra_event_kinds.is_empty(),
        "SDK event constants include non-active spec event kinds {extra_event_kinds:?}"
    );

    let spec_operation_ids = bundle.operation_registry["operations"]
        .as_array()
        .expect("operations array")
        .iter()
        .filter_map(|entry| entry["operation_id"].as_str())
        .collect::<BTreeSet<_>>();
    let sdk_operation_ids =
        ARTIFACT_BACKED_SERVICE_OPERATIONS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        sdk_operation_ids.len(),
        ARTIFACT_BACKED_SERVICE_OPERATIONS.len(),
        "SDK built-in operation constants contain duplicates"
    );
    let missing_operation_ids =
        spec_operation_ids.difference(&sdk_operation_ids).copied().collect::<Vec<_>>();
    let extra_operation_ids =
        sdk_operation_ids.difference(&spec_operation_ids).copied().collect::<Vec<_>>();
    assert!(
        missing_operation_ids.is_empty(),
        "SDK built-in operations missing spec operations {missing_operation_ids:?}"
    );
    assert!(
        extra_operation_ids.is_empty(),
        "SDK built-in operations include operations outside spec {extra_operation_ids:?}"
    );

    let schemas = bundle.schema_registry["schemas"].as_array().expect("schemas array");
    let schema_ids =
        schemas.iter().filter_map(|schema| schema["schema_id"].as_str()).collect::<BTreeSet<_>>();
    assert_eq!(
        ARTIFACT_BACKED_SCHEMA_IDS.len(),
        schema_ids.len(),
        "SDK artifact-backed schema coverage should cover the full schema registry"
    );
    for schema_id in ARTIFACT_BACKED_SCHEMA_IDS {
        assert!(schema_ids.contains(*schema_id), "missing schema artifact for {schema_id}");
    }
    let event_schema = schemas
        .iter()
        .find(|schema| schema["schema_id"] == EVENT_SCHEMA)
        .expect("event envelope schema registry entry");
    assert_eq!(event_schema["file"].as_str(), Some("schemas/event-envelope.schema.json"));

    for event_kind in ARTIFACT_BACKED_EVENT_KINDS {
        let entry =
            registry_entry(&bundle.event_kind_registry, "event_kinds", "event_kind", event_kind)
                .unwrap_or_else(|| panic!("missing event kind {event_kind}"));
        assert_eq!(entry["status"].as_str(), Some("active"), "{event_kind}");
        assert!(entry["wire_scope"].as_str().is_some(), "{event_kind}");
    }

    for operation_id in ARTIFACT_BACKED_SERVICE_OPERATIONS {
        assert!(
            registry_entry(&bundle.operation_registry, "operations", "operation_id", operation_id)
                .is_some(),
            "missing service operation {operation_id}"
        );
    }

    let profile_ids = bundle.profile_ids();
    for profile_id in ARTIFACT_BACKED_PROFILE_IDS {
        assert!(profile_ids.contains(*profile_id), "missing profile artifact for {profile_id}");
        let requirement = bundle
            .profile_requirement(profile_id)
            .unwrap_or_else(|error| panic!("invalid profile requirement {profile_id}: {error}"))
            .unwrap_or_else(|| panic!("missing profile requirement {profile_id}"));
        assert!(
            !requirement.required_endpoints.is_empty()
                || !requirement.required_event_kinds.is_empty()
                || !requirement.required_schemas.is_empty(),
            "profile requirement should not be empty: {profile_id}"
        );
    }

    for (kind, wire_form) in
        [("event", "ck:event:<uuid>"), ("space", "ck:space:<uuid>"), ("flow", "ck:flow:<uuid>")]
    {
        let entry = registry_entry(&bundle.id_kind_registry, "id_kinds", "kind", kind)
            .unwrap_or_else(|| panic!("missing id kind {kind}"));
        assert_eq!(entry["wire_form"].as_str(), Some(wire_form), "{kind}");
    }
}

#[test]
fn component_descriptor_resolves_canonical_and_alias_kinds() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let bundle = SpecArtifactBundle::load(artifacts_dir).unwrap();

    // Canonical kind owns its slot — no alias_of.
    let canonical = bundle
        .component("ck.capability.grant")
        .unwrap()
        .expect("ck.capability.grant should be registered");
    assert_eq!(canonical.criticality, Criticality::Required);
    assert!(canonical.component_type.starts_with("ck.component."));
    assert!(canonical.component_version >= 1);
    assert!(canonical.component_slot_alias_of.is_none());

    // Alias kind shares the canonical kind's slot.
    let alias = bundle
        .component("ck.capability.revoke")
        .unwrap()
        .expect("ck.capability.revoke should be registered");
    assert_eq!(
        alias.component_slot_alias_of.as_deref(),
        Some("ck.capability.grant"),
        "ck.capability.revoke should slot-alias ck.capability.grant"
    );
    assert_eq!(alias.component_type, canonical.component_type);
    assert_eq!(alias.component_version, canonical.component_version);

    // Unknown kind is a clean None, not an error.
    assert!(bundle.component("ck.bogus.kind").unwrap().is_none());
}

#[test]
fn evolution_plan_rejects_breaking_release_candidate() {
    let mut breaking_changes = BTreeSet::new();
    breaking_changes.insert(SchemaBreakingChange::NewRequiredField);
    let plan = SchemaEvolutionPlan {
        from_version: "0.1.0".to_owned(),
        to_version: "0.2.0".to_owned(),
        affected_schemas: vec![EVENT_SCHEMA.to_owned()],
        breaking_changes,
    };
    assert!(matches!(plan.validate_release_candidate(), Err(Error::Protocol(_))));
}
