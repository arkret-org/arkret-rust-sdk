use std::path::PathBuf;

use arkret_schema::{
    EventPayloadValidatorCatalog, default_spec_artifacts_dir,
    event_payload_validator_catalog_from_spec_artifacts,
};
use arkret_wire::{EventKind, SchemaId};
use serde_json::json;

fn live_payload_catalog() -> Option<EventPayloadValidatorCatalog> {
    let artifacts_dir = default_spec_artifacts_dir().or_else(|| {
        let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("arkret-spec")
            .join("spec")
            .join("v1")
            .join("artifacts");
        candidate.is_dir().then_some(candidate)
    })?;
    Some(event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap())
}

#[test]
fn registered_specialized_defs_take_priority_over_name_matches() {
    let Some(catalog) = live_payload_catalog() else {
        return;
    };

    assert_eq!(
        catalog.rules["ak.space.archive"].payload_schema_id,
        format!(
            "{schemaid_event_payload_v1}#/$defs/space_state_transition_payload",
            schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
        )
    );
    assert_eq!(
        catalog.rules["ak.space.restore"].payload_schema_id,
        format!(
            "{schemaid_event_payload_v1}#/$defs/space_state_transition_payload",
            schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
        )
    );
    assert_eq!(
        catalog.rules["ak.space.tombstone"].payload_schema_id,
        format!(
            "{schemaid_event_payload_v1}#/$defs/space_object_tombstone_payload",
            schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
        )
    );

    catalog
        .validate_payload(
            "ak.space.archive",
            &json!({
                "space_id": "ak:space:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD",
                "reason": "done"
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload("ak.space.archive", &json!({ "archived": true }))
            .is_err()
    );
}

#[test]
fn patch_event_family_maps_to_canonical_payloads() {
    let Some(catalog) = live_payload_catalog() else {
        return;
    };
    let patch_kinds = [
        (
            "ak.strand.update",
            "strand_patch_payload",
            json!({
                "target_ref": "ak:strand:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.morph.update",
            "morph_update_payload",
            json!({
                "target_ref": "ak:morph:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.space.update",
            "space_patch_payload",
            json!({
                "space_id": "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.profile.update",
            "object_patch_payload",
            json!({
                "target_ref": "ak:actor_profile:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
    ];
    for (event_kind, payload_def, payload) in patch_kinds {
        assert_eq!(
            catalog.rules[event_kind].payload_schema_id,
            format!(
                "{schemaid_event_payload_v1}#/$defs/{payload_def}",
                schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
            ),
            "{event_kind} must use the canonical patch payload schema"
        );
        catalog
            .validate_payload(event_kind, &payload)
            .unwrap_or_else(|err| panic!("{event_kind} should accept {payload_def}: {err}"));
    }

    assert_eq!(
        catalog.rules["ak.profile.realm_override"].payload_schema_id,
        format!(
            "{schemaid_event_payload_v1}#/$defs/profile_realm_override_payload",
            schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
        ),
        "ak.profile.realm_override must use the dedicated profile_realm_override_payload schema"
    );
    catalog
        .validate_payload(
            "ak.profile.realm_override",
            &json!({
                "target_ref": "ak:actor_profile:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "target_realm_id": "ak:realm:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ak.profile.realm_override should accept profile_realm_override_payload: {err}")
        });
    assert_eq!(
        catalog.rules["ak.strand.tracks.update"].payload_schema_id,
        format!(
            "{schemaid_event_payload_v1}#/$defs/generic_standard_payload",
            schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
        ),
        "ak.strand.tracks.update has dedicated track-table semantics and must not be folded into object_patch_payload"
    );
    catalog
        .validate_payload(
            "ak.strand.tracks.update",
            &json!({
                "strand_id": "ak:strand:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "tracks": {
                    "main": { "title": "Main", "rank": "a0" }
                }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ak.strand.tracks.update should accept track payloads: {err}")
        });
    assert!(
        catalog
            .validate_payload(
                "ak.strand.tracks.update",
                &json!({
                    "type": "ak.strand.tracks.update",
                    "strand_id": "ak:strand:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
                }),
            )
            .is_err(),
        "ak.strand.tracks.update must still reject the retired type discriminator"
    );
    assert!(
        catalog
            .validate_payload(
                "ak.strand.update",
                &json!({
                    "target_ref": "ak:morph:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                    "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
                }),
            )
            .is_err(),
        "ak.strand.update target_ref must be a Strand id"
    );
}

#[test]
fn morph_update_rejects_create_locked_morph_kind() {
    let Some(catalog) = live_payload_catalog() else {
        return;
    };

    catalog
        .validate_payload(
            "ak.morph.update",
            &json!({
                "target_ref": "ak:morph:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                "ak.morph.update",
                &json!({
                    "target_ref": "ak:morph:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                    "patch": { "morph_kind": { "$op": "set", "value": "task" } }
                }),
            )
            .is_err(),
        "ak.morph.update must reject create-locked morph_kind changes"
    );
    assert!(
        catalog
            .validate_payload(
                "ak.morph.update",
                &json!({
                    "target_ref": "ak:strand:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                    "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
                }),
            )
            .is_err(),
        "ak.morph.update target_ref must be a Morph id"
    );
}

#[test]
fn invite_create_payload_shape_is_enforced() {
    let Some(catalog) = live_payload_catalog() else {
        return;
    };
    let payload = json!({
        "invitee": "did:webvh:z6mkfixture:bob.example",
        "invite_delivery_target": {
            "recipient_service_id": "did:webvh:z6mkfixture:server.example",
            "recipient_service_kind": "principal_server"
        },
        "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "expires_at": "2026-06-14T10:00:00.000Z",
        "x_role": "member"
    });

    assert_eq!(
        catalog.rules[EventKind::INVITE_CREATE].payload_schema_id,
        format!(
            "{schemaid_event_payload_v1}#/$defs/invite_create_payload",
            schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
        )
    );
    assert!(
        catalog.rules[EventKind::INVITE_CREATE]
            .required_fields
            .iter()
            .any(|field| field == "invitee"),
        "ak.invite.create must require invitee"
    );
    catalog
        .validate_payload(EventKind::INVITE_CREATE, &payload)
        .unwrap_or_else(|err| panic!("ak.invite.create should accept directed invite: {err}"));

    let mut producer_selected_invite_id = payload.clone();
    producer_selected_invite_id["invite_id"] =
        json!("ak:invite:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19");
    assert!(
        catalog
            .validate_payload(EventKind::INVITE_CREATE, &producer_selected_invite_id)
            .is_err(),
        "ak.invite.create must reject producer-selected invite_id"
    );

    let mut missing_expires_at = payload;
    missing_expires_at
        .as_object_mut()
        .unwrap()
        .remove("expires_at");
    assert!(
        catalog
            .validate_payload(EventKind::INVITE_CREATE, &missing_expires_at)
            .is_err(),
        "ak.invite.create must reject directed invite payloads without expires_at"
    );
}
