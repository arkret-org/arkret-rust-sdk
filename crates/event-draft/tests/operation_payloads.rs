use arkret_canonical::canonical;
use arkret_event_draft::{StrandCreateObject, StrandTracksUpdatePayload};
use arkret_models_collaboration::events_payloads::ObjectCreatePayload;
use arkret_models_collaboration::objects::profiles::StrandTrackConfig;
use arkret_schema::event_payload_validator_catalog;
use arkret_wire::{Did, Patch, RealmId, STRAND_SCHEMA, StrandId};
use serde_json::json;

#[test]
fn object_create_payload_wraps_strand_draft() {
    let actor = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let strand_id = StrandId::new("ak:strand:01904100-0000-7000-8000-000000000002").unwrap();
    let strand = StrandCreateObject::new(strand_id, realm_id, actor)
        .with_metadata_title("Incident")
        .with_track("discussion", StrandTrackConfig::discussion_primary());
    let payload = ObjectCreatePayload::new(strand).to_value().unwrap();
    assert_eq!(payload["object"]["schema"], STRAND_SCHEMA);
    assert_eq!(payload["object"]["stage"], "draft");
    assert_eq!(payload["object"]["metadata"]["title"], "Incident");
    canonical::validate_timestamp_canonical(payload["object"]["created_at"].as_str().unwrap())
        .unwrap();
}

#[test]
fn strand_tracks_update_payload_uses_strand_id_not_target_ref() {
    let strand_id = StrandId::new("ak:strand:01904100-0000-7000-8000-000000000002").unwrap();
    let patch: Patch = serde_json::from_value(json!({
        "tracks.discussion.is_primary": {"$op": "set", "value": true}
    }))
    .unwrap();
    let payload = StrandTracksUpdatePayload::with_patch(strand_id, patch)
        .unwrap()
        .to_value()
        .unwrap();

    assert_eq!(
        payload["strand_id"],
        "ak:strand:01904100-0000-7000-8000-000000000002"
    );
    assert!(payload.get("target_ref").is_none());
    assert!(payload.get("patch").is_some());
    event_payload_validator_catalog()
        .unwrap()
        .validate_payload("ak.strand.tracks.update", &payload)
        .unwrap();
}
