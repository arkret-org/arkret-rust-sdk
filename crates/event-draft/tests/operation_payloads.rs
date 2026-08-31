use arkret_canonical::canonical;
use arkret_event_draft::StrandCreateObject;
use arkret_models_collaboration::events_payloads::{ObjectCreatePayload, StrandPatchPayload};
use arkret_models_collaboration::objects::profiles::StrandTrack;
use arkret_schema_conformance::event_payload_validator_catalog;
use arkret_wire::{ActorId, DidCoreId, Patch, RealmId, SchemaId, StrandId};
use serde_json::json;

#[test]
fn object_create_payload_wraps_strand_draft() {
    let actor = DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap();
    let realm_id = RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    // A create object carries no id: the Strand id is derived from the create
    // Event's own `event_id` (spec `zh/models/common-fields.md` section 6.0).
    let strand = StrandCreateObject::new(realm_id, ActorId::service(actor))
        .with_metadata_title("Incident")
        .with_track("discussion", StrandTrack::discussion_primary());
    let payload = ObjectCreatePayload::new(strand).to_value().unwrap();
    assert!(payload["object"].get("id").is_none());
    assert_eq!(payload["object"]["schema"], SchemaId::STRAND_V1);
    assert_eq!(payload["object"]["stage"], "draft");
    assert_eq!(payload["object"]["metadata"]["title"], "Incident");
    canonical::validate_timestamp_canonical(payload["object"]["created_at"].as_str().unwrap())
        .unwrap();
}

#[test]
fn strand_tracks_update_uses_shared_strand_patch_payload() {
    let strand_id =
        StrandId::new("ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
    let patch: Patch = serde_json::from_value(json!({
        "tracks.discussion.is_primary": {"$op": "set", "value": true}
    }))
    .unwrap();
    let payload = StrandPatchPayload::for_strand(strand_id, patch)
        .unwrap()
        .to_value()
        .unwrap();

    assert_eq!(
        payload["target_ref"],
        "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"
    );
    assert!(payload.get("strand_id").is_none());
    assert!(payload.get("tracks").is_none());
    assert!(payload.get("patch").is_some());
    event_payload_validator_catalog()
        .unwrap()
        .validate_payload("ak.strand.tracks.update", &payload)
        .unwrap();
}
