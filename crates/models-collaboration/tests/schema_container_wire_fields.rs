use arkret_models_collaboration::event_sync::ActorAggregateFrontierView;
use arkret_models_collaboration::governance::realm_governance::RealmLinkList;
use arkret_models_collaboration::http_bodies::{
    ContactList, EventsSubmitOutcome, ProjectionMorphList, ProjectionSpaceList,
    ProjectionStrandList,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const REALM_ID: &str = "ak:realm:AYlS_mnxn8_f65A0YrWEeLzd0F1vnM347xZzMSQEcrlz";
const ACTOR_ID: &str = "ak:did_core:webvh:QmTwPiXhFdKLBT4AvS2cg4hjiCEdwbmgSTRfhGaEKUVR7P";

fn round_trip<T>(value: Value) -> Value
where
    T: DeserializeOwned + Serialize,
{
    serde_json::to_value(serde_json::from_value::<T>(value).expect("schema-shaped DTO"))
        .expect("serialize DTO")
}

#[test]
fn projection_list_containers_use_schema_array_names() {
    let cases = [
        round_trip::<ProjectionSpaceList>(json!({
            "realm_id": REALM_ID,
            "spaces": [],
            "total": 0,
            "has_more": false
        })),
        round_trip::<ProjectionStrandList>(json!({
            "realm_id": REALM_ID,
            "strands": [],
            "total": 0,
            "has_more": false
        })),
        round_trip::<ProjectionMorphList>(json!({
            "realm_id": REALM_ID,
            "morphs": [],
            "total": 0,
            "has_more": false
        })),
    ];

    for (value, expected, forbidden) in [
        (&cases[0], "spaces", "projection_space_rows"),
        (&cases[1], "strands", "projection_strand_rows"),
        (&cases[2], "morphs", "projection_morph_rows"),
    ] {
        assert!(value.get(expected).is_some(), "missing {expected}: {value}");
        assert!(
            value.get(forbidden).is_none(),
            "leaked {forbidden}: {value}"
        );
    }
}

#[test]
fn submit_outcome_uses_schema_result_names_only() {
    let value = round_trip::<EventsSubmitOutcome>(json!({
        "status": "accepted",
        "accepted": [],
        "pending_delivery_count": 0,
        "rejections": [{
            "id": "ak:event:AXcPfjVv4gB4YXMmxykws6YCG5IZrhBAAzc4-yYUDIY4",
            "reason_code": "permission_denied"
        }],
        "frontiers": [{
            "kind": "realm_actor",
            "realm_id": REALM_ID,
            "actor_id": ACTOR_ID,
            "next_actor_seq": 0,
            "frontier_event_ids": [],
            "frontier_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }]
    }));

    assert!(value.get("rejections").is_some());
    assert!(value.get("frontiers").is_some());
    for forbidden in [
        "events_submit_rejected_rows",
        "realm_actor_frontier_views",
        "realm_frontiers",
    ] {
        assert!(
            value.get(forbidden).is_none(),
            "leaked {forbidden}: {value}"
        );
    }
}

#[test]
fn contact_and_realm_link_lists_use_schema_array_names() {
    let contacts = round_trip::<ContactList>(json!({
        "contacts": [],
        "has_more": false
    }));
    assert!(contacts.get("contacts").is_some());
    assert!(contacts.get("contact_list_rows").is_none());

    let links = round_trip::<RealmLinkList>(json!({
        "realm_id": REALM_ID,
        "direction": "outbound",
        "links": []
    }));
    assert!(links.get("links").is_some());
    assert!(links.get("realm_link_entries").is_none());
}

#[test]
fn actor_aggregate_uses_frontiers() {
    let value = round_trip::<ActorAggregateFrontierView>(json!({
        "kind": "actor_aggregate",
        "actor_id": ACTOR_ID,
        "frontiers": []
    }));
    assert!(value.get("frontiers").is_some());
    assert!(value.get("realm_actor_frontier_views").is_none());
}
