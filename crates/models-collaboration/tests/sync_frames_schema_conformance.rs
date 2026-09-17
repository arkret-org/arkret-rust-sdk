//! Schema conformance for the sync / subscription frame family.
//!
//! Two independent checks run against the live `arkret-spec` artifacts, not
//! against a copy vendored into this repository:
//!
//! 1. **Shape** — a representative document is validated by the spec schema (or the exact `$defs`
//!    fragment), then deserialized, re-serialized, and compared byte-for-byte with the input. A
//!    type that silently drops or renames a member fails here.
//! 2. **Field order** — the SDK convention is that a struct's field declaration order equals the
//!    schema's `properties` order byte-for-byte. JSON objects parse into a sorted map, so both
//!    orders are read from raw source text instead: the schema file as published, and the struct's
//!    own `serde_json::to_string` output.
//!
//! Every assertion names a live artifact path, so a renamed or deleted `$defs`
//! entry fails loudly rather than quietly passing against a stale copy.

use std::fs;
use std::path::PathBuf;

use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, RealmDetailBaseline, RealmSyncEntry, RealmSyncEventState, RealmTimeline,
};
use arkret_models_collaboration::sync_frames::account_sync::{
    AccountSubscribeRealmSummary, AccountSubscribeUnreadCounts, StateAtWindowStart,
    WindowStartActorProfile, WindowStartE2eeEpoch, WindowStartRealmMetadata,
};
use arkret_models_collaboration::sync_frames::current_results::{
    AccountCurrentCoverage, AccountCurrentResult,
};
use arkret_models_collaboration::sync_frames::demand_sync::{
    AccountBaselineSegment, RealmDetailUnavailable, RealmInvalidation, RealmListChanges,
    RealmListRow, RealmListPage, RealmListRemoval, RealmTimelineBaseline,
};
use arkret_models_collaboration::sync_frames::events_subscribe::{
    EpochRotationPayload, EventsStreamTrace, EventsSubscribeFrame, EventsSubscribeFrameKind,
};
use arkret_models_collaboration::sync_frames::websocket::{
    WebSocketAccountOpenParameters, WebSocketClientFrame, WebSocketConnectionDrainPayload,
    WebSocketConnectionLimits, WebSocketEventsOpenParameters, WebSocketServerFrame,
};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde::Serialize;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Spec artifact access
// ---------------------------------------------------------------------------

fn artifacts_dir() -> PathBuf {
    arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("the arkret-spec artifacts checkout must be reachable for conformance")
}

fn schema_text(file: &str) -> String {
    let path = artifacts_dir().join("schemas").join(file);
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    })
}

fn schema_value(file: &str) -> Value {
    serde_json::from_str(&schema_text(file)).expect("schema artifact must be valid JSON")
}

fn registry() -> ProtocolSchemaRegistry {
    schema_registry_from_spec_artifacts(artifacts_dir())
        .expect("the spec artifacts must produce a schema registry")
}

/// Validate `value` against one `$defs` fragment of a published schema file.
fn validate_fragment(file: &str, fragment: &str, value: &Value) {
    let mut registry = registry();
    let schema = schema_value(file);
    registry
        .register_reference_document(schema.clone())
        .expect("schema document declares an absolute $id");
    // The registry splits a schema id on `#`, so the lookup key must not
    // contain one; the fragment is stored beside the id, not inside it.
    let schema_id = format!("test:{file}{}", fragment.replace('#', "@"));
    registry
        .register_fragment(schema_id.clone(), schema, fragment)
        .unwrap_or_else(|error| panic!("{file}{fragment}: {error}"));
    registry
        .validate_value(&schema_id, value)
        .unwrap_or_else(|error| panic!("{file}{fragment} rejected the document: {error}"));
}

fn validate_document(file: &str, value: &Value) {
    validate_fragment(file, "#", value);
}

// ---------------------------------------------------------------------------
// Source-order scanner
//
// JSON objects deserialize into a sorted map, which destroys the very ordering
// this suite exists to assert. Both sides are therefore read from raw text: the
// published schema file, and serde's own `to_string` output for a struct (serde
// emits struct fields in declaration order).
// ---------------------------------------------------------------------------

/// Index just past the object/array/string/scalar starting at `start`.
fn value_end(text: &[u8], start: usize) -> usize {
    match text[start] {
        b'{' | b'[' => {
            let (open, close) = if text[start] == b'{' {
                (b'{', b'}')
            } else {
                (b'[', b']')
            };
            let mut depth = 0usize;
            let mut index = start;
            let mut in_string = false;
            let mut escaped = false;
            while index < text.len() {
                let byte = text[index];
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        in_string = false;
                    }
                } else if byte == b'"' {
                    in_string = true;
                } else if byte == open {
                    depth += 1;
                } else if byte == close {
                    depth -= 1;
                    if depth == 0 {
                        return index + 1;
                    }
                }
                index += 1;
            }
            panic!("unterminated JSON container");
        }
        b'"' => {
            let mut index = start + 1;
            let mut escaped = false;
            while index < text.len() {
                let byte = text[index];
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    return index + 1;
                }
                index += 1;
            }
            panic!("unterminated JSON string");
        }
        _ => {
            let mut index = start;
            while index < text.len()
                && !matches!(
                    text[index],
                    b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t'
                )
            {
                index += 1;
            }
            index
        }
    }
}

/// Top-level `(member name, value start)` pairs of the object at `start`, in
/// the order they appear in the source text.
fn object_members(text: &[u8], start: usize) -> Vec<(String, usize)> {
    assert_eq!(text[start], b'{', "expected a JSON object");
    let mut members = Vec::new();
    let mut index = start + 1;
    loop {
        while index < text.len() && text[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= text.len() || text[index] == b'}' {
            return members;
        }
        assert_eq!(text[index], b'"', "expected a member name");
        let key_end = value_end(text, index);
        let key: String =
            serde_json::from_str(std::str::from_utf8(&text[index..key_end]).unwrap()).unwrap();
        index = key_end;
        while index < text.len() && text[index] != b':' {
            index += 1;
        }
        index += 1;
        while index < text.len() && text[index].is_ascii_whitespace() {
            index += 1;
        }
        members.push((key, index));
        index = value_end(text, index);
        while index < text.len() && (text[index].is_ascii_whitespace() || text[index] == b',') {
            index += 1;
        }
    }
}

/// Walk `path` from the document root and return that object's member names in
/// source order. Each path element is a member name.
fn members_at(text: &str, path: &[&str]) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut start = bytes
        .iter()
        .position(|byte| *byte == b'{')
        .expect("document must be a JSON object");
    for segment in path {
        let members = object_members(bytes, start);
        start = members
            .into_iter()
            .find(|(key, _)| key == segment)
            .unwrap_or_else(|| panic!("no member `{segment}` at this level"))
            .1;
    }
    object_members(bytes, start)
        .into_iter()
        .map(|(key, _)| key)
        .collect()
}

/// Member names of `value`'s JSON object, in serde declaration order.
fn declaration_order<T: Serialize>(value: &T) -> Vec<String> {
    let text = serde_json::to_string(value).expect("value serializes");
    members_at(&text, &[])
}

/// Assert that a struct's field declaration order is byte-for-byte the schema's
/// `properties` order at `path`. The value must populate every optional field,
/// or the comparison would silently pass on a subset.
fn assert_field_order<T: Serialize>(value: &T, file: &str, path: &[&str]) {
    let mut schema_path = path.to_vec();
    schema_path.push("properties");
    let expected = members_at(&schema_text(file), &schema_path);
    let actual = declaration_order(value);
    assert_eq!(
        actual, expected,
        "{file} {path:?}: field declaration order must equal the schema properties order",
    );
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const REALM_A: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const REALM_B: &str = "ak:realm:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0";
const STRAND: &str = "ak:strand:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0";
const EVENT_A: &str = "ak:event:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq";
const COMMIT_A: &str = "ak:realm_commit:0199ad0e-6d5a-7f31-8c2e-4c5f1a2b3c4d";

fn actor(principal: &str) -> Value {
    json!({
        "principal_id": principal,
        "station_id": "ak:did_core:web:station.example",
    })
}

fn realm_stream_head(realm: &str) -> Value {
    json!({
        "stream_ref": {"kind": "realm", "realm_id": realm},
        "stream_position": 12,
        "commit_id": COMMIT_A,
    })
}

fn realm_list_row(realm: &str) -> Value {
    json!({
        "realm_id": realm,
        "revision": 9,
        "activity_position": 4,
        "membership": "join",
        "title": "Design",
        "default_strand_id": STRAND,
    })
}

// ---------------------------------------------------------------------------
// Demand-sync payloads
// ---------------------------------------------------------------------------

/// Round-trip one document through the spec schema and the Rust type.
fn round_trip<T>(file: &str, fragment: &str, value: Value) -> T
where
    T: serde::de::DeserializeOwned + Serialize,
{
    validate_fragment(file, fragment, &value);
    let parsed: T = serde_json::from_value(value.clone())
        .unwrap_or_else(|error| panic!("{file}{fragment} did not deserialize: {error}"));
    assert_eq!(
        serde_json::to_value(&parsed).unwrap(),
        value,
        "{file}{fragment} did not round-trip",
    );
    parsed
}

const ACCOUNT_FRAME: &str = "account-subscribe-frame.schema.json";
const EVENTS_FRAME: &str = "events-subscribe-frame.schema.json";
const WEBSOCKET_FRAME: &str = "websocket-frame.schema.json";
const ACCOUNT_CURRENT: &str = "account-current-result.schema.json";

#[test]
fn realm_list_item_matches_its_schema_shape_and_order() {
    let item: RealmListRow = round_trip(
        ACCOUNT_FRAME,
        "#/$defs/realm_list_row",
        realm_list_row(REALM_A),
    );
    item.validate().unwrap();
    assert_field_order(&item, ACCOUNT_FRAME, &["$defs", "realm_list_row"]);
}

#[test]
fn realm_list_page_matches_its_schema_shape_and_order() {
    let page: RealmListPage = round_trip(
        ACCOUNT_FRAME,
        "#/$defs/realm_list_page",
        json!({
            "snapshot_cursor": "ak:cursor:abc",
            "snapshot_revision": 31,
            "items": [realm_list_row(REALM_A)],
            "next_cursor": "ak:cursor:def",
        }),
    );
    page.validate().unwrap();
    assert_field_order(&page, ACCOUNT_FRAME, &["$defs", "realm_list_page"]);
}

#[test]
fn realm_list_changes_and_removal_match_their_schema_shapes() {
    let removal: RealmListRemoval = round_trip(
        ACCOUNT_FRAME,
        "#/$defs/realm_list_removal",
        json!({"realm_id": REALM_B, "revision": 3}),
    );
    assert_field_order(&removal, ACCOUNT_FRAME, &["$defs", "realm_list_removal"]);

    let changes: RealmListChanges = round_trip(
        ACCOUNT_FRAME,
        "#/$defs/realm_list_changes",
        json!({
            "upserts": [realm_list_row(REALM_A)],
            "removals": [{"realm_id": REALM_B, "revision": 3}],
        }),
    );
    changes.validate().unwrap();
    assert_field_order(&changes, ACCOUNT_FRAME, &["$defs", "realm_list_changes"]);
}

#[test]
fn account_baseline_segment_matches_its_schema_shape_and_order() {
    let segment: AccountBaselineSegment = round_trip(
        ACCOUNT_FRAME,
        "#/$defs/account_baseline_segment",
        json!({
            "snapshot_cursor": "ak:cursor:abc",
            "channels": ["account_data_events", "station_cas"],
            "completed_channels": ["station_cas"],
        }),
    );
    segment.validate().unwrap();
    assert_field_order(
        &segment,
        ACCOUNT_FRAME,
        &["$defs", "account_baseline_segment"],
    );
}

#[test]
fn realm_timeline_baseline_matches_its_schema_shape_and_order() {
    let baseline: RealmTimelineBaseline = round_trip(
        ACCOUNT_FRAME,
        "#/$defs/realm_timeline_baseline",
        json!({
            "snapshot_cursor": "ak:cursor:abc",
            "window_limit": 20,
            "complete": true,
        }),
    );
    baseline.validate().unwrap();
    assert_field_order(
        &baseline,
        ACCOUNT_FRAME,
        &["$defs", "realm_timeline_baseline"],
    );
}

#[test]
fn realm_detail_baseline_and_invalidation_match_their_schema_shapes() {
    let baseline: RealmDetailBaseline = round_trip(
        ACCOUNT_FRAME,
        "#/$defs/realm_detail_baseline",
        json!({
            "snapshot_cursor": "ak:cursor:abc",
            "cut_revision": 42,
            "coverage": {
                "realm_id": REALM_A,
                "stream_heads": [realm_stream_head(REALM_A)],
                "complete_for_authorized_streams": true,
            },
            "complete": true,
        }),
    );
    baseline.validate().unwrap();
    assert_field_order(
        &baseline,
        ACCOUNT_FRAME,
        &["$defs", "realm_detail_baseline"],
    );

    let invalidation: RealmInvalidation = round_trip(
        ACCOUNT_FRAME,
        "#/$defs/realm_invalidation",
        json!({"realm_id": REALM_A, "revision": 7}),
    );
    assert_field_order(
        &invalidation,
        ACCOUNT_FRAME,
        &["$defs", "realm_invalidation"],
    );
}

#[test]
fn realm_detail_unavailable_matches_its_schema_shape() {
    let unavailable: RealmDetailUnavailable = round_trip(
        ACCOUNT_FRAME,
        "#/$defs/realm_sync_entry/properties/unavailable",
        json!({"error_code": "temporarily_unavailable"}),
    );
    assert_field_order(
        &unavailable,
        ACCOUNT_FRAME,
        &["$defs", "realm_sync_entry", "properties", "unavailable"],
    );
}

// ---------------------------------------------------------------------------
// Per-Realm projections
// ---------------------------------------------------------------------------

#[test]
fn state_at_window_start_matches_its_schema_shape_and_order() {
    let state: StateAtWindowStart = round_trip(
        ACCOUNT_FRAME,
        "#/$defs/state_at_window_start",
        json!({
            "actor_profiles": [{
                "actor_id": actor("ak:did_core:web:alice.example"),
                "display_name": "Alice",
                "avatar_blob_ref": "ak:blob:sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            }],
            "realm_metadata": {
                "title": "Design",
                "summary": "Design realm",
                "join_rule": "invite",
                "collaboration_role": "direct_conversation",
            },
            "e2ee_epoch": {"epoch": 4, "key_ref": "ak:mls:epoch:4"},
        }),
    );
    state.validate().unwrap();
    assert_field_order(&state, ACCOUNT_FRAME, &["$defs", "state_at_window_start"]);
    assert_field_order(
        &state.actor_profiles[0],
        ACCOUNT_FRAME,
        &[
            "$defs",
            "state_at_window_start",
            "properties",
            "actor_profiles",
            "items",
        ],
    );
    assert_field_order(
        &state.realm_metadata,
        ACCOUNT_FRAME,
        &[
            "$defs",
            "state_at_window_start",
            "properties",
            "realm_metadata",
        ],
    );
}

#[test]
fn a_null_e2ee_epoch_is_a_real_answer() {
    let value = json!({
        "actor_profiles": [],
        "realm_metadata": {},
        "e2ee_epoch": null,
    });
    validate_fragment(ACCOUNT_FRAME, "#/$defs/state_at_window_start", &value);
    let state: StateAtWindowStart = serde_json::from_value(value.clone()).unwrap();
    state.validate().unwrap();
    assert!(state.e2ee_epoch.is_none());
    assert_eq!(serde_json::to_value(&state).unwrap(), value);
}

#[test]
fn window_start_e2ee_epoch_matches_its_schema_order() {
    let epoch = WindowStartE2eeEpoch {
        epoch: 4,
        key_ref: "ak:mls:epoch:4".to_owned(),
    };
    epoch.validate().unwrap();
    // The `oneOf` puts the object branch second; its `properties` order is the
    // declaration order this type must match.
    assert_field_order(
        &epoch,
        ACCOUNT_FRAME,
        &["$defs", "state_at_window_start", "properties", "e2ee_epoch"],
    );
}

#[test]
fn realm_summary_and_unread_counts_match_their_schema_shapes_and_order() {
    let summary: AccountSubscribeRealmSummary = round_trip(
        ACCOUNT_FRAME,
        "#/$defs/realm_summary",
        json!({
            "joined_member_count": 5,
            "invited_member_count": 2,
            "hero_ids": [actor("ak:did_core:web:alice.example")],
        }),
    );
    summary.validate().unwrap();
    assert_field_order(&summary, ACCOUNT_FRAME, &["$defs", "realm_summary"]);

    let counts: AccountSubscribeUnreadCounts = round_trip(
        ACCOUNT_FRAME,
        "#/$defs/unread_notification_counts",
        json!({"notification_count": 3, "highlight_count": 1}),
    );
    assert_field_order(
        &counts,
        ACCOUNT_FRAME,
        &["$defs", "unread_notification_counts"],
    );
}

#[test]
fn window_start_metadata_rejects_a_retired_collaboration_role() {
    assert!(
        serde_json::from_value::<WindowStartRealmMetadata>(json!({
            "collaboration_role": "broadcast"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<WindowStartActorProfile>(json!({
            "actor_id": actor("ak:did_core:web:alice.example"),
            "handle": "alice",
        }))
        .is_err(),
        "a naked handle string is not a window-start profile member",
    );
}

// ---------------------------------------------------------------------------
// Typed current results
// ---------------------------------------------------------------------------

#[test]
fn account_current_result_matches_its_schema_shape_and_order() {
    let current: AccountCurrentResult = round_trip(
        ACCOUNT_CURRENT,
        "#/$defs/current",
        json!({
            "realm_id": REALM_A,
            "authority_generation": 2,
            "stream_heads": [realm_stream_head(REALM_A)],
            "entries": [{
                "selector": {"kind": "realm_profile", "realm_id": REALM_A},
                "revision": {"commit_id": COMMIT_A, "stream_position": 12},
                "value": {"title": "Design"},
            }],
        }),
    );
    current.validate().unwrap();
    assert_field_order(&current, ACCOUNT_CURRENT, &["$defs", "current"]);
}

#[test]
fn account_current_result_refuses_two_values_for_one_selector() {
    let entry = json!({
        "selector": {"kind": "realm_profile", "realm_id": REALM_A},
        "revision": {"commit_id": COMMIT_A, "stream_position": 12},
        "value": {"title": "Design"},
    });
    let current: AccountCurrentResult = serde_json::from_value(json!({
        "realm_id": REALM_A,
        "authority_generation": 2,
        "stream_heads": [],
        "entries": [entry.clone(), entry],
    }))
    .unwrap();
    assert!(
        current
            .validate()
            .unwrap_err()
            .to_string()
            .contains("repeats a domain selector")
    );
}

#[test]
fn current_coverage_is_per_stream_and_never_a_single_position() {
    let coverage: AccountCurrentCoverage = round_trip(
        ACCOUNT_CURRENT,
        "#/$defs/coverage",
        json!({
            "realm_id": REALM_A,
            "stream_heads": [
                realm_stream_head(REALM_A),
                {
                    "stream_ref": {
                        "kind": "circle",
                        "realm_id": REALM_A,
                        "circle_id": REALM_B.replace("ak:realm:", "ak:circle:"),
                    },
                    "stream_position": 3,
                    "commit_id": COMMIT_A,
                },
            ],
            "complete_for_authorized_streams": false,
        }),
    );
    coverage.validate().unwrap();
    assert_eq!(coverage.stream_heads.len(), 2);
    assert_field_order(&coverage, ACCOUNT_CURRENT, &["$defs", "coverage"]);

    // Two heads for one stream is two answers to a single-valued question.
    let repeated: AccountCurrentCoverage = serde_json::from_value(json!({
        "realm_id": REALM_A,
        "stream_heads": [realm_stream_head(REALM_A), realm_stream_head(REALM_A)],
        "complete_for_authorized_streams": true,
    }))
    .unwrap();
    assert!(repeated.validate().is_err());
}

// ---------------------------------------------------------------------------
// Account frame composition
// ---------------------------------------------------------------------------

#[test]
fn account_frame_field_order_matches_the_schema() {
    let frame: AccountSubscribeFrame = serde_json::from_value(json!({
        "kind": "delta",
        "cursor": "ak:cursor:abc",
        "realms": {},
        "to_device": {"messages": []},
        "device_lists": {"changed_ids": [], "left_ids": []},
        "account_data": {"events": []},
        "notifications": {"items": []},
        "partial": false,
        "priority": "high",
        "realm_list": {
            "snapshot_cursor": "ak:cursor:abc",
            "snapshot_revision": 1,
            "items": [],
        },
        "realm_list_changes": {"upserts": [], "removals": []},
        "baseline": {
            "snapshot_cursor": "ak:cursor:abc",
            "channels": ["station_cas"],
            "completed_channels": [],
        },
        "realm_invalidations": [{"realm_id": REALM_A, "revision": 1}],
    }))
    .unwrap();
    // `reconnect_after_ms` is absent above because a `delta` may not carry it;
    // the schema order is asserted against the populated members only.
    let expected = members_at(&schema_text(ACCOUNT_FRAME), &["properties"])
        .into_iter()
        .filter(|key| key != "reconnect_after_ms")
        .collect::<Vec<_>>();
    assert_eq!(declaration_order(&frame), expected);
}

#[test]
fn realm_sync_entry_field_order_matches_the_schema() {
    let entry = RealmSyncEntry {
        timeline: Some(RealmTimeline {
            commits: Vec::new(),
            limited: false,
            prev_cursor: Some("ak:cursor:abc".to_owned()),
            preview_only: Some(false),
        }),
        timeline_baseline: Some(
            serde_json::from_value(json!({
                "snapshot_cursor": "ak:cursor:abc",
                "window_limit": 20,
                "complete": true,
            }))
            .unwrap(),
        ),
        state_at_window_start: Some(
            serde_json::from_value(json!({
                "actor_profiles": [],
                "realm_metadata": {},
                "e2ee_epoch": null,
            }))
            .unwrap(),
        ),
        current: Some(
            serde_json::from_value(json!({
                "realm_id": REALM_A,
                "authority_generation": 1,
                "stream_heads": [],
                "entries": [],
            }))
            .unwrap(),
        ),
        account_data: Some(serde_json::from_value(json!({"events": []})).unwrap()),
        summary: Some(serde_json::from_value(json!({"joined_member_count": 1})).unwrap()),
        member_roster: Some(json!({"entries": [], "limited": false})),
        unread_notifications: Some(
            serde_json::from_value(json!({"notification_count": 0})).unwrap(),
        ),
        event_states: Some(vec![
            serde_json::from_value::<RealmSyncEventState>(json!({
                "event_id": EVENT_A,
                "event_state": "control_committed",
            }))
            .unwrap(),
        ]),
        baseline: Some(
            serde_json::from_value(json!({
                "snapshot_cursor": "ak:cursor:abc",
                "cut_revision": 1,
                "coverage": {
                    "realm_id": REALM_A,
                    "stream_heads": [],
                    "complete_for_authorized_streams": true,
                },
                "complete": true,
            }))
            .unwrap(),
        ),
        unavailable: None,
    };
    let expected = members_at(
        &schema_text(ACCOUNT_FRAME),
        &["$defs", "realm_sync_entry", "properties"],
    )
    .into_iter()
    .filter(|key| key != "unavailable")
    .collect::<Vec<_>>();
    assert_eq!(declaration_order(&entry), expected);
}

#[test]
fn realm_sync_event_state_matches_its_schema_shape() {
    let state: RealmSyncEventState = round_trip(
        ACCOUNT_FRAME,
        "#/$defs/realm_sync_entry/properties/event_states/items",
        json!({
            "event_id": EVENT_A,
            "event_state": "fork_quarantine",
            "event_state_reason_code": "conflicting_commit",
        }),
    );
    assert_field_order(
        &state,
        ACCOUNT_FRAME,
        &[
            "$defs",
            "realm_sync_entry",
            "properties",
            "event_states",
            "items",
        ],
    );
}

// ---------------------------------------------------------------------------
// Events subscribe frames
// ---------------------------------------------------------------------------

#[test]
fn events_frame_top_level_order_matches_the_schema() {
    let frame = EventsSubscribeFrame {
        kind: EventsSubscribeFrameKind::Dropped,
        realm_id: Some(REALM_A.parse().unwrap()),
        cursor: Some("ak:cursor:abc".to_owned()),
        payload: None,
        reconnect_after_ms: Some(1_000),
    };
    frame.validate().unwrap();
    let expected = members_at(&schema_text(EVENTS_FRAME), &["properties"])
        .into_iter()
        .filter(|key| key != "payload")
        .collect::<Vec<_>>();
    assert_eq!(declaration_order(&frame), expected);
}

#[test]
fn epoch_rotation_payload_matches_its_schema_shape() {
    let payload: EpochRotationPayload = round_trip(
        EVENTS_FRAME,
        "#/$defs/epoch_rotation_payload",
        json!({"new_epoch": 9}),
    );
    assert_eq!(payload.new_epoch, 9);
    assert_field_order(&payload, EVENTS_FRAME, &["$defs", "epoch_rotation_payload"]);
}

#[test]
fn every_events_control_frame_is_accepted_by_the_schema_and_the_type() {
    for value in [
        json!({"kind": "checkpoint", "cursor": "ak:cursor:abc"}),
        json!({"kind": "catchup_complete", "cursor": "ak:cursor:abc"}),
        json!({"kind": "heartbeat"}),
        json!({
            "kind": "epoch_rotation",
            "realm_id": REALM_A,
            "payload": {"new_epoch": 3},
        }),
        json!({"kind": "dropped", "realm_id": REALM_A, "cursor": "ak:cursor:abc"}),
        json!({"kind": "resync_required", "reconnect_after_ms": 2000}),
        json!({"kind": "unauthorized"}),
    ] {
        validate_document(EVENTS_FRAME, &value);
        let frame = EventsSubscribeFrame::from_ndjson_line(&value.to_string())
            .unwrap_or_else(|error| panic!("{value}: {error}"))
            .expect("a non-blank line yields a frame");
        assert_eq!(serde_json::to_value(&frame).unwrap(), value);
    }
}

#[test]
fn the_type_refuses_every_shape_the_schema_refuses() {
    for value in [
        // heartbeat carries no coordinate at all
        json!({"kind": "heartbeat", "cursor": "ak:cursor:abc"}),
        json!({"kind": "heartbeat", "realm_id": REALM_A}),
        // checkpoint has no payload and no reconnect delay
        json!({"kind": "checkpoint", "cursor": "ak:cursor:abc", "reconnect_after_ms": 10}),
        // an event frame needs its Realm, cursor and payload together
        json!({"kind": "event", "realm_id": REALM_A}),
        json!({"kind": "event", "cursor": "ak:cursor:abc"}),
        // epoch_rotation is positionless
        json!({
            "kind": "epoch_rotation",
            "realm_id": REALM_A,
            "cursor": "ak:cursor:abc",
            "payload": {"new_epoch": 3},
        }),
        // resync_required has no resumable position
        json!({"kind": "resync_required", "cursor": "ak:cursor:abc"}),
        // unauthorized is not retryable by delay
        json!({"kind": "unauthorized", "reconnect_after_ms": 10}),
        // dropped must name the Realm whose frames were lost
        json!({"kind": "dropped", "cursor": "ak:cursor:abc"}),
    ] {
        assert!(
            EventsSubscribeFrame::from_ndjson_line(&value.to_string()).is_err(),
            "{value} must be rejected",
        );
    }
}

#[test]
fn a_dropped_frame_keeps_its_own_realm_and_cursor() {
    let frame = EventsSubscribeFrame::from_ndjson_line(
        &json!({"kind": "dropped", "realm_id": REALM_A, "cursor": "ak:cursor:abc"}).to_string(),
    )
    .unwrap()
    .unwrap();
    let interrupt = frame.interrupt().unwrap().expect("dropped is terminal");
    let rendered = format!("{interrupt:?}");
    assert!(rendered.contains(REALM_A), "{rendered}");
    assert!(rendered.contains("ak:cursor:abc"), "{rendered}");
}

#[test]
fn the_events_trace_refuses_a_frame_after_a_terminal_one() {
    let mut trace = EventsStreamTrace::new(false, None);
    let dropped = EventsSubscribeFrame::from_ndjson_line(
        &json!({"kind": "dropped", "realm_id": REALM_A, "cursor": "ak:cursor:abc"}).to_string(),
    )
    .unwrap()
    .unwrap();
    trace.push(&dropped).unwrap();
    assert!(trace.is_terminal());
    assert_eq!(trace.resume_cursor(), Some("ak:cursor:abc"));

    let heartbeat =
        EventsSubscribeFrame::from_ndjson_line(&json!({"kind": "heartbeat"}).to_string())
            .unwrap()
            .unwrap();
    assert!(trace.push(&heartbeat).is_err());
}

#[test]
fn catchup_complete_requires_replayed_data_first() {
    let mut trace = EventsStreamTrace::new(true, Some("ak:cursor:abc".to_owned()));
    let complete = EventsSubscribeFrame::from_ndjson_line(
        &json!({"kind": "catchup_complete", "cursor": "ak:cursor:def"}).to_string(),
    )
    .unwrap()
    .unwrap();
    assert!(trace.push(&complete).is_err());
}

// ---------------------------------------------------------------------------
// WebSocket frames
// ---------------------------------------------------------------------------

#[test]
fn websocket_welcome_limits_match_the_schema_order() {
    let limits = WebSocketConnectionLimits {
        max_frame_bytes: 65_536,
        max_channels: 4,
        max_connection_pending_bytes: 1_048_576,
        max_channel_pending_bytes: 262_144,
        max_connection_pending_frames: 256,
        max_channel_pending_frames: 64,
        heartbeat_interval_ms: 30_000,
    };
    limits.validate().unwrap();
    let expected = members_at(
        &schema_text(WEBSOCKET_FRAME),
        &["$defs", "welcome", "properties"],
    )
    .into_iter()
    .filter(|key| !matches!(key.as_str(), "kind" | "connection_id" | "auth_expires_at"))
    .collect::<Vec<_>>();
    assert_eq!(declaration_order(&limits), expected);
}

#[test]
fn websocket_welcome_frame_validates_against_the_schema() {
    let value = json!({
        "kind": "welcome",
        "connection_id": "conn-0000000000000001",
        "max_frame_bytes": 65536,
        "max_channels": 4,
        "max_connection_pending_bytes": 1048576,
        "max_channel_pending_bytes": 262144,
        "max_connection_pending_frames": 256,
        "max_channel_pending_frames": 64,
        "heartbeat_interval_ms": 30000,
        "auth_expires_at": "2026-09-16T12:00:00.000Z",
    });
    validate_fragment(WEBSOCKET_FRAME, "#/$defs/welcome", &value);
    let frame: WebSocketServerFrame = serde_json::from_value(value.clone()).unwrap();
    frame.validate().unwrap();
    assert_eq!(serde_json::to_value(&frame).unwrap(), value);
}

#[test]
fn websocket_connection_drain_matches_its_schema_shape_and_order() {
    let value = json!({
        "kind": "drain",
        "reconnect_after_ms": 2500,
        "deadline": "2026-09-16T12:00:00.000Z",
        "reason": "rotation",
    });
    validate_fragment(WEBSOCKET_FRAME, "#/$defs/connection_drain_payload", &value);
    let payload: WebSocketConnectionDrainPayload = serde_json::from_value(value.clone()).unwrap();
    payload.validate().unwrap();
    assert_eq!(serde_json::to_value(&payload).unwrap(), value);
    assert_field_order(
        &payload,
        WEBSOCKET_FRAME,
        &["$defs", "connection_drain_payload"],
    );
}

#[test]
fn websocket_events_open_parameters_match_their_schema_shape_and_order() {
    let value = json!({
        "realm_ids": [REALM_A],
        "actor_ids": [actor("ak:did_core:web:alice.example")],
        "after": "ak:cursor:abc",
        "catchup": true,
    });
    validate_fragment(WEBSOCKET_FRAME, "#/$defs/events_open_parameters", &value);
    let parameters: WebSocketEventsOpenParameters = serde_json::from_value(value.clone()).unwrap();
    parameters.validate().unwrap();
    assert_eq!(serde_json::to_value(&parameters).unwrap(), value);
    assert_field_order(
        &parameters,
        WEBSOCKET_FRAME,
        &["$defs", "events_open_parameters"],
    );
}

#[test]
fn websocket_account_open_parameters_keep_the_wait_for_branch_order() {
    let parameters = WebSocketAccountOpenParameters {
        after: Some("ak:cursor:abc".to_owned()),
        catchup: Some(true),
        filter: Some(serde_json::from_value(json!({"timeline_limit": 20})).unwrap()),
        wait_for: Some("ak:cursor:def".to_owned()),
        realm_list: Some(serde_json::from_value(json!({"limit": 20})).unwrap()),
        replace_filter: Some(true),
    };
    parameters.validate().unwrap();
    // `account_open_parameters` is a `oneOf` array, so the branch cannot be
    // reached by member name. Slice the raw text at the branch that declares
    // `wait_for` and read that branch's own `properties` order.
    let text = schema_text(WEBSOCKET_FRAME);
    let branch_start = text
        .find("\"wait_for\"")
        .expect("the wait_for branch must exist");
    let properties_start = text[..branch_start]
        .rfind("\"properties\"")
        .expect("the branch declares properties");
    let object_start = properties_start
        + text[properties_start..]
            .find('{')
            .expect("properties is an object");
    let branch_properties = object_members(text.as_bytes(), object_start)
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    assert_eq!(declaration_order(&parameters), branch_properties);
}

#[test]
fn websocket_client_open_frame_validates_against_the_schema() {
    let value = json!({
        "kind": "open",
        "channel_id": "events-1",
        "operation_id": "ak.self.events.stream.subscribe.v1",
        "parameters": {"realm_ids": [REALM_A]},
    });
    validate_fragment(WEBSOCKET_FRAME, "#/$defs/open_events", &value);
    let frame: WebSocketClientFrame = serde_json::from_value(value.clone()).unwrap();
    frame.validate().unwrap();
    assert_eq!(serde_json::to_value(&frame).unwrap(), value);
}

#[test]
fn websocket_signal_channel_takes_no_parameters() {
    let value = json!({
        "kind": "open",
        "channel_id": "signal-1",
        "operation_id": "ak.self.signal.stream.subscribe.v1",
        "parameters": {},
    });
    validate_fragment(WEBSOCKET_FRAME, "#/$defs/open_signal", &value);
    let frame: WebSocketClientFrame = serde_json::from_value(value.clone()).unwrap();
    frame.validate().unwrap();
    assert_eq!(serde_json::to_value(&frame).unwrap(), value);
}

// ---------------------------------------------------------------------------
// The removed vocabulary must stay removed
// ---------------------------------------------------------------------------

#[test]
fn no_sync_schema_reintroduces_a_removed_coordinate() {
    for file in [
        ACCOUNT_FRAME,
        EVENTS_FRAME,
        WEBSOCKET_FRAME,
        ACCOUNT_CURRENT,
    ] {
        let text = schema_text(file);
        for removed in [
            "\"frontier\"",
            "\"seal_ref\"",
            "\"seal_id\"",
            "\"cell_ref\"",
            "\"actor_seq\"",
            "\"policy_root\"",
            "\"state_root\"",
            "\"control_proposal",
            "\"global_position\"",
            "\"realm_position\"",
        ] {
            assert!(
                !text.contains(removed),
                "{file} still declares the removed member {removed}",
            );
        }
    }
}
