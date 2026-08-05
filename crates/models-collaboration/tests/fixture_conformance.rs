use std::collections::BTreeMap;

use arkret_canonical::canonical;
use arkret_models_collaboration::events_payloads::MorphSchemaMigratePayload;
use arkret_models_collaboration::http_bodies::{EventsSubscribeFrame, EventsSubscribeFrameKind};
use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame;
use arkret_models_collaboration::sync_frames::stream_trace::{
    StreamTraceFrame, StreamTraceFrameKind, StreamTraceValidator,
};
use arkret_schema::embedded_json_artifact;
use arkret_wire::{Cursor, MorphId};
use serde_json::{Value, json};

#[test]
fn account_subscribe_fixture_cases_match_typed_wire_model() {
    let fixture = embedded_json_artifact("fixtures/sync-fixture.json").unwrap();
    for case in fixture["account_subscribe_schema_cases"]
        .as_array()
        .unwrap()
    {
        let line = serde_json::to_string(&case["instance"]).unwrap();
        let accepted = AccountSubscribeFrame::from_ndjson_line(&line).is_ok();
        assert_eq!(
            accepted,
            case["expect_valid"].as_bool().unwrap(),
            "fixture case {} drifted",
            case["name"]
        );
    }
}

#[test]
fn morph_transformation_fixture_executes_all_registered_rules() {
    let fixture = embedded_json_artifact("fixtures/morph-schema-migration-fixture.json").unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let input = &vector["input"];
        let payload = &input["payload"];
        let migrate = MorphSchemaMigratePayload {
            morph_id: MorphId::new("ak:morph:0196419b-0000-8000-8000-000000000001").unwrap(),
            from_schema_refs: serde_json::from_value(payload["from_schema_refs"].clone()).unwrap(),
            to_schema_refs: serde_json::from_value(payload["to_schema_refs"].clone()).unwrap(),
            compatibility_class: payload["compatibility_class"].as_str().unwrap().to_owned(),
            transformation_rules: Some(
                serde_json::from_value(payload["transformation_rules"].clone()).unwrap(),
            ),
            migration_evidence: None,
        };
        let fields: BTreeMap<String, Value> =
            serde_json::from_value(input["fields"].clone()).unwrap();
        let output = migrate
            .apply_transformation(&fields)
            .unwrap_or_else(|error| panic!("{} failed: {error}", vector["vector_id"]));
        assert_eq!(
            serde_json::to_value(&output).unwrap(),
            vector["expected_output"],
            "{} output drifted",
            vector["vector_id"]
        );
        assert_eq!(
            canonical::canonical_sha256(&output).unwrap(),
            vector["expected_output_digest"].as_str().unwrap(),
            "{} digest drifted",
            vector["vector_id"]
        );
    }
}

#[derive(Clone, Copy)]
enum Surface {
    Account,
    Events,
}

enum SurfaceFrame {
    Account(Box<AccountSubscribeFrame>),
    Events(EventsSubscribeFrame),
}

impl StreamTraceFrame for SurfaceFrame {
    fn trace_kind(&self) -> StreamTraceFrameKind {
        match self {
            Self::Account(frame) => frame.trace_kind(),
            Self::Events(frame) => frame.trace_kind(),
        }
    }

    fn trace_cursor(&self) -> Option<&str> {
        match self {
            Self::Account(frame) => frame.trace_cursor(),
            Self::Events(frame) => frame.trace_cursor(),
        }
    }
}

fn surface_frame(surface: Surface, value: &Value) -> SurfaceFrame {
    match surface {
        Surface::Account => {
            SurfaceFrame::Account(Box::new(serde_json::from_value(value.clone()).unwrap()))
        }
        Surface::Events => {
            let kind = match value["kind"].as_str().unwrap() {
                "delta" => EventsSubscribeFrameKind::Event,
                "frontier" => EventsSubscribeFrameKind::Frontier,
                "heartbeat" => EventsSubscribeFrameKind::Heartbeat,
                "catchup_complete" => EventsSubscribeFrameKind::CatchupComplete,
                "dropped" => EventsSubscribeFrameKind::Dropped,
                "resync_required" => EventsSubscribeFrameKind::ResyncRequired,
                "unauthorized" => EventsSubscribeFrameKind::Unauthorized,
                other => panic!("unknown fixture frame kind {other}"),
            };
            SurfaceFrame::Events(EventsSubscribeFrame {
                kind,
                realm_id: None,
                cursor: value["cursor"]
                    .as_str()
                    .map(|cursor| Cursor::new(cursor.to_owned()).unwrap()),
                payload: None,
                reconnect_after_ms: value["reconnect_after_ms"].as_u64(),
            })
        }
    }
}

#[test]
fn registered_stream_sequence_vector_applies_to_both_surfaces() {
    let fixture = embedded_json_artifact("fixtures/sync-fixture.json").unwrap();
    let vector = &fixture["stream_frame_sequence"];
    assert_eq!(
        vector["vector_id"].as_str(),
        Some("ak.vector.sync.stream_frame_sequence.v1")
    );

    for surface in [Surface::Account, Surface::Events] {
        for case in vector["cases"].as_array().unwrap() {
            let catchup = case["request"]["catchup"].as_bool().unwrap();
            let initial_cursor = case["initial_reconnect_cursor"]
                .as_str()
                .map(ToOwned::to_owned);

            if case["name"] == "missing_drop_cursor_uses_resync_required" {
                let mut rejected = StreamTraceValidator::new(catchup, initial_cursor.clone());
                let error = rejected
                    .push(&surface_frame(surface, &case["forbidden_frame"]))
                    .unwrap_err();
                assert_eq!(error.violation(), "dropped_missing_cursor");

                let mut required = StreamTraceValidator::new(catchup, initial_cursor);
                let update = required
                    .push(&surface_frame(surface, &case["required_frame"]))
                    .unwrap();
                assert!(update.terminal);
                assert!(!update.cursor_advanced);
                assert!(required.reconnect_cursor().is_none());
                continue;
            }

            let mut validator = StreamTraceValidator::new(catchup, initial_cursor);
            let mut rejection = None;
            for frame in case["frames"].as_array().unwrap() {
                if let Err(error) = validator.push(&surface_frame(surface, frame)) {
                    rejection = Some(error);
                    break;
                }
            }

            if case["expected"]["result"] == "reject" {
                let error = rejection.expect("invalid trace must be rejected");
                assert_eq!(
                    error.violation(),
                    case["expected"]["trace_violation"].as_str().unwrap()
                );
                assert!(
                    validator
                        .push(&surface_frame(surface, &json!({"kind": "heartbeat"})))
                        .is_err()
                );
                continue;
            }

            assert!(rejection.is_none());
            validator.finish().unwrap();
            if let Some(expected_cursor) = case["expected"]["reconnect_after"].as_str() {
                assert_eq!(validator.reconnect_cursor(), Some(expected_cursor));
            }
            if case["expected"]["reconnect_cursor_advanced"] == false {
                assert!(validator.reconnect_cursor().is_none());
            }
        }
    }
}
