use arkret_models_collaboration::history_key::{
    HistoryKeyResponseAckRequest, HistoryKeyResponseListOutcome, HistoryKeyResponseSendReceipt,
    HistoryKeyResponseSendRequest,
};
use arkret_models_collaboration::http_bodies::{EventsSubscribeFrame, EventsSubscribeFrameKind};
use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame;
use arkret_models_collaboration::sync_frames::stream_trace::{
    StreamTraceFrame, StreamTraceFrameKind, StreamTraceValidator,
};
use arkret_schema::embedded_json_artifact;
use arkret_wire::Cursor;
use serde_json::{Value, json};

#[test]
fn history_response_stream_fixture_uses_production_wire_helpers() {
    let fixture = embedded_json_artifact("fixtures/history-key-recovery-fixture.json").unwrap();
    let kat = &fixture["response_stream_cases"];
    let send: HistoryKeyResponseSendRequest =
        serde_json::from_value(kat["wire_instances"]["manifest_send"].clone()).unwrap();
    send.validate().unwrap();
    let receipt: HistoryKeyResponseSendReceipt =
        serde_json::from_value(kat["wire_instances"]["first_send_receipt"].clone()).unwrap();
    receipt.validate().unwrap();
    assert_eq!(
        receipt.source_record_digest,
        send.source_record_digest().unwrap()
    );

    let list: HistoryKeyResponseListOutcome =
        serde_json::from_value(kat["wire_instances"]["sequence_ordered_list"].clone()).unwrap();
    list.validate().unwrap();
    let ack: HistoryKeyResponseAckRequest =
        serde_json::from_value(kat["wire_instances"]["ack_request"].clone()).unwrap();
    ack.validate().unwrap();
    let out_of_order: HistoryKeyResponseAckRequest =
        serde_json::from_value(kat["negative_cases"][2]["input"].clone()).unwrap();
    assert!(out_of_order.validate().is_err());

    let first = arkret_wire::base64url::base64url_decode(
        kat["byte_exact"]["first_receipt_jcs_b64u"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let retry = arkret_wire::base64url::base64url_decode(
        kat["byte_exact"]["exact_retry_receipt_jcs_b64u"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        first,
        arkret_wire::canonical::canonical_json_bytes(&serde_json::to_value(receipt).unwrap())
            .unwrap()
    );
    assert_eq!(retry, first);
}

#[test]
fn history_fresh_endpoint_fixture_executes_deterministic_model() {
    let fixture = embedded_json_artifact("fixtures/history-key-recovery-fixture.json").unwrap();
    let case = fixture["scope_and_endpoint_kats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "standard_fresh_endpoint_floor")
        .unwrap();
    let model = &case["deterministic_model"];
    assert_eq!(model["algorithm"], "ak.standard-fresh-endpoint-model.v1");

    let seed_hex = case["seed_hex"].as_str().unwrap();
    assert_eq!(seed_hex.len() % 2, 0);
    let seed = (0..seed_hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&seed_hex[offset..offset + 2], 16).unwrap())
        .collect::<Vec<_>>();

    let mut admitted = false;
    let mut current_epoch = None;
    let mut decryptable_epochs = Vec::new();
    let mut rejected_epochs = Vec::new();
    for step in model["steps"].as_array().unwrap() {
        let epoch = step["epoch"].as_u64().unwrap();
        match step["operation"].as_str().unwrap() {
            "application_before_admission" => {
                assert!(!admitted);
                assert_eq!(step["result"], "reject");
                rejected_epochs.push(epoch);
            }
            "winning_add_welcome_admission" => {
                assert!(!admitted);
                assert_eq!(step["result"], "admit_and_decrypt");
                admitted = true;
                current_epoch = Some(epoch);
                decryptable_epochs.push(epoch);
            }
            "sequential_commit" => {
                assert!(admitted);
                assert_eq!(step["requires_previous_epoch"].as_u64(), current_epoch);
                assert_eq!(step["result"], "advance_and_decrypt");
                current_epoch = Some(epoch);
                decryptable_epochs.push(epoch);
            }
            operation => panic!("unknown fresh endpoint operation {operation}"),
        }
    }

    let expected_epochs = |name: &str| {
        case["expected"][name]
            .as_array()
            .unwrap()
            .iter()
            .map(|epoch| epoch.as_u64().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(decryptable_epochs, expected_epochs("decryptable_epochs"));
    let expected_rejected_epochs = case["inputs"]["pre_admission_epochs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|epoch| epoch.as_u64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rejected_epochs, expected_rejected_epochs);
    assert_eq!(
        rejected_epochs.len() as u64,
        case["expected"]["rejected_pre_admission_epochs"]
            .as_u64()
            .unwrap()
    );

    for tag in model["transition_tags"].as_array().unwrap() {
        let operation = tag["operation"].as_str().unwrap();
        let epoch = tag["epoch"].as_u64().unwrap();
        let mut preimage = seed.clone();
        preimage.push(0);
        preimage.extend_from_slice(operation.as_bytes());
        preimage.extend_from_slice(&epoch.to_be_bytes());
        assert_eq!(
            arkret_canonical::sha256_hex(preimage),
            tag["sha256_hex"].as_str().unwrap()
        );
    }
}

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
