//! The `moderation_report` typed current row and the moderation queue View
//! item are judged by both the live Spec schema and the strong SDK types.

use std::fs;

use arkret_models_collaboration::events_payloads::moderation::ModerationReportPayload;
use arkret_models_collaboration::governance::moderation_queue::{
    ModerationQueueItem, ModerationQueueStatus, ModerationQueueVisibility,
};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::{CurrentSelector, EventId, TypedCurrentResult};
use serde_json::{Value, json};

const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const REPORT_EVENT: &str = "ak:event:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0";
const TARGET: &str = "ak:message:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";
const COMMIT: &str = "ak:realm_commit:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq";
const REPORTER: &str = "ak:did_core:web:reporter.example";

fn schema_accepts(file: &str, fragment: Option<&str>, value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value =
        serde_json::from_slice(&fs::read(artifacts.join("schemas").join(file)).unwrap()).unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    let id = format!(
        "test:moderation-report-current-{file}-{}",
        fragment.unwrap_or("root").replace('#', "@")
    );
    registry
        .register_fragment(id.clone(), schema, fragment.unwrap_or("#"))
        .unwrap();
    registry.validate_value(&id, value).is_ok()
}

fn payload() -> Value {
    json!({
        "realm_id": REALM,
        "target_ref": TARGET,
        "report_reason_code": "spam",
        "reporter_id": REPORTER,
        "provenance": "self"
    })
}

fn row() -> Value {
    json!({
        "selector": {"kind": "moderation_report", "event_id": REPORT_EVENT},
        "source_stream_ref": {"kind": "realm", "realm_id": REALM},
        "revision": {"commit_id": COMMIT, "stream_position": 7},
        "value": payload()
    })
}

fn row_accepted_by_both(value: &Value) -> bool {
    let schema = schema_accepts(
        "typed-current-result.schema.json",
        Some("#/$defs/moderation_report_result"),
        value,
    );
    let sdk = serde_json::from_value::<TypedCurrentResult>(value.clone())
        .ok()
        .and_then(|row| match row {
            TypedCurrentResult::Value {
                selector: CurrentSelector::ModerationReport { .. },
                value,
                ..
            } => serde_json::from_value::<ModerationReportPayload>(value).ok(),
            _ => None,
        })
        .is_some();
    assert_eq!(schema, sdk, "schema and SDK disagree on {value}");
    schema
}

#[test]
fn moderation_report_current_row_round_trips_through_strong_types() {
    let value = row();
    assert!(row_accepted_by_both(&value));
    let typed: TypedCurrentResult = serde_json::from_value(value.clone()).unwrap();
    let TypedCurrentResult::Value { selector, .. } = &typed;
    assert_eq!(
        selector,
        &CurrentSelector::ModerationReport {
            event_id: EventId::new(REPORT_EVENT).unwrap(),
        }
    );
    assert_eq!(serde_json::to_value(&typed).unwrap(), value);
}

#[test]
fn moderation_report_selector_drift_is_rejected_by_schema_and_sdk() {
    let mut extra = row();
    extra["selector"]["report_id"] =
        json!("ak:report:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0");
    assert!(!row_accepted_by_both(&extra));

    let mut missing = row();
    missing["selector"]
        .as_object_mut()
        .unwrap()
        .remove("event_id");
    assert!(!row_accepted_by_both(&missing));

    let mut retyped = row();
    retyped["selector"]["event_id"] = json!(TARGET);
    assert!(!row_accepted_by_both(&retyped));

    let mut no_source = row();
    no_source
        .as_object_mut()
        .unwrap()
        .remove("source_stream_ref");
    assert!(!row_accepted_by_both(&no_source));

    let mut open_value = row();
    open_value["value"]["status"] = json!("submitted");
    assert!(!row_accepted_by_both(&open_value));
}

fn queue_item() -> Value {
    json!({
        "id": REPORT_EVENT.replacen("ak:event:", "ak:moderation_queue_item:", 1),
        "report": payload(),
        "status": "submitted",
        "visibility": "plaintext_evidence",
        "created_at": "2026-09-24T00:00:00.000Z"
    })
}

fn queue_item_accepted_by_both(value: &Value) -> bool {
    let schema = schema_accepts("moderation-queue-item.schema.json", None, value);
    let sdk = serde_json::from_value::<ModerationQueueItem>(value.clone()).is_ok();
    assert_eq!(schema, sdk, "schema and SDK disagree on {value}");
    schema
}

#[test]
fn moderation_queue_view_item_is_the_retyped_report_view() {
    let value = queue_item();
    assert!(queue_item_accepted_by_both(&value));
    let item: ModerationQueueItem = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        item.id,
        ModerationQueueItem::id_for_report(&EventId::new(REPORT_EVENT).unwrap())
    );
    assert_eq!(item.status, ModerationQueueStatus::Submitted);
    assert_eq!(
        item.visibility,
        ModerationQueueVisibility::PlaintextEvidence
    );
    assert_eq!(serde_json::to_value(&item).unwrap(), value);
}

#[test]
fn moderation_queue_view_item_drift_is_rejected_by_schema_and_sdk() {
    for (member, drift) in [
        ("status", json!("triaged")),
        ("visibility", json!("public")),
        ("id", json!(REPORT_EVENT)),
        ("assigned_to", json!([REPORTER])),
        ("resolution", json!({"decision": "dismiss"})),
    ] {
        let mut value = queue_item();
        value[member] = drift;
        assert!(!queue_item_accepted_by_both(&value), "{member}");
    }
    let mut wrapped = queue_item();
    wrapped["report"] = json!({"report_event": {"event": {}}});
    assert!(!queue_item_accepted_by_both(&wrapped));
    let mut missing = queue_item();
    missing.as_object_mut().unwrap().remove("created_at");
    assert!(!queue_item_accepted_by_both(&missing));
}
