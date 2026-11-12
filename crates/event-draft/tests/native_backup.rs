use arkret_event_draft::EventSpec;
use arkret_models_collaboration::events_payloads::KeyBackupActiveSeries;
use arkret_wire::event_spec;

#[test]
fn native_series_typed_spec_rejects_programmatic_mixed_authority_and_zero_version() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-content-backup-fixture.json"
    ))
    .unwrap();
    let record: KeyBackupActiveSeries =
        serde_json::from_value(fixture["active_series"].clone()).unwrap();
    <event_spec::KeyBackupActiveSeries as EventSpec>::validate_payload(&record).unwrap();
    let mut bad = record.clone();
    bad.series_pointer_version = 0;
    assert!(<event_spec::KeyBackupActiveSeries as EventSpec>::validate_payload(&bad).is_err());
    let mut bad = record.clone();
    bad.manager_ref = None;
    assert!(<event_spec::KeyBackupActiveSeries as EventSpec>::validate_payload(&bad).is_err());
    let mut bad = record;
    bad.signature_proof.device_authorize_event_id = Some(
        fixture["native_packet"]["signature_proof"]["device_authorize_event_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    );
    assert!(<event_spec::KeyBackupActiveSeries as EventSpec>::validate_payload(&bad).is_err());
}
